# The safe version of vulnerable/app.py. The threadai scanner must report nothing here
# (the AI audit may still find design issues a line scanner cannot, e.g. missing authz).
import hashlib
import hmac
import json
import logging
import os
import secrets
import subprocess
import tempfile

import jwt
import requests
import yaml
from defusedxml import ElementTree as SafeXml
from flask import Flask, request
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/srv/app/uploads"
SECRET_KEY = os.environ["SECRET_KEY"]
DEBUG = os.environ.get("DEBUG") == "1"


@app.route("/load")
def load():
    return json.loads(request.data)


@app.route("/config")
def config():
    return yaml.safe_load(request.data)


@app.route("/thumb")
def thumb():
    # secure_filename strips paths and ImageMagick prefixes like "@" or "url:",
    # and the absolute base dir means the argument is always a plain local file.
    name = secure_filename(request.args["name"])
    if not name:
        return "invalid filename", 400
    subprocess.run(["convert", os.path.join(UPLOAD_DIR, name), "out.png"], check=True)
    os.system("clear")


@app.route("/hello")
def hello():
    return f"<p>Hello {escape(request.args['name'])}</p>"


def new_reset_token():
    return secrets.token_urlsafe(32)


def scratch_file():
    return tempfile.NamedTemporaryFile(delete=False).name


def read_claims(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])


@app.route("/xml")
def parse_xml():
    return SafeXml.fromstring(request.data).tag


def delete_everything(user):
    if not user.is_admin:
        raise PermissionError("admins only")


def store_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def file_checksum(data):
    return hashlib.sha256(data).hexdigest()


def call_partner(url):
    return requests.get(url, timeout=5, verify="/etc/ssl/partner-ca.pem")


def find_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


def check_token(provided_token, stored_token):
    return hmac.compare_digest(provided_token, stored_token)


def open_uploads():
    os.chmod("/srv/app/uploads", 0o750)


def login(username, password):
    logging.info("login attempt for %s", username)
