// The safe version of vulnerable/server.js. ThreadAI must report nothing here.
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const jwt = require("jsonwebtoken");
const { execFile } = require("child_process");

const app = express();
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));

const UPLOAD_DIR = "/srv/app/uploads";

app.get("/thumb", (req, res) => {
  // Plain filename only: blocks ../ traversal and ImageMagick prefixes ("@", "url:", "msl:").
  const name = String(req.query.file || "");
  if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(name)) return res.status(400).send("invalid");
  execFile("convert", [path.join(UPLOAD_DIR, name), "out.png"], () => res.send("ok"));
});

app.get("/me", (req, res) => {
  const claims = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, {
    algorithms: ["HS256"],
  });
  res.json(claims);
});

app.post("/reset", (req, res) => {
  const resetToken = crypto.randomBytes(32).toString("hex");
  res.json({ ok: true, id: resetToken.length });
});

app.get("/login/done", (req, res) => {
  const next = String(req.query.next || "/");
  res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
});

app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  const t = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ t });
});

app.get("/orders/:id", (req, res) => {
  db.query("SELECT * FROM orders WHERE id = $1", [req.params.id], (e, rows) => res.json(rows));
});

function sameSignature(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function fingerprint(data) {
  const m = /^[a-f0-9]+$/.exec(data);
  return m && crypto.createHash("sha256").update(data).digest("hex");
}

app.listen(3000);
