// Intentionally vulnerable sample for ThreadAI tests. NEVER deploy this.
// Each `expect:` comment names the rule(s) that must fire on the NEXT line.
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");

const app = express();
// expect: TAI-JS-006
app.use(cors({ origin: true, credentials: true }));
// expect: TAI-CORE-008
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

app.get("/thumb", (req, res) => {
  // expect: TAI-JS-003
  exec(`convert ${req.query.file} out.png`, () => res.send("ok"));
});

app.post("/calc", (req, res) => {
  // expect: TAI-JS-004
  const fn = new Function("a", req.body.code);
  res.json(fn(1));
});

app.get("/me", (req, res) => {
  // expect: TAI-JS-005
  const claims = jwt.decode(req.headers.authorization);
  res.json(claims);
});

app.post("/reset", (req, res) => {
  // expect: TAI-JS-007
  const resetToken = Math.random().toString(36).slice(2);
  res.json({ ok: true, id: resetToken.length });
});

app.get("/login/done", (req, res) => {
  // expect: TAI-JS-008
  res.redirect(req.query.next);
});

app.get("/preview", async (req, res) => {
  // expect: TAI-JS-009
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

app.post("/login", async (req, res) => {
  // expect: TAI-JS-010
  const user = await User.findOne(req.body);
  // expect: TAI-JS-011
  const t = jwt.sign({ id: user.id }, "hardcoded-signing-key");
  res.json({ t });
});

app.get("/orders/:id", (req, res) => {
  // expect: TAI-CORE-010
  db.query("SELECT * FROM orders WHERE id = " + req.params.id, (e, rows) => res.json(rows));
});

function fingerprint(data) {
  // expect: TAI-CORE-006
  return crypto.createHash("md5").update(data).digest("hex");
}

app.listen(3000);
