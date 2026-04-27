// Browser-side helpers for the cloud-ops dashboard.
// Intentional security issues for MCPSafe e2e testing.

const jwt = require("jsonwebtoken");
const express = require("express");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());

// MCP-230: JWT verification with algorithms: ["none"]
function verifyToken(token) {
  return jwt.verify(token, "secret", { algorithms: ["none"] });
}

// MCP-231: jwt.sign() issued without an expiry claim
function issueToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    process.env.JWT_KEY,
  );
}

// MCP-234: auth material stored in localStorage / sessionStorage
function persistSession(token, refresh) {
  localStorage.setItem("token", token);
  localStorage.setItem("auth", token);
  sessionStorage.setItem("api_key", refresh);
}

// MCP-235: state-changing routes with cookie session auth and no CSRF middleware
app.post("/provision", async (req, res) => {
  const userId = req.cookies.session;
  await provision(userId, req.body.region, req.body.size);
  res.json({ ok: true });
});

app.delete("/cluster", async (req, res) => {
  const userId = req.cookies.session;
  await deleteCluster(userId, req.body.id);
  res.json({ ok: true });
});

app.put("/iam", async (req, res) => {
  const userId = req.cookies.session;
  await updateIam(userId, req.body);
  res.json({ ok: true });
});

async function provision(_a, _b, _c) {}
async function deleteCluster(_a, _b) {}
async function updateIam(_a, _b) {}

module.exports = { verifyToken, issueToken, persistSession, app };
