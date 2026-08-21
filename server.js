const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json({ limit: "20mb" })); // large enough for base64 images
app.use(cors());

// ─── Your Anthropic API key — set this in Railway/Render as an env variable ──
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ─── App gate — set APPGATE in Railway environment variables ──────────────────
// Trimmed: a trailing space or newline on the Railway variable is invisible in
// the dashboard but makes every single request fail with 401.
const APPGATE = (process.env.APPGATE || "").trim();

// Short fingerprint for log lines — shows enough to compare two values without
// ever writing the secret itself into the logs.
const fingerprint = (s) =>
  s ? `${s.slice(0, 4)}…${s.slice(-4)}(len=${s.length})` : "<empty>";

// Fail closed. The previous `if (APPGATE && ...)` check silently disabled the
// gate whenever the variable was missing, leaving the paid proxy wide open.
if (!APPGATE) {
  console.error(
    "FATAL: APPGATE is not set (or is only whitespace). Refusing to start " +
    "rather than run an unauthenticated proxy to a paid API."
  );
  process.exit(1);
}
console.log(`APPGATE loaded: ${fingerprint(APPGATE)}`);

// ─── Rate limiting ────────────────────────────────────────────────────────────
// This stops any single user from spamming the API and running up your bill.
//
// How it works:
//   - Each user's IP address gets a counter
//   - If they make more than the allowed number of requests in the time window,
//     they get a 429 "Too Many Requests" error until the window resets
//   - Legitimate users will never hit these limits in normal use
//   - A bad actor trying to abuse your key gets blocked automatically

// General limit — 60 requests per 15 minutes per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60,
  message: { error: "Too many requests. Please wait a few minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Scan limit — 20 scans per hour per IP (scans are expensive, ~$0.03 each)
const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: { error: "Scan limit reached. You can do 20 scans per hour. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── App gate middleware — rejects requests without the correct header ─────────
app.use("/api", (req, res, next) => {
  const sent = String(req.headers["x-app-gate"] || "").trim();
  if (sent !== APPGATE) {
    // Logged so a rejection is visible in Railway logs instead of silent. The
    // two fingerprints side by side say whether this is a whitespace problem
    // (same 4+4, different len) or a genuinely different value (different 4+4).
    console.warn(
      `AUTH FAIL ${req.method} ${req.originalUrl} ` +
      `ip=${req.ip} xff=${req.headers["x-forwarded-for"] || "-"} ` +
      `sent=${fingerprint(sent)} expected=${fingerprint(APPGATE)}`
    );
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ status: "FridgeAI API running", version: "1.0.0" });
});

// ─── Main Claude proxy endpoint ───────────────────────────────────────────────
// The app sends requests here instead of directly to Anthropic.
// This server adds the secret API key and forwards the request.
app.post("/api/claude", generalLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: "Server not configured — API key missing." });
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(req.body),
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).json({ error: "Request failed. Please try again." });
  }
});

// ─── Scan-specific endpoint (stricter rate limit) ─────────────────────────────
app.post("/api/scan", scanLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: "Server not configured — API key missing." });
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(req.body),
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).json({ error: "Scan failed. Please try again." });
  }
});

// ─── Start server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FridgeAI backend running on port ${PORT}`);
});
