const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json({ limit: "20mb" })); // large enough for base64 images
app.use(cors());

// ─── Your Anthropic API key — set this in Railway/Render as an env variable ──
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

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

// Auth limit — 5 attempts per 15 minutes per IP (brute force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  skipSuccessfulRequests: true, // only failed attempts count toward the limit
  message: { error: "Too many login attempts. Please wait 15 minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
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

  // Basic input validation — reject malformed or oversized requests
  const { model, messages, max_tokens } = req.body || {};
  const ALLOWED_MODELS = ["claude-sonnet-4-6", "claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"];
  if (!model || !ALLOWED_MODELS.includes(model)) {
    return res.status(400).json({ error: "Invalid model." });
  }
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 20) {
    return res.status(400).json({ error: "messages must be an array of 1–20 items." });
  }
  if (typeof max_tokens !== "number" || max_tokens < 1 || max_tokens > 8096) {
    return res.status(400).json({ error: "max_tokens must be between 1 and 8096." });
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

  // Basic input validation
  const { model, messages, max_tokens } = req.body || {};
  const ALLOWED_MODELS = ["claude-sonnet-4-6", "claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"];
  if (!model || !ALLOWED_MODELS.includes(model)) {
    return res.status(400).json({ error: "Invalid model." });
  }
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 20) {
    return res.status(400).json({ error: "messages must be an array of 1–20 items." });
  }
  if (typeof max_tokens !== "number" || max_tokens < 1 || max_tokens > 8096) {
    return res.status(400).json({ error: "max_tokens must be between 1 and 8096." });
  }
  // Scan endpoint must include an image
  const hasImage = messages.some(m =>
    Array.isArray(m.content) && m.content.some(c => c.type === "image")
  );
  if (!hasImage) {
    return res.status(400).json({ error: "Scan endpoint requires an image." });
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
