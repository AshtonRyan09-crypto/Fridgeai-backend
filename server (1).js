const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();

// ─── Security headers ─────────────────────────────────────────────────────────
// Added manually since we're not using helmet — keeps dependencies minimal
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

// ─── CORS — open for native iOS app ──────────────────────────────────────────
// CORS restrictions only apply in browsers. A native iOS WKWebView app loaded
// from a local bundle doesn't send predictable Origin headers, so strict CORS
// would block your own app. Keeping this open is safe — the API key is the
// secret, and rate limiting is what protects against abuse.
app.use(cors());

// ─── Body parsing — cap at 10MB (large enough for images, blocks abuse) ───────
app.use(express.json({ limit: "10mb" }));

// ─── API key ──────────────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ─── Rate limiters ────────────────────────────────────────────────────────────

// Auth limiter — 5 attempts per 15 minutes per IP (brute force protection)
// Applied to any future /api/auth endpoint
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // only count failed attempts
  message: { error: "Too many login attempts. Please wait 15 minutes and try again." },
});

// General Claude limiter — 60 requests per 15 minutes per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please wait a few minutes and try again." },
});

// Scan limiter — 20 scans per hour per IP (each scan costs ~$0.03)
const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Scan limit reached. You can do 20 scans per hour. Please try again later." },
});

// ─── Input validation helpers ─────────────────────────────────────────────────

// Allowed Claude model names — reject anything else to prevent prompt injection
const ALLOWED_MODELS = [
  "claude-sonnet-4-6",
  "claude-sonnet-4-20250514",
  "claude-haiku-4-5-20251001",
];

// Validate and sanitize the request body before forwarding to Anthropic.
// Returns an error string if invalid, null if OK.
function validateClaudeBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "Request body must be a JSON object.";
  }

  // Model must be one of the allowed list
  if (!body.model || !ALLOWED_MODELS.includes(body.model)) {
    return `Invalid model. Allowed: ${ALLOWED_MODELS.join(", ")}`;
  }

  // max_tokens must be a reasonable number
  const tokens = body.max_tokens;
  if (typeof tokens !== "number" || tokens < 1 || tokens > 8096) {
    return "max_tokens must be between 1 and 8096.";
  }

  // messages must be a non-empty array
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    return "messages must be a non-empty array.";
  }

  // Cap at 20 messages to prevent prompt stuffing
  if (body.messages.length > 20) {
    return "Too many messages in request.";
  }

  // Each message must have a valid role and content
  for (const msg of body.messages) {
    if (!["user", "assistant"].includes(msg.role)) {
      return "Each message must have role 'user' or 'assistant'.";
    }
    if (!msg.content) {
      return "Each message must have content.";
    }
  }

  return null; // all good
}

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ status: "Crisper AI API running", version: "1.0.0" });
});

// ─── Main Claude proxy endpoint ───────────────────────────────────────────────
app.post("/api/claude", generalLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: "Server not configured — API key missing." });
  }

  // Validate input before touching Anthropic
  const validationError = validateClaudeBody(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
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
    console.error("Proxy error:", err.message);
    res.status(500).json({ error: "Request failed. Please try again." });
  }
});

// ─── Scan endpoint (stricter rate limit + image validation) ───────────────────
app.post("/api/scan", scanLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: "Server not configured — API key missing." });
  }

  const validationError = validateClaudeBody(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  // Extra check: scan endpoint must include an image
  const hasImage = req.body.messages?.some(m =>
    Array.isArray(m.content) && m.content.some(c => c.type === "image")
  );
  if (!hasImage) {
    return res.status(400).json({ error: "Scan endpoint requires an image in the request." });
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
    console.error("Scan error:", err.message);
    res.status(500).json({ error: "Scan failed. Please try again." });
  }
});

// ─── Auth proxy endpoint (strictest rate limit) ───────────────────────────────
// If you ever proxy auth calls through Railway, they go here.
// Currently Supabase auth is called directly from the client — this is a
// placeholder that protects any future auth endpoints.
app.post("/api/auth", authLimiter, (req, res) => {
  res.status(501).json({ error: "Auth is handled directly via Supabase." });
});

// ─── 404 catch-all ────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found." });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Internal server error." });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Crisper AI backend running on port ${PORT}`);
});
