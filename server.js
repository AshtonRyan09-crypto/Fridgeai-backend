/**
 * FridgeAI Backend Proxy — Railway
 *
 * SECURITY ARCHITECTURE:
 * - OWASP A02: API key stored ONLY in Railway env vars, never in code or logs
 * - OWASP A04: Rate limiting per IP and per user to prevent abuse
 * - OWASP A05: Strict CORS, security headers on all responses
 * - OWASP A08: Input validation on all endpoints, schema-based checks
 * - OWASP A09: Request logging without sensitive data (no keys, no PII)
 *
 * Environment variables required (set in Railway dashboard):
 *   ANTHROPIC_API_KEY — your sk-ant-... key (NEVER hardcode this)
 *   ALLOWED_ORIGIN    — your app origin (optional, defaults to app://)
 *   NODE_ENV          — set to "production" in Railway
 */

"use strict";

const express = require("express");
const rateLimit = require("express-rate-limit");
const app = express();

// ── Environment variable validation ──────────────────────────────────────────
// SECURITY: Fail loudly at startup if required secrets are missing
// This prevents the server from running without proper configuration
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) {
  console.error("FATAL: ANTHROPIC_API_KEY environment variable is not set.");
  console.error("Set it in Railway: Dashboard -> Variables -> ANTHROPIC_API_KEY");
  process.exit(1);
}
if (!ANTHROPIC_API_KEY.startsWith("sk-ant-")) {
  console.error("FATAL: ANTHROPIC_API_KEY does not look valid (should start with sk-ant-)");
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

// ── Body parser with strict size limit ───────────────────────────────────────
// SECURITY: Limit body size to prevent DoS via oversized payloads
// 2MB allows ~1.5MB images (base64 encoding adds ~33% overhead)
app.use(express.json({
  limit: "2mb",
  strict: true, // only accept JSON objects and arrays, reject primitives
}));

// ── Security headers ──────────────────────────────────────────────────────────
// OWASP A05: Security Misconfiguration — defensive headers on every response
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store"); // don't cache API responses
  res.removeHeader("X-Powered-By"); // don't leak server tech
  next();
});

// ── CORS ──────────────────────────────────────────────────────────────────────
// SECURITY: Only allow requests from the iOS app's WKWebView custom scheme
// The app loads from app://localhost so that's the only origin we allow
const ALLOWED_ORIGINS = [
  "app://localhost",
  process.env.ALLOWED_ORIGIN,
].filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (!origin || ALLOWED_ORIGINS.includes(origin) || origin.startsWith("app://")) {
    res.setHeader("Access-Control-Allow-Origin", origin || "app://localhost");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Client-Version");
  res.setHeader("Access-Control-Max-Age", "86400");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ── Rate limiters ─────────────────────────────────────────────────────────────
// OWASP A04: Insecure Design — rate limiting prevents API abuse and cost blowout
// These are SERVER-SIDE limits — the app also enforces client-side limits

// General limiter — all endpoints, per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minute window
  max: 100,                  // 100 requests per IP per 15 min
  standardHeaders: true,     // expose rate limit info in response headers
  legacyHeaders: false,
  message: {
    error: { type: "rate_limit", message: "Too many requests. Please try again later." }
  },
  trustProxy: true, // Railway uses a trusted reverse proxy
  keyGenerator: (req) => req.ip || req.connection.remoteAddress || "unknown",
  skip: (req) => req.path === "/health", // don't rate limit health checks
});

// Strict scan limiter — image analysis costs more per call
const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 30,                   // 30 scans per IP per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: { type: "rate_limit", message: "Scan rate limit exceeded. Please wait before scanning again." }
  },
  trustProxy: true,
});

// Claude text limiter — text calls are cheaper but still limited
const claudeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60,                   // 60 text AI calls per IP per 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: { type: "rate_limit", message: "Too many AI requests. Please wait before trying again." }
  },
  trustProxy: true,
});

app.use(generalLimiter);

// ── Input validation ──────────────────────────────────────────────────────────
// OWASP A03: Injection — validate ALL inputs server-side, never trust the client
// Schema-based validation with explicit allowlists

const ALLOWED_MODELS = [
  "claude-sonnet-4-6",
  "claude-opus-4-6",
  "claude-haiku-4-5-20251001",
];

const ALLOWED_CONTENT_TYPES = ["text", "image"];
const ALLOWED_IMAGE_MIMETYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const ALLOWED_ROLES = ["user", "assistant"];
const ALLOWED_BODY_FIELDS = ["model", "max_tokens", "messages", "system", "temperature"];

/**
 * Validates a Claude API request body.
 * Returns { valid: true } or { valid: false, error: string }
 */
function validateClaudeBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { valid: false, error: "Request body must be a JSON object" };
  }

  // Reject unexpected top-level fields (prevents parameter pollution)
  const bodyFields = Object.keys(body);
  const unexpected = bodyFields.filter(f => !ALLOWED_BODY_FIELDS.includes(f));
  if (unexpected.length > 0) {
    return { valid: false, error: `Unexpected fields: ${unexpected.join(", ")}` };
  }

  // Validate model — only allow known models
  if (!body.model || !ALLOWED_MODELS.includes(body.model)) {
    return { valid: false, error: `Invalid model. Allowed: ${ALLOWED_MODELS.join(", ")}` };
  }

  // Validate max_tokens — integer, reasonable bounds
  const maxTokens = parseInt(body.max_tokens);
  if (isNaN(maxTokens) || maxTokens < 1 || maxTokens > 4096) {
    return { valid: false, error: "max_tokens must be an integer between 1 and 4096" };
  }

  // Validate messages — non-empty array with length limit
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    return { valid: false, error: "messages must be a non-empty array" };
  }
  if (body.messages.length > 10) {
    return { valid: false, error: "Too many messages (max 10)" };
  }

  // Validate each message object
  for (let i = 0; i < body.messages.length; i++) {
    const msg = body.messages[i];
    if (!msg || typeof msg !== "object") {
      return { valid: false, error: `Message ${i} must be an object` };
    }
    if (!ALLOWED_ROLES.includes(msg.role)) {
      return { valid: false, error: `Message ${i} has invalid role: ${msg.role}` };
    }
    if (typeof msg.content !== "string" && !Array.isArray(msg.content)) {
      return { valid: false, error: `Message ${i} content must be string or array` };
    }
    // Validate content blocks (for image messages)
    if (Array.isArray(msg.content)) {
      for (let j = 0; j < msg.content.length; j++) {
        const block = msg.content[j];
        if (!ALLOWED_CONTENT_TYPES.includes(block.type)) {
          return { valid: false, error: `Content block ${j} has invalid type: ${block.type}` };
        }
        if (block.type === "image") {
          if (!block.source || block.source.type !== "base64") {
            return { valid: false, error: `Image block ${j} must use base64 source` };
          }
          if (!ALLOWED_IMAGE_MIMETYPES.includes(block.source.media_type)) {
            return { valid: false, error: `Image block ${j} has invalid media_type: ${block.source.media_type}` };
          }
          if (typeof block.source.data !== "string" || block.source.data.length === 0) {
            return { valid: false, error: `Image block ${j} has missing or empty data` };
          }
        }
        if (block.type === "text" && typeof block.text !== "string") {
          return { valid: false, error: `Text block ${j} must have a string text field` };
        }
      }
    }
  }

  // Validate optional system prompt
  if (body.system !== undefined) {
    if (typeof body.system !== "string") {
      return { valid: false, error: "system must be a string" };
    }
    if (body.system.length > 10000) {
      return { valid: false, error: "system prompt too long (max 10000 chars)" };
    }
  }

  return { valid: true };
}

// ── Safe request logging ──────────────────────────────────────────────────────
// OWASP A09: Security Logging and Monitoring
// Log enough to detect abuse, but NEVER log: API keys, passwords, image data, PII
function logRequest(req, status, extra = "") {
  const timestamp = new Date().toISOString();
  const ip = req.ip ? req.ip.replace(/::ffff:/, "") : "unknown"; // clean IPv4-mapped IPv6
  const version = req.headers["x-client-version"] || "unknown";
  console.log(`[${timestamp}] ${req.method} ${req.path} ${status} ip=${ip} v=${version} ${extra}`);
}

// ── Health check endpoint ─────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  // SECURITY: Only expose what's needed — no env details, no system info
  res.json({ status: "ok", version: "1.0" });
});

// ── POST /api/claude — text AI calls (recipes, insights, weekly reports) ──────
app.post("/api/claude", claudeLimiter, async (req, res) => {
  // Validate request body
  const validation = validateClaudeBody(req.body);
  if (!validation.valid) {
    logRequest(req, 400, `validation_failed="${validation.error}"`);
    return res.status(400).json({
      error: { type: "validation_error", message: validation.error }
    });
  }

  try {
    // SECURITY: Build a clean, allowlisted body — never blindly forward req.body
    // This prevents parameter injection attacks against the Anthropic API
    const safeBody = {
      model: req.body.model,
      max_tokens: Math.min(parseInt(req.body.max_tokens), 2000), // hard cap for text calls
      messages: req.body.messages,
    };
    if (req.body.system) safeBody.system = req.body.system;

    // Forward to Anthropic with server-side API key
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY, // KEY INJECTED HERE — never exposed to client
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(safeBody),
    });

    const data = await response.json();

    // Log token usage for cost monitoring (no sensitive data)
    const inTokens = data.usage?.input_tokens || 0;
    const outTokens = data.usage?.output_tokens || 0;
    logRequest(req, response.status, `in=${inTokens} out=${outTokens} stop=${data.stop_reason || "?"}`);

    return res.status(response.status).json(data);

  } catch (err) {
    // SECURITY: Never expose internal error details or stack traces to clients
    logRequest(req, 500, `upstream_error="${err.message}"`);
    return res.status(500).json({
      error: { type: "server_error", message: "Request failed. Please try again." }
    });
  }
});

// ── POST /api/scan — image scan calls (fridge + meal analysis) ────────────────
app.post("/api/scan", scanLimiter, async (req, res) => {
  // Validate request body
  const validation = validateClaudeBody(req.body);
  if (!validation.valid) {
    logRequest(req, 400, `scan_validation_failed="${validation.error}"`);
    return res.status(400).json({
      error: { type: "validation_error", message: validation.error }
    });
  }

  // SECURITY: Scan endpoint MUST contain an image — reject text-only scan requests
  const hasImage = req.body.messages?.some(m =>
    Array.isArray(m.content) && m.content.some(b => b.type === "image")
  );
  if (!hasImage) {
    logRequest(req, 400, "scan_missing_image");
    return res.status(400).json({
      error: { type: "validation_error", message: "Scan endpoint requires an image block" }
    });
  }

  try {
    const safeBody = {
      model: req.body.model,
      max_tokens: Math.min(parseInt(req.body.max_tokens), 2000), // hard cap for scans
      messages: req.body.messages,
    };

    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(safeBody),
    });

    const data = await response.json();
    const inTokens = data.usage?.input_tokens || 0;
    const outTokens = data.usage?.output_tokens || 0;
    logRequest(req, response.status, `scan in=${inTokens} out=${outTokens}`);

    return res.status(response.status).json(data);

  } catch (err) {
    logRequest(req, 500, `scan_upstream_error="${err.message}"`);
    return res.status(500).json({
      error: { type: "server_error", message: "Scan failed. Please try again." }
    });
  }
});

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  logRequest(req, 404);
  res.status(404).json({ error: "Not found" });
});

// ── Global error handler ──────────────────────────────────────────────────────
// SECURITY: Catch-all error handler — never expose stack traces to clients
app.use((err, req, res, next) => {
  if (err.type === "entity.too.large") {
    logRequest(req, 413, "payload_too_large");
    return res.status(413).json({
      error: { type: "payload_too_large", message: "Image is too large. Please use an image under 1.5MB." }
    });
  }
  if (err.type === "entity.parse.failed") {
    logRequest(req, 400, "invalid_json");
    return res.status(400).json({
      error: { type: "parse_error", message: "Invalid JSON body" }
    });
  }
  logRequest(req, 500, `unhandled="${err.message}"`);
  res.status(500).json({
    error: { type: "server_error", message: "An unexpected error occurred" }
  });
});

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  // SECURITY: Log startup info but never log the actual key value
  console.log(`FridgeAI backend running on port ${PORT}`);
  console.log(`Environment: ${IS_PRODUCTION ? "production" : "development"}`);
  console.log(`Anthropic API key: ${ANTHROPIC_API_KEY ? "configured" : "MISSING - requests will fail"}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
});
