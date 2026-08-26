const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();

// ─── Trust the Railway proxy ──────────────────────────────────────────────────
// Railway terminates TLS and forwards the real client address in X-Forwarded-For.
// Without this, req.ip is Railway's internal proxy address — identical for every
// user — so every rate limiter below would share ONE bucket across the entire
// user base, and any single client could exhaust it for everyone.
//
// TWO hops, not one. Measured against production: a request from a client at
// 103.22.147.94 arrives as
//     x-forwarded-for: 103.22.147.94, 152.233.15.120
// where the second entry is a Railway edge address that rotates between
// requests from the same client. With `1`, req.ip was that rotating edge
// address, so a single client's traffic was spread across several limiter
// buckets. With `2`, req.ip is the real client.
//
// Counting hops from the right (which is what Express does) is what makes this
// spoof-resistant: a client that forges extra X-Forwarded-For entries only
// lengthens the left of the chain, and the trusted count still lands on the
// address Railway actually observed. Re-verify this number if Railway ever
// changes its ingress topology.
app.set("trust proxy", 2);

// 2mb is ~12x headroom: both image paths resize to 768px before sending
// (index.html:995 and :1185), which is well under 200KB of base64.
app.use(express.json({ limit: "2mb" }));
app.use(cors());

// ─── Secrets, from the environment only ───────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// Trimmed: a trailing space or newline on the Railway variable is invisible in
// the dashboard but makes every request fail with 401.
const APPGATE = (process.env.APPGATE || "").trim();

// Short fingerprint for log lines — shows enough to compare two values without
// ever writing the secret itself into the logs.
const fingerprint = (s) =>
    s ? `${s.slice(0, 4)}…${s.slice(-4)}(len=${s.length})` : "<empty>";

// Fail closed. An earlier `if (APPGATE && ...)` check silently disabled the gate
// whenever the variable was missing, leaving the paid proxy wide open.
if (!APPGATE) {
    console.error(
        "FATAL: APPGATE is not set (or is only whitespace). Refusing to start " +
        "rather than run an unauthenticated proxy to a paid API."
    );
    process.exit(1);
}

// ─── Server-side request shape ────────────────────────────────────────────────
// The client cannot be trusted to choose any of these: index.html ships inside
// the app bundle, so every value in it is attacker-editable. The upstream request
// is rebuilt here from scratch rather than forwarded.

const MODEL = "claude-sonnet-4-6";        // pinned; req.body.model is ignored
const MAX_TOKENS_IMAGE = 4500;            // highest legitimate use: fridge scan
const MAX_TOKENS_TEXT = 1500;             // highest legitimate use: 1200 (recipe steps)
const MAX_IMAGES_PER_REQUEST = 1;         // every call site sends exactly one
const MAX_IMAGE_B64_CHARS = 1_500_000;    // ~1.1MB decoded; a 768px JPEG is far smaller
const MAX_MESSAGES = 8;
const MAX_TEXT_CHARS = 24_000;            // across all text blocks combined
const MAX_SYSTEM_CHARS = 8_000;
const UPSTREAM_TIMEOUT_MS = 120_000;

const ALLOWED_MEDIA_TYPES = new Set([
    "image/jpeg", "image/png", "image/gif", "image/webp",
]);

// ─── Daily circuit breaker ────────────────────────────────────────────────────
// A backstop against sustained abuse, independent of per-IP limits. In-process,
// so it resets on every deploy or container restart — treat the hard spend cap in
// the Anthropic Console as the authoritative ceiling, not this.
const DAILY_REQUEST_BUDGET = Number(process.env.DAILY_REQUEST_BUDGET || 3000);
const DAILY_IMAGE_BUDGET = Number(process.env.DAILY_IMAGE_BUDGET || 500);

const budget = { day: null, requests: 0, images: 0 };

function budgetAllows(isImage) {
    const today = new Date().toISOString().slice(0, 10);
    if (budget.day !== today) {
        budget.day = today;
        budget.requests = 0;
        budget.images = 0;
    }
    if (budget.requests >= DAILY_REQUEST_BUDGET) return false;
    if (isImage && budget.images >= DAILY_IMAGE_BUDGET) return false;
    budget.requests += 1;
    if (isImage) budget.images += 1;
    return true;
}

// ─── Request validation ───────────────────────────────────────────────────────

function contentBlocks(message) {
    if (!message || typeof message !== "object") return null;
    if (typeof message.content === "string") {
        return [{ type: "text", text: message.content }];
    }
    return Array.isArray(message.content) ? message.content : null;
}

function countImages(messages) {
    let n = 0;
    for (const m of messages) {
        for (const b of contentBlocks(m) || []) {
            if (b && b.type === "image") n += 1;
        }
    }
    return n;
}

/**
 * Rebuilds the upstream request from the client's, keeping only fields we allow
 * and clamping every size. Returns { body } on success or { error, status }.
 */
function buildUpstreamBody(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        return { status: 400, error: "Malformed request." };
    }
    if (!Array.isArray(raw.messages) || raw.messages.length === 0) {
        return { status: 400, error: "Malformed request." };
    }
    if (raw.messages.length > MAX_MESSAGES) {
        return { status: 400, error: "Too many messages in one request." };
    }

    let textChars = 0;
    let imageCount = 0;
    const messages = [];

    for (const m of raw.messages) {
        const blocks = contentBlocks(m);
        if (!blocks) return { status: 400, error: "Malformed request." };
        if (m.role !== "user" && m.role !== "assistant") {
            return { status: 400, error: "Malformed request." };
        }

        const clean = [];
        for (const b of blocks) {
            if (!b || typeof b !== "object") {
                return { status: 400, error: "Malformed request." };
            }
            if (b.type === "text") {
                if (typeof b.text !== "string") {
                    return { status: 400, error: "Malformed request." };
                }
                textChars += b.text.length;
                if (textChars > MAX_TEXT_CHARS) {
                    return { status: 413, error: "Request text is too long." };
                }
                clean.push({ type: "text", text: b.text });
            } else if (b.type === "image") {
                imageCount += 1;
                if (imageCount > MAX_IMAGES_PER_REQUEST) {
                    return { status: 400, error: "Only one image per request." };
                }
                const src = b.source;
                if (!src || src.type !== "base64" ||
                    !ALLOWED_MEDIA_TYPES.has(src.media_type) ||
                    typeof src.data !== "string") {
                    return { status: 400, error: "Unsupported image format." };
                }
                if (src.data.length > MAX_IMAGE_B64_CHARS) {
                    return { status: 413, error: "Image is too large." };
                }
                clean.push({
                    type: "image",
                    source: {
                        type: "base64",
                        media_type: src.media_type,
                        data: src.data,
                    },
                });
            } else {
                // Drop anything we don't explicitly support (tool_use, documents, …)
                return { status: 400, error: "Unsupported content type." };
            }
        }
        messages.push({ role: m.role, content: clean });
    }

    const ceiling = imageCount > 0 ? MAX_TOKENS_IMAGE : MAX_TOKENS_TEXT;
    const requested = Number(raw.max_tokens);
    const max_tokens = Number.isFinite(requested) && requested > 0
        ? Math.min(Math.floor(requested), ceiling)
        : ceiling;

    // model is deliberately NOT read from raw — it is pinned server-side.
    const body = { model: MODEL, max_tokens, messages };

    if (typeof raw.system === "string" && raw.system.length > 0) {
        body.system = raw.system.slice(0, MAX_SYSTEM_CHARS);
    }

    return { body, imageCount };
}

// ─── Request logging ──────────────────────────────────────────────────────────
// Status, timing and shape only. Never prompts, never image data, never tokens.
app.use((req, res, next) => {
    const started = Date.now();
    res.on("finish", () => {
        if (req.path === "/") return; // health checks are noise
        console.log(
            `${req.method} ${req.originalUrl} ${res.statusCode} ` +
            `${Date.now() - started}ms ip=${req.ip}`
        );
    });
    next();
});

// ─── App gate ─────────────────────────────────────────────────────────────────
// NOTE: this is not real authentication. The value ships inside index.html, so
// anyone who unzips the .ipa has it. Replacing this with verified Supabase JWTs
// is work package WP2.
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
        return res.status(401).json({
            error: { type: "unauthorized", message: "Unauthorized." },
        });
    }
    next();
});

// ─── Rate limiting ────────────────────────────────────────────────────────────
// Per client IP, which is only meaningful because of app.set("trust proxy", 1).
// Still per-IP rather than per-user: keying on a verified user id is WP2.
const rateLimitMessage = (msg) => ({
    error: { type: "rate_limited", message: msg },
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 60,
    message: rateLimitMessage(
        "Too many requests. Please wait a few minutes and try again."
    ),
    standardHeaders: true,
    legacyHeaders: false,
});

const scanLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 20,
    message: rateLimitMessage(
        "Scan limit reached. Please try again later."
    ),
    standardHeaders: true,
    legacyHeaders: false,
});

// Which limiter applies is decided by what the request CONTAINS, not which URL
// it arrived at. Previously /api/claude and /api/scan were byte-identical
// handlers with different limits, so the stricter scan limit was bypassed simply
// by posting the image payload to /api/claude.
function applyLimiter(req, res, next) {
    const isImage = Array.isArray(req.body && req.body.messages) &&
        countImages(req.body.messages) > 0;
    return isImage ? scanLimiter(req, res, next) : generalLimiter(req, res, next);
}

// ─── The proxy ────────────────────────────────────────────────────────────────

async function handleClaude(req, res) {
    if (!ANTHROPIC_API_KEY) {
        console.error("ANTHROPIC_API_KEY is not set");
        return res.status(500).json({
            error: { type: "server_error", message: "Service unavailable." },
        });
    }

    const built = buildUpstreamBody(req.body);
    if (built.error) {
        return res.status(built.status).json({
            error: { type: "invalid_request", message: built.error },
        });
    }

    if (!budgetAllows(built.imageCount > 0)) {
        console.warn(
            `DAILY BUDGET EXHAUSTED requests=${budget.requests} images=${budget.images}`
        );
        return res.status(503).json({
            error: {
                type: "capacity",
                message: "Service is at capacity today. Please try again tomorrow.",
            },
        });
    }

    try {
        const upstream = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            body: JSON.stringify(built.body),
            signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
        });

        const data = await upstream.json();

        if (!upstream.ok) {
            // Log the real upstream error for us; return a generic one to the
            // client. Anthropic's bodies can disclose account state (credit
            // balance, rate tier, permitted models) and an internal request_id.
            console.error(
                `UPSTREAM ${upstream.status} ` +
                `type=${data && data.error && data.error.type} ` +
                `request_id=${data && data.request_id} ` +
                `message=${data && data.error && data.error.message}`
            );
            const status = upstream.status === 429 ? 429 : 502;
            return res.status(status).json({
                error: {
                    type: status === 429 ? "rate_limited" : "upstream_error",
                    message: status === 429
                        ? "The AI service is busy. Please try again shortly."
                        : "The AI service returned an error. Please try again.",
                },
            });
        }

        return res.status(200).json(data);
    } catch (err) {
        if (err && err.name === "TimeoutError") {
            console.error("UPSTREAM TIMEOUT after", UPSTREAM_TIMEOUT_MS, "ms");
            return res.status(504).json({
                error: { type: "timeout", message: "The request took too long. Please try again." },
            });
        }
        console.error("PROXY ERROR:", err && err.message);
        return res.status(502).json({
            error: { type: "upstream_error", message: "Request failed. Please try again." },
        });
    }
}

// Both paths kept for backwards compatibility with the app already installed on
// people's phones. They now behave identically, and the limiter is chosen by
// content rather than by path.
app.post("/api/claude", applyLimiter, handleClaude);
app.post("/api/scan", applyLimiter, handleClaude);

// ─── Health check ─────────────────────────────────────────────────────────────
// No gate and no limiter (it sits outside the /api mount). Returns no config.
app.get("/", (req, res) => {
    res.json({ status: "FridgeAI API running", version: "1.1.0" });
});

// ─── Error handler ────────────────────────────────────────────────────────────
// Catches malformed JSON from express.json and anything else that escapes a
// route, so no stack trace or Express default HTML page ever reaches a client.
app.use((err, req, res, _next) => {
    if (err && (err.type === "entity.too.large")) {
        console.warn(`BODY TOO LARGE ${req.method} ${req.originalUrl} ip=${req.ip}`);
        return res.status(413).json({
            error: { type: "too_large", message: "Request is too large." },
        });
    }
    if (err && err.type === "entity.parse.failed") {
        return res.status(400).json({
            error: { type: "invalid_request", message: "Malformed request." },
        });
    }
    console.error("UNHANDLED:", err && err.message);
    return res.status(500).json({
        error: { type: "server_error", message: "Something went wrong." },
    });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`FridgeAI backend running on port ${PORT}`);
    console.log(`APPGATE loaded: ${fingerprint(APPGATE)}`);
    console.log(
        `model=${MODEL} maxTokens(image/text)=${MAX_TOKENS_IMAGE}/${MAX_TOKENS_TEXT} ` +
        `dailyBudget=${DAILY_REQUEST_BUDGET} dailyImageBudget=${DAILY_IMAGE_BUDGET}`
    );
});
