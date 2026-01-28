const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const crypto = require("crypto");
const geoip = require("geoip-lite");
const { Pool } = require("pg");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

function numberFromEnv(name, fallback) {
    const val = Number(process.env[name]);
    return Number.isFinite(val) ? val : fallback;
}

const PORT = numberFromEnv("PORT", 3000);
const SECRET = process.env.JWT_SECRET || "super-secret-key";
const JSON_LIMIT = process.env.JSON_LIMIT || "200kb";
const MAX_CODE_BYTES = numberFromEnv("MAX_CODE_BYTES", 200000);
const MAX_CREDIT_REQUEST = numberFromEnv("MAX_CREDIT_REQUEST", 1000);
const LOGIN_MAX = numberFromEnv("LOGIN_MAX", 8);
const LOGIN_WINDOW_MS = numberFromEnv("LOGIN_WINDOW_MS", 5 * 60 * 1000);

const ADMIN_USER = process.env.ADMIN_USER || "M.mp3";
const ADMIN_PASS = process.env.ADMIN_PASS || "kJx-A[:kAHe}t,/$i-ZX6C@PLeinjEvF";
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || "";

const corsOriginRaw = process.env.CORS_ORIGIN || "*";
const allowAnyOrigin = corsOriginRaw === "*";
const allowedOrigins = corsOriginRaw
    .split(",")
    .map(o => o.trim())
    .filter(Boolean);

app.use(cors({
    origin: (origin, cb) => {
        if (allowAnyOrigin) return cb(null, true);
        if (!origin || origin === "null") return cb(null, true);
        if (allowedOrigins.includes(origin)) return cb(null, true);
        return cb(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: JSON_LIMIT }));

/* ================= DB ================= */

const DATABASE_URL = process.env.DATABASE_URL || "";
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL }) : null;

async function ensureSchema() {
    if (!pool) return;
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            credits INTEGER NOT NULL DEFAULT 0
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    `);
    await pool.query("CREATE INDEX IF NOT EXISTS orders_status_idx ON orders(status);");
}

async function seedUsersFromEnv() {
    if (!pool) return;
    const seed = process.env.SEED_USERS || "";
    if (!seed) return;

    const entries = seed.split(",").map(item => item.trim()).filter(Boolean);
    for (const entry of entries) {
        const [username, password] = entry.split(":");
        if (!username || !password) continue;
        const hash = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING",
            [username, hash]
        );
    }
}

async function getUser(username) {
    const { rows } = await pool.query(
        "SELECT username, password_hash, credits FROM users WHERE username = $1",
        [username]
    );
    return rows[0] || null;
}

async function getAdminCountryLock() {
    const { rows } = await pool.query(
        "SELECT value FROM admin_settings WHERE key = 'country_lock'"
    );
    return rows[0] ? rows[0].value : "";
}

async function setAdminCountryLock(value) {
    await pool.query(
        "INSERT INTO admin_settings (key, value) VALUES ('country_lock', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        [value]
    );
}

function getCountryFromRequest(req) {
    let ip = req.ip || "";
    if (ip.includes(",")) ip = ip.split(",")[0].trim();
    const geo = ip ? geoip.lookup(ip) : null;
    return geo && geo.country ? geo.country : "";
}

/* ================= AUTH ================= */

function verifyUser(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.sendStatus(401);
    try {
        const token = header.split(" ")[1];
        req.user = jwt.verify(token, SECRET);
        if (!req.user || !req.user.username || req.user.role === "admin") return res.sendStatus(401);
        next();
    } catch {
        res.sendStatus(403);
    }
}

async function verifyAdmin(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.sendStatus(401);
    try {
        const token = header.split(" ")[1];
        req.admin = jwt.verify(token, SECRET);
        if (!req.admin || req.admin.role !== "admin") return res.sendStatus(401);

        if (!pool) return res.status(500).json({ error: "Database not configured" });
        const lock = await getAdminCountryLock();
        const country = getCountryFromRequest(req);
        if (!lock || !country || lock !== country) return res.status(403).json({ error: "Admin access denied" });

        next();
    } catch {
        res.sendStatus(403);
    }
}

const loginAttempts = new Map();
function tooManyLoginAttempts(ip) {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || entry.resetAt <= now) {
        loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
        return false;
    }
    entry.count += 1;
    if (entry.count > LOGIN_MAX) return true;
    return false;
}

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {
    if (!pool) return res.status(500).json({ error: "Database not configured" });

    const ip = req.ip || "unknown";
    if (tooManyLoginAttempts(ip)) return res.status(429).json({ error: "Too many attempts. Try again later." });

    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
    if (username.length > 64 || password.length > 128)
        return res.status(400).json({ error: "Invalid credentials" });

    if (username === ADMIN_USER) {
        let ok = false;
        if (ADMIN_PASS_HASH) {
            ok = await bcrypt.compare(password, ADMIN_PASS_HASH);
        } else {
            ok = password === ADMIN_PASS;
        }
        if (!ok) return res.status(401).json({ error: "Invalid credentials" });

        const country = getCountryFromRequest(req);
        if (!country) return res.status(403).json({ error: "Admin country lock unavailable" });
        const existing = await getAdminCountryLock();
        if (existing && existing !== country) return res.status(403).json({ error: "Admin access denied" });
        if (!existing) await setAdminCountryLock(country);

        const token = jwt.sign({ username, role: "admin" }, SECRET, { expiresIn: "4h" });
        return res.json({ token, role: "admin" });
    }

    const user = await getUser(username);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ username }, SECRET, { expiresIn: "2h" });
    res.json({ token, role: "user" });
});

/* ================= CREDITS ================= */

app.get("/api/credits", verifyUser, async (req, res) => {
    if (!pool) return res.status(500).json({ error: "Database not configured" });
    const user = await getUser(req.user.username);
    res.json({ credits: user ? user.credits : 0 });
});

/* ================= OBFUSCATE ================= */

app.post("/api/obfuscate", verifyUser, async (req, res) => {
    if (!pool) return res.status(500).json({ error: "Database not configured" });

    const code = typeof req.body.code === "string" ? req.body.code : "";
    if (!code) return res.status(400).json({ error: "No code" });
    if (Buffer.byteLength(code, "utf8") > MAX_CODE_BYTES)
        return res.status(413).json({ error: "Code too large" });

    const { rows } = await pool.query(
        "UPDATE users SET credits = credits - 1 WHERE username = $1 AND credits > 0 RETURNING credits",
        [req.user.username]
    );
    if (!rows[0]) return res.status(402).json({ error: "No credits left" });

    res.json({
        obfuscated: Buffer.from(code).toString("base64"),
        credits: rows[0].credits
    });
});

/* ================= ORDERS ================= */

function generateOrderID() {
    return crypto.randomBytes(24).toString("base64url").slice(0, 32);
}

app.post("/api/request-credits", verifyUser, async (req, res) => {
    if (!pool) return res.status(500).json({ error: "Database not configured" });

    const amount = Number(req.body.amount);
    if (!Number.isInteger(amount) || amount <= 0 || amount > MAX_CREDIT_REQUEST)
        return res.status(400).json({ error: "Invalid amount" });

    const order = generateOrderID();
    const user = req.user.username;

    await pool.query(
        "INSERT INTO orders (id, username, amount, status) VALUES ($1, $2, $3, $4)",
        [order, user, amount, "pending"]
    );

    res.json({ order });
});

app.post("/api/cancel-order", verifyUser, async (req, res) => {
    if (!pool) return res.status(500).json({ error: "Database not configured" });

    const { order } = req.body;
    if (!order) return res.sendStatus(400);

    await pool.query(
        "UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2 AND username = $3 AND status = $4",
        ["cancelled", order, req.user.username, "pending"]
    );

    res.json({ ok: true });
});

app.get("/api/order-status/:id", verifyUser, async (req, res) => {
    if (!pool) return res.status(500).json({ error: "Database not configured" });

    const id = String(req.params.id || "");
    if (!id || id.length > 64) return res.status(400).json({ error: "Invalid order id" });

    const { rows } = await pool.query(
        "SELECT status FROM orders WHERE id = $1 AND username = $2",
        [id, req.user.username]
    );

    if (!rows[0]) return res.json({ status: "unknown" });
    if (rows[0].status === "approved") return res.json({ status: "paid" });
    if (rows[0].status === "cancelled") return res.json({ status: "cancelled" });
    return res.json({ status: "pending" });
});

/* ================= ADMIN ORDERS ================= */

app.get("/api/admin/orders", verifyAdmin, async (req, res) => {
    const status = String(req.query.status || "pending");
    if (status === "all") {
        const { rows } = await pool.query(
            "SELECT id, username, amount, status, created_at FROM orders ORDER BY created_at DESC LIMIT 200"
        );
        return res.json({ orders: rows });
    }
    const { rows } = await pool.query(
        "SELECT id, username, amount, status, created_at FROM orders WHERE status = $1 ORDER BY created_at DESC LIMIT 200",
        [status]
    );
    res.json({ orders: rows });
});

app.post("/api/admin/orders/:id/approve", verifyAdmin, async (req, res) => {
    const id = String(req.params.id || "");
    if (!id || id.length > 64) return res.status(400).json({ error: "Invalid order id" });

    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        const { rows } = await client.query(
            "SELECT id, username, amount, status FROM orders WHERE id = $1 FOR UPDATE",
            [id]
        );
        if (!rows[0]) {
            await client.query("ROLLBACK");
            return res.status(404).json({ error: "Order not found" });
        }
        if (rows[0].status !== "pending") {
            await client.query("ROLLBACK");
            return res.json({ ok: true, status: rows[0].status });
        }
        await client.query(
            "UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2",
            ["approved", id]
        );
        await client.query(
            "UPDATE users SET credits = credits + $1 WHERE username = $2",
            [rows[0].amount, rows[0].username]
        );
        await client.query("COMMIT");
        res.json({ ok: true });
    } catch (err) {
        await client.query("ROLLBACK");
        res.status(500).json({ error: "Failed to approve order" });
    } finally {
        client.release();
    }
});

app.post("/api/admin/orders/:id/cancel", verifyAdmin, async (req, res) => {
    const id = String(req.params.id || "");
    if (!id || id.length > 64) return res.status(400).json({ error: "Invalid order id" });

    await pool.query(
        "UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2 AND status = $3",
        ["cancelled", id, "pending"]
    );

    res.json({ ok: true });
});

/* ================= START ================= */

async function start() {
    if (!pool) {
        console.warn("DATABASE_URL is not set. Server will not be able to persist data.");
    } else {
        await ensureSchema();
        await seedUsersFromEnv();
    }

    app.listen(PORT, () => {
        console.log(`Obscura server running at http://localhost:${PORT}`);
    });
}

start().catch(err => {
    console.error("Failed to start server:", err);
    process.exit(1);
});
