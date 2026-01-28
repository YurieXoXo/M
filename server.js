const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.disable("x-powered-by");

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

const corsOriginRaw = process.env.CORS_ORIGIN || "http://localhost:3000";
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
const CRED_PATH = path.join(__dirname, "ValidCredit.txt");
const CREDIT_DB = path.join(__dirname, "credits.json");
const ORDERS_PATH = path.join(__dirname, "Orders.txt");

/* ================= USERS ================= */

const USERS = new Map();

async function loadUsers() {
    const raw = fs.readFileSync(CRED_PATH, "utf8")
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(Boolean);

    USERS.clear();
    for (const line of raw) {
        const [username, password] = line.split(",");
        if (!username || !password) continue;
        const hash = await bcrypt.hash(password, 10);
        USERS.set(username, { username, hash });
    }
}

/* ================= STORAGE ================= */

function loadJSON(file, def = {}) {
    if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(def, null, 2));
    return JSON.parse(fs.readFileSync(file, "utf8"));
}
function saveJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

/* ================= AUTH ================= */

function verify(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.sendStatus(401);
    try {
        const token = header.split(" ")[1];
        req.user = jwt.verify(token, SECRET);
        if (!req.user || !USERS.has(req.user.username)) return res.sendStatus(401);
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
    const ip = req.ip || "unknown";
    if (tooManyLoginAttempts(ip)) return res.status(429).json({ error: "Too many attempts. Try again later." });

    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
    if (username.length > 64 || password.length > 128)
        return res.status(400).json({ error: "Invalid credentials" });

    const user = USERS.get(username);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ username }, SECRET, { expiresIn: "2h" });
    res.json({ token });
});

/* ================= CREDITS ================= */

app.get("/api/credits", verify, (req, res) => {
    const credits = loadJSON(CREDIT_DB);
    res.json({ credits: credits[req.user.username] || 0 });
});

/* ================= OBFUSCATE ================= */

app.post("/api/obfuscate", verify, (req, res) => {
    const code = typeof req.body.code === "string" ? req.body.code : "";
    if (!code) return res.status(400).json({ error: "No code" });
    if (Buffer.byteLength(code, "utf8") > MAX_CODE_BYTES)
        return res.status(413).json({ error: "Code too large" });

    const credits = loadJSON(CREDIT_DB);
    const user = req.user.username;

    if (!credits[user] || credits[user] < 1)
        return res.status(402).json({ error: "No credits left" });

    credits[user] -= 1;
    saveJSON(CREDIT_DB, credits);

    res.json({
        obfuscated: Buffer.from(code).toString("base64"),
        credits: credits[user]
    });
});

/* ================= ORDERS ================= */

const ACTIVE_ORDERS = new Map();

function generateOrderID() {
    return crypto.randomBytes(24).toString("base64url").slice(0,32);
}

app.post("/api/request-credits", verify, (req, res) => {
    const amount = Number(req.body.amount);
    if (!Number.isInteger(amount) || amount <= 0 || amount > MAX_CREDIT_REQUEST)
        return res.status(400).json({ error: "Invalid amount" });

    const order = generateOrderID();
    const user = req.user.username;

    fs.appendFileSync(ORDERS_PATH, `${order} - ${amount}\n`);
    ACTIVE_ORDERS.set(order, { user, amount });

    res.json({ order });
});

/* ---------- CANCEL ORDER ---------- */
app.post("/api/cancel-order", verify, (req, res) => {
    const { order } = req.body;
    if (!order) return res.sendStatus(400);

    if (!fs.existsSync(ORDERS_PATH)) return res.json({ ok: true });

    const lines = fs.readFileSync(ORDERS_PATH, "utf8")
        .split(/\r?\n/)
        .filter(l => l && !l.startsWith(order + " -"));

    fs.writeFileSync(ORDERS_PATH, lines.join("\n") + (lines.length ? "\n" : ""));
    ACTIVE_ORDERS.delete(order);

    res.json({ ok: true });
});

/* ---------- CHECK ORDER ---------- */
app.get("/api/order-status/:id", verify, (req, res) => {
    const id = String(req.params.id || "");
    if (!id || id.length > 64) return res.status(400).json({ error: "Invalid order id" });

    const file = fs.existsSync(ORDERS_PATH) ? fs.readFileSync(ORDERS_PATH, "utf8") : "";

    if (file.includes(id))
        return res.json({ status: "pending" });

    if (ACTIVE_ORDERS.has(id)) {
        const { user, amount } = ACTIVE_ORDERS.get(id);
        ACTIVE_ORDERS.delete(id);

        const credits = loadJSON(CREDIT_DB);
        credits[user] = (credits[user] || 0) + Number(amount);
        saveJSON(CREDIT_DB, credits);

        return res.json({ status: "paid", amount });
    }

    res.json({ status: "unknown" });
});

/* ================= START ================= */

async function start() {
    await loadUsers();
    if (!fs.existsSync(ORDERS_PATH)) fs.writeFileSync(ORDERS_PATH, "");
    app.listen(PORT, () => {
        console.log(`Obscura server running at http://localhost:${PORT}`);
    });
}

start().catch(err => {
    console.error("Failed to start server:", err);
    process.exit(1);
});
