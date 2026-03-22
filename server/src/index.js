require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { getDb, initDb } = require("./db");
const { createRoutes } = require("./routes");
const { setupWebSocket } = require("./websocket");

const PORT = parseInt(process.env.PORT) || 3000;

// ── Database ──────────────────────────────────────────────
const db = getDb();
initDb(db);

// ── Express App ───────────────────────────────────────────
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "wss:", "ws:", "https://api.open-meteo.com", "https://*.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:", "data:"],
      workerSrc: ["'self'", "blob:"],
    },
  },
  // Cloudflare compatibility: don't downgrade HTTPS
  crossOriginEmbedderPolicy: false,
}));

// Trust Cloudflare proxy headers (1 = trust first proxy only)
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, slow down" },
});
app.use("/api/", limiter);

// Stricter limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many login attempts, try again later" },
});
app.use("/api/auth/login", authLimiter);

// ── API Routes ────────────────────────────────────────────
app.use("/api", createRoutes(db));

// ── Static Files ──────────────────────────────────────────
app.use(express.static(path.join(__dirname, "../../public")));

// SPA fallback
app.get("/{*path}", (req, res) => {
  res.sendFile(path.join(__dirname, "../../public/index.html"));
});

// ── Error handler ─────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("Server error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ── Start Server ──────────────────────────────────────────
const server = http.createServer(app);
const { wss, getOnlineUserIds } = setupWebSocket(server, db);

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n  🏠 Family Hub running at http://localhost:${PORT}`);
    console.log(`  📡 WebSocket at ws://localhost:${PORT}/ws`);
    console.log(`  📁 Database: ${require("./db").DB_PATH}\n`);
  });
}

module.exports = { app, server, db };
