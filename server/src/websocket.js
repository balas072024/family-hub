const { WebSocketServer } = require("ws");
const { verifyToken } = require("./auth");

function setupWebSocket(server, db) {
  const wss = new WebSocketServer({ server, path: "/ws" });
  const clients = new Map(); // userId -> Set<ws>

  wss.on("connection", (ws, req) => {
    let userId = null;

    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });

    ws.on("message", (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      // First message must be auth
      if (msg.type === "auth") {
        try {
          const payload = verifyToken(msg.token);
          userId = payload.id;
          if (!clients.has(userId)) clients.set(userId, new Set());
          clients.get(userId).add(ws);

          db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(userId);

          // Broadcast online status
          broadcast({ type: "presence", userId, status: "online" }, userId);
          ws.send(JSON.stringify({ type: "auth_ok" }));
        } catch {
          ws.send(JSON.stringify({ type: "auth_error", error: "Invalid token" }));
          ws.close();
        }
        return;
      }

      if (!userId) {
        ws.send(JSON.stringify({ type: "error", error: "Not authenticated" }));
        return;
      }

      // Handle different message types
      if (msg.type === "chat") {
        if (!msg.content || typeof msg.content !== "string" || msg.content.trim().length === 0) return;
        const content = msg.content.trim().slice(0, 2000);

        const result = db.prepare(
          "INSERT INTO messages (user_id, content) VALUES (?, ?)"
        ).run(userId, content);

        const message = db.prepare(
          `SELECT m.id, m.content, m.type, m.created_at,
                  u.id as user_id, u.display_name, u.emoji, u.color
           FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = ?`
        ).get(result.lastInsertRowid);

        db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(userId);
        broadcastAll({ type: "new_message", message });
      }

      if (msg.type === "typing") {
        const user = db.prepare("SELECT display_name, emoji FROM users WHERE id = ?").get(userId);
        broadcast({ type: "typing", userId, name: user?.display_name, emoji: user?.emoji }, userId);
      }

      // ── WebRTC Call Signaling ──────────────────────────────
      // Forward call signals directly to the target user
      if (msg.type === "call_offer" || msg.type === "call_answer" || msg.type === "call_ice" || msg.type === "call_hangup") {
        const targetId = msg.targetUserId;
        if (!targetId || !clients.has(targetId)) {
          ws.send(JSON.stringify({ type: "call_error", error: "User is offline" }));
          return;
        }
        const caller = db.prepare("SELECT display_name, emoji FROM users WHERE id = ?").get(userId);
        const payload = { ...msg, fromUserId: userId, fromName: caller?.display_name, fromEmoji: caller?.emoji };
        const targetSockets = clients.get(targetId);
        const json = JSON.stringify(payload);
        for (const s of targetSockets) {
          if (s.readyState === 1) s.send(json);
        }
      }

      // Broadcast call to all (for group call ring)
      if (msg.type === "call_ring") {
        const caller = db.prepare("SELECT display_name, emoji FROM users WHERE id = ?").get(userId);
        broadcast({
          type: "call_ring",
          fromUserId: userId,
          fromName: caller?.display_name,
          fromEmoji: caller?.emoji,
          callType: msg.callType || "voice"
        }, userId);
      }
    });

    ws.on("close", () => {
      if (userId) {
        const userSockets = clients.get(userId);
        if (userSockets) {
          userSockets.delete(ws);
          if (userSockets.size === 0) {
            clients.delete(userId);
            db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(userId);
            broadcast({ type: "presence", userId, status: "offline" }, userId);
          }
        }
      }
    });
  });

  // Heartbeat to detect dead connections
  const heartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws.isAlive) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  wss.on("close", () => clearInterval(heartbeat));

  function broadcast(data, excludeUserId) {
    const json = JSON.stringify(data);
    for (const [uid, sockets] of clients) {
      if (uid === excludeUserId) continue;
      for (const ws of sockets) {
        if (ws.readyState === 1) ws.send(json);
      }
    }
  }

  function broadcastAll(data) {
    const json = JSON.stringify(data);
    for (const sockets of clients.values()) {
      for (const ws of sockets) {
        if (ws.readyState === 1) ws.send(json);
      }
    }
  }

  function getOnlineUserIds() {
    return [...clients.keys()];
  }

  return { wss, getOnlineUserIds };
}

module.exports = { setupWebSocket };
