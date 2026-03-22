const express = require("express");
const bcrypt = require("bcryptjs");
const { body, query, validationResult } = require("express-validator");
const { generateToken, authMiddleware, adminOnly } = require("./auth");

function createRoutes(db) {
  const router = express.Router();

  const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }
    next();
  };

  // ── Auth ──────────────────────────────────────────────────

  router.post("/auth/login",
    body("username").trim().notEmpty().withMessage("Username required"),
    body("password").notEmpty().withMessage("Password required"),
    validate,
    (req, res) => {
      const { username, password } = req.body;
      const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
      if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: "Invalid username or password" });
      }
      db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(user.id);
      const token = generateToken(user);
      res.json({
        token,
        user: { id: user.id, username: user.username, display_name: user.display_name, emoji: user.emoji, color: user.color, role: user.role }
      });
    }
  );

  router.get("/auth/me", authMiddleware, (req, res) => {
    const user = db.prepare("SELECT id, username, display_name, emoji, color, role, last_seen FROM users WHERE id = ?").get(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user });
  });

  router.post("/auth/change-password",
    authMiddleware,
    body("current_password").notEmpty().withMessage("Current password required"),
    body("new_password").isLength({ min: 6 }).withMessage("New password must be at least 6 characters"),
    validate,
    (req, res) => {
      const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
      if (!bcrypt.compareSync(req.body.current_password, user.password_hash)) {
        return res.status(401).json({ error: "Current password is incorrect" });
      }
      const hash = bcrypt.hashSync(req.body.new_password, 10);
      db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, req.user.id);
      res.json({ message: "Password changed successfully" });
    }
  );

  // ── Users ─────────────────────────────────────────────────

  router.get("/users", authMiddleware, (req, res) => {
    const users = db.prepare("SELECT id, username, display_name, emoji, color, role, last_seen FROM users").all();
    res.json({ users });
  });

  router.post("/users",
    authMiddleware, adminOnly,
    body("username").trim().isLength({ min: 2, max: 30 }).withMessage("Username must be 2-30 chars"),
    body("display_name").trim().isLength({ min: 1, max: 50 }).withMessage("Display name required"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 chars"),
    body("emoji").optional().trim(),
    body("color").optional().isHexColor().withMessage("Invalid color"),
    body("role").optional().isIn(["admin", "member"]),
    validate,
    (req, res) => {
      const { username, display_name, password, emoji, color, role } = req.body;
      const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
      if (existing) return res.status(409).json({ error: "Username already exists" });

      const id = require("crypto").randomUUID();
      const hash = bcrypt.hashSync(password, 10);
      db.prepare(
        "INSERT INTO users (id, username, display_name, emoji, color, role, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).run(id, username, display_name, emoji || "👤", color || "#7c6bff", role || "member", hash);

      res.status(201).json({ user: { id, username, display_name, emoji: emoji || "👤", color: color || "#7c6bff", role: role || "member" } });
    }
  );

  // ── Messages ──────────────────────────────────────────────

  router.get("/messages",
    authMiddleware,
    query("limit").optional().isInt({ min: 1, max: 200 }),
    query("before").optional().isInt(),
    validate,
    (req, res) => {
      const limit = parseInt(req.query.limit) || 50;
      const before = req.query.before ? parseInt(req.query.before) : null;

      let sql = `SELECT m.id, m.content, m.type, m.created_at,
                   u.id as user_id, u.display_name, u.emoji, u.color
                 FROM messages m JOIN users u ON m.user_id = u.id`;
      const params = [];
      if (before) {
        sql += " WHERE m.id < ?";
        params.push(before);
      }
      sql += " ORDER BY m.id DESC LIMIT ?";
      params.push(limit);

      const messages = db.prepare(sql).all(...params).reverse();
      res.json({ messages });
    }
  );

  router.post("/messages",
    authMiddleware,
    body("content").trim().isLength({ min: 1, max: 2000 }).withMessage("Message must be 1-2000 chars"),
    validate,
    (req, res) => {
      const result = db.prepare(
        "INSERT INTO messages (user_id, content) VALUES (?, ?)"
      ).run(req.user.id, req.body.content);

      const message = db.prepare(
        `SELECT m.id, m.content, m.type, m.created_at,
                u.id as user_id, u.display_name, u.emoji, u.color
         FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = ?`
      ).get(result.lastInsertRowid);

      db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(req.user.id);
      res.status(201).json({ message });
    }
  );

  router.delete("/messages/:id", authMiddleware, (req, res) => {
    const msg = db.prepare("SELECT user_id FROM messages WHERE id = ?").get(req.params.id);
    if (!msg) return res.status(404).json({ error: "Message not found" });
    if (msg.user_id !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized" });
    }
    db.prepare("DELETE FROM messages WHERE id = ?").run(req.params.id);
    res.json({ message: "Deleted" });
  });

  // ── Todos ─────────────────────────────────────────────────

  router.get("/todos", authMiddleware, (req, res) => {
    const todos = db.prepare(
      `SELECT t.*, u.display_name as created_by_name, a.display_name as assigned_to_name
       FROM todos t
       JOIN users u ON t.created_by = u.id
       LEFT JOIN users a ON t.assigned_to = a.id
       ORDER BY
         CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,
         t.done ASC, t.created_at DESC`
    ).all();
    res.json({ todos });
  });

  router.post("/todos",
    authMiddleware,
    body("text").trim().isLength({ min: 1, max: 500 }).withMessage("Task text required (max 500 chars)"),
    body("priority").optional().isIn(["low", "normal", "high", "urgent"]),
    body("due_date").optional({ values: "null" }).isISO8601().withMessage("Invalid date"),
    body("assigned_to").optional({ values: "null" }),
    validate,
    (req, res) => {
      const { text, priority, due_date, assigned_to } = req.body;
      const result = db.prepare(
        "INSERT INTO todos (text, priority, due_date, created_by, assigned_to) VALUES (?, ?, ?, ?, ?)"
      ).run(text, priority || "normal", due_date || null, req.user.id, assigned_to || null);

      const todo = db.prepare(
        `SELECT t.*, u.display_name as created_by_name, a.display_name as assigned_to_name
         FROM todos t JOIN users u ON t.created_by = u.id LEFT JOIN users a ON t.assigned_to = a.id
         WHERE t.id = ?`
      ).get(result.lastInsertRowid);
      res.status(201).json({ todo });
    }
  );

  router.patch("/todos/:id",
    authMiddleware,
    (req, res) => {
      const todo = db.prepare("SELECT * FROM todos WHERE id = ?").get(req.params.id);
      if (!todo) return res.status(404).json({ error: "Todo not found" });

      const { text, done, priority, due_date, assigned_to } = req.body;
      const updates = [];
      const params = [];

      if (text !== undefined) { updates.push("text = ?"); params.push(text); }
      if (done !== undefined) {
        updates.push("done = ?"); params.push(done ? 1 : 0);
        updates.push("completed_at = ?"); params.push(done ? new Date().toISOString() : null);
      }
      if (priority !== undefined) { updates.push("priority = ?"); params.push(priority); }
      if (due_date !== undefined) { updates.push("due_date = ?"); params.push(due_date); }
      if (assigned_to !== undefined) { updates.push("assigned_to = ?"); params.push(assigned_to); }

      if (updates.length === 0) return res.status(400).json({ error: "No fields to update" });

      params.push(req.params.id);
      db.prepare(`UPDATE todos SET ${updates.join(", ")} WHERE id = ?`).run(...params);

      const updated = db.prepare(
        `SELECT t.*, u.display_name as created_by_name, a.display_name as assigned_to_name
         FROM todos t JOIN users u ON t.created_by = u.id LEFT JOIN users a ON t.assigned_to = a.id
         WHERE t.id = ?`
      ).get(req.params.id);
      res.json({ todo: updated });
    }
  );

  router.delete("/todos/completed", authMiddleware, (req, res) => {
    const result = db.prepare("DELETE FROM todos WHERE done = 1").run();
    res.json({ message: "Deleted", count: result.changes });
  });

  router.delete("/todos/:id", authMiddleware, (req, res) => {
    const todo = db.prepare("SELECT created_by FROM todos WHERE id = ?").get(req.params.id);
    if (!todo) return res.status(404).json({ error: "Todo not found" });
    if (todo.created_by !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized" });
    }
    db.prepare("DELETE FROM todos WHERE id = ?").run(req.params.id);
    res.json({ message: "Deleted" });
  });

  // ── Notes ─────────────────────────────────────────────────

  router.get("/notes", authMiddleware, (req, res) => {
    const notes = db.prepare(
      `SELECT n.*, u.display_name as created_by_name
       FROM notes n JOIN users u ON n.created_by = u.id
       ORDER BY n.updated_at DESC`
    ).all();
    res.json({ notes });
  });

  router.post("/notes",
    authMiddleware,
    body("title").trim().isLength({ min: 1, max: 200 }).withMessage("Title required (max 200 chars)"),
    body("content").optional().trim().isLength({ max: 5000 }),
    validate,
    (req, res) => {
      const result = db.prepare(
        "INSERT INTO notes (title, content, created_by) VALUES (?, ?, ?)"
      ).run(req.body.title, req.body.content || "", req.user.id);

      const note = db.prepare(
        "SELECT n.*, u.display_name as created_by_name FROM notes n JOIN users u ON n.created_by = u.id WHERE n.id = ?"
      ).get(result.lastInsertRowid);
      res.status(201).json({ note });
    }
  );

  router.put("/notes/:id",
    authMiddleware,
    body("title").trim().isLength({ min: 1, max: 200 }),
    body("content").optional().trim().isLength({ max: 5000 }),
    validate,
    (req, res) => {
      const note = db.prepare("SELECT created_by FROM notes WHERE id = ?").get(req.params.id);
      if (!note) return res.status(404).json({ error: "Note not found" });
      if (note.created_by !== req.user.id && req.user.role !== "admin") {
        return res.status(403).json({ error: "Not authorized" });
      }
      db.prepare("UPDATE notes SET title = ?, content = ?, updated_at = datetime('now') WHERE id = ?")
        .run(req.body.title, req.body.content || "", req.params.id);
      const updated = db.prepare(
        "SELECT n.*, u.display_name as created_by_name FROM notes n JOIN users u ON n.created_by = u.id WHERE n.id = ?"
      ).get(req.params.id);
      res.json({ note: updated });
    }
  );

  router.delete("/notes/:id", authMiddleware, (req, res) => {
    const note = db.prepare("SELECT created_by FROM notes WHERE id = ?").get(req.params.id);
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (note.created_by !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized" });
    }
    db.prepare("DELETE FROM notes WHERE id = ?").run(req.params.id);
    res.json({ message: "Deleted" });
  });

  // ── Events / Calendar ─────────────────────────────────────

  router.get("/events", authMiddleware, (req, res) => {
    const events = db.prepare(
      `SELECT e.*, u.display_name as created_by_name
       FROM events e JOIN users u ON e.created_by = u.id
       ORDER BY e.event_date ASC, e.event_time ASC`
    ).all();
    res.json({ events });
  });

  router.post("/events",
    authMiddleware,
    body("title").trim().isLength({ min: 1, max: 200 }).withMessage("Title required"),
    body("event_date").isISO8601().withMessage("Valid date required"),
    body("event_time").optional().trim(),
    body("description").optional().trim().isLength({ max: 1000 }),
    validate,
    (req, res) => {
      const { title, description, event_date, event_time } = req.body;
      const result = db.prepare(
        "INSERT INTO events (title, description, event_date, event_time, created_by) VALUES (?, ?, ?, ?, ?)"
      ).run(title, description || "", event_date, event_time || null, req.user.id);

      const event = db.prepare(
        "SELECT e.*, u.display_name as created_by_name FROM events e JOIN users u ON e.created_by = u.id WHERE e.id = ?"
      ).get(result.lastInsertRowid);
      res.status(201).json({ event });
    }
  );

  router.delete("/events/:id", authMiddleware, (req, res) => {
    const event = db.prepare("SELECT created_by FROM events WHERE id = ?").get(req.params.id);
    if (!event) return res.status(404).json({ error: "Event not found" });
    if (event.created_by !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized" });
    }
    db.prepare("DELETE FROM events WHERE id = ?").run(req.params.id);
    res.json({ message: "Deleted" });
  });

  // ── Shopping Lists ───────────────────────────────────────

  router.get("/shopping", authMiddleware, (req, res) => {
    const lists = db.prepare(
      `SELECT s.*, u.display_name as created_by_name,
              (SELECT COUNT(*) FROM shopping_items WHERE list_id = s.id) as item_count,
              (SELECT COUNT(*) FROM shopping_items WHERE list_id = s.id AND checked = 1) as checked_count
       FROM shopping_lists s JOIN users u ON s.created_by = u.id
       ORDER BY s.created_at DESC`
    ).all();
    res.json({ lists });
  });

  router.post("/shopping",
    authMiddleware,
    body("name").trim().isLength({ min: 1, max: 100 }).withMessage("List name required"),
    validate,
    (req, res) => {
      const result = db.prepare("INSERT INTO shopping_lists (name, created_by) VALUES (?, ?)").run(req.body.name, req.user.id);
      const list = db.prepare(
        "SELECT s.*, u.display_name as created_by_name FROM shopping_lists s JOIN users u ON s.created_by = u.id WHERE s.id = ?"
      ).get(result.lastInsertRowid);
      res.status(201).json({ list: { ...list, item_count: 0, checked_count: 0 } });
    }
  );

  router.delete("/shopping/:id", authMiddleware, (req, res) => {
    const list = db.prepare("SELECT created_by FROM shopping_lists WHERE id = ?").get(req.params.id);
    if (!list) return res.status(404).json({ error: "List not found" });
    if (list.created_by !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized" });
    }
    db.prepare("DELETE FROM shopping_lists WHERE id = ?").run(req.params.id);
    res.json({ message: "Deleted" });
  });

  // Shopping items
  router.get("/shopping/:listId/items", authMiddleware, (req, res) => {
    const items = db.prepare(
      `SELECT i.*, u.display_name as added_by_name
       FROM shopping_items i JOIN users u ON i.added_by = u.id
       WHERE i.list_id = ? ORDER BY i.checked ASC, i.created_at DESC`
    ).all(req.params.listId);
    res.json({ items });
  });

  router.post("/shopping/:listId/items",
    authMiddleware,
    body("name").trim().isLength({ min: 1, max: 200 }).withMessage("Item name required"),
    body("quantity").optional().trim().isLength({ max: 50 }),
    validate,
    (req, res) => {
      const list = db.prepare("SELECT id FROM shopping_lists WHERE id = ?").get(req.params.listId);
      if (!list) return res.status(404).json({ error: "List not found" });
      const result = db.prepare(
        "INSERT INTO shopping_items (list_id, name, quantity, added_by) VALUES (?, ?, ?, ?)"
      ).run(req.params.listId, req.body.name, req.body.quantity || null, req.user.id);
      const item = db.prepare(
        "SELECT i.*, u.display_name as added_by_name FROM shopping_items i JOIN users u ON i.added_by = u.id WHERE i.id = ?"
      ).get(result.lastInsertRowid);
      res.status(201).json({ item });
    }
  );

  router.patch("/shopping/items/:id", authMiddleware, (req, res) => {
    const item = db.prepare("SELECT * FROM shopping_items WHERE id = ?").get(req.params.id);
    if (!item) return res.status(404).json({ error: "Item not found" });
    if (req.body.checked !== undefined) {
      db.prepare("UPDATE shopping_items SET checked = ? WHERE id = ?").run(req.body.checked ? 1 : 0, req.params.id);
    }
    const updated = db.prepare(
      "SELECT i.*, u.display_name as added_by_name FROM shopping_items i JOIN users u ON i.added_by = u.id WHERE i.id = ?"
    ).get(req.params.id);
    res.json({ item: updated });
  });

  router.delete("/shopping/items/:id", authMiddleware, (req, res) => {
    const item = db.prepare("SELECT added_by FROM shopping_items WHERE id = ?").get(req.params.id);
    if (!item) return res.status(404).json({ error: "Item not found" });
    db.prepare("DELETE FROM shopping_items WHERE id = ?").run(req.params.id);
    res.json({ message: "Deleted" });
  });

  // ── Family Journal ──────────────────────────────────────

  router.get("/journal", authMiddleware, (req, res) => {
    const entries = db.prepare(
      `SELECT j.*, u.display_name as created_by_name, u.emoji
       FROM journal_entries j JOIN users u ON j.created_by = u.id
       ORDER BY j.created_at DESC`
    ).all();
    res.json({ entries });
  });

  router.post("/journal",
    authMiddleware,
    body("title").trim().isLength({ min: 1, max: 200 }).withMessage("Title required"),
    body("content").optional().trim().isLength({ max: 5000 }),
    body("mood").optional().isIn(["happy", "grateful", "excited", "neutral", "tired", "sad"]),
    validate,
    (req, res) => {
      const { title, content, mood } = req.body;
      const result = db.prepare(
        "INSERT INTO journal_entries (title, content, mood, created_by) VALUES (?, ?, ?, ?)"
      ).run(title, content || "", mood || "neutral", req.user.id);
      const entry = db.prepare(
        "SELECT j.*, u.display_name as created_by_name, u.emoji FROM journal_entries j JOIN users u ON j.created_by = u.id WHERE j.id = ?"
      ).get(result.lastInsertRowid);
      res.status(201).json({ entry });
    }
  );

  router.delete("/journal/:id", authMiddleware, (req, res) => {
    const entry = db.prepare("SELECT created_by FROM journal_entries WHERE id = ?").get(req.params.id);
    if (!entry) return res.status(404).json({ error: "Entry not found" });
    if (entry.created_by !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not authorized" });
    }
    db.prepare("DELETE FROM journal_entries WHERE id = ?").run(req.params.id);
    res.json({ message: "Deleted" });
  });

  // ── Data Export ──────────────────────────────────────────

  router.get("/export", authMiddleware, (req, res) => {
    const userId = req.user.id;
    const messages = db.prepare(
      "SELECT m.id, m.content, m.type, m.created_at FROM messages m WHERE m.user_id = ? ORDER BY m.created_at DESC"
    ).all(userId);
    const todos = db.prepare(
      "SELECT t.id, t.text, t.done, t.priority, t.due_date, t.created_at, t.completed_at FROM todos t WHERE t.created_by = ? ORDER BY t.created_at DESC"
    ).all(userId);
    const notes = db.prepare(
      "SELECT n.id, n.title, n.content, n.created_at, n.updated_at FROM notes n WHERE n.created_by = ? ORDER BY n.updated_at DESC"
    ).all(userId);
    const events = db.prepare(
      "SELECT e.id, e.title, e.description, e.event_date, e.event_time, e.created_at FROM events e WHERE e.created_by = ? ORDER BY e.event_date ASC"
    ).all(userId);
    const shoppingLists = db.prepare(
      "SELECT s.id, s.name, s.created_at FROM shopping_lists s WHERE s.created_by = ? ORDER BY s.created_at DESC"
    ).all(userId);
    for (const list of shoppingLists) {
      list.items = db.prepare(
        "SELECT i.id, i.name, i.quantity, i.checked, i.created_at FROM shopping_items i WHERE i.list_id = ? ORDER BY i.created_at DESC"
      ).all(list.id);
    }
    const journalEntries = db.prepare(
      "SELECT j.id, j.title, j.content, j.mood, j.created_at FROM journal_entries j WHERE j.created_by = ? ORDER BY j.created_at DESC"
    ).all(userId);

    res.json({
      exported_at: new Date().toISOString(),
      user: { id: userId, username: req.user.username },
      messages,
      todos,
      notes,
      events,
      shopping_lists: shoppingLists,
      journal_entries: journalEntries
    });
  });

  // ── Health ────────────────────────────────────────────────

  router.get("/health", (req, res) => {
    res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
  });

  return router;
}

module.exports = { createRoutes };
