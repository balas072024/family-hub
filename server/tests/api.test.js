const request = require("supertest");
const path = require("path");
const fs = require("fs");

// Use test database
const TEST_DB = path.join(__dirname, "../../data/test.db");
process.env.DB_PATH = TEST_DB;
process.env.JWT_SECRET = "test-secret-key-for-testing-only";

const { getDb, initDb } = require("../src/db");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

let app, server, db;
let adminToken, memberToken;
let adminId, memberId;

beforeAll(async () => {
  // Clean test db
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);

  db = getDb();
  initDb(db);

  // Create test users
  adminId = crypto.randomUUID();
  memberId = crypto.randomUUID();
  const adminHash = bcrypt.hashSync("admin123", 10);
  const memberHash = bcrypt.hashSync("member123", 10);

  db.prepare("INSERT INTO users (id, username, display_name, emoji, color, role, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(adminId, "testadmin", "Test Admin", "👨", "#7c6bff", "admin", adminHash);
  db.prepare("INSERT INTO users (id, username, display_name, emoji, color, role, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(memberId, "testmember", "Test Member", "👩", "#00c9a7", "member", memberHash);

  // Import app after DB setup
  const appModule = require("../src/index");
  app = appModule.app;
  server = appModule.server;
});

afterAll(async () => {
  if (db) db.close();
  if (server) server.close();
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
});

// ── Auth Tests ────────────────────────────────────────────

describe("Auth", () => {
  test("POST /api/auth/login - success for admin", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: "testadmin", password: "admin123" });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.role).toBe("admin");
    adminToken = res.body.token;
  });

  test("POST /api/auth/login - success for member", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: "testmember", password: "member123" });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    memberToken = res.body.token;
  });

  test("POST /api/auth/login - wrong password", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: "testadmin", password: "wrong" });
    expect(res.status).toBe(401);
    expect(res.body.error).toBeDefined();
  });

  test("POST /api/auth/login - missing fields", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: "" });
    expect(res.status).toBe(400);
  });

  test("GET /api/auth/me - returns current user", async () => {
    const res = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.user.username).toBe("testadmin");
  });

  test("GET /api/auth/me - rejects no token", async () => {
    const res = await request(app).get("/api/auth/me");
    expect(res.status).toBe(401);
  });

  test("GET /api/auth/me - rejects invalid token", async () => {
    const res = await request(app)
      .get("/api/auth/me")
      .set("Authorization", "Bearer invalid-token");
    expect(res.status).toBe(401);
  });

  test("POST /api/auth/change-password - success", async () => {
    const res = await request(app)
      .post("/api/auth/change-password")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({ current_password: "member123", new_password: "newpass123" });
    expect(res.status).toBe(200);

    // Login with new password
    const login = await request(app)
      .post("/api/auth/login")
      .send({ username: "testmember", password: "newpass123" });
    expect(login.status).toBe(200);
    memberToken = login.body.token;

    // Reset password back
    await request(app)
      .post("/api/auth/change-password")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({ current_password: "newpass123", new_password: "member123" });
    const relogin = await request(app)
      .post("/api/auth/login")
      .send({ username: "testmember", password: "member123" });
    memberToken = relogin.body.token;
  });

  test("POST /api/auth/change-password - wrong current", async () => {
    const res = await request(app)
      .post("/api/auth/change-password")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({ current_password: "wrong", new_password: "newpass123" });
    expect(res.status).toBe(401);
  });
});

// ── Users Tests ───────────────────────────────────────────

describe("Users", () => {
  test("GET /api/users - list users", async () => {
    const res = await request(app)
      .get("/api/users")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.users.length).toBeGreaterThanOrEqual(2);
    // Password hash should NOT be in response
    expect(res.body.users[0].password_hash).toBeUndefined();
  });

  test("POST /api/users - admin can create user", async () => {
    const res = await request(app)
      .post("/api/users")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ username: "newuser", display_name: "New User", password: "pass123" });
    expect(res.status).toBe(201);
    expect(res.body.user.username).toBe("newuser");
  });

  test("POST /api/users - rejects duplicate username", async () => {
    const res = await request(app)
      .post("/api/users")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ username: "newuser", display_name: "Duplicate", password: "pass123" });
    expect(res.status).toBe(409);
  });

  test("POST /api/users - member cannot create user", async () => {
    const res = await request(app)
      .post("/api/users")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({ username: "hacker", display_name: "Hacker", password: "pass123" });
    expect(res.status).toBe(403);
  });
});

// ── Messages Tests ────────────────────────────────────────

describe("Messages", () => {
  let messageId;

  test("POST /api/messages - send message", async () => {
    const res = await request(app)
      .post("/api/messages")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ content: "Hello family!" });
    expect(res.status).toBe(201);
    expect(res.body.message.content).toBe("Hello family!");
    expect(res.body.message.display_name).toBe("Test Admin");
    messageId = res.body.message.id;
  });

  test("POST /api/messages - rejects empty", async () => {
    const res = await request(app)
      .post("/api/messages")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ content: "" });
    expect(res.status).toBe(400);
  });

  test("POST /api/messages - rejects too long", async () => {
    const res = await request(app)
      .post("/api/messages")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ content: "x".repeat(2001) });
    expect(res.status).toBe(400);
  });

  test("GET /api/messages - returns messages", async () => {
    const res = await request(app)
      .get("/api/messages")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBeGreaterThanOrEqual(1);
  });

  test("GET /api/messages?limit=1 - respects limit", async () => {
    // Add a second message
    await request(app)
      .post("/api/messages")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ content: "Second message" });

    const res = await request(app)
      .get("/api/messages?limit=1")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBe(1);
  });

  test("DELETE /api/messages/:id - owner can delete", async () => {
    const res = await request(app)
      .delete(`/api/messages/${messageId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });

  test("DELETE /api/messages/:id - non-owner member cannot delete", async () => {
    const msg = await request(app)
      .post("/api/messages")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ content: "Admin message" });

    const res = await request(app)
      .delete(`/api/messages/${msg.body.message.id}`)
      .set("Authorization", `Bearer ${memberToken}`);
    expect(res.status).toBe(403);
  });
});

// ── Todos Tests ───────────────────────────────────────────

describe("Todos", () => {
  let todoId;

  test("POST /api/todos - create todo", async () => {
    const res = await request(app)
      .post("/api/todos")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ text: "Buy groceries", priority: "high", due_date: "2026-04-01" });
    expect(res.status).toBe(201);
    expect(res.body.todo.text).toBe("Buy groceries");
    expect(res.body.todo.priority).toBe("high");
    expect(res.body.todo.done).toBe(0);
    todoId = res.body.todo.id;
  });

  test("POST /api/todos - rejects empty text", async () => {
    const res = await request(app)
      .post("/api/todos")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ text: "" });
    expect(res.status).toBe(400);
  });

  test("GET /api/todos - list todos", async () => {
    const res = await request(app)
      .get("/api/todos")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.todos.length).toBeGreaterThanOrEqual(1);
  });

  test("PATCH /api/todos/:id - toggle done", async () => {
    const res = await request(app)
      .patch(`/api/todos/${todoId}`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ done: true });
    expect(res.status).toBe(200);
    expect(res.body.todo.done).toBe(1);
    expect(res.body.todo.completed_at).toBeDefined();
  });

  test("PATCH /api/todos/:id - update text and priority", async () => {
    const res = await request(app)
      .patch(`/api/todos/${todoId}`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ text: "Updated task", priority: "urgent" });
    expect(res.status).toBe(200);
    expect(res.body.todo.text).toBe("Updated task");
    expect(res.body.todo.priority).toBe("urgent");
  });

  test("DELETE /api/todos/:id - owner can delete", async () => {
    const res = await request(app)
      .delete(`/api/todos/${todoId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });

  test("DELETE /api/todos/:id - 404 for nonexistent", async () => {
    const res = await request(app)
      .delete("/api/todos/99999")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });
});

// ── Notes Tests ───────────────────────────────────────────

describe("Notes", () => {
  let noteId;

  test("POST /api/notes - create note", async () => {
    const res = await request(app)
      .post("/api/notes")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "Shopping List", content: "Milk, Eggs, Bread" });
    expect(res.status).toBe(201);
    expect(res.body.note.title).toBe("Shopping List");
    noteId = res.body.note.id;
  });

  test("POST /api/notes - rejects empty title", async () => {
    const res = await request(app)
      .post("/api/notes")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "", content: "Some content" });
    expect(res.status).toBe(400);
  });

  test("GET /api/notes - list notes", async () => {
    const res = await request(app)
      .get("/api/notes")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.notes.length).toBeGreaterThanOrEqual(1);
  });

  test("PUT /api/notes/:id - update note", async () => {
    const res = await request(app)
      .put(`/api/notes/${noteId}`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "Updated List", content: "Milk, Eggs" });
    expect(res.status).toBe(200);
    expect(res.body.note.title).toBe("Updated List");
  });

  test("PUT /api/notes/:id - member cannot edit admin's note", async () => {
    const res = await request(app)
      .put(`/api/notes/${noteId}`)
      .set("Authorization", `Bearer ${memberToken}`)
      .send({ title: "Hacked", content: "Hacked content" });
    expect(res.status).toBe(403);
  });

  test("DELETE /api/notes/:id - owner can delete", async () => {
    const res = await request(app)
      .delete(`/api/notes/${noteId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });
});

// ── Events Tests ──────────────────────────────────────────

describe("Events", () => {
  let eventId;

  test("POST /api/events - create event", async () => {
    const res = await request(app)
      .post("/api/events")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "Family Dinner", event_date: "2026-04-15", event_time: "19:00", description: "At grandma's house" });
    expect(res.status).toBe(201);
    expect(res.body.event.title).toBe("Family Dinner");
    eventId = res.body.event.id;
  });

  test("POST /api/events - rejects missing date", async () => {
    const res = await request(app)
      .post("/api/events")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "No Date Event" });
    expect(res.status).toBe(400);
  });

  test("GET /api/events - list events", async () => {
    const res = await request(app)
      .get("/api/events")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.events.length).toBeGreaterThanOrEqual(1);
  });

  test("DELETE /api/events/:id - owner can delete", async () => {
    const res = await request(app)
      .delete(`/api/events/${eventId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });
});

// ── Shopping Lists Tests ──────────────────────────────────

describe("Shopping Lists", () => {
  let listId, itemId;

  test("POST /api/shopping - create list", async () => {
    const res = await request(app)
      .post("/api/shopping")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ name: "Weekly Groceries" });
    expect(res.status).toBe(201);
    expect(res.body.list.name).toBe("Weekly Groceries");
    listId = res.body.list.id;
  });

  test("GET /api/shopping - list all lists", async () => {
    const res = await request(app)
      .get("/api/shopping")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.lists.length).toBeGreaterThanOrEqual(1);
  });

  test("POST /api/shopping/:listId/items - add item", async () => {
    const res = await request(app)
      .post(`/api/shopping/${listId}/items`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ name: "Milk", quantity: "2L" });
    expect(res.status).toBe(201);
    expect(res.body.item.name).toBe("Milk");
    expect(res.body.item.quantity).toBe("2L");
    itemId = res.body.item.id;
  });

  test("GET /api/shopping/:listId/items - list items", async () => {
    const res = await request(app)
      .get(`/api/shopping/${listId}/items`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.items.length).toBe(1);
  });

  test("PATCH /api/shopping/items/:id - check item", async () => {
    const res = await request(app)
      .patch(`/api/shopping/items/${itemId}`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ checked: true });
    expect(res.status).toBe(200);
    expect(res.body.item.checked).toBe(1);
  });

  test("DELETE /api/shopping/items/:id - delete item", async () => {
    const res = await request(app)
      .delete(`/api/shopping/items/${itemId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });

  test("DELETE /api/shopping/:id - delete list", async () => {
    const res = await request(app)
      .delete(`/api/shopping/${listId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });
});

// ── Journal Tests ─────────────────────────────────────────

describe("Journal", () => {
  let entryId;

  test("POST /api/journal - create entry", async () => {
    const res = await request(app)
      .post("/api/journal")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "Amazing family day", content: "We went to the park!", mood: "happy" });
    expect(res.status).toBe(201);
    expect(res.body.entry.title).toBe("Amazing family day");
    expect(res.body.entry.mood).toBe("happy");
    entryId = res.body.entry.id;
  });

  test("POST /api/journal - rejects empty title", async () => {
    const res = await request(app)
      .post("/api/journal")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "", mood: "neutral" });
    expect(res.status).toBe(400);
  });

  test("POST /api/journal - rejects invalid mood", async () => {
    const res = await request(app)
      .post("/api/journal")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "Test", mood: "angry" });
    expect(res.status).toBe(400);
  });

  test("GET /api/journal - list entries", async () => {
    const res = await request(app)
      .get("/api/journal")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThanOrEqual(1);
  });

  test("DELETE /api/journal/:id - owner can delete", async () => {
    const res = await request(app)
      .delete(`/api/journal/${entryId}`)
      .set("Authorization", `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });

  test("DELETE /api/journal/:id - member cannot delete admin's entry", async () => {
    const entry = await request(app)
      .post("/api/journal")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ title: "Admin entry", mood: "neutral" });

    const res = await request(app)
      .delete(`/api/journal/${entry.body.entry.id}`)
      .set("Authorization", `Bearer ${memberToken}`);
    expect(res.status).toBe(403);
  });
});

// ── Health Tests ──────────────────────────────────────────

describe("Health", () => {
  test("GET /api/health - returns status (no auth needed)", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.uptime).toBeDefined();
  });
});

// ── Security Tests ────────────────────────────────────────

describe("Security", () => {
  test("XSS in message content is stored as-is but will be escaped on render", async () => {
    const res = await request(app)
      .post("/api/messages")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ content: '<script>alert("xss")</script>' });
    expect(res.status).toBe(201);
    // Content is stored as text, frontend escapes it
    expect(res.body.message.content).toBe('<script>alert("xss")</script>');
  });

  test("All protected routes reject unauthenticated requests", async () => {
    const routes = [
      { method: "get", path: "/api/users" },
      { method: "get", path: "/api/messages" },
      { method: "get", path: "/api/todos" },
      { method: "get", path: "/api/notes" },
      { method: "get", path: "/api/events" },
      { method: "get", path: "/api/shopping" },
      { method: "get", path: "/api/journal" },
    ];
    for (const r of routes) {
      const res = await request(app)[r.method](r.path);
      expect(res.status).toBe(401);
    }
  });
});
