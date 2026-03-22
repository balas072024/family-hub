require("dotenv").config();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { getDb, initDb } = require("./db");

const db = getDb();
initDb(db);

const defaultUsers = [
  { username: "bala", display_name: "Bala", emoji: "👨", color: "#7c6bff", role: "admin", password: "Family@2024" },
  { username: "wife", display_name: "Wife", emoji: "👩", color: "#00c9a7", role: "member", password: "Family@2024" },
  { username: "child", display_name: "Child", emoji: "👦", color: "#f59e0b", role: "member", password: "Family@2024" },
  { username: "parent1", display_name: "Parent 1", emoji: "👴", color: "#ff6b6b", role: "member", password: "Family@2024" },
  { username: "parent2", display_name: "Parent 2", emoji: "👵", color: "#3dd68c", role: "member", password: "Family@2024" },
];

const insert = db.prepare(
  "INSERT OR IGNORE INTO users (id, username, display_name, emoji, color, role, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)"
);

const insertMany = db.transaction((users) => {
  for (const u of users) {
    const hash = bcrypt.hashSync(u.password, 10);
    insert.run(crypto.randomUUID(), u.username, u.display_name, u.emoji, u.color, u.role, hash);
  }
});

insertMany(defaultUsers);

const count = db.prepare("SELECT COUNT(*) as c FROM users").get();
console.log(`✅ Seed complete. ${count.c} users in database.`);
console.log("Default password for all users: Family@2024");
console.log("⚠️  Change passwords after first login!\n");

db.close();
