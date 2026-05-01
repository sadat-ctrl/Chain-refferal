const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const db = new Database("./referral.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    paid INTEGER DEFAULT 0,
    parent_id TEXT REFERENCES members(id),
    level INTEGER DEFAULT 0,
    earnings REAL DEFAULT 0,
    pay_method TEXT DEFAULT 'tigo',
    ref_code TEXT UNIQUE NOT NULL,
    joined_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    from_id TEXT,
    to_id TEXT,
    amount REAL NOT NULL,
    method TEXT,
    status TEXT DEFAULT 'completed',
    note TEXT,
    ref TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS withdrawals (
    id TEXT PRIMARY KEY,
    member_id TEXT REFERENCES members(id),
    member_name TEXT,
    amount REAL NOT NULL,
    method TEXT NOT NULL,
    phone TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

const adminExists = db.prepare("SELECT id FROM members WHERE role='admin'").get();
if (!adminExists) {
  const adminId = uuidv4();
  const hash = bcrypt.hashSync("admin1234", 10);
  const now = new Date().toLocaleString();
  db.prepare(`
    INSERT INTO members (id,name,phone,password,role,paid,level,earnings,pay_method,ref_code,joined_at)
    VALUES (?,?,?,?,'admin',1,0,0,'tigo','ADMIN001',?)
  `).run(adminId, "Admin", "0770527179", hash, now);

  const st = db.prepare("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)");
  st.run("tigo_number", "+255770527179");
  st.run("voda_number", "+255799537179");
  st.run("selcom_number", "5525101542364");
  st.run("entry_fee", "2000");
  st.run("max_referrals", "2");
  console.log("Admin created!");
}

module.exports = db;
