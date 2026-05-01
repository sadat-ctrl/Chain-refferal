const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "referral_secret_2025";
const COMMISSION = [0, 500, 250, 125, 62, 31];

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Ingia kwanza" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Tokeni si sahihi" }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin tu" });
  next();
}

const now = () => new Date().toLocaleString();
const getSetting = (k) => db.prepare("SELECT value FROM settings WHERE key=?").get(k)?.value;
const getAdmin = () => db.prepare("SELECT * FROM members WHERE role='admin'").get();

function distributeCommissions(parentId, memberName, txnRef) {
  let ancId = parentId; let depth = 1;
  while (ancId && depth < COMMISSION.length) {
    const comm = COMMISSION[depth];
    if (comm) {
      db.prepare("UPDATE members SET earnings=earnings+? WHERE id=?").run(comm, ancId);
      db.prepare(`INSERT INTO transactions (id,type,from_id,to_id,amount,method,status,note,ref,created_at)
        VALUES (?,  'commission','admin',?,?,'internal','completed',?,?,?)`)
        .run(uuidv4(), ancId, comm, `Commission — ${memberName} (Kiwango ${depth})`, txnRef, now());
    }
    ancId = db.prepare("SELECT parent_id FROM members WHERE id=?").get(ancId)?.parent_id;
    depth++;
  }
}

// SIGNUP
app.post("/api/auth/signup", (req, res) => {
  try {
    const { name, phone, password, method, refCode } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "Weka jina!" });
    if (!phone?.trim()) return res.status(400).json({ error: "Weka simu!" });
    if (!password || password.length < 4) return res.status(400).json({ error: "Neno la siri liwe 4+" });

    if (db.prepare("SELECT id FROM members WHERE phone=?").get(phone.trim()))
      return res.status(400).json({ error: "Namba imeshasajiliwa!" });

    let parentId = getAdmin()?.id;
    if (refCode?.trim()) {
      const ref = db.prepare("SELECT * FROM members WHERE ref_code=?").get(refCode.trim().toUpperCase());
      if (!ref) return res.status(400).json({ error: "Referral code si sahihi!" });
      if (!ref.paid) return res.status(400).json({ error: "Aliyekualika hajalipa!" });
      const kids = db.prepare("SELECT COUNT(*) as c FROM members WHERE parent_id=?").get(ref.id).c;
      if (kids >= 2) return res.status(400).json({ error: "Aliyekualika amejaa!" });
      parentId = ref.id;
    }

    const parent = db.prepare("SELECT * FROM members WHERE id=?").get(parentId);
    const newId = uuidv4();
    const refCodeNew = name.trim().slice(0,3).toUpperCase() + uuidv4().slice(0,5).toUpperCase();

    db.prepare(`INSERT INTO members (id,name,phone,password,role,paid,parent_id,level,earnings,pay_method,ref_code,joined_at)
      VALUES (?,?,?,?,'member',0,?,?,0,?,?,?)`)
      .run(newId, name.trim(), phone.trim(), bcrypt.hashSync(password, 10), parentId, (parent?.level||0)+1, method||"tigo", refCodeNew, now());

    const token = jwt.sign({ id: newId, role: "member" }, JWT_SECRET, { expiresIn: "30d" });
    const member = db.prepare("SELECT id,name,phone,role,paid,level,earnings,pay_method,ref_code FROM members WHERE id=?").get(newId);
    res.json({ token, member, message: "Umesajiliwa! Sasa lipa kuanzisha akaunti." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// LOGIN
app.post("/api/auth/login", (req, res) => {
  try {
    const { phone, password } = req.body;
    const member = db.prepare("SELECT * FROM members WHERE phone=?").get(phone?.trim());
    if (!member || !bcrypt.compareSync(password, member.password))
      return res.status(400).json({ error: "Simu au neno la siri si sahihi!" });
    const token = jwt.sign({ id: member.id, role: member.role }, JWT_SECRET, { expiresIn: "30d" });
    const { password: _, ...safe } = member;
    res.json({ token, member: safe });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ME
app.get("/api/me", auth, (req, res) => {
  const member = db.prepare("SELECT id,name,phone,role,paid,level,earnings,pay_method,ref_code,parent_id FROM members WHERE id=?").get(req.user.id);
  const rows = db.prepare("SELECT key,value FROM settings").all();
  const settings = {}; rows.forEach(r => settings[r.key] = r.value);
  res.json({ member, settings });
});

// PAY CONFIRM
app.post("/api/pay/confirm", auth, (req, res) => {
  try {
    const member = db.prepare("SELECT * FROM members WHERE id=?").get(req.user.id);
    if (member.paid) return res.status(400).json({ error: "Umeshalipa!" });
    const fee = parseFloat(getSetting("entry_fee") || "2000");
    const txnRef = "TXN" + Date.now();
    db.prepare("UPDATE members SET paid=1 WHERE id=?").run(member.id);
    db.prepare(`INSERT INTO transactions (id,type,from_id,to_id,amount,method,status,note,ref,created_at)
      VALUES (?,  'payment',?,?,?,?,'completed',?,?,?)`)
      .run(uuidv4(), member.id, getAdmin()?.id, fee, member.pay_method, `Malipo — ${member.name}`, txnRef, now());
    if (member.parent_id) distributeCommissions(member.parent_id, member.name, txnRef);
    const updated = db.prepare("SELECT id,name,phone,role,paid,level,earnings,pay_method,ref_code FROM members WHERE id=?").get(member.id);
    res.json({ member: updated, message: "✅ Akaunti imewashwa!" });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// WITHDRAWAL REQUEST
app.post("/api/withdrawal/request", auth, (req, res) => {
  try {
    const { amount, method, phone } = req.body;
    const member = db.prepare("SELECT * FROM members WHERE id=?").get(req.user.id);
    const amt = parseFloat(amount);
    if (!amt || amt < 500) return res.status(400).json({ error: "Kiwango cha chini Tsh 500" });
    if (amt > member.earnings) return res.status(400).json({ error: "Mapato hayatoshi!" });
    db.prepare("UPDATE members SET earnings=earnings-? WHERE id=?").run(amt, member.id);
    db.prepare(`INSERT INTO withdrawals (id,member_id,member_name,amount,method,phone,status,created_at)
      VALUES (?,?,?,?,?,?,'pending',?)`)
      .run(uuidv4(), member.id, member.name, amt, method, phone.trim(), now());
    res.json({ message: "✅ Ombi limetumwa kwa Admin!" });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/withdrawal/my", auth, (req, res) => {
  res.json({ withdrawals: db.prepare("SELECT * FROM withdrawals WHERE member_id=? ORDER BY created_at DESC").all(req.user.id) });
});

app.get("/api/transactions/my", auth, (req, res) => {
  res.json({ transactions: db.prepare("SELECT * FROM transactions WHERE from_id=? OR to_id=? ORDER BY created_at DESC LIMIT 50").all(req.user.id, req.user.id) });
});

// ADMIN ROUTES
app.get("/api/admin/tree", auth, adminOnly, (req, res) => {
  res.json({ members: db.prepare("SELECT id,name,phone,paid,level,earnings,ref_code,parent_id,pay_method FROM members ORDER BY level").all() });
});

app.get("/api/admin/members", auth, adminOnly, (req, res) => {
  res.json({ members: db.prepare("SELECT id,name,phone,role,paid,level,earnings,pay_method,ref_code,parent_id,joined_at FROM members ORDER BY level").all() });
});

app.post("/api/admin/member/add", auth, adminOnly, (req, res) => {
  try {
    const { name, phone, method, parentId } = req.body;
    if (!name?.trim() || !phone?.trim()) return res.status(400).json({ error: "Weka jina na simu!" });
    if (db.prepare("SELECT id FROM members WHERE phone=?").get(phone.trim()))
      return res.status(400).json({ error: "Namba imeshasajiliwa!" });
    const pid = parentId || getAdmin()?.id;
    const parent = db.prepare("SELECT * FROM members WHERE id=?").get(pid);
    const kids = db.prepare("SELECT COUNT(*) as c FROM members WHERE parent_id=?").get(pid).c;
    if (kids >= 2) return res.status(400).json({ error: "Amejaa nafasi!" });
    const newId = uuidv4();
    const refCode = name.trim().slice(0,3).toUpperCase() + uuidv4().slice(0,5).toUpperCase();
    const defPass = phone.trim().slice(-4);
    const fee = parseFloat(getSetting("entry_fee") || "2000");
    const txnRef = "TXN" + Date.now();
    db.prepare(`INSERT INTO members (id,name,phone,password,role,paid,parent_id,level,earnings,pay_method,ref_code,joined_at)
      VALUES (?,?,?,?,'member',1,?,?,0,?,?,?)`)
      .run(newId, name.trim(), phone.trim(), bcrypt.hashSync(defPass,10), pid, (parent?.level||0)+1, method||"tigo", refCode, now());
    db.prepare(`INSERT INTO transactions (id,type,from_id,to_id,amount,method,status,note,ref,created_at)
      VALUES (?,'payment',?,?,?,?,'completed',?,?,?)`)
      .run(uuidv4(), newId, getAdmin()?.id, fee, method||"tigo", `Malipo — ${name}`, txnRef, now());
    distributeCommissions(pid, name.trim(), txnRef);
    res.json({ message: `✅ ${name} ameongezwa! Neno la siri: ${defPass}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/admin/withdrawals", auth, adminOnly, (req, res) => {
  res.json({ withdrawals: db.prepare("SELECT * FROM withdrawals ORDER BY created_at DESC").all() });
});

app.post("/api/admin/withdrawal/approve", auth, adminOnly, (req, res) => {
  try {
    const wd = db.prepare("SELECT * FROM withdrawals WHERE id=?").get(req.body.id);
    if (!wd || wd.status !== "pending") return res.status(400).json({ error: "Ombi halipatikani" });
    db.prepare("UPDATE withdrawals SET status='completed' WHERE id=?").run(wd.id);
    res.json({ message: `✅ Umelipa ${wd.amount} kwa ${wd.member_name}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/admin/withdrawal/reject", auth, adminOnly, (req, res) => {
  try {
    const wd = db.prepare("SELECT * FROM withdrawals WHERE id=?").get(req.body.id);
    if (!wd || wd.status !== "pending") return res.status(400).json({ error: "Ombi halipatikani" });
    db.prepare("UPDATE withdrawals SET status='rejected' WHERE id=?").run(wd.id);
    db.prepare("UPDATE members SET earnings=earnings+? WHERE id=?").run(wd.amount, wd.member_id);
    res.json({ message: "Ombi limekataliwa." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/admin/stats", auth, adminOnly, (req, res) => {
  res.json({
    totalMembers: db.prepare("SELECT COUNT(*) as c FROM members WHERE role!='admin'").get().c,
    paidMembers: db.prepare("SELECT COUNT(*) as c FROM members WHERE paid=1 AND role!='admin'").get().c,
    totalRevenue: db.prepare("SELECT SUM(amount) as s FROM transactions WHERE type='payment'").get().s || 0,
    totalCommissions: db.prepare("SELECT SUM(amount) as s FROM transactions WHERE type='commission'").get().s || 0,
    pendingWithdrawals: db.prepare("SELECT COUNT(*) as c FROM withdrawals WHERE status='pending'").get().c,
  });
});

app.get("/api/admin/settings", auth, adminOnly, (req, res) => {
  const rows = db.prepare("SELECT * FROM settings").all();
  const settings = {}; rows.forEach(r => settings[r.key] = r.value);
  res.json({ settings });
});

app.post("/api/admin/settings", auth, adminOnly, (req, res) => {
  const stmt = db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)");
  Object.entries(req.body.settings).forEach(([k,v]) => stmt.run(k, String(v)));
  res.json({ message: "✅ Mipangilio imehifadhiwa!" });
});

app.get("/api/admin/transactions", auth, adminOnly, (req, res) => {
  res.json({ transactions: db.prepare("SELECT * FROM transactions ORDER BY created_at DESC LIMIT 200").all() });
});

app.get("/api/settings/public", (req, res) => {
  const rows = db.prepare("SELECT key,value FROM settings WHERE key IN ('tigo_number','voda_number','selcom_number','entry_fee')").all();
  const settings = {}; rows.forEach(r => settings[r.key] = r.value);
  res.json({ settings });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`Server inaendesha port ${PORT}`));
