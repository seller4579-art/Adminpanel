require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, "public")));

const CREDIT = { credit: "@Boss_Hcrr", developer: "@Boss_Hcrr" };

const API_REGISTRY = [
  { type: "number",  label: "Number Info",  prefix: "num_",  route: "/lookup",   paramName: "number",     icon: "📞" },
  { type: "osint",   label: "Number Adv",   prefix: "osin_", route: "/osint",    paramName: "query",      icon: "🔍" },
  { type: "vehicle", label: "Vehicle Info", prefix: "veh_",  route: "/vehicle",  paramName: "number",     icon: "🚗" },
  { type: "tgnum",   label: "TG to Number", prefix: "tgn_",  route: "/tgnum",    paramName: "tgusername", icon: "📲" },
  { type: "email",   label: "Email Info",   prefix: "eml_",  route: "/email",    paramName: "email",      icon: "📧" },
  { type: "ip",      label: "IP Lookup",    prefix: "ip_",   route: "/iplookup", paramName: "ip",         icon: "🌐" },
  { type: "gst",     label: "GST Info",     prefix: "gst_",  route: "/gst",      paramName: "gstin",      icon: "🏢" },
  { type: "pan2gst", label: "PAN to GST",   prefix: "p2g_",  route: "/pan2gst",  paramName: "pan",        icon: "🔎" },
  { type: "ai",      label: "AI Chat",      prefix: "ai_",   route: "/ai",       paramName: "msg",        icon: "🤖" },
];

// AI fallback chain — no env needed
const AI_APIS = [
  { url: "https://api-llama3.vercel.app/",                   param: "msg" },
  { url: "https://api-chatgpt4.eternalowner06.workers.dev/", param: "prompt" },
  { url: "https://api-rebix.vercel.app/api/deepseek-v3",    param: "q" },
];

// Credit pricing: 1 credit = 7 days, 2 = 15 days, 4 = 30 days
const CREDIT_PLANS = [
  { credits: 1, days: 7,  label: "1 Credit → 7 Days" },
  { credits: 2, days: 15, label: "2 Credits → 15 Days" },
  { credits: 4, days: 30, label: "4 Credits → 30 Days" },
];

// ─── SCHEMAS ──────────────────────────────────────────────────────────────────
const AdminSchema = new mongoose.Schema({
  username:     { type: String, unique: true, required: true },
  password:     { type: String, required: true },
  allowedTypes: { type: [String], default: ["all"] },
  credits:      { type: Number, default: 0 },
  createdAt:    { type: Date, default: Date.now },
});

const ApiKeySchema = new mongoose.Schema({
  key:        { type: String, unique: true, required: true },
  keyType:    { type: String, required: true },
  label:      { type: String, default: "" },
  createdBy:  { type: String, required: true },
  expiresAt:  { type: Date, required: true },
  usageCount: { type: Number, default: 0 },
  usageLimit: { type: Number, default: null },
  dailyLimit: { type: Number, default: null },
  dailyUsed:  { type: Number, default: 0 },
  dailyReset: { type: Date, default: Date.now },
  isActive:   { type: Boolean, default: true },
  createdAt:  { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: null },
});

const SessionSchema = new mongoose.Schema({
  username:  { type: String, required: true },
  sessionId: { type: String, unique: true, required: true },
  userAgent: { type: String, default: "" },
  ip:        { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  lastSeen:  { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
});

const Admin   = mongoose.model("Admin", AdminSchema);
const ApiKey  = mongoose.model("ApiKey", ApiKeySchema);
const Session = mongoose.model("Session", SessionSchema);

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function makeKey(type) {
  const api = API_REGISTRY.find(a => a.type === type);
  return (api ? api.prefix : "key_") + crypto.randomBytes(20).toString("hex");
}
function signToken(payload, sessionId) {
  return jwt.sign({ ...payload, sessionId }, process.env.JWT_SECRET, { expiresIn: "8h" });
}
function isSuperAdmin(u) { return u === process.env.SUPER_ADMIN_USERNAME; }
function getIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown";
}
function addCredit(data) {
  if (data && typeof data === "object" && !Array.isArray(data)) {
    data.credit = "@Boss_Hcrr";
    data.developer = "@Boss_Hcrr";
  }
  return data;
}

// Safe upstream GET — always returns JSON
async function upstreamGet(url, params = {}, extraHeaders = {}) {
  const r = await axios.get(url, {
    params, timeout: 15000, responseType: "text",
    headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json", ...extraHeaders },
  });
  const text = typeof r.data === "string" ? r.data.trim() : JSON.stringify(r.data);
  if (text.startsWith("{") || text.startsWith("[")) return JSON.parse(text);
  throw new Error("Non-JSON response: " + text.substring(0, 120));
}

async function createSession(username, req) {
  const sessionId = crypto.randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + 8 * 3600 * 1000);
  await Session.create({ username, sessionId, userAgent: req.headers["user-agent"] || "", ip: getIp(req), expiresAt });
  return sessionId;
}
async function cleanSessions() {
  await Session.deleteMany({ expiresAt: { $lt: new Date() } });
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
async function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const session = await Session.findOne({ sessionId: decoded.sessionId });
    if (!session || session.expiresAt < new Date()) {
      if (session) await Session.findByIdAndDelete(session._id);
      return res.status(401).json({ error: "Session expired" });
    }
    await Session.findByIdAndUpdate(session._id, { lastSeen: new Date() });
    req.user = decoded;
    next();
  } catch { return res.status(401).json({ error: "Invalid token" }); }
}
function superOnly(req, res, next) {
  if (!req.user || !isSuperAdmin(req.user.username))
    return res.status(403).json({ error: "Super admin only" });
  next();
}

async function validateKey(apiKey, requiredType) {
  const doc = await ApiKey.findOne({ key: apiKey });
  if (!doc)          return { error: "Invalid API key", status: 401 };
  if (!doc.isActive) return { error: "API key disabled", status: 403 };
  if (doc.keyType !== requiredType) return { error: `Key not authorized for ${requiredType}`, status: 403 };
  if (doc.expiresAt < new Date())   return { error: "API key expired", status: 403 };
  if (doc.usageLimit && doc.usageCount >= doc.usageLimit) return { error: "Usage limit reached", status: 429 };
  if (doc.dailyLimit) {
    const now = new Date();
    if (now - new Date(doc.dailyReset) > 86400000) {
      await ApiKey.findByIdAndUpdate(doc._id, { dailyUsed: 0, dailyReset: now });
      doc.dailyUsed = 0;
    }
    if (doc.dailyUsed >= doc.dailyLimit) return { error: "Daily limit reached", status: 429 };
  }
  return { keyDoc: doc };
}
async function incUsage(keyId) {
  await ApiKey.findByIdAndUpdate(keyId, { $inc: { usageCount: 1, dailyUsed: 1 }, lastUsedAt: new Date() });
}

// ─── HTML ROUTES ──────────────────────────────────────────────────────────────
app.get("/admin", (req, res) => {
  const token = req.cookies?.token;
  if (token && process.env.JWT_SECRET) {
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      if (user?.username) return res.redirect(isSuperAdmin(user.username) ? "/admin/dashboard" : "/admin/panel");
    } catch { res.clearCookie("token"); }
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});
app.get("/admin/dashboard", authMiddleware, superOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "mainadmin.html"));
});
app.get("/admin/panel", authMiddleware, (req, res) => {
  if (isSuperAdmin(req.user.username)) return res.redirect("/admin/dashboard");
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
  if (isSuperAdmin(username)) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD)
      return res.status(401).json({ error: "Invalid credentials" });
    const sid = await createSession(username, req);
    res.cookie("token", signToken({ username, role: "superadmin" }, sid), { httpOnly: true, sameSite: "lax", maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password)))
    return res.status(401).json({ error: "Invalid credentials" });
  const sid = await createSession(username, req);
  res.cookie("token", signToken({ username, role: "admin" }, sid), { httpOnly: true, sameSite: "lax", maxAge: 8 * 3600 * 1000 });
  return res.json({ success: true, role: "admin" });
});

app.post("/admin/logout", authMiddleware, async (req, res) => {
  await Session.findOneAndDelete({ sessionId: req.user?.sessionId });
  res.clearCookie("token");
  res.json({ success: true });
});

app.get("/admin/api/me", authMiddleware, async (req, res) => {
  if (isSuperAdmin(req.user.username))
    return res.json({ username: req.user.username, role: "superadmin", allowedTypes: ["all"], credits: 999999 });
  const admin = await Admin.findOne({ username: req.user.username });
  res.json({
    username: req.user.username, role: "admin",
    allowedTypes: admin?.allowedTypes || ["all"],
    credits: admin?.credits || 0,
    creditPlans: CREDIT_PLANS,
  });
});

app.get("/admin/api/config", authMiddleware, (req, res) => {
  res.json({
    apiTypes: API_REGISTRY.map(a => ({ type: a.type, label: a.label, icon: a.icon, route: a.route, paramName: a.paramName, prefix: a.prefix })),
    creditPlans: CREDIT_PLANS,
  });
});

// ─── STATS ────────────────────────────────────────────────────────────────────
app.get("/admin/api/stats", authMiddleware, superOnly, async (req, res) => {
  await cleanSessions();
  const [totalAdmins, totalKeys, activeKeys, totalSessions] = await Promise.all([
    Admin.countDocuments(), ApiKey.countDocuments(),
    ApiKey.countDocuments({ isActive: true, expiresAt: { $gt: new Date() } }),
    Session.countDocuments(),
  ]);
  res.json({ totalAdmins, totalKeys, activeKeys, totalSessions });
});

// ─── SESSIONS ─────────────────────────────────────────────────────────────────
app.get("/admin/api/sessions/me", authMiddleware, async (req, res) => {
  await cleanSessions();
  res.json({ sessions: await Session.find({ username: req.user.username }).sort({ lastSeen: -1 }).lean() });
});
app.get("/admin/api/sessions/all", authMiddleware, superOnly, async (req, res) => {
  await cleanSessions();
  const sessions = await Session.find().sort({ username: 1, lastSeen: -1 }).lean();
  const byUser = {};
  for (const s of sessions) { if (!byUser[s.username]) byUser[s.username] = []; byUser[s.username].push(s); }
  res.json({ byUser, total: sessions.length });
});
app.delete("/admin/api/sessions/:id", authMiddleware, async (req, res) => {
  const s = await Session.findById(req.params.id);
  if (!s) return res.status(404).json({ error: "Not found" });
  if (!isSuperAdmin(req.user.username) && s.username !== req.user.username) return res.status(403).json({ error: "Forbidden" });
  await Session.findByIdAndDelete(req.params.id);
  res.json({ message: "Revoked" });
});
app.delete("/admin/api/sessions/user/:username", authMiddleware, superOnly, async (req, res) => {
  if (isSuperAdmin(req.params.username)) return res.status(400).json({ error: "Cannot revoke superadmin" });
  await Session.deleteMany({ username: req.params.username });
  res.json({ message: "Sessions revoked" });
});

// ─── ADMINS ───────────────────────────────────────────────────────────────────
app.get("/admin/api/admins", authMiddleware, superOnly, async (req, res) => {
  const admins = await Admin.find({}, { password: 0 }).lean();
  const result = await Promise.all(admins.map(async a => ({
    ...a,
    keyCount: await ApiKey.countDocuments({ createdBy: a.username }),
    sessionCount: await Session.countDocuments({ username: a.username }),
  })));
  res.json({ admins: result });
});

app.post("/admin/api/admins", authMiddleware, superOnly, async (req, res) => {
  const { username, password, allowedTypes = ["all"], credits = 0 } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Reserved username" });
  if (await Admin.findOne({ username })) return res.status(409).json({ error: "Already exists" });
  await Admin.create({ username, password: await bcrypt.hash(password, 10), allowedTypes, credits });
  res.status(201).json({ message: `Admin "${username}" created` });
});

app.delete("/admin/api/admins/:username", authMiddleware, superOnly, async (req, res) => {
  if (isSuperAdmin(req.params.username)) return res.status(400).json({ error: "Cannot delete superadmin" });
  const admin = await Admin.findOneAndDelete({ username: req.params.username });
  if (!admin) return res.status(404).json({ error: "Not found" });
  await ApiKey.deleteMany({ createdBy: req.params.username });
  await Session.deleteMany({ username: req.params.username });
  res.json({ message: `Deleted "${req.params.username}"` });
});

// Add credits to admin
app.patch("/admin/api/admins/:username/credits", authMiddleware, superOnly, async (req, res) => {
  const { credits } = req.body;
  if (credits === undefined) return res.status(400).json({ error: "credits required" });
  const admin = await Admin.findOneAndUpdate(
    { username: req.params.username },
    { $inc: { credits: parseInt(credits) } },
    { new: true, select: "-password" }
  );
  if (!admin) return res.status(404).json({ error: "Not found" });
  res.json({ message: "Credits updated", credits: admin.credits });
});

// ─── KEYS ─────────────────────────────────────────────────────────────────────
app.get("/admin/api/my-keys", authMiddleware, async (req, res) => {
  res.json({ keys: await ApiKey.find({ createdBy: req.user.username }).sort({ createdAt: -1 }).lean() });
});

app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days, credits, customDays, usageLimit = 0, dailyLimit = 0, keyType = "number" } = req.body;
  if (!API_REGISTRY.find(a => a.type === keyType)) return res.status(400).json({ error: "Invalid key type" });

  let finalDays = 1;

  if (isSuperAdmin(req.user.username)) {
    // Superadmin: can use days, credits, or customDays directly
    if (customDays) finalDays = parseInt(customDays);
    else if (credits) {
      const plan = CREDIT_PLANS.find(p => p.credits === parseInt(credits));
      finalDays = plan ? plan.days : parseInt(credits) * 7;
    } else finalDays = parseInt(days) || 1;
  } else {
    // Admin: must spend credits
    const admin = await Admin.findOne({ username: req.user.username });
    const allowed = admin?.allowedTypes || ["all"];
    if (!allowed.includes("all") && !allowed.includes(keyType))
      return res.status(403).json({ error: `No access to ${keyType}` });

    const creditCost = parseInt(credits) || 1;
    if ((admin?.credits || 0) < creditCost)
      return res.status(402).json({ error: `Not enough credits. You have ${admin?.credits || 0}, need ${creditCost}` });

    const plan = CREDIT_PLANS.find(p => p.credits === creditCost);
    finalDays = plan ? plan.days : creditCost * 7;

    // Deduct credits
    await Admin.findByIdAndUpdate(admin._id, { $inc: { credits: -creditCost } });
  }

  const key = makeKey(keyType);
  const expiresAt = new Date(Date.now() + finalDays * 24 * 3600 * 1000);
  await ApiKey.create({
    key, label: label || "", createdBy: req.user.username, expiresAt, keyType,
    usageLimit: usageLimit > 0 ? usageLimit : null,
    dailyLimit: dailyLimit > 0 ? dailyLimit : null,
  });
  res.status(201).json({ key, expiresAt, days: finalDays, message: "Key created" });
});

// Update key — extend/reduce time, change limits
app.patch("/admin/api/my-keys/:id", authMiddleware, async (req, res) => {
  const { addDays, setDays, usageLimit, dailyLimit, isActive } = req.body;
  const filter = { _id: req.params.id };
  if (!isSuperAdmin(req.user.username)) filter.createdBy = req.user.username;
  const doc = await ApiKey.findOne(filter);
  if (!doc) return res.status(404).json({ error: "Not found or unauthorized" });
  const update = {};
  if (addDays) {
    const base = doc.expiresAt > new Date() ? doc.expiresAt : new Date();
    update.expiresAt = new Date(base.getTime() + parseInt(addDays) * 24 * 3600 * 1000);
  }
  if (setDays) update.expiresAt = new Date(Date.now() + parseInt(setDays) * 24 * 3600 * 1000);
  if (usageLimit !== undefined) update.usageLimit = parseInt(usageLimit) > 0 ? parseInt(usageLimit) : null;
  if (dailyLimit !== undefined) update.dailyLimit = parseInt(dailyLimit) > 0 ? parseInt(dailyLimit) : null;
  if (isActive !== undefined) update.isActive = Boolean(isActive);
  const updated = await ApiKey.findByIdAndUpdate(doc._id, update, { new: true });
  res.json({ message: "Key updated", key: updated });
});

app.delete("/admin/api/my-keys/:id", authMiddleware, async (req, res) => {
  const filter = { _id: req.params.id };
  if (!isSuperAdmin(req.user.username)) filter.createdBy = req.user.username;
  const key = await ApiKey.findOneAndDelete(filter);
  if (!key) return res.status(404).json({ error: "Not found" });
  res.json({ message: "Deleted" });
});

app.get("/admin/api/all-keys", authMiddleware, superOnly, async (req, res) => {
  res.json({ keys: await ApiKey.find().sort({ createdAt: -1 }).lean() });
});

app.patch("/admin/api/all-keys/:id", authMiddleware, superOnly, async (req, res) => {
  const { addDays, setDays, usageLimit, dailyLimit, isActive } = req.body;
  const doc = await ApiKey.findById(req.params.id);
  if (!doc) return res.status(404).json({ error: "Not found" });
  const update = {};
  if (addDays) {
    const base = doc.expiresAt > new Date() ? doc.expiresAt : new Date();
    update.expiresAt = new Date(base.getTime() + parseInt(addDays) * 24 * 3600 * 1000);
  }
  if (setDays) update.expiresAt = new Date(Date.now() + parseInt(setDays) * 24 * 3600 * 1000);
  if (usageLimit !== undefined) update.usageLimit = parseInt(usageLimit) > 0 ? parseInt(usageLimit) : null;
  if (dailyLimit !== undefined) update.dailyLimit = parseInt(dailyLimit) > 0 ? parseInt(dailyLimit) : null;
  if (isActive !== undefined) update.isActive = Boolean(isActive);
  const updated = await ApiKey.findByIdAndUpdate(doc._id, update, { new: true });
  res.json({ message: "Key updated", key: updated });
});

app.delete("/admin/api/all-keys/:id", authMiddleware, superOnly, async (req, res) => {
  const key = await ApiKey.findByIdAndDelete(req.params.id);
  if (!key) return res.status(404).json({ error: "Not found" });
  res.json({ message: "Deleted" });
});

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC APIs
// ═══════════════════════════════════════════════════════════════════════════════

// 1. NUMBER INFO
app.get("/lookup", async (req, res) => {
  const { number, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!number) return res.status(400).json({ error: "number required", ...CREDIT });
  if (!key)    return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "number");
  if (error) return res.status(status).json({ error, ...CREDIT });
  if (!process.env.UPSTREAM_API_URL) return res.status(503).json({ error: "Not configured", ...CREDIT });
  try {
    const data = await upstreamGet(`${process.env.UPSTREAM_API_URL}?number=${encodeURIComponent(number)}`, {}, { "ngrok-skip-browser-warning": "true" });
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) { return res.status(500).json({ error: err.message, ...CREDIT }); }
});

// 2. NUMBER ADV
app.get("/osint", async (req, res) => {
  const { query, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!query) return res.status(400).json({ error: "query required", ...CREDIT });
  if (!key)   return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "osint");
  if (error) return res.status(status).json({ error, ...CREDIT });
  if (!process.env.OSINT_API_URL) return res.status(503).json({ error: "Not configured", ...CREDIT });
  try {
    const data = await upstreamGet(process.env.OSINT_API_URL, { key: process.env.OSINT_API_KEY, query });
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) { return res.status(500).json({ error: err.message, ...CREDIT }); }
});

// 3. VEHICLE INFO — fixed HTML response
app.get("/vehicle", async (req, res) => {
  const { number, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!number) return res.status(400).json({ error: "number required (e.g. RJ14CV0002)", ...CREDIT });
  if (!key)    return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "vehicle");
  if (error) return res.status(status).json({ error, ...CREDIT });
  if (!process.env.UPSTREAM_VEHICLE_URL) return res.status(503).json({ error: "Not configured", ...CREDIT });
  try {
    const r = await axios.get(`${process.env.UPSTREAM_VEHICLE_URL}?number=${encodeURIComponent(number)}`, {
      timeout: 15000,
      responseType: "text",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, */*",
        "Referer": "https://vehicle-info-vert.vercel.app/",
        "x-requested-with": "XMLHttpRequest",
      },
    });
    let text = typeof r.data === "string" ? r.data.trim() : JSON.stringify(r.data);
    // If HTML returned, extract JSON from script tags or return error
    if (text.startsWith("<")) {
      // Try to extract JSON from HTML
      const match = text.match(/\{[\s\S]*\}/);
      if (match) {
        try {
          const data = JSON.parse(match[0]);
          await incUsage(keyDoc._id);
          return res.json(addCredit(data));
        } catch {}
      }
      return res.status(502).json({ error: "Vehicle API returned HTML — check UPSTREAM_VEHICLE_URL", ...CREDIT });
    }
    const data = JSON.parse(text);
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ error: err.message, ...CREDIT });
    return res.status(500).json({ error: err.message, ...CREDIT });
  }
});

// 4. TG TO NUMBER
app.get("/tgnum", async (req, res) => {
  const { tgusername, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!tgusername) return res.status(400).json({ error: "tgusername required", ...CREDIT });
  if (!key)        return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "tgnum");
  if (error) return res.status(status).json({ error, ...CREDIT });
  if (!process.env.UPSTREAM_TG_NUM_URL) return res.status(503).json({ error: "Not configured", ...CREDIT });
  try {
    const data = await upstreamGet(process.env.UPSTREAM_TG_NUM_URL, { tgusername });
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) { return res.status(500).json({ error: err.message, ...CREDIT }); }
});

// 5. EMAIL INFO
app.get("/email", async (req, res) => {
  const { email, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!email) return res.status(400).json({ error: "email required", ...CREDIT });
  if (!key)   return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!email.includes("@")) return res.status(400).json({ error: "Invalid email", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "email");
  if (error) return res.status(status).json({ error, ...CREDIT });
  if (!process.env.UPSTREAM_EMAIL_URL) return res.status(503).json({ error: "Not configured", ...CREDIT });
  try {
    const data = await upstreamGet(process.env.UPSTREAM_EMAIL_URL, { key: process.env.EMAIL_API_KEY, email });
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) { return res.status(500).json({ error: err.message, ...CREDIT }); }
});

// 6. IP LOOKUP
app.get("/iplookup", async (req, res) => {
  const { ip, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  const targetIp = ip || getIp(req);
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "ip");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    const data = await upstreamGet(`http://ip-api.com/json/${encodeURIComponent(targetIp)}`, {
      fields: "status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"
    });
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) { return res.status(500).json({ error: err.message, ...CREDIT }); }
});

// 7. GST INFO
app.get("/gst", async (req, res) => {
  const { gstin, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!gstin) return res.status(400).json({ error: "gstin required", ...CREDIT });
  if (!key)   return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "gst");
  if (error) return res.status(status).json({ error, ...CREDIT });
  if (!process.env.UPSTREAM_GST_API_URL) return res.status(503).json({ error: "Not configured", ...CREDIT });
  try {
    const data = await upstreamGet(`${process.env.UPSTREAM_GST_API_URL}?gstin=${encodeURIComponent(gstin)}`);
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) { return res.status(500).json({ error: err.message, ...CREDIT }); }
});

// 8. PAN TO GST
app.get("/pan2gst", async (req, res) => {
  const { pan, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!pan) return res.status(400).json({ error: "pan required", ...CREDIT });
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/i.test(pan)) return res.status(400).json({ error: "Invalid PAN", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "pan2gst");
  if (error) return res.status(status).json({ error, ...CREDIT });
  if (!process.env.UPSTREAM_PAN_GST_API_URL) return res.status(503).json({ error: "Not configured", ...CREDIT });
  try {
    const data = await upstreamGet(`${process.env.UPSTREAM_PAN_GST_API_URL}?pan=${encodeURIComponent(pan.toUpperCase())}`);
    await incUsage(keyDoc._id);
    return res.json(addCredit(data));
  } catch (err) { return res.status(500).json({ error: err.message, ...CREDIT }); }
});

// 9. AI CHAT — auto fallback, no env needed
app.get("/ai", async (req, res) => {
  const { msg, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!msg) return res.status(400).json({ error: "msg required", ...CREDIT });
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "ai");
  if (error) return res.status(status).json({ error, ...CREDIT });
  for (const ai of AI_APIS) {
    try {
      const params = {};
      params[ai.param] = msg;
      const data = await upstreamGet(ai.url, params);
      await incUsage(keyDoc._id);
      return res.json(addCredit(data));
    } catch { continue; }
  }
  return res.status(500).json({ error: "All AI APIs failed, try again later", ...CREDIT });
});

// ─── START ────────────────────────────────────────────────────────────────────
async function start() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("MongoDB connected");
  await cleanSessions();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server: http://localhost:${PORT}/admin`);
    console.log("Credit: @Boss_Hcrr | Developer: @Boss_Hcrr");
  });
}

start().catch(err => { console.error(err); process.exit(1); });
