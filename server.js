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
  { type: "number",   label: "Number Info",   prefix: "num_",  route: "/lookup",   paramName: "number", icon: "📞", envKey: "UPSTREAM_API_URL" },
  { type: "telegram", label: "Telegram Info", prefix: "tg_",   route: "/tg",       paramName: "userid", icon: "✈️",  envKey: "UPSTREAM_TG_API_URL" },
  { type: "upi",      label: "UPI Info",      prefix: "upi_",  route: "/upi",      paramName: "upi",    icon: "💳", envKey: "UPSTREAM_UPI_API_URL" },
  { type: "imei",     label: "IMEI Info",     prefix: "imei_", route: "/imei",     paramName: "imei",   icon: "📱", envKey: "UPSTREAM_IMEI_API_URL" },
  { type: "aadhar",   label: "Aadhar Info",   prefix: "aad_",  route: "/aadhar",   paramName: "aadhar", icon: "🆔", envKey: "UPSTREAM_AADHAR_API_URL" },
  { type: "pan",      label: "PAN Info",      prefix: "pan_",  route: "/pan",      paramName: "pan",    icon: "🪪", envKey: "UPSTREAM_PAN_API_URL" },
  { type: "rto",      label: "RTO Info",      prefix: "rto_",  route: "/rto",      paramName: "rc",     icon: "🚗", envKey: "UPSTREAM_RTO_API_URL" },
  { type: "ip",       label: "IP Lookup",     prefix: "ip_",   route: "/iplookup", paramName: "ip",     icon: "🌐", envKey: "UPSTREAM_IP_API_URL" },
  { type: "gst",      label: "GST Info",      prefix: "gst_",  route: "/gst",      paramName: "gstin",  icon: "🏢", envKey: "UPSTREAM_GST_API_URL" },
  { type: "pan2gst",  label: "PAN to GST",    prefix: "p2g_",  route: "/pan2gst",  paramName: "pan",    icon: "🔎", envKey: "UPSTREAM_PAN_GST_API_URL" },
  { type: "osint",    label: "Number Adv",    prefix: "osin_", route: "/osint",    paramName: "query",  icon: "🔍", envKey: "OSINT_API_URL" },
  { type: "tgnum",    label: "TG to Number",  prefix: "tgn_",  route: "/tgnum",    paramName: "tgusername", icon: "📲", envKey: "UPSTREAM_TG_NUM_URL" },
  { type: "aadharv2", label: "Aadhar Adv",    prefix: "aadv_", route: "/aadharv2", paramName: "aadhar", icon: "🆔", envKey: "UPSTREAM_AADHAR_V2_URL" },
];

const AdminSchema = new mongoose.Schema({
  username:     { type: String, unique: true, required: true },
  password:     { type: String, required: true },
  allowedTypes: { type: [String], default: ["all"] },
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

function makeKey(type) {
  const api = API_REGISTRY.find(a => a.type === type);
  const prefix = api ? api.prefix : "key_";
  return prefix + crypto.randomBytes(20).toString("hex");
}

function signToken(payload, sessionId) {
  return jwt.sign({ ...payload, sessionId }, process.env.JWT_SECRET, { expiresIn: "8h" });
}

function isSuperAdmin(username) {
  return username === process.env.SUPER_ADMIN_USERNAME;
}

function getIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown";
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

// ─── AUTH MIDDLEWARE ── FIXED: strict token validation ───────────────────────
async function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized - No token" });
  if (!process.env.JWT_SECRET) return res.status(500).json({ error: "Server misconfigured" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // Verify session exists in DB
    const session = await Session.findOne({ sessionId: decoded.sessionId });
    if (!session) return res.status(401).json({ error: "Session expired or invalid" });
    if (session.expiresAt < new Date()) {
      await Session.findByIdAndDelete(session._id);
      return res.status(401).json({ error: "Session expired" });
    }
    await Session.findByIdAndUpdate(session._id, { lastSeen: new Date() });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
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

// ─── HTML ROUTES ── FIXED: proper login bypass protection ────────────────────
app.get("/admin", (req, res) => {
  const token = req.cookies?.token;
  if (token && process.env.JWT_SECRET) {
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      if (user && user.username) {
        return res.redirect(isSuperAdmin(user.username) ? "/admin/dashboard" : "/admin/panel");
      }
    } catch (e) {
      // Invalid token — clear it and show login
      res.clearCookie("token");
    }
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

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (isSuperAdmin(username)) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD)
      return res.status(401).json({ error: "Invalid credentials" });
    const sessionId = await createSession(username, req);
    const token = signToken({ username, role: "superadmin" }, sessionId);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }

  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password)))
    return res.status(401).json({ error: "Invalid credentials" });
  const sessionId = await createSession(username, req);
  const token = signToken({ username, role: "admin" }, sessionId);
  res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 8 * 3600 * 1000 });
  return res.json({ success: true, role: "admin" });
});

app.post("/admin/logout", authMiddleware, async (req, res) => {
  await Session.findOneAndDelete({ sessionId: req.user?.sessionId });
  res.clearCookie("token");
  res.json({ success: true });
});

app.get("/admin/api/me", authMiddleware, async (req, res) => {
  if (isSuperAdmin(req.user.username))
    return res.json({ username: req.user.username, role: "superadmin", allowedTypes: ["all"] });
  const admin = await Admin.findOne({ username: req.user.username });
  res.json({ username: req.user.username, role: "admin", allowedTypes: admin?.allowedTypes || ["all"] });
});

app.get("/admin/api/config", authMiddleware, (req, res) => {
  res.json({
    apiTypes: API_REGISTRY.map(a => ({
      type: a.type, label: a.label, icon: a.icon, route: a.route, paramName: a.paramName, prefix: a.prefix
    }))
  });
});

app.get("/admin/api/stats", authMiddleware, superOnly, async (req, res) => {
  await cleanSessions();
  const [totalAdmins, totalKeys, activeKeys, totalSessions] = await Promise.all([
    Admin.countDocuments(),
    ApiKey.countDocuments(),
    ApiKey.countDocuments({ isActive: true, expiresAt: { $gt: new Date() } }),
    Session.countDocuments(),
  ]);
  res.json({ totalAdmins, totalKeys, activeKeys, totalSessions });
});

app.get("/admin/api/sessions/me", authMiddleware, async (req, res) => {
  await cleanSessions();
  const sessions = await Session.find({ username: req.user.username }).sort({ lastSeen: -1 }).lean();
  res.json({ sessions });
});

app.get("/admin/api/sessions/all", authMiddleware, superOnly, async (req, res) => {
  await cleanSessions();
  const sessions = await Session.find().sort({ username: 1, lastSeen: -1 }).lean();
  const byUser = {};
  for (const s of sessions) {
    if (!byUser[s.username]) byUser[s.username] = [];
    byUser[s.username].push(s);
  }
  res.json({ byUser, total: sessions.length });
});

app.delete("/admin/api/sessions/:id", authMiddleware, async (req, res) => {
  const s = await Session.findById(req.params.id);
  if (!s) return res.status(404).json({ error: "Not found" });
  if (!isSuperAdmin(req.user.username) && s.username !== req.user.username)
    return res.status(403).json({ error: "Forbidden" });
  await Session.findByIdAndDelete(req.params.id);
  res.json({ message: "Session revoked" });
});

app.delete("/admin/api/sessions/user/:username", authMiddleware, superOnly, async (req, res) => {
  if (isSuperAdmin(req.params.username)) return res.status(400).json({ error: "Cannot revoke superadmin" });
  await Session.deleteMany({ username: req.params.username });
  res.json({ message: "Sessions revoked" });
});

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
  const { username, password, allowedTypes = ["all"] } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Reserved username" });
  if (await Admin.findOne({ username })) return res.status(409).json({ error: "Already exists" });
  const hashed = await bcrypt.hash(password, 10);
  await Admin.create({ username, password: hashed, allowedTypes });
  res.status(201).json({ message: `Admin "${username}" created` });
});

app.delete("/admin/api/admins/:username", authMiddleware, superOnly, async (req, res) => {
  if (isSuperAdmin(req.params.username)) return res.status(400).json({ error: "Cannot delete superadmin" });
  const admin = await Admin.findOneAndDelete({ username: req.params.username });
  if (!admin) return res.status(404).json({ error: "Not found" });
  await ApiKey.deleteMany({ createdBy: req.params.username });
  await Session.deleteMany({ username: req.params.username });
  res.json({ message: `Admin "${req.params.username}" deleted` });
});

app.get("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const keys = await ApiKey.find({ createdBy: req.user.username }).sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days = 7, usageLimit = 0, dailyLimit = 0, keyType = "number" } = req.body;
  if (!API_REGISTRY.find(a => a.type === keyType))
    return res.status(400).json({ error: "Invalid key type" });
  if (!isSuperAdmin(req.user.username)) {
    const admin = await Admin.findOne({ username: req.user.username });
    const allowed = admin?.allowedTypes || ["all"];
    if (!allowed.includes("all") && !allowed.includes(keyType))
      return res.status(403).json({ error: `No access to ${keyType} keys` });
  }
  const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000);
  const key = makeKey(keyType);
  await ApiKey.create({
    key, label: label || "", createdBy: req.user.username, expiresAt, keyType,
    usageLimit: usageLimit > 0 ? usageLimit : null,
    dailyLimit: dailyLimit > 0 ? dailyLimit : null,
  });
  res.status(201).json({ key, expiresAt, message: "Key created" });
});

app.delete("/admin/api/my-keys/:id", authMiddleware, async (req, res) => {
  const filter = { _id: req.params.id };
  if (!isSuperAdmin(req.user.username)) filter.createdBy = req.user.username;
  const key = await ApiKey.findOneAndDelete(filter);
  if (!key) return res.status(404).json({ error: "Not found or unauthorized" });
  res.json({ message: "Key deleted" });
});

app.get("/admin/api/all-keys", authMiddleware, superOnly, async (req, res) => {
  const keys = await ApiKey.find().sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

app.delete("/admin/api/all-keys/:id", authMiddleware, superOnly, async (req, res) => {
  const key = await ApiKey.findByIdAndDelete(req.params.id);
  if (!key) return res.status(404).json({ error: "Not found" });
  res.json({ message: "Key deleted" });
});

// ─── PUBLIC API: NUMBER LOOKUP ── FIXED: UPSTREAM_API_URL ────────────────────
app.get("/lookup", async (req, res) => {
  const { number, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;

  if (!number) return res.status(400).json({ error: "number param required", ...CREDIT });
  if (!key)    return res.status(401).json({ error: "API key required", ...CREDIT });

  const { error, status, keyDoc } = await validateKey(key, "number");
  if (error) return res.status(status).json({ error, ...CREDIT });

  const baseUrl = process.env.UPSTREAM_API_URL;
  if (!baseUrl) return res.status(503).json({ error: "Number API not configured", ...CREDIT });

  try {
    const upstreamUrl = `${baseUrl}?number=${encodeURIComponent(number)}`;
    const response = await axios.get(upstreamUrl, {
      timeout: 15000,
      headers: {
        "ngrok-skip-browser-warning": "true",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
      }
    });
    await incUsage(keyDoc._id);
    const data = response.data;
    if (data && typeof data === "object") {
      if (data.data && typeof data.data === "object") {
        data.data.credit = "@Boss_Hcrr";
        data.data.developer = "@Boss_Hcrr";
      }
      data.credit = "@Boss_Hcrr";
      data.developer = "@Boss_Hcrr";
    }
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "Upstream API error: " + err.message, ...CREDIT });
  }
});

app.get("/tg", async (req, res) => {
  const { userid, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!userid) return res.status(400).json({ error: "userid required", ...CREDIT });
  if (!key)    return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "telegram");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (!process.env.UPSTREAM_TG_API_URL) return res.status(503).json({ error: "Telegram API not configured", ...CREDIT });
    const r = await axios.get(`${process.env.UPSTREAM_TG_API_URL}?type=sms&term=${encodeURIComponent(userid)}`, { timeout: 10000 });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "Telegram API error", ...CREDIT });
  }
});

app.get("/upi", async (req, res) => {
  const { upi, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!upi) return res.status(400).json({ error: "upi required", ...CREDIT });
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!upi.includes("@")) return res.status(400).json({ error: "Invalid UPI format", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "upi");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (process.env.UPSTREAM_UPI_API_URL) {
      const r = await axios.get(`${process.env.UPSTREAM_UPI_API_URL}?upi=${encodeURIComponent(upi)}`, { timeout: 10000 });
      await incUsage(keyDoc._id);
      return res.json({ ...r.data, ...CREDIT });
    }
    const [prefix, handle] = upi.split("@");
    const banks = { okhdfcbank:"HDFC Bank", okicici:"ICICI Bank", oksbi:"SBI", ybl:"Yes Bank", apl:"Axis Bank", paytm:"Paytm", fam:"PhonePe", gpay:"Google Pay", airtel:"Airtel Payments Bank" };
    await incUsage(keyDoc._id);
    return res.json({ success: true, upi_id: upi, valid: true, handle, bank: banks[handle.toLowerCase()] || "Unknown", ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "UPI API error", ...CREDIT });
  }
});

app.get("/imei", async (req, res) => {
  const { imei, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!imei) return res.status(400).json({ error: "imei required", ...CREDIT });
  if (!key)  return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!/^\d{15}$/.test(imei)) return res.status(400).json({ error: "IMEI must be 15 digits", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "imei");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (!process.env.UPSTREAM_IMEI_API_URL) return res.status(503).json({ error: "IMEI API not configured", ...CREDIT });
    const r = await axios.get(`${process.env.UPSTREAM_IMEI_API_URL}/?imei_num=${encodeURIComponent(imei)}`, { timeout: 15000 });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "IMEI API error", ...CREDIT });
  }
});

app.get("/aadhar", async (req, res) => {
  const { aadhar, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!aadhar) return res.status(400).json({ error: "aadhar required", ...CREDIT });
  if (!key)    return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!/^\d{12}$/.test(aadhar)) return res.status(400).json({ error: "Aadhar must be 12 digits", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "aadhar");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (!process.env.UPSTREAM_AADHAR_API_URL) return res.status(503).json({ error: "Aadhar API not configured", ...CREDIT });
    const r = await axios.get(`${process.env.UPSTREAM_AADHAR_API_URL}?num=${encodeURIComponent(aadhar)}`, { timeout: 15000 });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "Aadhar API error", ...CREDIT });
  }
});

app.get("/pan", async (req, res) => {
  const { pan, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!pan) return res.status(400).json({ error: "pan required", ...CREDIT });
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(pan.toUpperCase())) return res.status(400).json({ error: "Invalid PAN format (e.g. ABCDE1234F)", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "pan");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (!process.env.UPSTREAM_PAN_API_URL) return res.status(503).json({ error: "PAN API not configured", ...CREDIT });
    const r = await axios.get(`${process.env.UPSTREAM_PAN_API_URL}?pan=${encodeURIComponent(pan.toUpperCase())}`, { timeout: 15000 });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "PAN API error", ...CREDIT });
  }
});

app.get("/rto", async (req, res) => {
  const { rc, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!rc)  return res.status(400).json({ error: "rc required", ...CREDIT });
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "rto");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (!process.env.UPSTREAM_RTO_API_URL) return res.status(503).json({ error: "RTO API not configured", ...CREDIT });
    const r = await axios.get(`${process.env.UPSTREAM_RTO_API_URL}?rc=${encodeURIComponent(rc)}`, { timeout: 10000 });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "RTO API error", ...CREDIT });
  }
});

app.get("/iplookup", async (req, res) => {
  const { ip, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  const targetIp = ip || getIp(req);
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "ip");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    const r = await axios.get(`http://ip-api.com/json/${encodeURIComponent(targetIp)}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query`, { timeout: 10000 });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    return res.status(500).json({ error: "IP API error", ...CREDIT });
  }
});

app.get("/gst", async (req, res) => {
  const { gstin, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!gstin) return res.status(400).json({ error: "gstin required", ...CREDIT });
  if (!key)   return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "gst");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (!process.env.UPSTREAM_GST_API_URL) return res.status(503).json({ error: "GST API not configured", ...CREDIT });
    const r = await axios.get(`${process.env.UPSTREAM_GST_API_URL}?gstin=${encodeURIComponent(gstin)}`, {
      timeout: 10000,
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" }
    });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "GST API error", ...CREDIT });
  }
});

// ─── PUBLIC API: PAN TO GST ───────────────────────────────────────────────────
app.get("/pan2gst", async (req, res) => {
  const { pan, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!pan) return res.status(400).json({ error: "pan required (e.g. AAYFK4129N)", ...CREDIT });
  if (!key) return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/i.test(pan)) return res.status(400).json({ error: "Invalid PAN format", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "pan2gst");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    if (!process.env.UPSTREAM_PAN_GST_API_URL) return res.status(503).json({ error: "PAN to GST API not configured", ...CREDIT });
    const r = await axios.get(`${process.env.UPSTREAM_PAN_GST_API_URL}?pan=${encodeURIComponent(pan.toUpperCase())}`, {
      timeout: 10000,
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" }
    });
    await incUsage(keyDoc._id);
    return res.json({ ...r.data, ...CREDIT });
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "PAN to GST API error", ...CREDIT });
  }
});

// ─── PUBLIC API: OSINT / NUMBER ADV ──────────────────────────────────────────
app.get("/osint", async (req, res) => {
  const { query, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!query) return res.status(400).json({ error: "query required (phone number)", ...CREDIT });
  if (!key)   return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "osint");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    const baseUrl = process.env.OSINT_API_URL;
    const osintKey = process.env.OSINT_API_KEY;
    if (!baseUrl) return res.status(503).json({ error: "OSINT API not configured", ...CREDIT });
    const r = await axios.get(baseUrl, {
      params: { key: osintKey, query: query },
      timeout: 15000,
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" }
    });
    await incUsage(keyDoc._id);
    const data = r.data;
    if (data && typeof data === "object") {
      data.credit = "@Boss_Hcrr";
      data.developer = "@Boss_Hcrr";
    }
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "OSINT API error: " + err.message, ...CREDIT });
  }
});

// ─── PUBLIC API: TG TO NUMBER ────────────────────────────────────────────────
app.get("/tgnum", async (req, res) => {
  const { tgusername, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!tgusername) return res.status(400).json({ error: "tgusername required (e.g. @username)", ...CREDIT });
  if (!key)        return res.status(401).json({ error: "API key required", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "tgnum");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    const baseUrl = process.env.UPSTREAM_TG_NUM_URL;
    if (!baseUrl) return res.status(503).json({ error: "TG Num API not configured", ...CREDIT });
    const r = await axios.get(baseUrl, {
      params: { tgusername },
      timeout: 15000,
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" }
    });
    await incUsage(keyDoc._id);
    const data = r.data;
    if (data && typeof data === "object") {
      data.credit = "@Boss_Hcrr";
      data.developer = "@Boss_Hcrr";
    }
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "TG Num API error: " + err.message, ...CREDIT });
  }
});

// ─── PUBLIC API: AADHAR ADV (V2) ─────────────────────────────────────────────
app.get("/aadharv2", async (req, res) => {
  const { aadhar, apikey } = req.query;
  const key = req.headers["x-api-key"] || apikey;
  if (!aadhar) return res.status(400).json({ error: "aadhar required (12 digits)", ...CREDIT });
  if (!key)    return res.status(401).json({ error: "API key required", ...CREDIT });
  if (!/^\d{12}$/.test(aadhar)) return res.status(400).json({ error: "Aadhar must be 12 digits", ...CREDIT });
  const { error, status, keyDoc } = await validateKey(key, "aadharv2");
  if (error) return res.status(status).json({ error, ...CREDIT });
  try {
    const baseUrl = process.env.UPSTREAM_AADHAR_V2_URL;
    if (!baseUrl) return res.status(503).json({ error: "Aadhar V2 API not configured", ...CREDIT });
    const r = await axios.get(baseUrl, {
      params: { aadhar },
      timeout: 15000,
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" }
    });
    await incUsage(keyDoc._id);
    const data = r.data;
    if (data && typeof data === "object") {
      data.credit = "@Boss_Hcrr";
      data.developer = "@Boss_Hcrr";
    }
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json({ ...err.response.data, ...CREDIT });
    return res.status(500).json({ error: "Aadhar V2 API error: " + err.message, ...CREDIT });
  }
});

async function start() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("MongoDB connected");
  await cleanSessions();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server: http://localhost:${PORT}`);
    console.log(`Admin:  http://localhost:${PORT}/admin`);
    console.log("Credit: @Boss_Hcrr | Developer: @Boss_Hcrr");
  });
}

start().catch(err => { console.error(err); process.exit(1); });
