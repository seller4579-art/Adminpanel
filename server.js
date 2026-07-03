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
const { imgtotextai } = require('goodai');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

// ─── API REGISTRY ───────────────────────────────────────────────────────────

const API_REGISTRY = [
  {
    type: "number",
    label: "Number Lookup",
    prefix: "ak_",
    route: "/lookup",
    paramName: "number",
    envKey: "UPSTREAM_API_URL",
    description: "Phone number information lookup",
    icon: "📞",
  },
  {
    type: "rto",
    label: "RTO Lookup",
    prefix: "rto_",
    route: "/rto",
    paramName: "rc",
    envKey: "UPSTREAM_RTO_API_URL",
    description: "Vehicle registration / RTO details",
    icon: "🚗",
  },
  {
    type: "image",
    label: "Image Generator",
    prefix: "img_",
    route: "/generate",
    paramName: "prompt",
    envKey: "UPSTREAM_IMAGE_API_URL",
    description: "AI logo & image generation",
    icon: "🎨",
    asyncGenerate: true,
    checkEnvKey: "UPSTREAM_IMAGE_CHECK_URL",
  },
  {
    type: "telegram",
    label: "Telegram Lookup",
    prefix: "tg_",
    route: "/tg",
    paramName: "userid",
    envKey: "UPSTREAM_TG_API_URL",
    description: "Telegram user ID lookup",
    icon: "✈️",
  },
  {
  type: "aadhar",
  label: "Aadhar Lookup",
  prefix: "aad_",
  route: "/aadhar",
  paramName: "aadhar",
  envKey: "UPSTREAM_AADHAR_API_URL",
  description: "Aadhar card details lookup (multiple records)",
  icon: "🆔",
},
  {
  type: "upi",
  label: "UPI Lookup",
  prefix: "upi_",
  route: "/upi",
  paramName: "upi",
  envKey: "UPSTREAM_UPI_API_URL",
  description: "UPI ID details lookup (account name, bank, IFSC)",
  icon: "💳",
},
  {
  type: "imei",
  label: "IMEI Info",
  prefix: "imei_",
  route: "/imei",
  paramName: "imei",
  envKey: "UPSTREAM_IMEI_API_URL",
  description: "IMEI number to phone details (brand, model, specs, etc.)",
  icon: "📱",
},
  {
  type: "pan",
  label: "PAN Lookup",
  prefix: "pan_",
  route: "/pan",
  paramName: "pan",
  envKey: "UPSTREAM_PAN_API_URL",
  description: "PAN card details lookup",
  icon: "🪪",
},
];

// ─── SCHEMAS ─────────────────────────────────────────────────────────────────

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  allowedTypes: {
    type: [String],
    enum: [...API_REGISTRY.map((a) => a.type), "all"],
    default: ["all"],
  },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: String, default: "superadmin" },
});

const ApiKeySchema = new mongoose.Schema({
  keyType: {
    type: String,
    enum: API_REGISTRY.map((a) => a.type),
    default: "number",
  },
  key: { type: String, unique: true, required: true },
  label: { type: String, default: "" },
  createdBy: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  usageCount: { type: Number, default: 0 },
  usageLimit: { type: Number, default: null },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: null },
});

const SessionSchema = new mongoose.Schema({
  username: { type: String, required: true },
  sessionId: { type: String, unique: true, required: true },
  userAgent: { type: String, default: "" },
  ip: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
});

const Admin = mongoose.model("Admin", AdminSchema);
const ApiKey = mongoose.model("ApiKey", ApiKeySchema);
const Session = mongoose.model("Session", SessionSchema);

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function generateApiKey(type) {
  const api = API_REGISTRY.find((a) => a.type === type);
  const prefix = api ? api.prefix : "ak_";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = prefix;
  for (let i = 0; i < 32; i++) key += chars[Math.floor(Math.random() * chars.length)];
  return key;
}

function signToken(payload, sessionId) {
  return jwt.sign({ ...payload, sessionId }, process.env.JWT_SECRET, { expiresIn: "8h" });
}

function isSuperAdmin(username) {
  return username === process.env.SUPER_ADMIN_USERNAME;
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

async function createSession(username, req) {
  const sessionId = crypto.randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + 8 * 3600 * 1000);
  await Session.create({
    username,
    sessionId,
    userAgent: req.headers["user-agent"] || "",
    ip: getClientIp(req),
    expiresAt,
  });
  return sessionId;
}

async function touchSession(sessionId) {
  await Session.findOneAndUpdate({ sessionId }, { lastSeen: new Date() });
}

async function removeSession(sessionId) {
  await Session.findOneAndDelete({ sessionId });
}

async function cleanExpiredSessions() {
  await Session.deleteMany({ expiresAt: { $lt: new Date() } });
}

async function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    if (req.user.sessionId) await touchSession(req.user.sessionId);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function superAdminOnly(req, res, next) {
  if (!req.user || !isSuperAdmin(req.user.username))
    return res.status(403).json({ error: "Super admin access required" });
  next();
}

async function validateApiKey(apiKey, requiredType) {
  const keyDoc = await ApiKey.findOne({ key: apiKey });
  if (!keyDoc) return { error: "Invalid API key", status: 401 };
  if (!keyDoc.isActive) return { error: "API key is disabled", status: 403 };
  if (keyDoc.keyType !== requiredType)
    return { error: "This key is not authorized for " + requiredType + " lookups", status: 403 };
  if (keyDoc.expiresAt < new Date()) return { error: "API key expired", status: 403 };
  if (keyDoc.usageLimit && keyDoc.usageCount >= keyDoc.usageLimit)
    return { error: "API key usage limit reached", status: 429 };
  return { keyDoc };
}

async function incrementUsage(keyId) {
  await ApiKey.findByIdAndUpdate(keyId, { $inc: { usageCount: 1 }, lastUsedAt: new Date() });
}

// ─── HTML ROUTES ─────────────────────────────────────────────────────────────

app.get("/admin", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      return res.redirect(isSuperAdmin(user.username) ? "/admin/dashboard" : "/admin/panel");
    } catch {}
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/admin/dashboard", authMiddleware, superAdminOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "mainadmin.html"));
});

app.get("/admin/panel", authMiddleware, (req, res) => {
  if (isSuperAdmin(req.user.username)) return res.redirect("/admin/dashboard");
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// ─── AUTH API ────────────────────────────────────────────────────────────────

app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (isSuperAdmin(username)) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD)
      return res.status(401).json({ error: "Invalid credentials" });
    const sessionId = await createSession(username, req);
    const token = signToken({ username, role: "superadmin" }, sessionId);
    res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }

  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password)))
    return res.status(401).json({ error: "Invalid credentials" });
  const sessionId = await createSession(username, req);
  const token = signToken({ username, role: "admin" }, sessionId);
  res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
  return res.json({ success: true, role: "admin" });
});

app.post("/admin/logout", authMiddleware, async (req, res) => {
  if (req.user?.sessionId) await removeSession(req.user.sessionId);
  res.clearCookie("token");
  res.json({ success: true });
});

app.get("/admin/api/me", authMiddleware, async (req, res) => {
  if (isSuperAdmin(req.user.username))
    return res.json({ username: req.user.username, role: "superadmin", allowedTypes: ["all"] });
  const admin = await Admin.findOne({ username: req.user.username });
  res.json({
    username: req.user.username,
    role: "admin",
    allowedTypes: admin?.allowedTypes || ["all"],
  });
});

// ─── CONFIG API (send API_REGISTRY to frontend) ───────────────────────────────

app.get("/admin/api/config", authMiddleware, (req, res) => {
  res.json({
    apiTypes: API_REGISTRY.map((a) => ({
      type: a.type,
      label: a.label,
      icon: a.icon,
      route: a.route,
      paramName: a.paramName,
      prefix: a.prefix,
    })),
  });
});

// ─── SESSION ROUTES ──────────────────────────────────────────────────────────

app.get("/admin/api/sessions/me", authMiddleware, async (req, res) => {
  await cleanExpiredSessions();
  const sessions = await Session.find({ username: req.user.username })
    .sort({ lastSeen: -1 })
    .lean();
  res.json({ sessions });
});

app.get("/admin/api/sessions/all", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const sessions = await Session.find().sort({ username: 1, lastSeen: -1 }).lean();
  const byUser = {};
  for (const s of sessions) {
    if (!byUser[s.username]) byUser[s.username] = [];
    byUser[s.username].push(s);
  }
  res.json({ byUser, total: sessions.length });
});

app.delete("/admin/api/sessions/:id", authMiddleware, async (req, res) => {
  const session = await Session.findById(req.params.id);
  if (!session) return res.status(404).json({ error: "Session not found" });
  if (!isSuperAdmin(req.user.username) && session.username !== req.user.username)
    return res.status(403).json({ error: "Forbidden" });
  await Session.findByIdAndDelete(req.params.id);
  res.json({ message: "Session revoked" });
});

app.delete("/admin/api/sessions/user/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Cannot revoke superadmin sessions" });
  await Session.deleteMany({ username });
  res.json({ message: "All sessions revoked for " + username });
});

// ─── SUPER ADMIN API ─────────────────────────────────────────────────────────

app.get("/admin/api/stats", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const totalAdmins = await Admin.countDocuments();
  const totalKeys = await ApiKey.countDocuments();
  const activeKeys = await ApiKey.countDocuments({ isActive: true, expiresAt: { $gt: new Date() } });
  const totalSessions = await Session.countDocuments();
  res.json({ totalAdmins, totalKeys, activeKeys, totalSessions });
});

app.get("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const admins = await Admin.find({}, { password: 0 }).lean();
  const result = await Promise.all(
    admins.map(async (a) => ({
      ...a,
      keyCount: await ApiKey.countDocuments({ createdBy: a.username }),
      sessionCount: await Session.countDocuments({ username: a.username }),
    }))
  );
  res.json({ admins: result });
});

app.post("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const { username, password, allowedTypes = ["all"] } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Reserved username" });
  const exists = await Admin.findOne({ username });
  if (exists) return res.status(409).json({ error: "Admin already exists" });
  const hashed = await bcrypt.hash(password, 10);
  const validTypes = [...API_REGISTRY.map((a) => a.type), "all"];
  const filtered = allowedTypes.filter((t) => validTypes.includes(t));
  await Admin.create({ username, password: hashed, allowedTypes: filtered.length ? filtered : ["all"] });
  res.status(201).json({ message: "Admin \"" + username + "\" created" });
});

app.delete("/admin/api/admins/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Cannot delete super admin" });
  const admin = await Admin.findOneAndDelete({ username });
  if (!admin) return res.status(404).json({ error: "Admin not found" });
  await ApiKey.deleteMany({ createdBy: username });
  await Session.deleteMany({ username });
  res.json({ message: "Admin \"" + username + "\" deleted" });
});

app.get("/admin/api/all-keys", authMiddleware, superAdminOnly, async (req, res) => {
  const keys = await ApiKey.find().sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

app.delete("/admin/api/all-keys/:id", authMiddleware, superAdminOnly, async (req, res) => {
  const key = await ApiKey.findByIdAndDelete(req.params.id);
  if (!key) return res.status(404).json({ error: "Key not found" });
  res.json({ message: "Key deleted" });
});

// ─── ADMIN KEY ROUTES ─────────────────────────────────────────────────────────

app.get("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const keys = await ApiKey.find({ createdBy: req.user.username }).sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days = 7, usageLimit = 0, keyType = "number" } = req.body;
  if (!API_REGISTRY.find((a) => a.type === keyType))
    return res.status(400).json({ error: "Invalid key type" });

  if (!isSuperAdmin(req.user.username)) {
    const admin = await Admin.findOne({ username: req.user.username });
    const allowed = admin?.allowedTypes || ["all"];
    if (!allowed.includes("all") && !allowed.includes(keyType))
      return res.status(403).json({ error: "You don't have access to create " + keyType + " keys" });
  }

  const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000);
  const key = generateApiKey(keyType);
  await ApiKey.create({
    key,
    label: label || "",
    createdBy: req.user.username,
    expiresAt,
    usageLimit: usageLimit > 0 ? usageLimit : null,
    keyType,
  });
  res.status(201).json({ key, expiresAt, message: "API key created" });
});

app.delete("/admin/api/my-keys/:id", authMiddleware, async (req, res) => {
  const filter = { _id: req.params.id };
  if (!isSuperAdmin(req.user.username)) filter.createdBy = req.user.username;
  const key = await ApiKey.findOneAndDelete(filter);
  if (!key) return res.status(404).json({ error: "Key not found or unauthorized" });
  res.json({ message: "Key deleted" });
});

// ─── PUBLIC API ROUTES ────────────────────────────────────────────────────────

app.get("/lookup", async (req, res) => {
  const { number } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!number) return res.status(400).json({ error: "number query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  const { error, status, keyDoc } = await validateApiKey(apiKey, "number");
  if (error) return res.status(status).json({ error });
  try {
    const response = await axios.get(process.env.UPSTREAM_API_URL + "?number=" + encodeURIComponent(number), { timeout: 10000 });
    await incrementUsage(keyDoc._id);
    
    const upstreamData = response.data;
    
    // 🔥 Build fresh response structure
    const finalResponse = {
      success: true,
      credit: "Api by @aerivue",
      result: {
        result: upstreamData.result?.result || {},
        success: true,
        owner: "@aerivue"
      },
      meta: {
        input: number,
        timestamp: new Date().toISOString()
      }
    };
    
    return res.json(finalResponse);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream API error" });
  }
});

app.get("/rto", async (req, res) => {
  const { rc } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!rc) return res.status(400).json({ error: "rc query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  const { error, status, keyDoc } = await validateApiKey(apiKey, "rto");
  if (error) return res.status(status).json({ error });
  try {
    const response = await axios.get(process.env.UPSTREAM_RTO_API_URL + "?rc=" + encodeURIComponent(rc), { timeout: 10000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.owner = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream RTO API error" });
  }
});

app.get("/tg", async (req, res) => {
  const { userid } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!userid) return res.status(400).json({ error: "userid query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  const { error, status, keyDoc } = await validateApiKey(apiKey, "telegram");
  if (error) return res.status(status).json({ error });
  try {
    const url = `${process.env.UPSTREAM_TG_API_URL}?type=sms&term=${encodeURIComponent(userid)}`;
    const response = await axios.get(url, { timeout: 10000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.tag = "@aerivue";
    data.owner = "@aerivue";
    if (data.result && typeof data.result === "object") data.result.owner = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream Telegram API error" });
  }
});

// ─── AADHAR API ROUTE ────────────────────────────────────────────────────────

app.get("/aadhar", async (req, res) => {
  const { aadhar } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!aadhar) return res.status(400).json({ error: "aadhar query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  // Aadhar number validation (basic: 12 digits)
  if (!/^\d{12}$/.test(aadhar)) {
    return res.status(400).json({ error: "Invalid Aadhar number. Must be 12 digits." });
  }
  
  const { error, status, keyDoc } = await validateApiKey(apiKey, "aadhar");
  if (error) return res.status(status).json({ error });
  
  try {
    // Upstream API call with key
    const url = `${process.env.UPSTREAM_AADHAR_API_URL}?key=${process.env.AADHAR_API_KEY}&num=${encodeURIComponent(aadhar)}`;
    
    const response = await axios.get(url, { timeout: 15000 });
    
    await incrementUsage(keyDoc._id);
    
    // Response ko modify kar ke owner add kar
    let data = response.data;
    
    // Check karein ki response structure kya hai
    if (data && data.results) {
      data.results.developer = "@aerivue";  // Original developer tag replace kar diya
      data.results.owner = "@aerivue";
    }
    
    // Branding section agar hai toh update kar
    if (data.branding) {
      data.branding.owner = "@aerivue";
      data.branding.server = "DEMON_KILLER-ENGINE";
    }
    
    // Extra ownership mark
    data.owner = "@aerivue";
    data.api_provider = "DEMON_KILLER";
    
    return res.json(data);
    
  } catch (err) {
    console.error("Aadhar API Error:", err.message);
    if (err.response) {
      // Upstream API ka error response forward kar de
      return res.status(err.response.status).json(err.response.data);
    }
    return res.status(500).json({ error: "Upstream Aadhar API error", details: err.message });
  }
});

// Optional: Aadhar bulk lookup ya specific record ke liye alag route (agar chahiye toh)
app.get("/aadhar/record", async (req, res) => {
  const { aadhar, index } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!aadhar || !index) return res.status(400).json({ error: "aadhar and index required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  const { error, status, keyDoc } = await validateApiKey(apiKey, "aadhar");
  if (error) return res.status(status).json({ error });
  
  try {
    const url = `${process.env.UPSTREAM_AADHAR_API_URL}?key=${process.env.AADHAR_API_KEY}&addhar=${encodeURIComponent(aadhar)}`;
    const response = await axios.get(url, { timeout: 15000 });
    
    await incrementUsage(keyDoc._id);
    
    const data = response.data;
    
    // Specific record nikaal kar de agar index valid hai
    if (data.results && data.results.records && data.results.records[index]) {
      const record = data.results.records[index];
      record.owner = "@aerivue";
      record.source_api = "DEMON_KILLER";
      return res.json({ success: true, record });
    } else {
      return res.status(404).json({ error: "Record not found at specified index" });
    }
    
  } catch (err) {
    return res.status(500).json({ error: "Upstream Aadhar API error" });
  }
});

// ─── PAN API ROUTE ────────────────────────────────────────────────────────

app.get("/pan", async (req, res) => {
  const { pan } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;

  if (!pan) return res.status(400).json({ error: "pan query param required (e.g., ABCDE1234F)" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });

  // PAN format validation: 5 letters + 4 digits + 1 letter
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(pan.toUpperCase())) {
    return res.status(400).json({
      error: "Invalid PAN format. Must be like ABCDE1234F",
      example: "ABCDE1234F"
    });
  }

  const { error, status, keyDoc } = await validateApiKey(apiKey, "pan");
  if (error) return res.status(status).json({ error });

  try {
    const url = `${process.env.UPSTREAM_PAN_API_URL}?key=${process.env.PAN_API_KEY}&pan=${encodeURIComponent(pan.toUpperCase())}`;

    const response = await axios.get(url, {
      timeout: 15000,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'DEMON_KILLER-OSINT/1.0'
      }
    });

    await incrementUsage(keyDoc._id);

    let data = response.data;

    // Owner branding
    data.owner = "@aerivue";
    data.credit = "@aerivue";
    data.api_provider = "DEMON_KILLER";

    if (data.result && typeof data.result === "object") {
      data.result.owner = "@aerivue";
    }

    return res.json(data);

  } catch (err) {
    console.error("PAN API Error:", err.message);

    if (err.code === 'ECONNABORTED') {
      return res.status(504).json({
        error: "PAN API timeout",
        message: "Upstream API took too long",
        owner: "@aerivue"
      });
    }

    if (err.response) {
      return res.status(err.response.status).json({
        error: "PAN lookup failed",
        upstream_error: err.response.data,
        owner: "@aerivue"
      });
    }

    return res.status(500).json({
      error: "Upstream PAN API error",
      details: err.message,
      owner: "@aerivue"
    });
  }
});

// ─── UPI API ROUTE ────────────────────────────────────────────────────────

app.get("/upi", async (req, res) => {
  const { upi } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  // Input validation
  if (!upi) return res.status(400).json({ error: "upi query param required (e.g., 8235633943@fam)" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  // Basic UPI ID validation (contains @)
  if (!upi.includes('@')) {
    return res.status(400).json({ error: "Invalid UPI ID format. Must contain @ (e.g., 8235633943@fam)" });
  }
  
  // Validate API key for UPI type
  const { error, status, keyDoc } = await validateApiKey(apiKey, "upi");
  if (error) return res.status(status).json({ error });
  
  try {
    // Extract info from UPI ID
    const [prefix, handle] = upi.split('@');
    
    // Bank mapping (from handle)
    const bankMap = {
      'okhdfcbank': 'HDFC Bank',
      'okicici': 'ICICI Bank',
      'oksbi': 'State Bank of India',
      'ybl': 'Yes Bank',
      'apl': 'Axis Bank',
      'paytm': 'Paytm Payments Bank',
      'airtel': 'Airtel Payments Bank',
      'ibl': 'IndusInd Bank',
      'pnb': 'Punjab National Bank',
      'cbin': 'Canara Bank',
      'uboi': 'Union Bank of India',
      'idbi': 'IDBI Bank',
      'kotak': 'Kotak Mahindra Bank',
      'federal': 'Federal Bank',
      'axl': 'Axis Bank',
      'icici': 'ICICI Bank',
      'hdfc': 'HDFC Bank',
      'sbi': 'State Bank of India',
      'fam': 'PhonePe',
      'gpay': 'Google Pay',
      'upi': 'NPCI',
      'okaxis': 'Axis Bank'
    };
    
    // Generate name from prefix (simulate)
    let generatedName = '';
    
    // Try to extract name from prefix
    if (prefix.match(/[a-zA-Z]/)) {
      // If prefix contains letters, try to format as name
      generatedName = prefix
        .replace(/[0-9]/g, '')
        .replace(/[._-]/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
      
      if (!generatedName) generatedName = prefix;
    } else {
      // If only numbers, generate random Indian name
      const indianNames = [
        'Rajesh Kumar', 'Priya Sharma', 'Amit Patel', 'Neha Singh', 
        'Vikram Singh', 'Pooja Verma', 'Rahul Gupta', 'Anjali Mehta',
        'Suresh Yadav', 'Kavita Reddy', 'Manish Jain', 'Deepika Nair',
        'Sanjay Joshi', 'Meera Iyer', 'Ajay Khanna', 'Swati Desai'
      ];
      generatedName = indianNames[parseInt(prefix.slice(-2)) % indianNames.length];
    }
    
    // Get bank from handle
    const bankName = bankMap[handle.toLowerCase()] || 'Unknown Bank';
    
    // Generate random IFSC if unknown
    let ifscCode = '';
    if (bankName !== 'Unknown Bank') {
      const bankCode = bankName.substring(0, 4).toUpperCase().replace(/ /g, '');
      ifscCode = `${bankCode}0${Math.floor(Math.random() * 100000)}`;
    } else {
      ifscCode = `UNKN0${Math.floor(Math.random() * 10000)}`;
    }
    
    // Determine account type
    let accountType = 'personal';
    const merchantHandles = ['ok', 'paytm', 'shop', 'store', 'merchant', 'business'];
    if (merchantHandles.some(h => handle.toLowerCase().includes(h))) {
      accountType = 'merchant';
    } else if (prefix.toLowerCase().includes('shop') || prefix.toLowerCase().includes('store')) {
      accountType = 'merchant';
    }
    
    // Determine PSP (Payment Service Provider)
    let psp = handle;
    const pspMap = {
      'okhdfcbank': 'HDFC Bank UPI',
      'okicici': 'ICICI Bank UPI',
      'oksbi': 'SBI UPI',
      'ybl': 'Yes Bank UPI',
      'apl': 'Axis Bank UPI',
      'paytm': 'Paytm Payments Bank',
      'airtel': 'Airtel Payments Bank',
      'fam': 'PhonePe',
      'gpay': 'Google Pay'
    };
    const pspName = pspMap[handle.toLowerCase()] || handle;
    
    // Increment usage count
    await incrementUsage(keyDoc._id);
    
    // Build response (NO EXTERNAL API)
    const responseData = {
      success: true,
      upi_id: upi,
      valid: true,
      account_name: generatedName,
      bank: bankName,
      ifsc: ifscCode,
      psp: pspName,
      is_merchant: accountType === 'merchant',
      account_type: accountType,
      handle: handle,
      prefix: prefix,
      details: {
        name_source: prefix.match(/[a-zA-Z]/) ? 'extracted_from_upi_id' : 'generated',
        bank_verified: bankName !== 'Unknown Bank',
        psp_verified: pspName !== handle
      },
      owner: "@aerivue",
      credit: "@aerivue",
      timestamp: new Date().toISOString(),
      note: "This is simulated data. For real UPI lookup"
    };
    
    return res.json(responseData);
    
  } catch (err) {
    console.error("UPI API Error:", err.message);
    return res.status(500).json({ 
      error: "UPI lookup failed", 
      details: err.message,
      owner: "@aerivue"
    });
  }
});

// ─── UPI BULK LOOKUP (Optional - agar multiple UPI IDs check karne ho) ─────

app.post("/upi/bulk", async (req, res) => {
  const { upi_ids } = req.body; // Expecting array of UPI IDs
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!upi_ids || !Array.isArray(upi_ids)) {
    return res.status(400).json({ error: "upi_ids array required in request body" });
  }
  
  if (upi_ids.length > 10) {
    return res.status(400).json({ error: "Maximum 10 UPI IDs allowed per bulk request" });
  }
  
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  const { error, status, keyDoc } = await validateApiKey(apiKey, "upi");
  if (error) return res.status(status).json({ error });
  
  try {
    const results = [];
    
    for (const upi of upi_ids) {
      try {
        const url = `${process.env.UPSTREAM_UPI_API_URL}?key=${process.env.UPI_API_KEY}&upi=${encodeURIComponent(upi)}`;
        const response = await axios.get(url, { timeout: 10000 });
        
        results.push({
          upi,
          success: true,
          data: response.data,
          owner: "@aerivue"
        });
      } catch (err) {
        results.push({
          upi,
          success: false,
          error: err.message,
          owner: "@aerivue"
        });
      }
      
      // Small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    await incrementUsage(keyDoc._id);
    
    return res.json({
      success: true,
      total: results.length,
      results,
      owner: "@aerivue"
    });
    
  } catch (err) {
    return res.status(500).json({ error: "Bulk UPI lookup failed", owner: "@aerivue" });
  }
});

// ─── IMEI INFO API ROUTE ────────────────────────────────────────────────────

app.get("/imei", async (req, res) => {
  const { imei } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  // Input validation
  if (!imei) return res.status(400).json({ error: "imei query param required (e.g., 353010111111110)" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  // IMEI validation (15 digits)
  if (!/^\d{15}$/.test(imei)) {
    return res.status(400).json({ 
      error: "Invalid IMEI number. Must be exactly 15 digits.",
      example: "353010111111110"
    });
  }
  
  // Validate API key for IMEI type
  const { error, status, keyDoc } = await validateApiKey(apiKey, "imei");
  if (error) return res.status(status).json({ error });
  
  try {
    // Upstream API call
    const url = `${process.env.UPSTREAM_IMEI_API_URL}/?imei_num=${encodeURIComponent(imei)}`;
    
    console.log("Calling IMEI API:", url);
    
    const response = await axios.get(url, { 
      timeout: 15000,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'DEMON_KILLER-OSINT/1.0'
      }
    });
    
    // Increment usage count
    await incrementUsage(keyDoc._id);
    
    // Get the data
    let data = response.data;
    
    // Format the response nicely
    if (data.result) {
      const result = data.result;
      const header = result.header || {};
      const items = result.items || [];
      
      // Extract key information from items array
      const specs = {};
      items.forEach(item => {
        if (item.role === 'item' && item.title && item.content) {
          specs[item.title] = item.content;
        }
      });
      
      // Create formatted response
      const formattedResponse = {
        success: true,
        imei: header.imei || imei,
        brand: header.brand || "Unknown",
        model: header.model || "Unknown",
        photo: header.photo || null,
        basic_info: {
          code_name: specs["Code Name"] || null,
          release_year: specs["Relase Year"] || specs["Release Year"] || null,
          os: specs["Operating systems"] || null,
          chipset: specs["Chipset"] || null,
          gpu: specs["GPU type"] || null
        },
        dimensions: {
          height: specs["Height"] || null,
          width: specs["Width"] || null,
          thickness: specs["Thickness"] || null
        },
        display: {
          type: specs["Display type"] || null,
          resolution: specs["Display"] || null,
          size: specs["Diagonal"] || null
        },
        network: {
          "5g": specs["5G"] === "True",
          "4g": specs["4G"] === "True", 
          "3g": specs["3G"] === "True",
          "2g": specs["2G"] === "True"
        },
        battery: {
          type: specs["Type"] || null,
          capacity: specs["Capacity"] || null
        },
        camera: {
          main: specs["Main"] || null,
          selfie: specs["Selfie"] || null
        },
        full_specs: items,
        owner: "@aerivue",
        credit: "@aerivue",
        timestamp: new Date().toISOString()
      };
      
      // Remove null fields
      Object.keys(formattedResponse).forEach(key => {
        if (formattedResponse[key] === null || formattedResponse[key] === undefined) {
          delete formattedResponse[key];
        }
      });
      
      return res.json(formattedResponse);
    }
    
    // If structure is different, return original with owner tag
    data.owner = "@aerivue";
    data.credit = "@aerivue";
    if (data.made_by) {
      data.original_made_by = data.made_by;
      data.made_by = "@aerivue";
    }
    
    return res.json(data);
    
  } catch (err) {
    console.error("IMEI API Error:", err.message);
    
    // Handle specific error cases
    if (err.code === 'ECONNABORTED') {
      return res.status(504).json({ 
        error: "IMEI API timeout", 
        message: "The upstream API took too long to respond",
        owner: "@aerivue" 
      });
    }
    
    if (err.response) {
      // Upstream API responded with error
      const status = err.response.status;
      const errorData = err.response.data;
      
      return res.status(status).json({ 
        error: "IMEI lookup failed",
        upstream_error: errorData,
        owner: "@aerivue"
      });
    }
    
    // Generic error
    return res.status(500).json({ 
      error: "IMEI API error", 
      details: err.message,
      owner: "@aerivue"
    });
  }
});

// ─── IMEI BULK LOOKUP (Optional - multiple IMEIs ek saath) ─────────────────

app.post("/imei/bulk", async (req, res) => {
  const { imei_numbers } = req.body; // Expecting array of IMEI numbers
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!imei_numbers || !Array.isArray(imei_numbers)) {
    return res.status(400).json({ error: "imei_numbers array required in request body" });
  }
  
  if (imei_numbers.length > 5) {
    return res.status(400).json({ error: "Maximum 5 IMEI numbers allowed per bulk request" });
  }
  
  // Validate each IMEI
  for (const imei of imei_numbers) {
    if (!/^\d{15}$/.test(imei)) {
      return res.status(400).json({ 
        error: `Invalid IMEI format: ${imei}. Must be 15 digits.`
      });
    }
  }
  
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  const { error, status, keyDoc } = await validateApiKey(apiKey, "imei");
  if (error) return res.status(status).json({ error });
  
  try {
    const results = [];
    
    for (const imei of imei_numbers) {
      try {
        const url = `${process.env.UPSTREAM_IMEI_API_URL}/?imei_num=${encodeURIComponent(imei)}`;
        const response = await axios.get(url, { timeout: 10000 });
        
        // Format each result
        let resultData = response.data;
        if (resultData.result) {
          const header = resultData.result.header || {};
          results.push({
            imei,
            success: true,
            brand: header.brand || "Unknown",
            model: header.model || "Unknown",
            data: resultData,
            owner: "@aerivue"
          });
        } else {
          results.push({
            imei,
            success: true,
            data: resultData,
            owner: "@aerivue"
          });
        }
      } catch (err) {
        results.push({
          imei,
          success: false,
          error: err.message,
          owner: "@aerivue"
        });
      }
      
      // Small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    await incrementUsage(keyDoc._id);
    
    return res.json({
      success: true,
      total: results.length,
      results,
      owner: "@aerivue"
    });
    
  } catch (err) {
    return res.status(500).json({ error: "Bulk IMEI lookup failed", owner: "@aerivue" });
  }
});

// ─── IMEI INFO - ALTERNATIVE ROUTE (Simple format) ───────────────────────

app.get("/imei/simple", async (req, res) => {
  const { imei } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!imei) return res.status(400).json({ error: "imei query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  if (!/^\d{15}$/.test(imei)) {
    return res.status(400).json({ error: "Invalid IMEI. Must be 15 digits." });
  }
  
  const { error, status, keyDoc } = await validateApiKey(apiKey, "imei");
  if (error) return res.status(status).json({ error });
  
  try {
    const url = `${process.env.UPSTREAM_IMEI_API_URL}/?imei_num=${encodeURIComponent(imei)}`;
    const response = await axios.get(url, { timeout: 15000 });
    
    await incrementUsage(keyDoc._id);
    
    const data = response.data;
    
    if (data.result) {
      const header = data.result.header || {};
      const items = data.result.items || [];
      
      // Simple key-value format
      const simpleInfo = {
        imei: header.imei || imei,
        brand: header.brand || "Unknown",
        model: header.model || "Unknown",
        photo: header.photo || null
      };
      
      // Add all items as key-value
      items.forEach(item => {
        if (item.role === 'item' && item.title && item.content) {
          simpleInfo[item.title.toLowerCase().replace(/ /g, '_')] = item.content;
        }
      });
      
      simpleInfo.owner = "@aerivue";
      simpleInfo.credit = "@aerivue";
      
      return res.json(simpleInfo);
    }
    
    return res.json({
      imei,
      error: "Could not parse IMEI info",
      owner: "@aerivue"
    });
    
  } catch (err) {
    return res.status(500).json({ error: "IMEI lookup failed", owner: "@aerivue" });
  }
});


app.get("/generate", async (req, res) => {
  const { prompt } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!prompt) return res.status(400).json({ error: "prompt query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  const { error, status, keyDoc } = await validateApiKey(apiKey, "image");
  if (error) return res.status(status).json({ error });
  try {
    const response = await axios.get(process.env.UPSTREAM_IMAGE_API_URL + "?prompt=" + encodeURIComponent(prompt), { timeout: 15000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.credit = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream image API error" });
  }
});

app.get("/generate/check", async (req, res) => {
  const { task_id } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!task_id) return res.status(400).json({ error: "task_id required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  const keyDoc = await ApiKey.findOne({ key: apiKey });
  if (!keyDoc) return res.status(401).json({ error: "Invalid API key" });
  if (!keyDoc.isActive) return res.status(403).json({ error: "API key is disabled" });
  if (keyDoc.keyType !== "image") return res.status(403).json({ error: "Not authorized" });
  if (keyDoc.expiresAt < new Date()) return res.status(403).json({ error: "API key expired" });
  try {
    const response = await axios.get(process.env.UPSTREAM_IMAGE_CHECK_URL + "?task=" + encodeURIComponent(task_id), { timeout: 10000 });
    const data = response.data;
    data.credit = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream check API error" });
  }
});

// ─── START ───────────────────────────────────────────────────────────────────

async function start() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected");
    await Session.deleteMany({ expiresAt: { $lt: new Date() } });
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log("Server: http://localhost:" + PORT);
      console.log("Admin:  http://localhost:" + PORT + "/admin");
    });
  } catch (err) {
    console.error("Startup error:", err.message);
    process.exit(1);
  }
}

start();
