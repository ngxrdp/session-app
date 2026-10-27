import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import {
  parseAndValidate,
  validateHexKey,
  validateTelethonString,
  validatePyrogramString,
  validateSqliteSession,
  validateTdataZip,
  buildTelethon,
  buildPyrogram
} from "./session_validator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── SESSION URL ENCODING ────────────────────────────────────────────────────
// Encodes a single session as base64url for #tgs= param (auto-login)
function encodeSessionURL(baseUrl, session) {
  const data = {
    dcId: session.dcId,
    key: session.hex || session.authKeyHex || session.key,
    label: session.label || (session.firstName ? `${session.firstName} (DC ${session.dcId})` : `Session (DC ${session.dcId})`),
    userId: session.userId
  };
  const b64 = Buffer.from(JSON.stringify(data), "utf-8").toString("base64url");
  return `${baseUrl}/#tgs=${b64}`;
}

// Encodes multiple sessions as base64url for #tgss= param (picker modal)
function encodeSessionsURL(baseUrl, sessions) {
  const data = sessions.map((s, i) => ({
    dcId: s.dcId,
    key: s.hex || s.authKeyHex || s.key,
    label: s.label || (s.firstName ? `${s.firstName} (DC ${s.dcId})` : `Session ${i + 1} (DC ${s.dcId})`),
    userId: s.userId
  }));
  const b64 = Buffer.from(JSON.stringify(data), "utf-8").toString("base64url");
  return `${baseUrl}/#tgss=${b64}`;
}

// Telegram rejects web_app button URLs above ~2048 characters, so the
// session payload must stay inside a safe budget. With sessions growing a
// few hundred characters each, only a limited set of sessions fits into
// "Open App"; older ones keep working through the import modal instead.
const MAX_WEBAPP_URL_LENGTH = 1950;

// Build the best Open App URL for a user (with sessions if any)
function buildWebAppUrl(baseUrl, userId) {
  const sessions = db.sessions[String(userId)] || [];
  if (sessions.length === 0) return baseUrl;
  if (sessions.length === 1) {
    const url = encodeSessionURL(baseUrl, sessions[0]);
    return url.length <= MAX_WEBAPP_URL_LENGTH ? url : baseUrl;
  }

  // Multiple sessions: keep as many of the MOST RECENT as the URL budget
  // allows; dropped (oldest) sessions still work via the import modal.
  for (let n = sessions.length; n >= 2; n--) {
    const url = encodeSessionsURL(baseUrl, sessions.slice(sessions.length - n));
    if (url.length <= MAX_WEBAPP_URL_LENGTH) return url;
  }
  const single = encodeSessionURL(baseUrl, sessions[sessions.length - 1]);
  return single.length <= MAX_WEBAPP_URL_LENGTH ? single : baseUrl;
}

// ─── CONFIG ────────────────────────────────────────────────────────────────────
const BOT_TOKEN = (process.env.BOT_TOKEN || "8131936475:AAE3XrvMztqBmGhPxhyGCEgKU2aXxNbf2dM").trim();
const TG_API    = `https://api.telegram.org/bot${BOT_TOKEN}`;
const PORT      = Number(process.env.PORT || 3000);
const DIST_DIR  = path.resolve(__dirname, "../telegram-web");
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data.json");
const MAX_SESSION_UPLOAD_BYTES = 8 * 1024 * 1024;
const MAX_TDATA_UPLOAD_BYTES = 32 * 1024 * 1024;
const MAX_JSON_BODY_BYTES = 1024 * 1024;
const MAX_SESSIONS_PER_USER = 25;
const PYTHON_PACKAGES = path.join(__dirname, "python_packages");
const SESSION_BRIDGE = process.env.SESSION_BRIDGE || path.join(__dirname, "telegram_session_bridge.py");
const LOGIN_BRIDGE = process.env.LOGIN_BRIDGE || path.join(__dirname, "login_bridge.py");
const LOGIN_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const PYTHON_BIN = process.env.PYTHON_BIN
  || resolvePythonBin();

// Locate a Python interpreter that can import Telethon. Resolution order:
// 1. PYTHON_BIN env var  2. legacy bundled runtime path  3. PATH lookup
// (py launcher on Windows, python3/python elsewhere) with Telethon importable
// either from the local python_packages folder or the interpreter's own site
// packages. Without it, session verification with Telegram is impossible.
function resolvePythonBin() {
  const inheritedPath = process.env.PYTHONPATH
    ? `${PYTHON_PACKAGES}${path.delimiter}${process.env.PYTHONPATH}`
    : PYTHON_PACKAGES;
  const candidates = [
    path.join(os.homedir(), ".cache", "codex-runtimes", "codex-primary-runtime", "dependencies", "python", "python.exe"),
    "py",
    "python3",
    "python",
  ];
  for (const candidate of candidates) {
    try {
      const probe = spawnSync(candidate, ["-c", "import telethon; print('ok')"], {
        timeout: 20000,
        encoding: "utf8",
        env: { ...process.env, PYTHONPATH: inheritedPath },
      });
      if (!probe.error && probe.status === 0) return candidate;
    } catch (e) {}
  }
  return null;
}

const VERIFY_UNAVAILABLE_ERROR = "Session verification with Telegram is unavailable on this server: a Python interpreter with the Telethon package is missing. The bot admin must install Python 3 and Telethon (see README, 'Python session validator').";
let telethonAvailabilityLogged = false;
function logTelethonUnavailable() {
  if (telethonAvailabilityLogged) return;
  telethonAvailabilityLogged = true;
  console.error("[Session] Telethon unavailable — uploads are structurally validated only. Install Python 3 + telethon on this server for live Telegram verification.");
}
// Accepts a structurally valid session when live verification is impossible.
function unverifiedFallback(acc, dcId, keyHex) {
  const dc = Number.isInteger(dcId) ? dcId : (acc && acc.dcId);
  const meta = acc || {};
  return {
    success: true,
    unverified: true,
    dcId: dc,
    authKeyHex: keyHex,
    userId: meta.userId,
    firstName: meta.firstName,
    phone: meta.phone,
    telethon: buildTelethon(dc, keyHex)
  };
}
function isTelethonUnavailable(err) {
  return /verification with Telegram is unavailable|Telethon package is missing/i.test((err && err.message) || "");
}

function verifySessionWithTelegram({ buffer, session }) {
  return new Promise((resolve, reject) => {
    if (!PYTHON_BIN || !fs.existsSync(SESSION_BRIDGE)) {
      reject(new Error(VERIFY_UNAVAILABLE_ERROR));
      return;
    }

    const inheritedPath = process.env.PYTHONPATH ? `${PYTHON_PACKAGES}${path.delimiter}${process.env.PYTHONPATH}` : PYTHON_PACKAGES;
    const child = spawn(PYTHON_BIN, [SESSION_BRIDGE], {
      cwd: __dirname,
      env: { ...process.env, PYTHONPATH: inheritedPath },
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(reject, new Error("Telegram session validation timed out."));
    }, 50000);

    child.stdout.on("data", chunk => {
      stdout += chunk.toString("utf8");
      if (stdout.length > 1024 * 1024) child.kill();
    });
    child.stderr.on("data", chunk => {
      if (stderr.length < 8192) stderr += chunk.toString("utf8");
    });
    child.on("error", err => finish(reject, err));
    child.on("close", code => {
      try {
        const result = JSON.parse(stdout.trim() || "{}");
        if (code !== 0 && !result.error) throw new Error("Python session validator failed.");
        finish(resolve, result);
      } catch (err) {
        console.error("[Session] Python validator failed:", stderr.trim() || err.message);
        finish(reject, new Error("Could not validate this session with Telegram."));
      }
    });

    const payload = session
      ? { session }
      : { data: Buffer.from(buffer || []).toString("base64") };
    child.stdin.end(JSON.stringify(payload));
  });
}

async function verifyParsedAccount(acc) {
  const keyHex = (acc.authKeyHex || acc.hex || "").toLowerCase();
  if (!Number.isInteger(acc.dcId) || acc.dcId < 1 || acc.dcId > 5 || !/^[0-9a-f]{512}$/.test(keyHex)) {
    return { success: false, error: "Session is missing a valid data center or auth key." };
  }
  try {
    return await verifySessionWithTelegram({ session: buildTelethon(acc.dcId, keyHex) });
  } catch (err) {
    if (!isTelethonUnavailable(err)) throw err;
    logTelethonUnavailable();
    return unverifiedFallback(acc, acc.dcId, keyHex);
  }
}

// ─── ADMIN IDs ─────────────────────────────────────────────────────────────────
const ADMIN_IDS = (process.env.ADMIN_IDS || "7113666466")
  .split(",").map(s => s.trim()).filter(Boolean).map(Number);

// ─── MIME ──────────────────────────────────────────────────────────────────────
const MIME = {
  ".html": "text/html", ".js": "application/javascript", ".mjs": "application/javascript",
  ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json",
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp",
  ".svg": "image/svg+xml", ".ico": "image/x-icon", ".mp3": "audio/mpeg", ".mp4": "video/mp4",
  ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
  ".webmanifest": "application/manifest+json", ".bin": "application/octet-stream", ".map": "application/json",
};

// ─── DATA ──────────────────────────────────────────────────────────────────────
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
      return {
        admins: Array.isArray(parsed.admins) ? parsed.admins.map(Number).filter(Number.isSafeInteger) : [],
        users: parsed.users && typeof parsed.users === "object" ? parsed.users : {},
        sessions: parsed.sessions && typeof parsed.sessions === "object" ? parsed.sessions : {}
      };
    }
  } catch (e) {
    console.error("[Data] Could not load data.json:", e.message);
  }
  return { admins: [...ADMIN_IDS], users: {}, sessions: {} };
}
function saveData(data) {
  const tempFile = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), { encoding: "utf-8", mode: 0o600 });
  fs.renameSync(tempFile, DATA_FILE);
  try { fs.chmodSync(DATA_FILE, 0o600); } catch (e) {}
}

let db = loadData();
for (const id of ADMIN_IDS) { if (!db.admins.includes(id)) db.admins.push(id); }

// ─── PERMISSIONS ───────────────────────────────────────────────────────────────
function isAdmin(userId) { return db.admins.includes(Number(userId)); }

function isPermitted(userId) {
  if (isAdmin(userId)) return true;
  const u = db.users[String(userId)];
  if (!u) return false;
  if (u.grantedUntil === null) return true;
  return u.grantedUntil > Math.floor(Date.now() / 1000);
}

function timeLeft(userId) {
  const u = db.users[String(userId)];
  if (!u) return null;
  if (u.grantedUntil === null) return "Permanent";
  const secs = u.grantedUntil - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "Expired";
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stateKey(chatId, userId) { return `${chatId}:${userId}`; }

function getUserSessions(userId) {
  const sessions = db.sessions[String(userId)];
  return Array.isArray(sessions) ? sessions : [];
}

function canAddSessions(userId, count = 1) {
  return getUserSessions(userId).length + count <= MAX_SESSIONS_PER_USER;
}

function safeFilename(value, fallback = "session") {
  const cleaned = String(value || fallback).replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^\.+/, "");
  return (cleaned || fallback).slice(0, 80);
}

function boundedText(value, fallback, maxLength = 80) {
  const text = String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return (text || fallback).slice(0, maxLength);
}


// ─── TELEGRAM API ──────────────────────────────────────────────────────────────
async function tgCall(method, body = null) {
  if (tgCallHook) return tgCallHook(method, body);
  const opts = { method: body ? "POST" : "GET", headers: body ? { "Content-Type": "application/json" } : {}, signal: AbortSignal.timeout(35000) };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(`${TG_API}/${method}`, opts);
  const result = await r.json();
  if (!r.ok || !result.ok) {
    throw new Error(result.description || `Telegram API ${method} failed with HTTP ${r.status}`);
  }
  return result;
}

// Test seam: when set (by the automated tests), every outbound Telegram API
// call is routed through this function instead of hitting api.telegram.org.
let tgCallHook = null;
function setTgCallHook(fn) {
  tgCallHook = typeof fn === "function" ? fn : null;
}

async function send(chatId, text, extra = {}) {
  return tgCall("sendMessage", { chat_id: chatId, text, parse_mode: "HTML", ...extra });
}

async function sendDoc(chatId, filename, content, caption = "") {
  const boundary = "----FormBoundary" + Math.random().toString(36).slice(2);
  const chunks = [];
  const field = (name, value) => chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${String(value)}\r\n`));
  field("chat_id", chatId);
  field("caption", caption);
  chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="${safeFilename(filename)}"\r\nContent-Type: application/octet-stream\r\n\r\n`));
  chunks.push(Buffer.isBuffer(content) ? content : Buffer.from(String(content), "utf8"));
  chunks.push(Buffer.from(`\r\n--${boundary}--\r\n`));
  const r = await fetch(`${TG_API}/sendDocument`, {
    method: "POST",
    headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
    signal: AbortSignal.timeout(35000),
    body: Buffer.concat(chunks),
  });
  const result = await r.json();
  if (!r.ok || !result.ok) throw new Error(result.description || `Telegram API sendDocument failed with HTTP ${r.status}`);
  return result;
}

// ─── STATE MACHINE ─────────────────────────────────────────────────────────────
const STATE = {};
function getState(chatId, userId) { return STATE[stateKey(chatId, userId)] || {}; }
function setState(chatId, userId, s) { STATE[stateKey(chatId, userId)] = s; }
function clearState(chatId, userId) { delete STATE[stateKey(chatId, userId)]; }

// ─── OTP LOGIN ENGINE (persistent worker per chat) ────────────────────────────
// A Python/Telethon worker keeps the login conversation alive so that the
// phone_code_hash returned for "start" stays valid for the "code"/"password"
// steps. See login_bridge.py for the JSON-lines protocol.
function loginAvailable() {
  return Boolean(PYTHON_BIN && fs.existsSync(LOGIN_BRIDGE));
}

function loginUnavailableMessage() {
  return "<b>OTP login is unavailable on this server.</b>\n\n" +
    "The admin must install Python 3 with Telethon (see README, 'Python session validator').\n" +
    "You can still save a session via <code>/session</code>, a document upload, or the web app import.";
}

// Stop the login worker and drop all of its state for the chat.
function finishLogin(chatId, userId) {
  const st = getState(chatId, userId);
  if (st && st.loginChild) {
    try { if (st.idleTimer) clearTimeout(st.idleTimer); } catch (e) {}
    try { st.loginChild.kill(); } catch (e) {}
    st.loginChild = null;
  }
  if (st && typeof st.step === "string" && st.step.startsWith("login:")) {
    clearState(chatId, userId);
  }
}

// Send one request to the login worker and await its next JSON event.
function loginRequest(chatId, userId, payload, timeoutMs = 90000) {
  const st = getState(chatId, userId);
  const child = st && st.loginChild;
  if (!child || !child.stdin || child.stdin.writable !== true || child.killed) {
    clearState(chatId, userId);
    return Promise.reject(new Error("The login worker is not running. Start the OTP login again from the menu."));
  }
  if (st.idleTimer) clearTimeout(st.idleTimer);
  const childRef = child;
  st.idleTimer = setTimeout(() => {
    const cur = getState(chatId, userId);
    if (cur && cur.loginChild === childRef) finishLogin(chatId, userId);
  }, LOGIN_IDLE_TIMEOUT_MS);
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        finishLogin(chatId, userId);
        reject(new Error("The login worker did not respond in time."));
      }
    }, timeoutMs);
    st.loginPendingOwner = child;
    st.loginPending = (event) => {
      if (settled) return;
      settled = true;
      delete st.loginPendingOwner;
      delete st.loginPending;
      clearTimeout(timer);
      resolve(event);
    };
    try {
      child.stdin.write(JSON.stringify(payload) + "\n");
    } catch (err) {
      st.loginPending({ event: "error", fatal: true, message: "The login worker stopped accepting requests." });
    }
  });
}

function spawnLoginWorker(chatId, userId) {
  const inheritedPath = process.env.PYTHONPATH
    ? `${PYTHON_PACKAGES}${path.delimiter}${process.env.PYTHONPATH}`
    : PYTHON_PACKAGES;
  const child = spawn(PYTHON_BIN, [LOGIN_BRIDGE], {
    cwd: __dirname,
    env: { ...process.env, PYTHONPATH: inheritedPath },
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"]
  });
  let lineBuffer = "";

  child.stdout.on("data", (chunk) => {
    lineBuffer += chunk.toString("utf8");
    let newlineIndex;
    while ((newlineIndex = lineBuffer.indexOf("\n")) >= 0) {
      const line = lineBuffer.slice(0, newlineIndex).trim();
      lineBuffer = lineBuffer.slice(newlineIndex + 1);
      if (!line) continue;
      let event;
      try {
        event = JSON.parse(line);
      } catch (e) {
        continue;
      }
      const st = getState(chatId, userId);
      const pending = st && st.loginPendingOwner === child ? st.loginPending : null;
      if (pending) pending(event);
    }
  });
  child.stderr.on("data", () => {});
  child.on("error", (err) => {
    const st = getState(chatId, userId);
    const pending = st && st.loginPendingOwner === child ? st.loginPending : null;
    if (pending) pending({ event: "error", fatal: true, message: `The login worker failed to start: ${err.message}` });
  });
  child.on("close", () => {
    const st = getState(chatId, userId);
    const pending = st && st.loginPendingOwner === child ? st.loginPending : null;
    if (st && st.loginChild === child) st.loginChild = null;
    if (pending) pending({ event: "error", fatal: true, message: "The login worker exited unexpectedly." });
  });

  // Persist the worker handle next to the flow state for this chat.
  const st = getState(chatId, userId);
  st.loginChild = child;
  st.idleTimer = setTimeout(() => {
    const cur = getState(chatId, userId);
    if (cur && cur.loginChild === child) finishLogin(chatId, userId);
  }, LOGIN_IDLE_TIMEOUT_MS);
  return child;
}

function saveOtpLoginSession(userId, ev) {
  const sessions = db.sessions[String(userId)] || [];
  const entry = {
    id: Date.now(),
    label: `Session ${sessions.length + 1} (DC ${ev.dcId})`,
    dcId: ev.dcId,
    authKeyHex: ev.authKeyHex,
    userId: ev.userId || String(userId),
    firstName: boundedText(ev.firstName, "Telegram User"),
    phone: ev.phone || null,
    username: null,
    telethon: ev.telethon || buildTelethon(ev.dcId, ev.authKeyHex),
    pyrogram: buildPyrogram(ev.dcId, ev.authKeyHex, ev.userId || userId),
    hex: ev.authKeyHex,
    type: "OTP Login",
    createdAt: Math.floor(Date.now() / 1000),
  };
  sessions.push(entry);
  db.sessions[String(userId)] = sessions;
  saveData(db);
  return entry;
}

function otpSessionSavedMessage(entry) {
  return "<b>Session Created!</b>\n\n" +
    `Name: <b>${escapeHtml(entry.firstName)}</b>\n` +
    `Phone: <b>${escapeHtml(entry.phone || "-")}</b>\n` +
    `User ID: <code>${escapeHtml(entry.userId)}</code>\n` +
    `DC: <b>${entry.dcId}</b>\n\n` +
    "Tap <b>Open App</b> to launch with the session, or use <code>/export</code>.";
}

// Handle an "authorized" event uniformly for both the code and password steps.
async function completeOtpLogin(chatId, userId, ev, webAppUrl) {
  try {
    const entry = saveOtpLoginSession(userId, ev);
    finishLogin(chatId, userId);
    await send(chatId, otpSessionSavedMessage(entry), { reply_markup: userKeyboard(webAppUrl, userId) });
  } catch (err) {
    finishLogin(chatId, userId);
    await send(chatId, `<b>Login failed.</b>\n\nReason: <code>${escapeHtml(err.message)}</code>`);
  }
}

// ─── KEYBOARDS (no emojis) ─────────────────────────────────────────────────────
function adminKeyboard() {
  return {
    inline_keyboard: [
      [{ text: "List Users", callback_data: "admin:list" }, { text: "Add User", callback_data: "admin:add" }],
      [{ text: "Set Time", callback_data: "admin:settime" }, { text: "Remove User", callback_data: "admin:remove" }],
      [{ text: "Sessions", callback_data: "admin:sessions" }, { text: "Refresh", callback_data: "admin:refresh" }],
    ],
  };
}

function userKeyboard(webAppUrl, userId) {
  const appUrl = buildWebAppUrl(webAppUrl, userId);
  return {
    inline_keyboard: [
      [{ text: "Open App", web_app: { url: appUrl } }],
      [{ text: "My Sessions", callback_data: "user:sessions" }, { text: "Login by OTP", callback_data: "user:login" }],
      [{ text: "Export Sessions", callback_data: "export:menu" }],
      [{ text: "My Access Info", callback_data: "user:info" }],
    ],
  };
}

function adminStartKeyboard(webAppUrl, userId) {
  const appUrl = buildWebAppUrl(webAppUrl, userId);
  return {
    inline_keyboard: [
      [{ text: "Open App", web_app: { url: appUrl } }],
      [{ text: "Admin Panel", callback_data: "admin:refresh" }],
      [{ text: "My Sessions", callback_data: "user:sessions" }, { text: "Login by OTP", callback_data: "user:login" }],
      [{ text: "Export Sessions", callback_data: "export:menu" }],
    ],
  };
}

function exportMenuKeyboard(userId) {
  const sessions = db.sessions[String(userId)] || [];
  if (sessions.length === 0) {
    return { inline_keyboard: [[{ text: "No sessions saved", callback_data: "noop" }], [{ text: "Back", callback_data: "user:back" }]] };
  }
  const rows = sessions.map((s, i) => [{ text: boundedText(`Session ${i + 1}${s.label ? ' — ' + s.label : ''}`, `Session ${i + 1}`, 60), callback_data: `export:pick:${i}` }]);
  rows.push([{ text: "Export All Sessions", callback_data: "export:all" }]);
  rows.push([{ text: "Back", callback_data: "user:back" }]);
  return { inline_keyboard: rows };
}

function exportFormatKeyboard(idx) {
  return {
    inline_keyboard: [
      [{ text: "Telethon String", callback_data: `export:fmt:${idx}:telethon` }],
      [{ text: "Pyrogram String", callback_data: `export:fmt:${idx}:pyrogram` }],
      [{ text: "Hex Auth Key", callback_data: `export:fmt:${idx}:hex` }],
      [{ text: "JSON (all fields)", callback_data: `export:fmt:${idx}:json` }],
      [{ text: "All Formats at Once", callback_data: `export:fmt:${idx}:all` }],
      [{ text: "Back", callback_data: "export:menu" }],
    ],
  };
}

// ─── HANDLERS ──────────────────────────────────────────────────────────────────
async function handleStart(msg, webAppUrl) {
  const chatId  = msg.chat.id;
  const userId  = msg.from.id;
  const name    = msg.from?.first_name || "User";

  if (!isPermitted(userId)) {
    return send(chatId,
      `<b>Access Restricted</b>\n\n` +
      `Hello <b>${escapeHtml(name)}</b>!\n\n` +
      `You do not have access to this bot.\n` +
      `Contact the admin and share your ID: <code>${userId}</code>`
    );
  }

  // Admin start screen
  if (isAdmin(userId)) {
    const userCount    = Object.keys(db.users).length;
    const sessionCount = Object.values(db.sessions).reduce((a, b) => a + b.length, 0);
    const mySessions   = (db.sessions[String(userId)] || []).length;
    const sessionNote  = mySessions > 0 ? `\nTap <b>Open App</b> to launch with your session pre-loaded.` : `\nUse /session to save a session and auto-login next time.`;
    return send(chatId,
      `<b>Welcome, ${escapeHtml(name)}</b>\n\n` +
      `<b>Admin Dashboard</b>\n\n` +
      `Users registered: <b>${userCount}</b>\n` +
      `Sessions stored (all): <b>${sessionCount}</b>\n` +
      `Your sessions: <b>${mySessions}</b>${sessionNote}`,
      { reply_markup: adminStartKeyboard(webAppUrl, userId) }
    );
  }

  // Regular user start screen
  const left       = timeLeft(userId) || "Permanent";
  const mySessions = (db.sessions[String(userId)] || []).length;
  const sessionNote = mySessions > 0 ? `\nTap <b>Open App</b> — your session will auto-login.` : `\nUse /session to save a session and auto-login next time.`;
  return send(chatId,
    `<b>Welcome, ${escapeHtml(name)}</b>\n\n` +
    `Access: <b>${left}</b>\n` +
    `Your sessions: <b>${mySessions}</b>${sessionNote}`,
    { reply_markup: userKeyboard(webAppUrl, userId) }
  );
}

async function handleAdmin(msg) {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (!isAdmin(userId)) {
    return send(chatId, `Access denied.\n\nYour ID: <code>${userId}</code>`);
  }

  const userCount    = Object.keys(db.users).length;
  const sessionCount = Object.values(db.sessions).reduce((a, b) => a + b.length, 0);
  return send(chatId,
    `<b>Admin Panel</b>\n\n` +
    `Users: <b>${userCount}</b>\n` +
    `Sessions stored: <b>${sessionCount}</b>\n` +
    `Admins: <b>${db.admins.length}</b>\n\n` +
    `Select an action:`,
    { reply_markup: adminKeyboard() }
  );
}

async function handleSaveSession(msg) {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  if (!isPermitted(userId)) return send(chatId, "Access denied.");
  if (!canAddSessions(userId)) return send(chatId, `Session limit reached (${MAX_SESSIONS_PER_USER}).`);
  setState(chatId, userId, { step: "await_session" });
  return send(chatId,
    `<b>Save Session</b>\n\n` +
    `Send your session string:\n` +
    `- Telethon (starts with <code>1...</code>)\n` +
    `- Pyrogram string session\n` +
    `- JSON auth key with <code>authKey</code> and <code>dcId</code>\n\n` +
    `Send /cancel to abort.`
  );
}

async function handleText(msg, webAppUrl) {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const text   = msg.text.trim();
  const state  = getState(chatId, userId);

  if (text === "/cancel") {
    const step = state.step || "";
    finishLogin(chatId, userId);
    clearState(chatId, userId);
    return send(chatId, step.startsWith("login:") ? "Login cancelled." : "Cancelled.");
  }

  if (state.step?.startsWith("admin:") && !isAdmin(userId)) {
    clearState(chatId, userId);
    return send(chatId, "Admin only.");
  }

  if (state.step === "admin:add:id") {
    if (!/^\d+$/.test(text)) return send(chatId, "Invalid user ID. Send digits only.");
    setState(chatId, userId, { step: "admin:add:time", data: { targetId: text } });
    return send(chatId,
      `Set access duration for user <code>${text}</code>:\n\n` +
      `<code>permanent</code> — no expiry\n` +
      `<code>7d</code> — 7 days\n` +
      `<code>12h</code> — 12 hours\n` +
      `<code>30m</code> — 30 minutes\n\nSend /cancel to abort.`
    );
  }

  if (state.step === "admin:add:time") {
    const { targetId } = state.data;
    let grantedUntil = null;
    if (text.toLowerCase() !== "permanent") {
      const secs = parseDuration(text);
      if (!secs) return send(chatId, "Invalid duration. Use <code>7d</code>, <code>12h</code>, <code>30m</code>, or <code>permanent</code>.");
      grantedUntil = Math.floor(Date.now() / 1000) + secs;
    }
    db.users[targetId] = { username: "unknown", name: "unknown", grantedUntil, addedBy: userId, addedAt: Math.floor(Date.now() / 1000) };
    saveData(db); clearState(chatId, userId);
    const exp = grantedUntil ? new Date(grantedUntil * 1000).toUTCString() : "Permanent";
    return send(chatId, `User <code>${targetId}</code> added.\nAccess until: <b>${exp}</b>`);
  }

  if (state.step === "admin:settime:id") {
    if (!/^\d+$/.test(text)) return send(chatId, "Invalid user ID.");
    if (!db.users[text] && !db.admins.includes(Number(text))) return send(chatId, `User <code>${text}</code> not found.`);
    setState(chatId, userId, { step: "admin:settime:dur", data: { targetId: text } });
    return send(chatId,
      `New duration for <code>${text}</code>:\n\n<code>permanent</code> / <code>7d</code> / <code>12h</code> / <code>30m</code>\n\nSend /cancel to abort.`
    );
  }

  if (state.step === "admin:settime:dur") {
    const { targetId } = state.data;
    let grantedUntil = null;
    if (text.toLowerCase() !== "permanent") {
      const secs = parseDuration(text);
      if (!secs) return send(chatId, "Invalid duration format.");
      grantedUntil = Math.floor(Date.now() / 1000) + secs;
    }
    if (!db.users[targetId]) db.users[targetId] = { username: "unknown", name: "unknown", addedBy: userId, addedAt: Date.now() };
    db.users[targetId].grantedUntil = grantedUntil;
    saveData(db); clearState(chatId, userId);
    const exp = grantedUntil ? new Date(grantedUntil * 1000).toUTCString() : "Permanent";
    return send(chatId, `Access updated for <code>${targetId}</code>.\nUntil: <b>${exp}</b>`);
  }

  if (state.step === "admin:remove:id") {
    if (db.users[text]) {
      delete db.users[text]; saveData(db); clearState(chatId, userId);
      return send(chatId, `User <code>${text}</code> removed.`);
    }
    clearState(chatId, userId);
    return send(chatId, `User <code>${text}</code> not found.`);
  }

  if (state.step === "login:phone") {
    if (!isPermitted(userId)) { finishLogin(chatId, userId); return send(chatId, "Access denied."); }
    if (!loginAvailable()) { finishLogin(chatId, userId); return send(chatId, loginUnavailableMessage()); }
    if (!canAddSessions(userId)) { finishLogin(chatId, userId); return send(chatId, `Session limit reached (${MAX_SESSIONS_PER_USER}).`); }
    const phoneMatch = text.match(/\d/g);
    const phone = phoneMatch ? `+${phoneMatch.join("")}` : "";
    if (!/^\+\d{7,15}$/.test(phone)) {
      return send(chatId, "Invalid number. Include the country code, e.g. <code>+15551234567</code>, or send /cancel.");
    }
    clearState(chatId, userId);
    setState(chatId, userId, { step: "login:code", data: { phone } });
    spawnLoginWorker(chatId, userId);
    try {
      const event = await loginRequest(chatId, userId, { cmd: "start", phone });
      if (event.event === "code_sent") {
        return send(chatId,
          "<b>OTP Sent!</b>\n\n" +
          `Phone: <code>${escapeHtml(phone)}</code>` +
          (event.hint ? `\n${escapeHtml(event.hint)}` : "") + "\n\n" +
          "Enter the verification code:"
        );
      }
      throw new Error(event.message || "Telegram did not send a login code.");
    } catch (err) {
      finishLogin(chatId, userId);
      return send(chatId, `<b>Login failed.</b>\n\nReason: <code>${escapeHtml(err.message)}</code>\n\nTry again from the menu.`);
    }
  }

  if (state.step === "login:code") {
    if (!state.data || !state.data.phone) { finishLogin(chatId, userId); return send(chatId, "Login state lost. Start a new OTP login from the menu."); }
    if (!/^\d{3,8}$/.test(text)) {
      return send(chatId, "The code is numeric. Enter the digits Telegram sent, or send /cancel.");
    }
    let event;
    try {
      event = await loginRequest(chatId, userId, { cmd: "code", code: text, phone: state.data.phone });
    } catch (err) {
      return send(chatId, `<b>Login failed.</b>\n\nReason: <code>${escapeHtml(err.message)}</code>`);
    }
    if (event.event === "authorized" && event.success) {
      return completeOtpLogin(chatId, userId, event, webAppUrl);
    }
    if (event.event === "password_required") {
      setState(chatId, userId, { step: "login:password", data: state.data, loginChild: state.loginChild, idleTimer: state.idleTimer });
      return send(chatId,
        "<b>2FA Required</b>\n\n" +
        "This account has two-factor verification.\n" +
        "Send the account password (it is not stored anywhere):"
      );
    }
    const message = event.message || "The code did not work. Try again.";
    if (event.fatal) {
      finishLogin(chatId, userId);
      return send(chatId, `<b>Login failed.</b>\n\nReason: <code>${escapeHtml(message)}</code>\n\nTry again from the menu.`);
    }
    if (event.event === "expired") {
      finishLogin(chatId, userId);
      return send(chatId, `<b>${escapeHtml(message)}</b>`);
    }
    if (event.event === "error" && /expired|flood|banned|worker is not running|failed to start|restarted/i.test(message)) {
      finishLogin(chatId, userId);
      return send(chatId, `<b>Login failed.</b>\n\nReason: <code>${escapeHtml(message)}</code>\n\nStart a new login from the menu.`);
    }
    return send(chatId, escapeHtml(message));
  }

  if (state.step === "login:password") {
    if (text.length < 4 || text.length > 128) {
      return send(chatId, "Send the two-factor password (4+ characters), or send /cancel.");
    }
    try {
      const event = await loginRequest(chatId, userId, { cmd: "password", password: text, phone: state.data.phone }, 120000);
      if (event.event === "authorized" && event.success) {
        return completeOtpLogin(chatId, userId, event, webAppUrl);
      }
      const message = event.message || "The password did not work. Try again.";
      if (event.fatal || event.event === "expired" || event.event !== "error") {
        finishLogin(chatId, userId);
        return send(chatId, `<b>Login failed.</b>\n\nReason: <code>${escapeHtml(message)}</code>\n\nStart a new login from the menu.`);
      }
      return send(chatId, escapeHtml(message));
    } catch (err) {
      finishLogin(chatId, userId);
      return send(chatId, `<b>Login failed.</b>\n\nReason: <code>${escapeHtml(err.message)}</code>`);
    }
  }

  if (state.step === "await_session") {
    if (!isPermitted(userId)) return send(chatId, "Access denied.");
    if (!canAddSessions(userId)) return send(chatId, `Session limit reached (${MAX_SESSIONS_PER_USER}).`);
    if (text.length > 20000) return send(chatId, "Session input is too large.");
    const parsed = await parseAndValidate(text);
    if (!parsed.valid) {
      return send(chatId,
        `<b>Session is Invalid!</b>\n\n` +
        `<b>Reason:</b> <code>${escapeHtml(parsed.error)}</code>\n\n` +
        `Please send a valid session string:\n` +
        `• Telethon (starts with <code>1...</code>)\n` +
        `• Pyrogram session string\n` +
        `• JSON auth key with <code>authKey</code> and <code>dcId</code>\n\n` +
        `Send /cancel to abort.`
      );
    }

    const sessions = db.sessions[String(userId)] || [];
    const entry = {
      id: Date.now(),
      label: `Session ${sessions.length + 1} (DC ${parsed.dcId})`,
      dcId: parsed.dcId,
      authKeyHex: parsed.authKeyHex,
      userId: parsed.userId || userId,
      firstName: boundedText(parsed.firstName, "Telegram User"),
      phone: null,
      username: null,
      telethon:  parsed.telethon,
      pyrogram:  parsed.userId ? parsed.pyrogram : buildPyrogram(parsed.dcId, parsed.authKeyHex, userId),
      hex:       parsed.authKeyHex,
      type:      boundedText(parsed.type, "Session"),
      createdAt: Math.floor(Date.now() / 1000),
    };
    sessions.push(entry);
    db.sessions[String(userId)] = sessions;
    saveData(db); clearState(chatId, userId);
    return send(chatId,
      `<b>Session Valid & Saved!</b>\n\n` +
      `Type: <b>${escapeHtml(entry.type)}</b>\n` +
      `DC: <b>${entry.dcId}</b>\n` +
      `User ID: <code>${entry.userId}</code>\n` +
      `Label: <b>${escapeHtml(entry.label)}</b>\n\n` +
      `Use /export to export your sessions, or tap <b>Open App</b> to auto-login.`,
      { reply_markup: userKeyboard(webAppUrl, userId) }
    );
  }
}

// ─── CALLBACK QUERIES ──────────────────────────────────────────────────────────
async function handleCallback(cb, webAppUrl) {
  const chatId = cb.message?.chat?.id;
  const userId = cb.from.id;
  const data   = cb.data;

  if (cb.id !== "0") await tgCall("answerCallbackQuery", { callback_query_id: cb.id });
  if (!chatId) return; // original message was deleted or is unavailable

  // ── ADMIN ────────────────────────────────────────────────────────────────
  if (data.startsWith("admin:")) {
    if (!isAdmin(userId)) return send(chatId, "Admin only.");
    const action = data.slice(6);

    if (action === "list") {
      const entries = Object.entries(db.users);
      if (!entries.length) return send(chatId, "No users added yet.");
      const lines = entries.map(([uid, u]) => {
        const left = u.grantedUntil === null ? "Permanent" : (u.grantedUntil > Date.now() / 1000 ? timeLeft(uid) : "Expired");
        return `• <code>${uid}</code> — ${left}`;
      });
      return send(chatId, `<b>Users (${entries.length})</b>\n\n${lines.join("\n")}`, { reply_markup: adminKeyboard() });
    }

    if (action === "add") {
      setState(chatId, userId, { step: "admin:add:id" });
      return send(chatId, "<b>Add User</b>\n\nSend the Telegram <b>User ID</b> to grant access:\n\nSend /cancel to abort.");
    }

    if (action === "settime") {
      setState(chatId, userId, { step: "admin:settime:id" });
      return send(chatId, "<b>Set Access Time</b>\n\nSend the Telegram <b>User ID</b>:\n\nSend /cancel to abort.");
    }

    if (action === "remove") {
      setState(chatId, userId, { step: "admin:remove:id" });
      return send(chatId, "<b>Remove User</b>\n\nSend the Telegram <b>User ID</b> to remove:\n\nSend /cancel to abort.");
    }

    if (action === "sessions") {
      const total = Object.values(db.sessions).reduce((a, b) => a + b.length, 0);
      const lines = Object.entries(db.sessions)
        .filter(([, s]) => s.length)
        .map(([uid, s]) => `• <code>${uid}</code>: ${s.length} session(s)`);
      return send(chatId,
        `<b>Sessions Overview</b>\n\nTotal: <b>${total}</b>\n\n${lines.join("\n") || "None yet"}`,
        { reply_markup: adminKeyboard() }
      );
    }

    if (action === "refresh") {
      const userCount    = Object.keys(db.users).length;
      const sessionCount = Object.values(db.sessions).reduce((a, b) => a + b.length, 0);
      return send(chatId,
        `<b>Admin Panel</b>\n\nUsers: <b>${userCount}</b>\nSessions: <b>${sessionCount}</b>\nAdmins: <b>${db.admins.length}</b>`,
        { reply_markup: adminKeyboard() }
      );
    }
  }

  // ── USER ─────────────────────────────────────────────────────────────────
  if (data === "user:info") {
    if (!isPermitted(userId)) return send(chatId, "Access denied.");
    const left     = isAdmin(userId) ? "Admin (unlimited)" : timeLeft(userId);
    const sessions = (db.sessions[String(userId)] || []).length;
    return send(chatId,
      `<b>Your Info</b>\n\n` +
      `ID: <code>${userId}</code>\n` +
      `Access: <b>${left}</b>\n` +
      `Saved sessions: <b>${sessions}</b>`
    );
  }

  if (data === "user:login") {
    if (!isPermitted(userId)) return send(chatId, "Access denied.");
    if (!canAddSessions(userId)) return send(chatId, `Session limit reached (${MAX_SESSIONS_PER_USER}).`);
    if (!loginAvailable()) return send(chatId, loginUnavailableMessage());
    setState(chatId, userId, { step: "login:phone" });
    return send(chatId,
      "<b>Login by OTP</b>\n\n" +
      "1. Send the phone number with the country code, e.g. <code>+15551234567</code>\n" +
      "2. Telegram sends a login code — enter it here.\n" +
      "3. If the account has a 2FA password you will be asked for it.\n\n" +
      "Send /cancel to abort."
    );
  }

  if (data === "user:sessions") {
    if (!isPermitted(userId)) return send(chatId, "Access denied.");
    const sessions = db.sessions[String(userId)] || [];
    if (!sessions.length) {
      return send(chatId,
        `<b>Your Sessions</b>\n\nYou have no sessions saved yet.\n\nUse /session to save one.`
      );
    }
    const lines = sessions.map((s, i) =>
      `${i + 1}. <b>${escapeHtml(s.label || "Session " + (i + 1))}</b>\n   Type: ${escapeHtml(s.type)}\n   DC: ${s.dcId}\n   Added: ${new Date(s.createdAt * 1000).toLocaleDateString()}`
    );
    return send(chatId,
      `<b>Your Sessions (${sessions.length})</b>\n\n${lines.join("\n\n")}`,
      { reply_markup: { inline_keyboard: [[{ text: "Export Sessions", callback_data: "export:menu" }]] } }
    );
  }

  if (data === "user:back") {
    if (isAdmin(userId)) {
      return send(chatId, "Select an option:", { reply_markup: adminStartKeyboard(webAppUrl, userId) });
    }
    return send(chatId, "Select an option:", { reply_markup: userKeyboard(webAppUrl, userId) });
  }

  // ── EXPORT ───────────────────────────────────────────────────────────────
  if (data.startsWith("export:")) {
    if (!isPermitted(userId)) return send(chatId, "Access denied.");
    const parts  = data.split(":");
    const action = parts[1];

    if (action === "menu") {
      const sessions = db.sessions[String(userId)] || [];
      if (!sessions.length) {
        return send(chatId,
          `<b>Export Sessions</b>\n\nYou have no sessions saved.\n\nUse /session to save a session first.`
        );
      }
      return send(chatId,
        `<b>Export Sessions</b>\n\nYou have <b>${sessions.length}</b> session(s). Select one:`,
        { reply_markup: exportMenuKeyboard(userId) }
      );
    }

    if (action === "pick") {
      return send(chatId, `<b>Choose export format:</b>`, { reply_markup: exportFormatKeyboard(parts[2]) });
    }

    if (action === "all") {
      return send(chatId, `<b>Export all sessions — choose format:</b>`, { reply_markup: exportFormatKeyboard("all") });
    }

    if (action === "fmt") {
      const idxStr  = parts[2];
      const fmt     = parts[3];
      const sessions = db.sessions[String(userId)] || [];
      if (!sessions.length) return send(chatId, "No sessions to export.");

      const targets = idxStr === "all" ? sessions : [sessions[Number(idxStr)]].filter(Boolean);
      if (!targets.length) return send(chatId, "Session not found.");

      const doExport = async (s, format) => {
        const label = s.label || `session_${s.id}`;
        if (format === "telethon") {
          await send(chatId, `<b>Telethon StringSession</b> — ${escapeHtml(label)}:\n\n<code>${escapeHtml(s.telethon)}</code>`);
        } else if (format === "pyrogram") {
          await send(chatId, `<b>Pyrogram StringSession</b> — ${escapeHtml(label)}:\n\n<code>${escapeHtml(s.pyrogram)}</code>`);
        } else if (format === "hex") {
          await send(chatId, `<b>Hex Auth Key</b> — ${escapeHtml(label)}:\n\n<code>${escapeHtml(s.hex)}</code>`);
        } else if (format === "json") {
          const j = JSON.stringify({ label: s.label, dcId: s.dcId, type: s.type, telethon: s.telethon, pyrogram: s.pyrogram, hex: s.hex, createdAt: new Date(s.createdAt * 1000).toISOString() }, null, 2);
          await sendDoc(chatId, `${label}.json`, j, `JSON export — ${label}`);
        } else if (format === "all") {
          const text =
            `=== ${label} ===\n` +
            `DC: ${s.dcId}\nType: ${s.type}\n\n` +
            `[Telethon StringSession]\n${s.telethon}\n\n` +
            `[Pyrogram StringSession]\n${s.pyrogram}\n\n` +
            `[Hex Auth Key]\n${s.hex}\n`;
          await sendDoc(chatId, `${label}_all_formats.txt`, text, `All formats — ${label}`);
        }
      };

      if (targets.length === 1) {
        await doExport(targets[0], fmt);
      } else {
        if (fmt === "json") {
          const arr = targets.map(s => ({ label: s.label, dcId: s.dcId, type: s.type, telethon: s.telethon, pyrogram: s.pyrogram, hex: s.hex, createdAt: new Date(s.createdAt * 1000).toISOString() }));
          await sendDoc(chatId, "sessions_all.json", JSON.stringify(arr, null, 2), "All sessions JSON export");
        } else if (fmt === "all") {
          const text = targets.map(s =>
            `=== ${s.label} ===\nDC: ${s.dcId}\nType: ${s.type}\n\n[Telethon]\n${s.telethon}\n\n[Pyrogram]\n${s.pyrogram}\n\n[Hex]\n${s.hex}\n`
          ).join("\n" + "─".repeat(40) + "\n");
          await sendDoc(chatId, "all_sessions_all_formats.txt", text, "All sessions, all formats");
        } else {
          for (const s of targets) await doExport(s, fmt);
        }
      }
      return;
    }
  }

  if (data === "noop") return;
}

// ─── SESSION PARSER ─────────────────────────────────────────────────────────────
function parseSessionInput(raw) {
  const str = raw.trim();
  if (!str) throw new Error("Session string is empty");
  if (/^[0-9a-fA-F]{512}$/.test(str)) throw new Error("Raw hex auth keys require a data center. Send JSON with authKey and dcId.");
  let decoded;
  try {
    let s = str.replace(/[^\w+/=]/g, "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4 !== 0) s += "=";
    const bin = atob(s);
    decoded = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) decoded[i] = bin.charCodeAt(i);
  } catch (e) { throw new Error("Invalid session string — could not base64 decode"); }
  if (decoded.length === 256) throw new Error("Raw auth keys require a data center. Send JSON with authKey and dcId.");
  if (decoded.length >= 261) {
    const dcId = (decoded[0] >= 1 && decoded[0] <= 5) ? decoded[0] : null;
    if (!dcId) throw new Error("Session string does not contain a valid data center.");
    const hex  = Array.from(decoded.slice(decoded.length - 256)).map(b => b.toString(16).padStart(2, "0")).join("");
    return { type: "Telethon/Pyrogram StringSession", dcId, authKeyHex: hex };
  }
  throw new Error("Unrecognized format. Use Telethon, Pyrogram, or 512-char hex Auth Key.");
}

function parseDuration(str) {
  const normalized = str.trim().toLowerCase();
  if (!/^(?:\d+\s*[dhm]\s*)+$/.test(normalized)) return 0;
  let total = 0;
  const re = /(\d+)\s*([dhm])/gi;
  let m;
  while ((m = re.exec(normalized)) !== null) {
    const n = parseInt(m[1]), unit = m[2].toLowerCase();
    if (!Number.isSafeInteger(n)) return 0;
    if (unit === "d") total += n * 86400;
    else if (unit === "h") total += n * 3600;
    else if (unit === "m") total += n * 60;
    if (!Number.isSafeInteger(total) || total > 10 * 365 * 86400) return 0;
  }
  return total;
}

// ─── POLLING ────────────────────────────────────────────────────────────────────
async function startPolling(webAppUrl) {
  let offset = 0;
  console.log("Bot polling started...");
  while (true) {
    try {
      const updates = await tgCall("getUpdates", { offset, timeout: 25, allowed_updates: ["message", "callback_query", "web_app_data"] });
      if (updates.ok && Array.isArray(updates.result)) {
        for (const upd of updates.result) {
          offset = upd.update_id + 1;
          try {
            if (upd.callback_query) {
              await handleCallback(upd.callback_query, webAppUrl);
            } else if (upd.message?.text) {
              const txt = upd.message.text.trim();
              if (txt.startsWith("/start"))       await handleStart(upd.message, webAppUrl);
              else if (txt === "/admin")          await handleAdmin(upd.message);
              else if (txt === "/session")        await handleSaveSession(upd.message);
              else if (txt === "/export") {
                if (!isPermitted(upd.message.from.id)) await send(upd.message.chat.id, "Access denied.");
                else await handleCallback({ id: "0", from: upd.message.from, message: upd.message, data: "export:menu" }, webAppUrl);
              }
              else if (txt === "/help") {
                await send(upd.message.chat.id,
                  `<b>Commands</b>\n\n` +
                  `/start — Open dashboard\n` +
                  `/session — Save a session\n` +
                  `/export — Export sessions\n` +
                  `/admin — Admin panel\n` +
                  `/cancel — Cancel current action\n` +
                  `/help — Show this message`
                );
              }
              else await handleText(upd.message, webAppUrl);
            } else if (upd.message?.document) {
              const chatId = upd.message.chat.id;
              const userId = upd.message.from.id;
              if (isPermitted(userId)) {
                await send(chatId, "Validating session document...");
                try {
                  const doc = upd.message.document;
                  if (!canAddSessions(userId)) throw new Error(`Session limit reached (${MAX_SESSIONS_PER_USER}).`);
                  if (doc.file_size && doc.file_size > MAX_TDATA_UPLOAD_BYTES) throw new Error("Document is too large (32 MB maximum).");
                  const fileInfo = await tgCall("getFile", { file_id: doc.file_id });
                  if (fileInfo.ok && fileInfo.result?.file_path) {
                    const fileRes = await fetch(`https://api.telegram.org/file/bot${BOT_TOKEN}/${fileInfo.result.file_path}`);
                    if (!fileRes.ok) throw new Error(`Telegram file download failed with HTTP ${fileRes.status}.`);
                    const buf = Buffer.from(await fileRes.arrayBuffer());
                    if (buf.length > MAX_TDATA_UPLOAD_BYTES) throw new Error("Document is too large (32 MB maximum).");
                    const parsed = await parseAndValidate(buf);
                    if (!parsed.valid) {
                      await send(chatId,
                        `<b>Document is Invalid!</b>\n\n` +
                        `<b>Reason:</b> <code>${escapeHtml(parsed.error)}</code>\n\n` +
                        `Please provide a valid SQLite .session file, Pyrogram/Telethon string, or TData .zip.`
                      );
                    } else {
                      const sessions = db.sessions[String(userId)] || [];
                      const accounts = parsed.accounts || [parsed];
                      if (!canAddSessions(userId, accounts.length)) throw new Error(`Import would exceed the ${MAX_SESSIONS_PER_USER}-session limit.`);
                      for (const acc of accounts) {
                        const entry = {
                          id: Date.now() + Math.floor(Math.random() * 1000),
                          label: boundedText(acc.label || (doc.file_name ? doc.file_name.replace(/\.[^.]+$/, '') : `Session ${sessions.length + 1}`), `Session ${sessions.length + 1}`),
                          dcId: acc.dcId,
                          authKeyHex: acc.authKeyHex,
                          userId: acc.userId || userId,
                          firstName: boundedText(acc.firstName, "Telegram User"),
                          telethon: acc.telethon || buildTelethon(acc.dcId, acc.authKeyHex),
                          pyrogram: acc.userId && acc.pyrogram
                            ? acc.pyrogram
                            : buildPyrogram(acc.dcId, acc.authKeyHex, acc.userId || userId),
                          hex: acc.authKeyHex,
                          type: boundedText(acc.type, "Document Import"),
                          createdAt: Math.floor(Date.now() / 1000),
                        };
                        sessions.push(entry);
                      }
                      db.sessions[String(userId)] = sessions;
                      saveData(db);
                      clearState(chatId, userId);
                      await send(chatId,
                        `<b>Session Valid & Saved!</b>\n\n` +
                        `Loaded <b>${accounts.length}</b> session(s) from <code>${escapeHtml(doc.file_name)}</code>.\n` +
                        `Type: <b>${escapeHtml(accounts[0].type)}</b> (DC ${accounts[0].dcId})\n\n` +
                        `Use /export to export or tap <b>Open App</b> to launch.`,
                        { reply_markup: userKeyboard(webAppUrl, userId) }
                      );
                    }
                  } else {
                    await send(chatId, "Failed to retrieve document from Telegram.");
                  }
                } catch (e) {
                  await send(chatId, `Error analyzing document: ${escapeHtml(e.message)}`);
                }
              }
            } else if (upd.message?.web_app_data) {
              // ── Session sent FROM miniapp via sendData ────────────────
              const chatId = upd.message.chat.id;
              const userId = upd.message.from.id;
              if (isPermitted(userId)) {
                try {
                  const payload = JSON.parse(upd.message.web_app_data.data);
                  if (payload.action === 'save_session' && payload.key && payload.dcId) {
                    if (!canAddSessions(userId)) throw new Error(`Session limit reached (${MAX_SESSIONS_PER_USER}).`);
                    const validatedKey = validateHexKey(String(payload.key));
                    const dcId = Number(payload.dcId);
                    if (!validatedKey.valid || !Number.isInteger(dcId) || dcId < 1 || dcId > 5) {
                      throw new Error('Invalid session payload from Mini App.');
                    }
                    const sessions = db.sessions[String(userId)] || [];
                    const key = validatedKey.authKeyHex;
                    const tSession = buildTelethon(dcId, key);
                    const savedUserId = payload.userId || userId;
                    const pSession = buildPyrogram(dcId, key, savedUserId);
                    const entry = {
                      id: Date.now(),
                      label: boundedText(payload.label || (payload.firstName ? `${payload.firstName} (${payload.phone || savedUserId || 'Session'})` : `Session ${sessions.length + 1}`), `Session ${sessions.length + 1}`),
                      dcId,
                      authKeyHex: key,
                      telethon: tSession,
                      pyrogram: pSession,
                      hex: key,
                      userId: savedUserId,
                      firstName: boundedText(payload.firstName, "Telegram User"),
                      phone: boundedText(payload.phone, "", 32),
                      type: boundedText(payload.type, 'MiniApp Import'),
                      createdAt: Math.floor(Date.now() / 1000),
                    };
                    sessions.push(entry);
                    db.sessions[String(userId)] = sessions;
                    saveData(db);
                    const userLine = entry.firstName ? `User: <b>${escapeHtml(entry.firstName)}</b> (${escapeHtml(entry.userId || 'N/A')})\nPhone: <code>${escapeHtml(entry.phone || 'N/A')}</code>\n` : '';
                    await send(chatId,
                      `<b>Session saved from app!</b>\n\n` +
                      userLine +
                      `Type: <b>${escapeHtml(entry.type)}</b>\n` +
                      `DC: <b>${entry.dcId}</b>\n` +
                      `Label: <b>${escapeHtml(entry.label)}</b>\n\n` +
                      `Next time you tap <b>Open App</b>, it will auto-login.`,
                      { reply_markup: userKeyboard(webAppUrl, userId) }
                    );
                  }
                } catch (e) { console.error('web_app_data parse error:', e); }
              }
            }
          } catch (e) { console.error("Handler error:", e); }
        }
      }
    } catch (err) { console.error("Poll error:", err.message); await new Promise(r => setTimeout(r, 3000)); }
  }
}

// ─── HTTP SERVER ────────────────────────────────────────────────────────────────
function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(body));
}

function readBody(req, res, maxBytes, callback) {
  const contentLength = Number(req.headers["content-length"] || 0);
  if (contentLength > maxBytes) {
    sendJson(res, 413, { success: false, error: "Upload is too large." });
    req.resume();
    return;
  }
  const chunks = [];
  let size = 0;
  let rejected = false;
  req.on("data", chunk => {
    if (rejected) return;
    size += chunk.length;
    if (size > maxBytes) {
      rejected = true;
      sendJson(res, 413, { success: false, error: "Upload is too large." });
      return;
    }
    chunks.push(chunk);
  });
  req.on("end", () => { if (!rejected) callback(Buffer.concat(chunks)); });
  req.on("error", err => {
    if (!res.headersSent) sendJson(res, 400, { success: false, error: "Request body could not be read." });
    console.error("[HTTP] Request error:", err.message);
  });
}

const apiRateLimits = new Map();
function allowApiRequest(req, res, limit) {
  if (req.headers["sec-fetch-site"] === "cross-site") {
    sendJson(res, 403, { success: false, error: "Cross-site requests are not allowed." });
    return false;
  }
  // Do not trust client-controlled forwarding headers for throttling. The
  // public tunnel may add them, but a direct caller can spoof them and evade
  // the limiter; the socket address is the only value this process can trust.
  const clientId = req.socket.remoteAddress || "unknown";
  const key = `${clientId}:${req.url.split("?")[0]}`;
  const now = Date.now();
  const current = apiRateLimits.get(key);
  if (!current || current.expiresAt <= now) {
    if (apiRateLimits.size > 10000) {
      for (const [storedKey, value] of apiRateLimits) {
        if (value.expiresAt <= now) apiRateLimits.delete(storedKey);
      }
      if (apiRateLimits.size > 10000) apiRateLimits.clear();
    }
    apiRateLimits.set(key, { count: 1, expiresAt: now + 60000 });
    return true;
  }
  current.count++;
  if (current.count <= limit) return true;
  res.setHeader("Retry-After", "60");
  sendJson(res, 429, { success: false, error: "Too many requests. Try again shortly." });
  return false;
}

function createServer() {
  return http.createServer((req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    if (req.method === "OPTIONS") { res.writeHead(204, { "Allow": "GET, HEAD, POST, OPTIONS" }); return res.end(); }

    let reqPath;
    try {
      reqPath = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    } catch (e) {
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("Bad request");
    }

    // ── API: Upload & parse TData ZIP (Pure JS) ────────────────────
    if (req.method === "POST" && reqPath === "/api/upload-tdata") {
      if (!allowApiRequest(req, res, 8)) return;
      const passcode = String(req.headers["x-tdata-passcode"] || "").slice(0, 1024);
      readBody(req, res, MAX_TDATA_UPLOAD_BYTES, async buffer => {
        try {
          if (!buffer.length) {
            res.writeHead(400, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "No file data uploaded." }));
          }

          const resVal = validateTdataZip(buffer, passcode);
          if (resVal.valid && resVal.accounts && resVal.accounts.length) {
            const accounts = [];
            for (const parsedAccount of resVal.accounts) {
              const verified = await verifyParsedAccount(parsedAccount);
              if (verified.success) accounts.push({ ...parsedAccount, ...verified, type: parsedAccount.type || "TData" });
            }
            if (!accounts.length) {
              res.writeHead(400, { "Content-Type": "application/json" });
              return res.end(JSON.stringify({ success: false, error: "Telegram rejected every account in this TData archive. The sessions may be expired or revoked." }));
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({
              success: true,
              accounts
            }));
          }

          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: resVal.error || "Could not find valid MTProto auth key in TData ZIP archive." }));
        } catch (err) {
          console.error("[HTTP] TData parsing failed:", err.message);
          if (/not installed|Timed out|timed out/i.test(err.message || "")) {
            res.writeHead(503, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: err.message }));
          }
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: "TData parsing failed." }));
        }
      });
      return;
    }

    // ── API: Upload & parse .session file (Pure JS SQLite / text / zip) ──
    if (req.method === "POST" && reqPath === "/api/upload-session") {
      if (!allowApiRequest(req, res, 20)) return;
      readBody(req, res, MAX_SESSION_UPLOAD_BYTES, async buffer => {
        try {
          if (!buffer.length) {
            res.writeHead(400, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "No file data uploaded." }));
          }

          const parsed = await parseAndValidate(buffer);
          if (parsed && parsed.valid) {
            const acc = (parsed.accounts && parsed.accounts.length) ? parsed.accounts[0] : parsed;
            const keyHex = (acc.authKeyHex || acc.hex || "").toLowerCase();
            if (!Number.isInteger(acc.dcId) || acc.dcId < 1 || acc.dcId > 5 || !/^[0-9a-f]{512}$/.test(keyHex)) {
              res.writeHead(400, { "Content-Type": "application/json" });
              return res.end(JSON.stringify({ success: false, error: "Session is missing a valid data center or auth key." }));
            }
            const verified = await verifyParsedAccount({ ...acc, authKeyHex: keyHex });
            if (!verified.success) {
              res.writeHead(400, { "Content-Type": "application/json" });
              return res.end(JSON.stringify({ success: false, error: verified.error || "Telegram rejected this session." }));
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({
              success: true,
              dcId: verified.dcId,
              authKeyHex: verified.authKeyHex,
              userId: verified.userId,
              firstName: verified.firstName || "Telegram User",
              type: acc.type || "Session File",
              unverified: verified.unverified === true,
              telethon: verified.telethon,
              pyrogram: buildPyrogram(verified.dcId, verified.authKeyHex, verified.userId)
            }));
          }

          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: parsed.error || "Could not recognize session keys in file." }));
        } catch (err) {
          console.error("[HTTP] Session parsing failed:", err.message);
          if (/not installed|Timed out|timed out/i.test(err.message || "")) {
            res.writeHead(503, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: err.message }));
          }
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: "Session parsing failed." }));
        }
      });
      return;
    }

    // ── API: Resolve & verify session (Pure JS, Instant) ────────────
    if (req.method === "POST" && reqPath === "/api/resolve-session") {
      if (!allowApiRequest(req, res, 30)) return;
      readBody(req, res, MAX_JSON_BODY_BYTES, async buffer => {
        try {
          const body = JSON.parse(buffer.toString("utf-8") || "{}");
          const input = String(body.authKeyHex || body.key || body.session || "").trim();
          if (!input) {
            res.writeHead(400, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "Auth key or session string required." }));
          }

          const requestedDc = Number(body.dcId);
          const hasRequestedDc = Number.isInteger(requestedDc) && requestedDc >= 1 && requestedDc <= 5;
          const parseInput = /^[0-9a-fA-F]{512}$/.test(input) && hasRequestedDc
            ? JSON.stringify({ authKey: input, dcId: requestedDc, userId: body.userId })
            : input;
          const parsed = await parseAndValidate(parseInput);
          if (parsed && parsed.valid) {
            const acc = (parsed.accounts && parsed.accounts.length) ? parsed.accounts[0] : parsed;
            const dcId = hasRequestedDc ? requestedDc : acc.dcId;
            const keyHex = (acc.authKeyHex || acc.hex || "").toLowerCase();
            if (!Number.isInteger(dcId) || dcId < 1 || dcId > 5 || !/^[0-9a-f]{512}$/.test(keyHex)) {
              res.writeHead(400, { "Content-Type": "application/json" });
              return res.end(JSON.stringify({ success: false, error: "Session is missing a valid data center or auth key." }));
            }
            let verified;
            try {
              verified = await verifySessionWithTelegram({ session: buildTelethon(dcId, keyHex) });
            } catch (verifyErr) {
              if (!isTelethonUnavailable(verifyErr)) throw verifyErr;
              logTelethonUnavailable();
              verified = unverifiedFallback(acc, dcId, keyHex);
            }
            if (!verified.success) {
              res.writeHead(400, { "Content-Type": "application/json" });
              return res.end(JSON.stringify({ success: false, error: verified.error || "Telegram rejected this session." }));
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({
              success: true,
              dcId: verified.dcId,
              authKeyHex: verified.authKeyHex,
              userId: verified.userId,
              firstName: verified.firstName || "Telegram User",
              type: acc.type,
              unverified: verified.unverified === true,
              telethon: verified.telethon,
              pyrogram: buildPyrogram(verified.dcId, verified.authKeyHex, verified.userId)
            }));
          }

          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: parsed.error || "Invalid session string or auth key." }));
        } catch (err) {
          if (err instanceof SyntaxError) {
            res.writeHead(400, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "Malformed JSON request." }));
          }
          console.error("[HTTP] Session resolution failed:", err.message);
          if (/not installed|Timed out|timed out/i.test(err.message || "")) {
            res.writeHead(503, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: err.message }));
          }
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: "Session resolution failed." }));
        }
      });
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Allow": "GET, HEAD, POST, OPTIONS" });
      return res.end("Method not allowed");
    }

    if (reqPath === "/" || reqPath === "/a" || reqPath === "/z" || reqPath === "/k") reqPath = "/index.html";

    const relativePath = reqPath.replace(/^[/\\]+/, "");
    let filePath = path.resolve(DIST_DIR, relativePath);
    const distPrefix = `${DIST_DIR}${path.sep}`;
    if (filePath !== DIST_DIR && !filePath.startsWith(distPrefix)) {
      res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("Forbidden");
    }
    if (!fs.existsSync(filePath)) {
      if (!path.extname(reqPath)) filePath = path.join(DIST_DIR, "index.html");
      else { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); return res.end("Not found"); }
    } else if (fs.statSync(filePath).isDirectory()) {
      filePath = path.join(filePath, "index.html");
      if (!fs.existsSync(filePath)) filePath = path.join(DIST_DIR, "index.html");
    }

    const ext = path.extname(filePath).toLowerCase();
    const ct  = MIME[ext] || "application/octet-stream";
    fs.readFile(filePath, (err, content) => {
      if (err) {
        console.error("[HTTP] Static file read failed:", err.message);
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Internal server error");
      }
      else {
        res.writeHead(200, {
          "Content-Type": ct,
          "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
          "Pragma": "no-cache",
          "Expires": "0"
        });
        res.end(req.method === "HEAD" ? undefined : content);
      }
    });
  });
}

// ─── CLOUDFLARE TUNNEL ─────────────────────────────────────────────────────────
async function startCloudflaredTunnel(port, attempt = 1) {
  const MAX_ATTEMPTS = 3;
  const WAIT_MS      = 30000; // 30s timeout per attempt

  console.log(`[Tunnel] Starting cloudflared (attempt ${attempt}/${MAX_ATTEMPTS})...`);

  return new Promise((resolve, reject) => {
    const localExe = path.join(__dirname, "cloudflared.exe");
    const exePath  = fs.existsSync(localExe) ? localExe : "cloudflared";

    // Use 'quick-tunnel' sub-command which is more reliable
    const cf = spawn(exePath, [
      "tunnel", "--no-autoupdate",
      "--url", `http://localhost:${port}`,
      "--logfile", path.join(__dirname, "cloudflared.log"),
      "--loglevel", "info",
    ], { windowsHide: true });

    let resolved = false;
    let outputBuf = "";

    const tryResolve = (url) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        console.log(`[Tunnel] Public URL: ${url}`);
        resolve({ url, proc: cf });
      }
    };

    const onData = (chunk) => {
      const text = chunk.toString();
      outputBuf += text;
      // Cloudflared prints the URL to stderr in recent versions
      const match = outputBuf.match(/https:\/\/[a-zA-Z0-9][a-zA-Z0-9-]+\.trycloudflare\.com/);
      if (match) tryResolve(match[0]);
    };

    cf.stdout.on("data", onData);
    cf.stderr.on("data", onData);

    cf.on("error", (err) => {
      console.error(`[Tunnel] cloudflared error: ${err.message}`);
      if (!resolved) { resolved = true; clearTimeout(timer); reject(err); }
    });

    cf.on("exit", (code) => {
      if (!resolved) {
        console.error(`[Tunnel] cloudflared exited with code ${code}`);
        // Try reading the log file for the URL
        try {
          const log = fs.readFileSync(path.join(__dirname, "cloudflared.log"), "utf-8");
          const m = log.match(/https:\/\/[a-zA-Z0-9][a-zA-Z0-9-]+\.trycloudflare\.com/);
          if (m) { resolved = true; clearTimeout(timer); resolve({ url: m[0], proc: null }); return; }
        } catch (e) {}
        resolved = true; clearTimeout(timer); reject(new Error(`exited ${code}`));
      }
    });

    const timer = setTimeout(() => {
      if (!resolved) {
        // Last chance: read log file
        try {
          const log = fs.readFileSync(path.join(__dirname, "cloudflared.log"), "utf-8");
          const m = log.match(/https:\/\/[a-zA-Z0-9][a-zA-Z0-9-]+\.trycloudflare\.com/);
          if (m) { tryResolve(m[0]); return; }
        } catch (e) {}
        console.error(`[Tunnel] Timed out after ${WAIT_MS / 1000}s`);
        resolved = true;
        cf.kill();
        reject(new Error("timeout"));
      }
    }, WAIT_MS);
  }).catch(async (err) => {
    console.error(`[Tunnel] Attempt ${attempt} failed: ${err.message}`);
    if (attempt < MAX_ATTEMPTS) {
      console.log(`[Tunnel] Retrying in 3s...`);
      await new Promise(r => setTimeout(r, 3000));
      return startCloudflaredTunnel(port, attempt + 1);
    }
    console.error("[Tunnel] All attempts failed. Bot will run on localhost only.");
    console.error("[Tunnel] Set APP_URL env var to use a custom public URL.");
    return { url: `http://localhost:${port}`, proc: null };
  });
}

// ─── MAIN ───────────────────────────────────────────────────────────────────────
async function main() {
  console.log("╔══════════════════════════════════════════╗");
  console.log("║     Telegram Web Session Bot             ║");
  console.log("╚══════════════════════════════════════════╝");

  if (!/^\d{6,12}:[A-Za-z0-9_-]{30,}$/.test(BOT_TOKEN)) {
    throw new Error("BOT_TOKEN is missing or invalid. Set it in the environment; never hardcode it in source.");
  }
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    throw new Error("PORT must be an integer from 1 to 65535.");
  }
  if (db.admins.length === 0) {
    throw new Error("No admin is configured. Set ADMIN_IDS to at least one trusted Telegram user ID.");
  }

  // Validate bot token
  const me = await tgCall("getMe");
  global.__botUsername = me.result.username;
  console.log(`[Bot] Authenticated as @${me.result.username}`);
  console.log(`[Bot] Admins: ${db.admins.join(", ")}`);

  // Start HTTP server
  const server = createServer();
  await new Promise(res => server.listen(PORT, res));
  console.log(`[Server] Listening on http://localhost:${PORT}`);
  console.log(`[Server] Serving files from: ${DIST_DIR}`);

  // Get public URL
  let webAppUrl = process.env.APP_URL?.trim().replace(/\/+$/, "");
  if (webAppUrl) {
    const parsedUrl = new URL(webAppUrl);
    if (parsedUrl.protocol !== "https:" || parsedUrl.username || parsedUrl.password) {
      throw new Error("APP_URL must be a public HTTPS URL without embedded credentials.");
    }
    console.log(`[Tunnel] Using custom APP_URL: ${webAppUrl}`);
  } else {
    console.log(`[Tunnel] Starting cloudflared tunnel...`);
    const t = await startCloudflaredTunnel(PORT);
    webAppUrl = t.url;
  }

  if (webAppUrl.startsWith("http://localhost")) {
    console.warn("[Tunnel] WARNING: Running on localhost only.");
    console.warn("[Tunnel] Telegram MiniApp requires HTTPS. Bot commands will work but 'Open App' won't.");
    console.warn("[Tunnel] Fix: set APP_URL env var to your deployed HTTPS URL.");
  }

  // Register bot menu button & commands
  try {
    await tgCall("setChatMenuButton", {
      menu_button: { type: "web_app", text: "Open App", web_app: { url: webAppUrl } }
    });
    console.log("[Bot] Menu button set");
  } catch (e) { console.warn("[Bot] Menu button failed:", e.message); }

  try {
    await tgCall("setMyCommands", { commands: [
      { command: "start",   description: "Open dashboard" },
      { command: "session", description: "Save a session" },
      { command: "export",  description: "Export sessions" },
      { command: "admin",   description: "Admin panel" },
      { command: "help",    description: "Show commands" },
    ]});
    console.log("[Bot] Commands registered");
  } catch (e) { console.warn("[Bot] Commands failed:", e.message); }

  console.log("\n" + "═".repeat(50));
  console.log(`Bot link : https://t.me/${me.result.username}`);
  console.log(`App URL  : ${webAppUrl}`);
  console.log("═".repeat(50) + "\n");

  startPolling(webAppUrl);
}

export {
  createServer,
  escapeHtml,
  parseDuration,
  handleText,
  handleCallback,
  userKeyboard,
  setTgCallHook,
};

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main().catch(err => { console.error("[Fatal]", err.message); process.exit(1); });
}
