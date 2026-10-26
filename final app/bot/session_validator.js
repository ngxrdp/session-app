import crypto from "node:crypto";
import initSqlJs from "sql.js";
import AdmZip from "adm-zip";

const MAX_TDATA_ENTRIES = 512;
const MAX_TDATA_ENTRY_BYTES = 16 * 1024 * 1024;
const MAX_TDATA_UNCOMPRESSED_BYTES = 64 * 1024 * 1024;

// Cache sql.js instance
let SQL = null;
async function getSql() {
  if (!SQL) SQL = await initSqlJs();
  return SQL;
}

// Telegram DC IP addresses
const DC_IPS = {
  1: [149, 154, 175, 53],
  2: [149, 154, 167, 51],
  3: [149, 154, 175, 100],
  4: [149, 154, 167, 91],
  5: [91, 108, 56, 130]
};

// ─── UTILITY HELPERS ────────────────────────────────────────────────────────
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const clean = hex.trim().toLowerCase();
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

export function safeB64Decode(str) {
  let s = str.trim().replace(/[\r\n\s]/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  const buf = Buffer.from(s, "base64");
  return new Uint8Array(buf);
}

export function buildTelethon(dcId, authKeyHex) {
  const dc = Number(dcId) || 4;
  const ip = DC_IPS[dc] || DC_IPS[4];
  const port = 443;
  const keyBytes = hexToBytes(authKeyHex);
  const buf = new Uint8Array(1 + 4 + 2 + 256);
  buf[0] = dc;
  buf[1] = ip[0]; buf[2] = ip[1]; buf[3] = ip[2]; buf[4] = ip[3];
  buf[5] = (port >> 8) & 0xff;
  buf[6] = port & 0xff;
  for (let i = 0; i < 256 && i < keyBytes.length; i++) buf[7 + i] = keyBytes[i];
  // Telethon's StringSession decoder expects the URL-safe base64 padding.
  return "1" + Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

export function buildPyrogram(dcId, authKeyHex, userId = 0) {
  const dc = Number(dcId) || 4;
  const keyBytes = hexToBytes(authKeyHex);
  const buf = new Uint8Array(2 + 256 + 8 + 1);
  buf[0] = dc & 0xff;
  buf[1] = 0;
  for (let i = 0; i < 256 && i < keyBytes.length; i++) buf[2 + i] = keyBytes[i];
  let uid = BigInt(userId || 0);
  for (let i = 7; i >= 0; i--) {
    buf[258 + i] = Number(uid & 0xffn);
    uid >>= 8n;
  }
  buf[266] = 0;
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ─── ENTROPY CHECK ──────────────────────────────────────────────────────────
export function hasValidKeyEntropy(keyBytes) {
  if (!keyBytes || keyBytes.length !== 256) return false;
  let nonZero = 0;
  const seen = new Set();
  for (let i = 0; i < 32; i++) {
    const b = keyBytes[i];
    if (b !== 0 && b !== 0xff) nonZero++;
    seen.add(b);
  }
  return nonZero >= 20 && seen.size >= 8;
}

// ─── 1. HEX KEY VALIDATOR ───────────────────────────────────────────────────
export function validateHexKey(rawHex) {
  if (!rawHex || typeof rawHex !== "string") {
    return { valid: false, error: "Hex auth key is empty." };
  }
  const clean = rawHex.trim().toLowerCase().replace(/[\r\n\s]/g, "");

  if (!/^[0-9a-fA-F]+$/.test(clean)) {
    return { valid: false, error: "Hex key contains invalid characters. Only hexadecimal (0-9, a-f) characters allowed." };
  }

  if (clean.length !== 512) {
    return {
      valid: false,
      error: `Invalid Hex Key length: expected exactly 512 characters (256 bytes), received ${clean.length} characters.`
    };
  }

  const bytes = hexToBytes(clean);
  if (!hasValidKeyEntropy(bytes)) {
    return { valid: false, error: "Invalid Hex Key: auth key cannot be all zeroes or repetitive dummy filler." };
  }

  const dcId = 4;
  return {
    valid: true,
    dcId,
    authKeyHex: clean,
    userId: null,
    firstName: "Telegram User",
    telethon: buildTelethon(dcId, clean),
    pyrogram: buildPyrogram(dcId, clean, 0),
    type: "Raw Hex Auth Key"
  };
}

// ─── 2. TELETHON STRING VALIDATOR ───────────────────────────────────────────
export function validateTelethonString(rawStr) {
  const str = rawStr.trim();
  if (!str) return { valid: false, error: "Telethon session string is empty." };

  let decoded;
  try {
    const b64 = str.startsWith("1") ? str.slice(1) : str;
    decoded = safeB64Decode(b64);
  } catch (e) {
    return { valid: false, error: "Invalid Telethon session: could not base64-decode string." };
  }

  if (decoded.length < 261) {
    return {
      valid: false,
      error: `Invalid Telethon session length: expected at least 261 bytes, decoded ${decoded.length} bytes.`
    };
  }

  const dcId = decoded[0];
  if (dcId < 1 || dcId > 5) {
    return {
      valid: false,
      error: `Invalid DC ID in Telethon session: DC ${dcId} is not a valid Telegram Data Center (1-5).`
    };
  }

  const keyBytes = decoded.subarray(decoded.length - 256);
  if (!hasValidKeyEntropy(keyBytes)) {
    return { valid: false, error: "Invalid Telethon session: auth key contains insufficient entropy (all zeroes or corrupted)." };
  }

  const keyHex = bytesToHex(keyBytes);
  return {
    valid: true,
    dcId,
    authKeyHex: keyHex,
    userId: null,
    firstName: "Telegram User",
    telethon: str.startsWith("1") ? str : ("1" + str),
    pyrogram: buildPyrogram(dcId, keyHex, 0),
    type: "Telethon StringSession"
  };
}

// ─── 3. PYROGRAM STRING VALIDATOR ───────────────────────────────────────────
export function validatePyrogramString(rawStr) {
  const str = rawStr.trim();
  if (!str) return { valid: false, error: "Pyrogram session string is empty." };

  let decoded;
  try {
    decoded = safeB64Decode(str);
  } catch (e) {
    return { valid: false, error: "Invalid Pyrogram session: could not base64-decode string." };
  }

  const len = decoded.length;
  let dcId = 4;
  let keyBytes = null;
  let userId = null;

  if (len === 271) {
    // Pyrogram v2: >BI?256sQ?
    // DC (1 byte) + api_id (4 bytes) + test_mode (1 byte) + auth_key (256 bytes) + user_id (8 bytes) + is_bot (1 byte)
    dcId = decoded[0];
    keyBytes = decoded.subarray(6, 262);
    try {
      let uid = 0n;
      for (let i = 262; i < 270; i++) uid = (uid << 8n) | BigInt(decoded[i]);
      if (uid > 0n && uid < 0x7fffffffffffffffn) userId = Number(uid);
    } catch (e) {}
  } else if (len === 267) {
    // Pyrogram v1 with 64-bit user ID: >B?256sQ?
    dcId = decoded[0];
    keyBytes = decoded.subarray(2, 258);
    try {
      let uid = 0n;
      for (let i = 258; i < 266; i++) uid = (uid << 8n) | BigInt(decoded[i]);
      if (uid > 0n && uid < 0x7fffffffffffffffn) userId = Number(uid);
    } catch (e) {}
  } else if (len === 263) {
    // Pyrogram v1 with 32-bit user ID: >B?256sI?
    dcId = decoded[0];
    keyBytes = decoded.subarray(2, 258);
    try {
      let uid = 0;
      for (let i = 258; i < 262; i++) uid = (uid << 8) | decoded[i];
      if (uid > 0) userId = uid;
    } catch (e) {}
  } else if (len === 260) {
    // Pyrogram v1 without user ID
    dcId = decoded[0];
    keyBytes = decoded.subarray(4, 260);
  } else if (len === 256) {
    return {
      valid: false,
      error: "A raw auth key does not contain its data center. Wrap it in JSON with authKey and dcId."
    };
  } else {
    return {
      valid: false,
      error: `Invalid Pyrogram session length: got ${len} bytes (expected 271, 267, or 263 bytes).`
    };
  }

  if (dcId < 1 || dcId > 5) {
    return {
      valid: false,
      error: `Invalid DC ID in Pyrogram session: DC ${dcId} is not a valid Telegram Data Center (1-5).`
    };
  }

  if (!hasValidKeyEntropy(keyBytes)) {
    return { valid: false, error: "Invalid Pyrogram session: auth key contains insufficient entropy (all zeroes or corrupted)." };
  }

  const keyHex = bytesToHex(keyBytes);
  return {
    valid: true,
    dcId,
    authKeyHex: keyHex,
    userId,
    firstName: "Telegram User",
    telethon: buildTelethon(dcId, keyHex),
    pyrogram: str,
    type: len === 271 ? "Pyrogram v2 StringSession" : "Pyrogram v1 StringSession"
  };
}

// ─── 4. SQLITE .SESSION VALIDATOR ───────────────────────────────────────────
export async function validateSqliteSession(buffer) {
  if (!buffer || buffer.length < 16) {
    return { valid: false, error: "Session file is too small or empty." };
  }

  const isSqliteHeader = buffer[0] === 0x53 && buffer[1] === 0x51 && buffer[2] === 0x4c && buffer[3] === 0x69;
  if (!isSqliteHeader) {
    return { valid: false, error: "File is not a valid SQLite .session database." };
  }

  try {
    const sql = await getSql();
    const db = new sql.Database(buffer);

    // Check if sessions or session table exists
    const tables = db.exec("SELECT name FROM sqlite_master WHERE type='table' AND (name='sessions' OR name='session')");
    if (!tables.length || !tables[0].values.length) {
      db.close();
      return { valid: false, error: "Invalid Telegram session file: 'sessions' table not found in SQLite database." };
    }

    const tableName = tables[0].values[0][0];
    const result = db.exec(`SELECT * FROM ${tableName}`);
    if (!result.length || !result[0].values.length) {
      db.close();
      return { valid: false, error: `Invalid session file: '${tableName}' table is empty (no active session saved).` };
    }

    const columns = result[0].columns;
    const row = result[0].values[0];

    const authKeyIdx = columns.findIndex(c => c.toLowerCase() === "auth_key");
    const dcIdIdx    = columns.findIndex(c => c.toLowerCase() === "dc_id");
    const userIdIdx  = columns.findIndex(c => c.toLowerCase() === "user_id");

    if (authKeyIdx === -1) {
      db.close();
      return { valid: false, error: "Invalid session file: 'auth_key' column missing from sessions table." };
    }

    const authKeyRaw = row[authKeyIdx];
    let keyBytes = null;
    if (authKeyRaw instanceof Uint8Array || Buffer.isBuffer(authKeyRaw)) {
      keyBytes = authKeyRaw;
    } else if (Array.isArray(authKeyRaw)) {
      keyBytes = new Uint8Array(authKeyRaw);
    } else if (typeof authKeyRaw === "string") {
      keyBytes = hexToBytes(authKeyRaw);
    }

    if (!keyBytes || keyBytes.length !== 256) {
      db.close();
      return {
        valid: false,
        error: `Invalid auth_key in session file: expected 256 bytes, found ${keyBytes ? keyBytes.length : 0} bytes.`
      };
    }

    if (!hasValidKeyEntropy(keyBytes)) {
      db.close();
      return { valid: false, error: "Invalid session file: auth_key is empty, all zeroes, or corrupted." };
    }

    let dcId = dcIdIdx !== -1 ? Number(row[dcIdIdx]) : 4;
    if (dcId < 1 || dcId > 5) dcId = 4;

    let userId = null;
    if (userIdIdx !== -1 && row[userIdIdx]) {
      const u = Number(row[userIdIdx]);
      if (u > 0) userId = u;
    }

    // Try reading peers or entities table for profile details
    let firstName = "Telegram User";
    let phone = null;
    let username = null;
    try {
      const peerTables = db.exec("SELECT name FROM sqlite_master WHERE type='table' AND (name='peers' OR name='entities')");
      if (peerTables.length && peerTables[0].values.length) {
        const pTable = peerTables[0].values[0][0];
        const pRows = userId
          ? db.exec(`SELECT * FROM ${pTable} WHERE id = ${userId} LIMIT 1`)
          : db.exec(`SELECT * FROM ${pTable} LIMIT 1`);
        if (pRows.length && pRows[0].values.length) {
          const pCols = pRows[0].columns.map(c => c.toLowerCase());
          const pVal = pRows[0].values[0];
          const idIdx = pCols.findIndex(c => c === "id");
          const nameIdx = pCols.findIndex(c => c === "name" || c === "first_name");
          const phoneIdx = pCols.findIndex(c => c === "phone_number" || c === "phone");
          const userIdx = pCols.findIndex(c => c === "username");
          if (idIdx !== -1 && !userId && pVal[idIdx]) {
            const u = Number(pVal[idIdx]);
            if (u > 0) userId = u;
          }
          if (nameIdx !== -1 && pVal[nameIdx]) firstName = String(pVal[nameIdx]);
          if (phoneIdx !== -1 && pVal[phoneIdx]) phone = String(pVal[phoneIdx]);
          if (userIdx !== -1 && pVal[userIdx]) username = String(pVal[userIdx]);
        }
      }
    } catch (e) {}

    db.close();

    const keyHex = bytesToHex(keyBytes);
    return {
      valid: true,
      dcId,
      authKeyHex: keyHex,
      userId,
      firstName,
      phone,
      username,
      telethon: buildTelethon(dcId, keyHex),
      pyrogram: buildPyrogram(dcId, keyHex, userId || 0),
      type: "SQLite .session"
    };
  } catch (err) {
    return { valid: false, error: `SQLite parsing error: ${err.message}` };
  }
}

// ─── TDATA CRYPTO HELPERS ───────────────────────────────────────────────────
class BufferReader {
  constructor(buf) {
    this.buf = buf;
    this.offset = 0;
  }
  readUInt32BE() {
    const val = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return val;
  }
  readInt32BE() {
    const val = this.buf.readInt32BE(this.offset);
    this.offset += 4;
    return val;
  }
  readBigUInt64BE() {
    const val = this.buf.readBigUInt64BE(this.offset);
    this.offset += 8;
    return val;
  }
  readQByteArray() {
    if (this.offset + 4 > this.buf.length) return Buffer.alloc(0);
    const len = this.readUInt32BE();
    if (len === 0xffffffff || len === 0) return Buffer.alloc(0);
    if (this.offset + len > this.buf.length) return Buffer.alloc(0);
    const slice = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }
}

function aesEcbDec(key, data) {
  const decipher = crypto.createDecipheriv("aes-256-ecb", key, null);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function igeDec(ct, key, iv) {
  let prevC = iv.subarray(0, 16);
  let prevP = iv.subarray(16, 32);
  const out = Buffer.alloc(ct.length);
  for (let i = 0; i < ct.length; i += 16) {
    const c = ct.subarray(i, i + 16);
    const x = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) x[j] = c[j] ^ prevP[j];
    const dec = aesEcbDec(key, x);
    const p = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) p[j] = dec[j] ^ prevC[j];
    p.copy(out, i);
    prevC = c;
    prevP = p;
  }
  return out;
}

function prepareAes(key, msg, x = 8) {
  const sha1a = crypto.createHash("sha1").update(Buffer.concat([msg.subarray(0, 16), key.subarray(x, x + 32)])).digest();
  const sha1b = crypto.createHash("sha1").update(Buffer.concat([key.subarray(x + 32, x + 48), msg.subarray(0, 16), key.subarray(x + 48, x + 64)])).digest();
  const sha1c = crypto.createHash("sha1").update(Buffer.concat([key.subarray(x + 64, x + 96), msg.subarray(0, 16)])).digest();
  const sha1d = crypto.createHash("sha1").update(Buffer.concat([msg.subarray(0, 16), key.subarray(x + 96, x + 128)])).digest();
  const ak = Buffer.concat([sha1a.subarray(0, 8), sha1b.subarray(8, 20), sha1c.subarray(4, 16)]);
  const iv = Buffer.concat([sha1a.subarray(8, 20), sha1b.subarray(0, 8), sha1c.subarray(16, 20), sha1d.subarray(0, 8)]);
  return { ak, iv };
}

function createLocalKey(salt, passcode = "") {
  const passBuf = Buffer.isBuffer(passcode) ? passcode : Buffer.from(passcode, "utf-8");
  const it = passBuf.length > 0 ? 100000 : 1;
  const hk = crypto.createHash("sha512").update(Buffer.concat([salt, passBuf, salt])).digest();
  return crypto.pbkdf2Sync(hk, salt, it, 256, "sha512");
}

function createLegacyLocalKey(salt, passcode = "") {
  const passBuf = Buffer.isBuffer(passcode) ? passcode : Buffer.from(passcode, "utf-8");
  const it = passBuf.length > 0 ? 100000 : 1;
  return crypto.pbkdf2Sync(passBuf, salt, it, 256, "sha512");
}

function decryptLocal(blob, key) {
  if (blob.length <= 16 || (blob.length - 16) % 16 !== 0) {
    throw new Error("Bad encrypted size");
  }
  const msg = blob.subarray(0, 16);
  const ct = blob.subarray(16);
  const { ak, iv } = prepareAes(key, msg, 8);
  const plain = igeDec(ct, ak, iv);
  const hash = crypto.createHash("sha1").update(plain).digest().subarray(0, 16);
  if (!hash.equals(msg)) {
    throw new Error("Bad decrypt key (wrong password or corrupted data)");
  }
  const len = plain.readUInt32LE(0);
  if (len < 4 || len > plain.length) {
    throw new Error("Bad decrypted data size");
  }
  return plain.subarray(4, len);
}

function parseMtp(buf) {
  const reader = new BufferReader(buf);
  let userId = 0;
  let mainDc = 4;
  const tag = reader.readBigUInt64BE();
  if (tag === 0xffffffffffffffffn) {
    userId = Number(reader.readBigUInt64BE());
    mainDc = reader.readInt32BE();
  } else {
    reader.offset = 0;
    userId = reader.readInt32BE() >>> 0;
    mainDc = reader.readInt32BE();
  }
  const keysCount = reader.readInt32BE();
  const keys = {};
  for (let k = 0; k < keysCount; k++) {
    const dc = reader.readInt32BE();
    if (reader.offset + 256 <= reader.buf.length) {
      const keyBytes = reader.buf.subarray(reader.offset, reader.offset + 256);
      reader.offset += 256;
      if (dc >= 1 && dc <= 5) {
        keys[dc] = keyBytes;
      }
    }
  }
  if (keys[mainDc] || Object.keys(keys).length > 0) {
    const chosenDc = keys[mainDc] ? mainDc : Number(Object.keys(keys)[0]);
    return {
      userId,
      mainDc: chosenDc,
      authKeyBytes: keys[chosenDc],
      allKeys: keys
    };
  }
  return null;
}

function scanMtp(plain) {
  const sig = Buffer.from([0x00, 0x00, 0x00, 0x4b]);
  let idx = plain.indexOf(sig);
  while (idx !== -1) {
    try {
      if (idx + 8 <= plain.length) {
        const len = plain.readUInt32BE(idx + 4);
        if (len >= 20 && idx + 8 + len <= plain.length) {
          const slice = plain.subarray(idx + 8, idx + 8 + len);
          const r = parseMtp(slice);
          if (r) return r;
        }
      }
    } catch (e) {}
    idx = plain.indexOf(sig, idx + 1);
  }
  return null;
}

// ─── 5. TDATA ZIP ARCHIVE VALIDATOR ─────────────────────────────────────────
export function validateTdataZip(buffer, passcode = "") {
  if (!buffer || buffer.length < 22) {
    return { valid: false, error: "Uploaded TData file is empty or too small." };
  }

  let zip;
  try {
    zip = new AdmZip(buffer);
  } catch (e) {
    return { valid: false, error: "File is not a valid ZIP archive." };
  }

  const entries = zip.getEntries();
  if (!entries || !entries.length) {
    return { valid: false, error: "TData ZIP archive is empty." };
  }
  if (entries.length > MAX_TDATA_ENTRIES) {
    return { valid: false, error: `TData ZIP contains too many files (maximum ${MAX_TDATA_ENTRIES}).` };
  }

  let totalUncompressedBytes = 0;
  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const uncompressedBytes = Number(entry.header?.size || 0);
    if (!Number.isSafeInteger(uncompressedBytes) || uncompressedBytes < 0 || uncompressedBytes > MAX_TDATA_ENTRY_BYTES) {
      return { valid: false, error: "TData ZIP contains an oversized or invalid entry." };
    }
    totalUncompressedBytes += uncompressedBytes;
    if (!Number.isSafeInteger(totalUncompressedBytes) || totalUncompressedBytes > MAX_TDATA_UNCOMPRESSED_BYTES) {
      return { valid: false, error: "TData ZIP expands beyond the 64 MB safety limit." };
    }
  }

  // 1. Locate key_data / key_datas entry
  let keyEntry = entries.find(e => {
    if (e.isDirectory) return false;
    const n = e.entryName.toLowerCase().replace(/\\/g, "/");
    const base = n.split("/").pop();
    return base === "key_datas" || base === "key_data";
  });

  if (!keyEntry) {
    keyEntry = entries.find(e => {
      if (e.isDirectory) return false;
      const n = e.entryName.toLowerCase().replace(/\\/g, "/");
      return n.includes("key_data");
    });
  }

  // If key_data is found, perform authentic Telegram Desktop decryption
  if (keyEntry) {
    try {
      const keyDataRaw = keyEntry.getData();
      if (keyDataRaw.length >= 32 && keyDataRaw.subarray(0, 4).toString("ascii") === "TDF$") {
        const keyBody = keyDataRaw.subarray(8, keyDataRaw.length - 16);
        const kr = new BufferReader(keyBody);
        const salt = kr.readQByteArray();
        const keyEncrypted = kr.readQByteArray();

        if (salt.length && keyEncrypted.length) {
          let localKey = null;

          // Attempt decryption with modern CreateLocalKey
          try {
            const pk = createLocalKey(salt, passcode);
            const decryptedInner = decryptLocal(keyEncrypted, pk);
            if (decryptedInner && decryptedInner.length >= 256) {
              localKey = decryptedInner.subarray(0, 256);
            }
          } catch (e) {
            // Attempt legacy CreateLegacyLocalKey
            try {
              const pkLegacy = createLegacyLocalKey(salt, passcode);
              const decryptedInner = decryptLocal(keyEncrypted, pkLegacy);
              if (decryptedInner && decryptedInner.length >= 256) {
                localKey = decryptedInner.subarray(0, 256);
              }
            } catch (e2) {}
          }

          if (!localKey) {
            return {
              valid: false,
              error: passcode
                ? "Incorrect passcode for TData archive."
                : "TData is password-protected. Please enter your desktop passcode."
            };
          }

          // Scan archive files for account MTProto auth blocks
          const accounts = [];
          const seenKeys = new Set();

          for (const entry of entries) {
            if (entry.isDirectory) continue;
            const entryName = entry.entryName.toLowerCase().replace(/\\/g, "/");
            const baseName = entryName.split("/").pop();

            // Skip key_data, settings, usertags
            if (baseName.startsWith("key_data") || baseName.startsWith("settings") || baseName.startsWith("usertag")) {
              continue;
            }

            const data = entry.getData();
            if (!data || data.length < 32) continue;
            if (data.subarray(0, 4).toString("ascii") !== "TDF$") continue;

            try {
              const body = data.subarray(8, data.length - 16);
              const br = new BufferReader(body);
              const blob = br.readQByteArray();
              if (!blob.length) continue;

              const plain = decryptLocal(blob, localKey);
              const mtp = scanMtp(plain);
              if (mtp && Number.isSafeInteger(mtp.userId) && mtp.userId > 0 && mtp.authKeyBytes && hasValidKeyEntropy(mtp.authKeyBytes)) {
                const keyHex = bytesToHex(mtp.authKeyBytes);
                if (!seenKeys.has(keyHex)) {
                  seenKeys.add(keyHex);
                  const uid = mtp.userId;
                  accounts.push({
                    accountIndex: accounts.length,
                    dcId: mtp.mainDc,
                    authKeyHex: keyHex,
                    userId: uid,
                    firstName: `TData User`,
                    label: `TData Account ${accounts.length + 1} (DC ${mtp.mainDc})`,
                    telethon: buildTelethon(mtp.mainDc, keyHex),
                    pyrogram: buildPyrogram(mtp.mainDc, keyHex, uid),
                    type: "TData Desktop"
                  });
                }
              }
            } catch (err) {
              // Ignore individual account decryption failures (e.g. non-account TDF files)
            }
          }

          if (accounts.length > 0) {
            return {
              valid: true,
              accounts
            };
          }
        }
      }
    } catch (e) {
      // Fall through to scanner fallback
    }
  }

  // Never guess credentials by scanning arbitrary archive bytes. Random data can
  // look like a DC byte followed by a high-entropy key and create a false login.
  const hasTdataFiles = entries.some(e => {
    const name = e.entryName.toLowerCase();
    return name.includes("key_data") || name.includes("d877f783d5d3ef8c") || name.includes("settings") || name.includes("tdata");
  });

  if (!hasTdataFiles) {
    return {
      valid: false,
      error: "Archive does not contain Telegram Desktop 'tdata' folder files (missing 'key_datas' or account files)."
    };
  }

  return {
    valid: false,
    error: passcode
      ? "Could not decrypt TData with the provided passcode."
      : "Could not find valid MTProto auth key in TData. If a desktop passcode is set, please enter it."
  };
}

// ─── 6. UNIFIED PARSER & VALIDATOR ──────────────────────────────────────────
export async function parseAndValidate(input, options = {}) {
  // If buffer or Uint8Array
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);

    // SQLite header (SQLite format 3\0)
    if (buf.length >= 16 && buf[0] === 0x53 && buf[1] === 0x51 && buf[2] === 0x4c && buf[3] === 0x69) {
      return await validateSqliteSession(buf);
    }

    // ZIP header (PK\x03\x04 or PK\x05\x06)
    if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b) {
      return validateTdataZip(buf, options.passcode || "");
    }

    // Attempt text decode
    const text = buf.toString("utf-8").trim();
    return parseAndValidate(text, options);
  }

  // If string
  if (typeof input === "string") {
    const str = input.trim();
    if (!str) return { valid: false, error: "Input is empty." };

    // JSON session object
    if (str.startsWith("{") && str.endsWith("}")) {
      try {
        const obj = JSON.parse(str);
        const inner = obj.session_string || obj.sessionString || obj.session || obj.string || obj.telethon || obj.pyrogram;
        if (inner && typeof inner === "string") {
          const nested = await parseAndValidate(inner, options);
          if (nested.valid) {
            const rawUserId = obj.user_id ?? obj.userId;
            const userId = Number(rawUserId);
            if (Number.isSafeInteger(userId) && userId > 0) nested.userId = userId;
            const rawDc = obj.dc_id ?? obj.dcId ?? obj.dc;
            const dc = Number(rawDc);
            if (Number.isInteger(dc) && dc >= 1 && dc <= 5) {
              nested.dcId = dc;
              if (nested.authKeyHex) {
                nested.telethon = buildTelethon(dc, nested.authKeyHex);
                nested.pyrogram = buildPyrogram(dc, nested.authKeyHex, nested.userId || 0);
              }
            }
          }
          return nested;
        }
        const key = obj.auth_key || obj.authKey || obj.key || obj.hex;
        if (key) {
          const dc = Number(obj.dc_id || obj.dcId || obj.dc);
          if (!Number.isInteger(dc) || dc < 1 || dc > 5) {
            return { valid: false, error: "Raw auth keys require JSON containing a valid dcId (1-5)." };
          }
          const keyHex = key.length === 512 ? key.toLowerCase() : bytesToHex(safeB64Decode(key));
          const hexRes = validateHexKey(keyHex);
          if (hexRes.valid) {
            hexRes.dcId = dc;
            const rawUserId = obj.user_id ?? obj.userId;
            const userId = Number(rawUserId);
            if (Number.isSafeInteger(userId) && userId > 0) hexRes.userId = userId;
            hexRes.telethon = buildTelethon(dc, hexRes.authKeyHex);
            hexRes.pyrogram = buildPyrogram(dc, hexRes.authKeyHex, hexRes.userId || 0);
            if (obj.first_name || obj.firstName) hexRes.firstName = String(obj.first_name || obj.firstName);
          }
          return hexRes;
        }
      } catch (e) {
        return { valid: false, error: "Invalid JSON session: syntax error." };
      }
    }

    // Clean whitespace
    const cleanStr = str.replace(/[\r\n\s]/g, "");

    // 512-character Hex Key
    if (/^[0-9a-fA-F]{512}$/.test(cleanStr)) {
      return {
        valid: false,
        error: "A raw auth key does not contain its data center. Wrap it in JSON with authKey and dcId."
      };
    }

    // Telethon string starting with '1'
    if (cleanStr.startsWith("1")) {
      const telRes = validateTelethonString(cleanStr);
      if (telRes.valid) return telRes;
    }

    // Pyrogram base64
    const pyroRes = validatePyrogramString(cleanStr);
    if (pyroRes.valid) return pyroRes;

    // Telethon base64 without '1'
    const telRes2 = validateTelethonString(cleanStr);
    if (telRes2.valid) return telRes2;

    // Partial Hex Key check with helpful message
    if (/^[0-9a-fA-F]+$/.test(cleanStr)) {
      return {
        valid: false,
        error: `Invalid Hex Key length: expected exactly 512 characters, received ${cleanStr.length}.`
      };
    }

    return {
      valid: false,
      error: "Unrecognized session format. Expected Telethon (starts with 1), Pyrogram string, 512-hex key, SQLite .session, or TData .zip."
    };
  }

  return { valid: false, error: "Invalid session input provided." };
}
