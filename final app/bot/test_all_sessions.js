import crypto from "node:crypto";
import AdmZip from "adm-zip";
import initSqlJs from "sql.js";
import {
  parseAndValidate,
  validateHexKey,
  validateTelethonString,
  validatePyrogramString,
  validateSqliteSession,
  validateTdataZip,
  buildTelethon,
  buildPyrogram,
  bytesToHex,
  hexToBytes
} from "./session_validator.js";

// ─── AES IGE HELPER FOR MOCK TDATA ──────────────────────────────────────────
function aesEcbEnc(key, data) {
  const cipher = crypto.createCipheriv("aes-256-ecb", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function igeEnc(pt, key, iv) {
  let prevC = iv.subarray(0, 16);
  let prevP = iv.subarray(16, 32);
  const out = Buffer.alloc(pt.length);
  for (let i = 0; i < pt.length; i += 16) {
    const p = pt.subarray(i, i + 16);
    const x = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) x[j] = p[j] ^ prevC[j];
    const enc = aesEcbEnc(key, x);
    const c = Buffer.alloc(16);
    for (let j = 0; j < 16; j++) c[j] = enc[j] ^ prevP[j];
    c.copy(out, i);
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

function encryptLocal(plain, key) {
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(plain.length + 4, 0);
  let full = Buffer.concat([lenBuf, plain]);
  const pad = (16 - (full.length % 16)) % 16;
  if (pad > 0) full = Buffer.concat([full, crypto.randomBytes(pad)]);
  const msg = crypto.createHash("sha1").update(full).digest().subarray(0, 16);
  const { ak, iv } = prepareAes(key, msg, 8);
  const ct = igeEnc(full, ak, iv);
  return Buffer.concat([msg, ct]);
}

function writeQByteArray(data) {
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  return Buffer.concat([lenBuf, data]);
}

function makeTdataZip({ passcode = "", dcId = 2, userId = 123456789, authKey = null } = {}) {
  const keyBytes = authKey || crypto.randomBytes(256);
  const localKey = crypto.randomBytes(256);
  const salt = crypto.randomBytes(32);

  // Derive passcode key
  const passBuf = Buffer.from(passcode, "utf-8");
  const it = passBuf.length > 0 ? 100000 : 1;
  const hk = crypto.createHash("sha512").update(Buffer.concat([salt, passBuf, salt])).digest();
  const passKey = crypto.pbkdf2Sync(hk, salt, it, 256, "sha512");

  // Encrypt localKey
  const encLocalKey = encryptLocal(localKey, passKey);

  // Build key_datas file: "TDF$" + version(4) + QByteArray(salt) + QByteArray(encLocalKey) + md5(16)
  const kdBody = Buffer.concat([writeQByteArray(salt), writeQByteArray(encLocalKey)]);
  const kdMd5 = crypto.createHash("md5").update(kdBody).digest();
  const kdHeader = Buffer.from("TDF$\x01\x00\x00\x00", "binary");
  const kdFile = Buffer.concat([kdHeader, kdBody, kdMd5]);

  // Build account payload:
  // dbiMtpAuthorization = 0x0000004b
  // followed by QByteArray(mtpPayload)
  // mtpPayload: kWideIdsTag(8) + userId(8) + mainDc(4) + keysCount(4) + [dc(4) + key(256)]
  const mtpBuf = Buffer.alloc(8 + 8 + 4 + 4 + 4 + 256);
  let o = 0;
  mtpBuf.writeBigUInt64BE(0xffffffffffffffffn, o); o += 8;
  mtpBuf.writeBigUInt64BE(BigInt(userId), o); o += 8;
  mtpBuf.writeInt32BE(dcId, o); o += 4;
  mtpBuf.writeInt32BE(1, o); o += 4; // 1 key
  mtpBuf.writeInt32BE(dcId, o); o += 4;
  keyBytes.copy(mtpBuf, o);

  const sig = Buffer.from([0x00, 0x00, 0x00, 0x4b]);
  const mtpBlock = Buffer.concat([sig, writeQByteArray(mtpBuf)]);

  // Encrypt account file with localKey
  const encAccBlob = encryptLocal(mtpBlock, localKey);
  const accBody = writeQByteArray(encAccBlob);
  const accMd5 = crypto.createHash("md5").update(accBody).digest();
  const accHeader = Buffer.from("TDF$\x01\x00\x00\x00", "binary");
  const accFile = Buffer.concat([accHeader, accBody, accMd5]);

  const zip = new AdmZip();
  zip.addFile("tdata/key_datas", kdFile);
  zip.addFile("tdata/D877F783D5D3EF8C/data", accFile);
  return { zipBuffer: zip.toBuffer(), authKeyHex: bytesToHex(keyBytes), userId, dcId };
}

async function makeSqliteSession({ dcId = 2, userId = 987654321, authKey = null, firstName = "TestUser", phone = "+1234567890" } = {}) {
  const SQL = await initSqlJs();
  const db = new SQL.Database();
  const keyBytes = authKey || crypto.randomBytes(256);

  db.run("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, server_address TEXT, port INTEGER, auth_key BLOB, takeout_id INTEGER);");
  db.run("CREATE TABLE peers (id INTEGER PRIMARY KEY, name TEXT, first_name TEXT, username TEXT, phone_number TEXT);");

  db.run("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)", [dcId, "149.154.167.51", 443, keyBytes, null]);
  db.run("INSERT INTO peers VALUES (?, ?, ?, ?, ?)", [userId, firstName, firstName, "testuser", phone]);

  const binary = db.export();
  db.close();
  return { buffer: Buffer.from(binary), authKeyHex: bytesToHex(keyBytes), dcId, userId, firstName, phone };
}

// ─── TEST SUITE RUNNER ───────────────────────────────────────────────────────
async function runTests() {
  console.log("=================================================================");
  console.log("       COMPREHENSIVE TELEGRAM SESSION VALIDATOR TEST SUITE       ");
  console.log("=================================================================\n");

  let passed = 0;
  let failed = 0;

  function assert(desc, condition, details = "") {
    if (condition) {
      console.log(`  [PASS] ${desc}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${desc} ${details ? "-> " + details : ""}`);
      failed++;
    }
  }

  // ── TEST GROUP 1: HEX AUTH KEY ───────────────────────────────────────────
  console.log("--- 1. Raw Hex Auth Key Tests ---");
  const validHexKey = bytesToHex(crypto.randomBytes(256));
  const hexRes = validateHexKey(validHexKey);
  assert("Valid 512-hex key returns valid: true", hexRes.valid === true);
  assert("Valid hex key has correct authKeyHex", hexRes.authKeyHex === validHexKey.toLowerCase());
  assert("Valid hex key has Telethon string generated", hexRes.telethon && hexRes.telethon.startsWith("1"));
  assert("Valid hex key has Pyrogram string generated", hexRes.pyrogram && hexRes.pyrogram.length > 50);

  const shortHex = validHexKey.slice(0, 500);
  const shortHexRes = validateHexKey(shortHex);
  assert("Short hex key returns valid: false", shortHexRes.valid === false);
  assert("Short hex key provides length error", shortHexRes.error.includes("512 characters"));

  const badCharHex = validHexKey.slice(0, 510) + "ZZ";
  const badCharRes = validateHexKey(badCharHex);
  assert("Hex key with invalid characters returns valid: false", badCharRes.valid === false);

  const zeroHex = "00".repeat(256);
  const zeroHexRes = validateHexKey(zeroHex);
  assert("All-zero hex key rejected for zero entropy", zeroHexRes.valid === false);

  // ── TEST GROUP 2: TELETHON STRING SESSION ────────────────────────────────
  console.log("\n--- 2. Telethon StringSession Tests ---");
  const telString = buildTelethon(2, validHexKey);
  const telRes = validateTelethonString(telString);
  assert("Valid Telethon string returns valid: true", telRes.valid === true);
  assert("Valid Telethon string extracts correct DC ID (2)", telRes.dcId === 2);
  assert("Valid Telethon string extracts matching auth key", telRes.authKeyHex === validHexKey.toLowerCase());

  const badB64Tel = "1!@#$%^&*()";
  const badB64TelRes = validateTelethonString(badB64Tel);
  assert("Corrupted base64 Telethon string returns valid: false", badB64TelRes.valid === false);

  const badDcTel = "1" + Buffer.from(new Uint8Array(263).fill(0).map((_, i) => i === 0 ? 9 : 0xaa)).toString("base64");
  const badDcTelRes = validateTelethonString(badDcTel);
  assert("Telethon string with DC 9 rejected", badDcTelRes.valid === false);

  // ── TEST GROUP 3: PYROGRAM STRING SESSION ────────────────────────────────
  console.log("\n--- 3. Pyrogram StringSession Tests ---");
  const pyroString = buildPyrogram(2, validHexKey, 777888999);
  const pyroRes = validatePyrogramString(pyroString);
  assert("Valid Pyrogram string returns valid: true", pyroRes.valid === true);
  assert("Valid Pyrogram string extracts correct DC ID (2)", pyroRes.dcId === 2);
  assert("Valid Pyrogram string extracts matching auth key", pyroRes.authKeyHex === validHexKey.toLowerCase());

  const invalidPyroLen = Buffer.from(new Uint8Array(100).fill(0x55)).toString("base64");
  const invalidPyroRes = validatePyrogramString(invalidPyroLen);
  assert("Pyrogram with invalid length rejected", invalidPyroRes.valid === false);

  // ── TEST GROUP 4: SQLITE .SESSION FILE ───────────────────────────────────
  console.log("\n--- 4. SQLite .session File Tests ---");
  const mockSqlite = await makeSqliteSession({ dcId: 2, userId: 11223344, firstName: "Alice", phone: "+18005550199" });
  const sqlRes = await validateSqliteSession(mockSqlite.buffer);
  assert("Valid SQLite .session buffer returns valid: true", sqlRes.valid === true);
  assert("Valid SQLite .session extracts DC 2", sqlRes.dcId === 2);
  assert("Valid SQLite .session extracts correct authKeyHex", sqlRes.authKeyHex === mockSqlite.authKeyHex.toLowerCase());
  assert("Valid SQLite .session extracts user profile (Alice)", sqlRes.firstName === "Alice");
  assert("Valid SQLite .session extracts phone number (+18005550199)", sqlRes.phone === "+18005550199");

  const corruptSqlite = Buffer.from("SQLite format 3\0" + "corrupted garbage data".repeat(10));
  const corruptSqlRes = await validateSqliteSession(corruptSqlite);
  assert("Corrupted SQLite file returns valid: false", corruptSqlRes.valid === false);

  // ── TEST GROUP 5: TDATA ZIP ARCHIVE ──────────────────────────────────────
  console.log("\n--- 5. TData ZIP Archive Tests ---");
  // 5a. Unencrypted TData (no passcode)
  const mockTdata = makeTdataZip({ passcode: "", dcId: 2, userId: 99887766 });
  const tdataRes = validateTdataZip(mockTdata.zipBuffer);
  assert("Valid unencrypted TData ZIP returns valid: true", tdataRes.valid === true);
  assert("Valid TData ZIP extracts accounts array", tdataRes.accounts && tdataRes.accounts.length > 0);
  if (tdataRes.accounts && tdataRes.accounts.length) {
    const acc = tdataRes.accounts[0];
    assert("Valid TData extracts correct DC ID (2)", acc.dcId === 2);
    assert("Valid TData extracts correct userId (99887766)", acc.userId === 99887766);
    assert("Valid TData extracts matching authKeyHex", acc.authKeyHex === mockTdata.authKeyHex.toLowerCase());
  }

  // 5b. Passcode-protected TData
  const protectedTdata = makeTdataZip({ passcode: "Secret1234", dcId: 4, userId: 55443322 });
  const noPassRes = validateTdataZip(protectedTdata.zipBuffer, "");
  assert("Passcode-protected TData without passcode asks for passcode", noPassRes.valid === false && noPassRes.error.includes("password-protected"));

  const wrongPassRes = validateTdataZip(protectedTdata.zipBuffer, "WrongPassword");
  assert("Passcode-protected TData with wrong passcode reports incorrect passcode", wrongPassRes.valid === false && wrongPassRes.error.includes("Incorrect passcode"));

  const correctPassRes = validateTdataZip(protectedTdata.zipBuffer, "Secret1234");
  assert("Passcode-protected TData with correct passcode returns valid: true", correctPassRes.valid === true);
  if (correctPassRes.accounts && correctPassRes.accounts.length) {
    const acc = correctPassRes.accounts[0];
    assert("Decrypted TData extracts DC 4", acc.dcId === 4);
    assert("Decrypted TData extracts userId (55443322)", acc.userId === 55443322);
    assert("Decrypted TData extracts correct authKeyHex", acc.authKeyHex === protectedTdata.authKeyHex.toLowerCase());
  }

  // 5c. Corrupt ZIP
  const badZipBuffer = Buffer.from("PK\x03\x04" + "random not a real zip content".repeat(20));
  const badZipRes = validateTdataZip(badZipBuffer);
  assert("Corrupted ZIP archive returns valid: false", badZipRes.valid === false);

  const oversizedZip = new AdmZip();
  oversizedZip.addFile("tdata/oversized", Buffer.alloc(17 * 1024 * 1024, 1));
  const oversizedZipRes = validateTdataZip(oversizedZip.toBuffer());
  assert("ZIP entry over 16 MB is rejected before extraction", oversizedZipRes.valid === false && oversizedZipRes.error.includes("oversized"));

  // ── TEST GROUP 6: UNIFIED PARSEANDVALIDATE DISPATCHER ────────────────────
  console.log("\n--- 6. Unified parseAndValidate Dispatcher Tests ---");
  const uvHex = await parseAndValidate(validHexKey);
  assert("parseAndValidate rejects raw hex without a data center", uvHex.valid === false && uvHex.error.includes("data center"));

  const uvTel = await parseAndValidate(telString);
  assert("parseAndValidate detects Telethon string", uvTel.valid === true && uvTel.type === "Telethon StringSession");

  const uvPyro = await parseAndValidate(pyroString);
  assert("parseAndValidate detects Pyrogram string", uvPyro.valid === true);

  const uvSqlite = await parseAndValidate(mockSqlite.buffer);
  assert("parseAndValidate detects SQLite buffer", uvSqlite.valid === true && uvSqlite.type === "SQLite .session");

  const uvTdata = await parseAndValidate(mockTdata.zipBuffer);
  assert("parseAndValidate detects TData ZIP buffer", uvTdata.valid === true && uvTdata.accounts.length > 0);

  const uvJson = await parseAndValidate(JSON.stringify({ dcId: 2, auth_key: validHexKey, userId: 1234 }));
  assert("parseAndValidate detects JSON session object", uvJson.valid === true && uvJson.dcId === 2);

  const uvInvalid = await parseAndValidate("completely invalid gibberish");
  assert("parseAndValidate properly rejects invalid text", uvInvalid.valid === false);

  // ── TEST GROUP 7: HTTP API ENDPOINTS ─────────────────────────────────────
  console.log("\n--- 7. HTTP API Endpoints Tests ---");
  const http = await import("node:http");
  const testServer = http.createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

    const reqPath = req.url.split("?")[0];

    // POST /api/upload-tdata
    if (req.method === "POST" && reqPath === "/api/upload-tdata") {
      const chunks = [];
      const urlObj = new URL(req.url, "http://localhost");
      const passcode = urlObj.searchParams.get("passcode") || req.headers["x-tdata-passcode"] || "";
      req.on("data", chunk => chunks.push(chunk));
      req.on("end", async () => {
        try {
          const buffer = Buffer.concat(chunks);
          if (!buffer.length) {
            res.writeHead(400, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "No file data uploaded." }));
          }
          const resVal = validateTdataZip(buffer, passcode);
          if (resVal.valid && resVal.accounts && resVal.accounts.length) {
            res.writeHead(200, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: true, accounts: resVal.accounts }));
          }
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: resVal.error || "Could not find valid MTProto auth key in TData ZIP archive." }));
        } catch (err) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: err.message }));
        }
      });
      return;
    }

    // POST /api/upload-session
    if (req.method === "POST" && reqPath === "/api/upload-session") {
      const chunks = [];
      req.on("data", chunk => chunks.push(chunk));
      req.on("end", async () => {
        try {
          const buffer = Buffer.concat(chunks);
          if (!buffer.length) {
            res.writeHead(400, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ success: false, error: "No file data uploaded." }));
          }
          const parsed = await parseAndValidate(buffer);
          if (parsed && parsed.valid) {
            const acc = (parsed.accounts && parsed.accounts.length) ? parsed.accounts[0] : parsed;
            const keyHex = (acc.authKeyHex || acc.hex || "").toLowerCase();
            res.writeHead(200, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({
              success: true,
              dcId: acc.dcId || 4,
              authKeyHex: keyHex,
              userId: acc.userId,
              firstName: acc.firstName || "Telegram User",
              type: acc.type || "Session File",
              telethon: acc.telethon || buildTelethon(acc.dcId || 4, keyHex),
              pyrogram: acc.pyrogram || buildPyrogram(acc.dcId || 4, keyHex, acc.userId)
            }));
          }
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: parsed.error || "Could not recognize session keys in file." }));
        } catch (err) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: err.message }));
        }
      });
      return;
    }

    // POST /api/resolve-session
    if (req.method === "POST" && reqPath === "/api/resolve-session") {
      const chunks = [];
      req.on("data", chunk => chunks.push(chunk));
      req.on("end", async () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf-8") || "{}");
          const input = (body.authKeyHex || body.key || body.session || "").trim();
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
            res.writeHead(200, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({
              success: true,
              dcId,
              authKeyHex: keyHex,
              userId: acc.userId,
              firstName: acc.firstName || "Telegram User",
              type: acc.type,
              telethon: acc.telethon || buildTelethon(dcId, keyHex),
              pyrogram: acc.pyrogram || buildPyrogram(dcId, keyHex, acc.userId)
            }));
          }
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: parsed.error || "Invalid session string or auth key." }));
        } catch (err) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: err.message }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise(r => testServer.listen(0, r));
  const testPort = testServer.address().port;
  const baseUrl = `http://localhost:${testPort}`;

  // 7a. OPTIONS preflight
  const optRes = await fetch(`${baseUrl}/api/upload-tdata`, { method: "OPTIONS" });
  assert("OPTIONS preflight returns 204", optRes.status === 204);
  assert("Access-Control-Allow-Methods includes POST", (optRes.headers.get("access-control-allow-methods") || "").includes("POST"));

  // 7b. POST /api/upload-tdata valid unencrypted
  const upTdataRes = await fetch(`${baseUrl}/api/upload-tdata`, {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: mockTdata.zipBuffer
  });
  const upTdataJson = await upTdataRes.json();
  assert("POST /api/upload-tdata valid returns 200", upTdataRes.status === 200 && upTdataJson.success === true);
  assert("POST /api/upload-tdata returns accounts array", upTdataJson.accounts && upTdataJson.accounts.length === 1);

  // 7c. POST /api/upload-tdata invalid
  const upBadTdataRes = await fetch(`${baseUrl}/api/upload-tdata`, {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: badZipBuffer
  });
  const upBadTdataJson = await upBadTdataRes.json();
  assert("POST /api/upload-tdata invalid returns 400", upBadTdataRes.status === 400 && upBadTdataJson.success === false);
  assert("POST /api/upload-tdata invalid returns descriptive error", upBadTdataJson.error.length > 0);

  // 7d. POST /api/upload-tdata password protected
  const upProtTdataRes = await fetch(`${baseUrl}/api/upload-tdata`, {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: protectedTdata.zipBuffer
  });
  const upProtTdataJson = await upProtTdataRes.json();
  assert("POST /api/upload-tdata protected (no pass) returns 400 with password prompt", upProtTdataRes.status === 400 && upProtTdataJson.error.includes("password-protected"));

  // 7e. POST /api/upload-tdata password protected with correct passcode
  const upProtPassRes = await fetch(`${baseUrl}/api/upload-tdata?passcode=Secret1234`, {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: protectedTdata.zipBuffer
  });
  const upProtPassJson = await upProtPassRes.json();
  assert("POST /api/upload-tdata protected with passcode returns 200", upProtPassRes.status === 200 && upProtPassJson.success === true);

  // 7f. POST /api/upload-session valid
  const upSqlRes = await fetch(`${baseUrl}/api/upload-session`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: mockSqlite.buffer
  });
  const upSqlJson = await upSqlRes.json();
  assert("POST /api/upload-session valid returns 200", upSqlRes.status === 200 && upSqlJson.success === true);
  assert("POST /api/upload-session returns authKeyHex and dcId", upSqlJson.authKeyHex === mockSqlite.authKeyHex.toLowerCase() && upSqlJson.dcId === 2);

  // 7g. POST /api/upload-session invalid
  const upBadSqlRes = await fetch(`${baseUrl}/api/upload-session`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: Buffer.from("not a real session file")
  });
  const upBadSqlJson = await upBadSqlRes.json();
  assert("POST /api/upload-session invalid returns 400", upBadSqlRes.status === 400 && upBadSqlJson.success === false);

  // 7h. POST /api/resolve-session valid
  const resValidRes = await fetch(`${baseUrl}/api/resolve-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session: validHexKey, dcId: 2 })
  });
  const resValidJson = await resValidRes.json();
  assert("POST /api/resolve-session valid returns 200", resValidRes.status === 200 && resValidJson.success === true);
  assert("POST /api/resolve-session returns telethon string", resValidJson.telethon && resValidJson.telethon.startsWith("1"));

  // 7i. POST /api/resolve-session invalid
  const resBadRes = await fetch(`${baseUrl}/api/resolve-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session: "bad_dummy_value" })
  });
  const resBadJson = await resBadRes.json();
  assert("POST /api/resolve-session invalid returns 400", resBadRes.status === 400 && resBadJson.success === false);

  testServer.close();

  // ── SUMMARY ──────────────────────────────────────────────────────────────
  console.log("\n=================================================================");
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log("=================================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error("Test runner error:", err);
  process.exit(1);
});
