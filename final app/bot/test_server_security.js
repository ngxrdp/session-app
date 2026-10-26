import assert from "node:assert/strict";
import { createServer, escapeHtml, parseDuration } from "./bot.js";

const server = createServer();
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;

try {
  const indexResponse = await fetch(`${baseUrl}/`, { method: "HEAD" });
  assert.equal(indexResponse.status, 200);
  assert.equal(await indexResponse.text(), "");
  assert.equal(indexResponse.headers.get("x-content-type-options"), "nosniff");
  assert.equal(indexResponse.headers.get("access-control-allow-origin"), null);

  const traversalResponse = await fetch(`${baseUrl}/..%2fbot%2fdata.json`);
  assert.equal(traversalResponse.status, 403);

  const malformedResponse = await fetch(`${baseUrl}/api/resolve-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{"
  });
  assert.equal(malformedResponse.status, 400);
  assert.equal((await malformedResponse.json()).error, "Malformed JSON request.");

  const validKey = "00".repeat(256);
  const validResponse = await fetch(`${baseUrl}/api/resolve-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session: validKey, dcId: 4 })
  });
  // A structurally valid key is not a valid login. The live Telegram check
  // must reject fabricated, expired, and revoked auth keys.
  assert.equal(validResponse.status, 400);
  const validResult = await validResponse.json();
  assert.match(validResult.error, /entropy|rejected|expired|revoked|invalid|incomplete/i);

  const crossSiteResponse = await fetch(`${baseUrl}/api/resolve-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Sec-Fetch-Site": "cross-site" },
    body: JSON.stringify({ session: validKey })
  });
  assert.equal(crossSiteResponse.status, 403);

  const oversizedResponse = await fetch(`${baseUrl}/api/upload-session`, {
    method: "POST",
    body: Buffer.alloc(8 * 1024 * 1024 + 1)
  });
  assert.equal(oversizedResponse.status, 413);

  const wrongMethodResponse = await fetch(`${baseUrl}/index.html`, { method: "POST", body: "x" });
  assert.equal(wrongMethodResponse.status, 405);

  assert.equal(parseDuration("2d12h"), 216000);
  assert.equal(parseDuration("junk 7d"), 0);
  assert.equal(parseDuration("999999999999d"), 0);
  assert.equal(escapeHtml('<script>"x"</script>'), "&lt;script&gt;&quot;x&quot;&lt;/script&gt;");

  console.log("Server security regression tests passed.");
} finally {
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
