import fs from "node:fs";

function patchFile(filepath) {
  if (!fs.existsSync(filepath)) return;
  let c = fs.readFileSync(filepath, "utf8");

  // 1. Fix getSelf() fallback so worker never crashes on uninitialized user
  const oldGetSelf = "getSelf(){return this.getUser(this.userId)}";
  const newGetSelf = 'getSelf(){return this.getUser(this.userId)||{id:this.userId||0,pFlags:{self:!0},first_name:"Telegram User"}}';
  if (c.includes(oldGetSelf)) {
    c = c.replace(oldGetSelf, newGetSelf);
    console.log("Patched getSelf in:", filepath);
  }

  // 2. Fix WebSocket endpoints for all DCs
  const targetWS = "return`wss://${L.suffix.toLowerCase()}ws${r}${i}.web.telegram.org/${a}`}";
  const replacementWS = 'let _d="kws"+r;return`wss://${_d}${i}.web.telegram.org/${a}`}';
  if (c.includes(targetWS)) {
    c = c.replace(targetWS, replacementWS);
    console.log("Patched targetWS in:", filepath);
  }

  const targetWS2 = "return`wss://${a.suffix.toLowerCase()}ws${r}${i}.web.telegram.org/${o}`}";
  const replacementWS2 = 'let _d="kws"+r;return`wss://${_d}${i}.web.telegram.org/${o}`}';
  if (c.includes(targetWS2)) {
    c = c.replace(targetWS2, replacementWS2);
    console.log("Patched targetWS2 in:", filepath);
  }

  fs.writeFileSync(filepath, c, "utf8");
}

patchFile("d:/tg/final app/telegram-web/index.worker-D-oUJ7CX.js");
patchFile("d:/tg/final app/telegram-web/index.worker-CHAcBazd.js");
console.log("All patches applied.");
