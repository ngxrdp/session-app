# Telegram Web Session Bot

A Telegram bot + self-hosted Telegram Web K miniapp that lets users **import sessions** (Telethon, Pyrogram, Hex Auth Key), **auto-login** to the web app, and **export sessions** in any format — with a full admin panel for access control.

---

## Features

- **Telegram Web K** served as a MiniApp (full mobile UI)
- **Session import** — Telethon, Pyrogram, 512-hex Auth Key
- **Auto-login** — bot encodes session in the Open App URL → app auto-injects and logs in
- **Session export** — Telethon string, Pyrogram string, Hex, JSON, all formats at once, bulk export
- **Admin panel** — add/remove users, set custom access duration (7d, 12h, permanent…)
- **Permission system** — only permitted users can access; access expires automatically
- **Cloudflare tunnel** — free public HTTPS URL via cloudflared (auto-restarts on failure)

---

## Project Structure

```
final app/
├── bot/
│   ├── bot.js            ← Main bot + HTTP server
│   ├── cloudflared.exe   ← Cloudflare tunnel binary (Windows)
│   ├── data.json         ← Persistent users/sessions (auto-created)
│   └── package.json
└── telegram-web/         ← Telegram Web K built files
    ├── index.html
    ├── session-importer.js  ← Session injection + "Use other method" button
    └── ... (all other built assets)
```

---

## Quick Start (Local / Windows)

### 1. Prerequisites

- **Node.js v18+** → [nodejs.org](https://nodejs.org)
- **Telegram Bot Token** → create via [@BotFather](https://t.me/BotFather) → `/newbot`

### 2. Set your Bot Token

Open `bot/bot.js` and find line ~42:

```js
const BOT_TOKEN = process.env.BOT_TOKEN;
```

Set the token through an environment variable. Never place a live token in source code or documentation:

```powershell
$env:BOT_TOKEN = "YOUR_NEW_BOT_TOKEN"
$env:ADMIN_IDS = "YOUR_TELEGRAM_USER_ID"
```

### 3. Install dependencies

```powershell
cd "d:\tg\final app\bot"
npm install
```

### 4. Run the bot

```powershell
node bot.js
```

The bot will:
1. Authenticate with Telegram
2. Start an HTTP server on port 3000
3. Start a Cloudflare tunnel (auto-gets public HTTPS URL)
4. Register bot commands
5. Begin polling for messages

You'll see output like:
```
╔══════════════════════════════════════════╗
║     Telegram Web Session Bot             ║
╚══════════════════════════════════════════╝
[Bot] Authenticated as @YourBotName
[Server] Listening on http://localhost:3000
[Tunnel] Starting cloudflared (attempt 1/3)...
[Tunnel] Public URL: https://xyz-abc.trycloudflare.com
══════════════════════════════════════════════════
Bot link : https://t.me/YourBotName
App URL  : https://xyz-abc.trycloudflare.com
══════════════════════════════════════════════════
```

### 5. Admin setup

Set `ADMIN_IDS` before starting the bot. Automatic first-user promotion is intentionally disabled so a stranger cannot claim a new deployment.

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BOT_TOKEN` | Telegram bot token | required; no default |
| `PORT` | HTTP server port | `3000` |
| `APP_URL` | Custom public HTTPS URL (skips tunnel) | auto via cloudflared |
| `ADMIN_IDS` | Comma-separated admin Telegram IDs | required on a new install |

**Example with all vars:**
```powershell
$env:BOT_TOKEN = "YOUR_TOKEN"
$env:ADMIN_IDS = "123456789,987654321"
$env:PORT = "3000"
node bot.js
```

---

## Python session validator

Uploading a session (bot chat or `/api/upload-*` endpoints) is verified against Telegram itself using **Telethon** through `bot/telegram_session_bridge.py`. This requires a Python 3 interpreter on the machine running the bot.

```bash
# Linux / macOS
python3 -m pip install telethon

# Windows
py -m pip install telethon
```

The bot automatically finds `py` (Windows) or `python3`/`python` (Linux/macOS) and checks that Telethon imports cleanly. Optional overrides:

| Variable | Description | Default |
|----------|-------------|---------|
| `PYTHON_BIN` | Explicit Python executable path with Telethon available | auto-detected |
| `SESSION_BRIDGE` | Path to the bridge script | `bot/telegram_session_bridge.py` |

**How validation behaves without Telethon:** uploads are always structurally validated in pure JavaScript (format, data center, auth-key entropy). Sessions that pass are **accepted and marked `unverified: true`** in the API response — Telethon only adds the live check against Telegram's servers. If Telethon is installed but Telegram cannot be reached, endpoints return a descriptive 503 error instead of failing silently.

---

## Log in by phone (OTP)

Every permitted user can log an account into the bot **without any file or string** — the same flow as the classic phone-OTP login:

1. Tap **Login by OTP** in the bot menu (or any keyboard that shows it).
2. Send the phone number with country code, e.g. `+15551234567`.
3. Telegram delivers a login code — paste it in the chat.
4. Accounts with two-factor verification ask for the password next (it is never stored).
5. On success the account is saved to `data.json` as an `OTP Login` session and the bot shows the **Open App** button.

Implementation notes:

- The flow runs through `bot/login_bridge.py`, a persistent Telethon worker (JSON-lines over stdio). One live Telegram connection spans the whole `phone → code → 2FA` conversation, because Telegram binds each `phone_code_hash` to the client that requested it.
- API credentials: the bot's `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` if set, otherwise the operator pair from the working Python core, with three well-known official-client pairs as fallbacks (`38785545`, `2040`, `4`, `6`).
- `/cancel` (or 5 minutes of inactivity) kills the worker immediately; the Telegram connection is dropped on both ends.
- If Telethon is missing on the server, the button explains it and the other import paths keep working.

---

## Tunnel Troubleshooting

The bot uses **Cloudflare Quick Tunnels** (free, no account needed). Each restart gives a **new random URL**.

### If tunnel fails to start:

**Option A — Restart** (tunnel retries 3 times automatically):
```powershell
node bot.js
```

**Option B — Check cloudflared log:**
```powershell
Get-Content "bot\cloudflared.log" -Tail 30
```

**Option C — Test cloudflared manually:**
```powershell
.\bot\cloudflared.exe tunnel --url http://localhost:3000
```
Look for the `https://....trycloudflare.com` URL in the output.

**Option D — Use a fixed URL (recommended for production):**
```powershell
$env:APP_URL = "https://your-fixed-url.com"
node bot.js
```

### Common tunnel errors:

| Error | Fix |
|-------|-----|
| Timeout after 30s | Check internet connection; try again |
| `exited 1` | Run `cloudflared.exe --version` to verify binary works |
| URL changes on restart | Use a permanent tunnel (see Hosting section) |

---

## Hosting Options

### Option 1: VPS / Cloud VM (Recommended for 24/7)

**Best choice: Railway, Render, DigitalOcean, Hetzner**

#### Steps for any Linux VPS:

```bash
# 1. Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 2. Copy files to VPS (from Windows)
# Use WinSCP, FileZilla, or rsync

# 3. Install dependencies
cd /opt/tg-bot
npm install

# 4. Install PM2 (process manager)
npm install -g pm2

# 5. Create .env file
cat > .env << EOF
BOT_TOKEN=YOUR_TOKEN_HERE
ADMIN_IDS=YOUR_TELEGRAM_ID
PORT=3000
APP_URL=https://yourdomain.com
EOF

# 6. Start with PM2
pm2 start bot.js --name tg-bot
pm2 save
pm2 startup  # auto-start on reboot
```

#### With Nginx reverse proxy (for custom domain):

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Get free SSL with Certbot
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

### Option 2: Railway (Free tier, easiest)

1. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
2. Push this folder to a GitHub repo
3. Set environment variables in Railway dashboard:
   - `BOT_TOKEN` = your token
   - `ADMIN_IDS` = your Telegram ID
   - `PORT` = `3000`
   - `APP_URL` = `https://your-app.railway.app`
4. Railway gives you a permanent HTTPS URL automatically

**`package.json` for Railway:**
```json
{
  "name": "tg-session-bot",
  "type": "module",
  "scripts": {
    "start": "node bot.js"
  }
}
```

---

### Option 3: Render (Free tier)

1. Go to [render.com](https://render.com) → New Web Service
2. Connect GitHub repo
3. Build Command: `npm install`
4. Start Command: `node bot.js`
5. Set env vars: `BOT_TOKEN`, `ADMIN_IDS`, `APP_URL` (use Render's auto-URL)

---

### Option 4: Cloudflare Tunnel with Named Tunnel (Permanent URL)

Get a **permanent** cloudflare tunnel URL (no account restart issues):

```bash
# 1. Login to Cloudflare
cloudflared login

# 2. Create named tunnel
cloudflared tunnel create my-tg-bot

# 3. Configure tunnel
cat > ~/.cloudflared/config.yml << EOF
tunnel: my-tg-bot
credentials-file: /root/.cloudflared/TUNNEL_ID.json

ingress:
  - hostname: tgbot.yourdomain.com
    service: http://localhost:3000
  - service: http_status:404
EOF

# 4. Add DNS record
cloudflared tunnel route dns my-tg-bot tgbot.yourdomain.com

# 5. Run tunnel (permanent)
cloudflared tunnel run my-tg-bot

# 6. Set APP_URL and run bot
APP_URL=https://tgbot.yourdomain.com node bot.js
```

---

## Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Open dashboard (shows session count, access time) |
| `/session` | Save a new session (Telethon / Pyrogram / Hex) |
| `/export` | Export your saved sessions |
| `/admin` | Admin panel (admins only) |
| `/cancel` | Cancel current operation |
| `/help` | Show all commands |

---

## Admin Panel

Access with `/admin`. Options:

| Button | Action |
|--------|--------|
| List Users | Show all permitted users with access time |
| Add User | Grant access by Telegram User ID + set duration |
| Set Time | Change access duration for existing user |
| Remove User | Revoke access |
| Sessions | Overview of all stored sessions |
| Refresh | Refresh stats |

### Access duration format:
- `permanent` — never expires
- `7d` — 7 days
- `12h` — 12 hours
- `30m` — 30 minutes
- `2d12h` — 2 days 12 hours

---

## Session Import (in MiniApp)

When you open the app and are not logged in, tap **"Use other method"** button.

Supported formats:
- **Telethon** — starts with `1AgABB...` (long base64)
- **Pyrogram** — long base64, doesn't start with `1`
- **Hex Auth Key** — exactly 512 hex characters

### Auto-login flow:
1. Save a session via `/session` in the bot
2. Tap **Open App** — the session is encoded in the URL
3. The miniapp auto-injects the session and logs you in instantly

---

## Session Export Formats

| Format | Description |
|--------|-------------|
| Telethon String | Ready to use in Telethon scripts |
| Pyrogram String | Ready to use in Pyrogram scripts |
| Hex Auth Key | Raw 512-char hex auth key |
| JSON | All fields: DC, type, all formats, timestamp |
| All Formats at Once | TXT file with everything |

Use `/export` → pick session → pick format → get file/text in chat.

---

## Security Notes

- Sessions are stored in `bot/data.json` — **keep this file private**
- The `data.json` contains raw auth keys — treat like passwords
- Admin IDs should be set via `ADMIN_IDS` env var, not hardcoded
- Use HTTPS (cloudflare or nginx+certbot) — Telegram requires HTTPS for MiniApps
- Cloudflare quick tunnels are ephemeral — URL changes on restart unless you use named tunnels

---

## Running 24/7 on Windows (without a server)

Use **NSSM** or **PM2 for Windows**:

```powershell
# Install PM2
npm install -g pm2

# Start bot
pm2 start bot.js --name tg-bot

# Auto-start on Windows boot
pm2 startup
pm2 save

# View logs
pm2 logs tg-bot

# Restart
pm2 restart tg-bot
```

Or create a `.bat` file for manual restart:

```bat
@echo off
cd /d "d:\tg\final app\bot"
set BOT_TOKEN=YOUR_TOKEN_HERE
set ADMIN_IDS=YOUR_TELEGRAM_ID
node bot.js
pause
```

---

## Files Reference

| File | Purpose |
|------|---------|
| `bot/bot.js` | Main application — bot logic, HTTP server, tunnel |
| `bot/data.json` | Users, sessions, admins (auto-created) |
| `bot/cloudflared.exe` | Cloudflare tunnel binary |
| `bot/cloudflared.log` | Tunnel log (check if URL not found) |
| `telegram-web/index.html` | Telegram Web K entry point |
| `telegram-web/session-importer.js` | Session inject UI + bot↔app bridge |
