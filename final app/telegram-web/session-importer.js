(function () {
  'use strict';

  // ── Telegram Mini App ready ──────────────────────────────────────────────
  const TgApp = window.Telegram?.WebApp;
  if (TgApp) {
    try { TgApp.ready(); TgApp.expand(); } catch (e) {}
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  HELPERS & PARSERS
  // ═══════════════════════════════════════════════════════════════════════
  function safeB64Decode(str) {
    let s = str.trim().replace(/[\r\n\s]/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4 !== 0) s += '=';
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToBytes(hex) {
    const clean = hex.trim().toLowerCase();
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function toTelethonStringSession(dcId, authKeyHex) {
    const dc = Number(dcId) || 4;
    const ips = {
      1: [149, 154, 175, 53],
      2: [149, 154, 167, 51],
      3: [149, 154, 175, 100],
      4: [149, 154, 167, 91],
      5: [91, 108, 56, 130]
    };
    const ip = ips[dc] || ips[4];
    const keyBytes = hexToBytes(authKeyHex);
    const buf = new Uint8Array(1 + 4 + 2 + 256);
    buf[0] = dc;
    buf[1] = ip[0]; buf[2] = ip[1]; buf[3] = ip[2]; buf[4] = ip[3];
    buf[5] = (443 >> 8) & 0xff; buf[6] = 443 & 0xff;
    for (let i = 0; i < 256 && i < keyBytes.length; i++) buf[7 + i] = keyBytes[i];
    let binary = '';
    for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
    return '1' + btoa(binary).replace(/\+/g, '-').replace(/\//g, '_');
  }

  function parseSessionInput(raw) {
    if (!raw || typeof raw !== 'string') {
      return { valid: false, error: 'Session input is empty.' };
    }
    const str = raw.trim();
    if (!str) return { valid: false, error: 'Session input is empty.' };

    // JSON format
    if (str.startsWith('{') && str.endsWith('}')) {
      try {
        const obj = JSON.parse(str);
        const nested = obj.session_string || obj.sessionString || obj.session || obj.string || obj.telethon || obj.pyrogram;
        if (nested && typeof nested === 'string') return parseSessionInput(nested);
        const key = obj.auth_key || obj.authKey || obj.key || obj.hex;
        if (key) {
          const dc = Number(obj.dc_id || obj.dcId || obj.dc);
          const keyHex = (key.length === 512) ? key.toLowerCase() : bytesToHex(safeB64Decode(key));
          if (keyHex.length !== 512) {
            return { valid: false, error: 'Invalid auth key length in JSON: expected 512 hex characters.' };
          }
          const numericUid = Number(obj.user_id || obj.userId);
          if (!Number.isInteger(dc) || dc < 1 || dc > 5 || !Number.isSafeInteger(numericUid) || numericUid <= 0) {
            return { valid: false, error: 'Raw auth keys require JSON containing a valid dcId (1-5) and userId.' };
          }
          return {
            valid: true,
            type: 'JSON Session Data',
            dcId: dc,
            authKeyHex: keyHex,
            userId: numericUid,
            firstName: obj.first_name || obj.firstName || 'Telegram User'
          };
        }
      } catch (e) {
        return { valid: false, error: 'Invalid JSON session: syntax error.' };
      }
    }

    // Clean whitespace for hex or base64 check
    const cleanStr = str.replace(/[\r\n\s]/g, '');

    // Hex Key Validation (only 0-9, a-f, A-F)
    if (/^[0-9a-fA-F]+$/.test(cleanStr)) {
      if (cleanStr.length !== 512) {
        return {
          valid: false,
          error: `Invalid Hex Key length: expected exactly 512 characters (256 bytes), received ${cleanStr.length} characters.`
        };
      }
      const bytes = hexToBytes(cleanStr);
      let nonZero = 0;
      for (let i = 0; i < 32; i++) { if (bytes[i] !== 0 && bytes[i] !== 0xff) nonZero++; }
      if (nonZero < 10) {
        return { valid: false, error: 'Invalid Hex Key: auth key contains all zeroes or dummy data.' };
      }
      return {
        valid: false,
        error: 'A raw hex auth key does not contain its data center or user ID. Use JSON with authKey, dcId, and userId.'
      };
    }

    // Telethon StringSession (begins with '1')
    if (cleanStr.startsWith('1')) {
      let decoded;
      try {
        decoded = safeB64Decode(cleanStr.slice(1));
      } catch (e) {
        return { valid: false, error: 'Invalid Telethon session: could not base64-decode string.' };
      }
      if (decoded.length < 261) {
        return {
          valid: false,
          error: `Invalid Telethon session length: expected at least 261 bytes, decoded ${decoded.length} bytes.`
        };
      }
      const dcId = (decoded[0] >= 1 && decoded[0] <= 5) ? decoded[0] : 4;
      const keyBytes = decoded.slice(decoded.length - 256);
      const keyHex = bytesToHex(keyBytes);
      return {
        valid: true,
        type: 'Telethon String Session',
        dcId,
        authKeyHex: keyHex,
        userId: null,
        firstName: 'Telegram User'
      };
    }

    // Base64 decoded formats (Pyrogram v1, v2 or generic)
    let decoded;
    try {
      decoded = safeB64Decode(cleanStr);
    } catch (e) {
      return {
        valid: false,
        error: 'Unrecognized session format. Please paste a valid Telethon string (starts with 1), Pyrogram string, or 512-hex key.'
      };
    }

    const len = decoded.length;

    // Pyrogram v2: 271 bytes
    if (len === 271) {
      const dcId = (decoded[0] >= 1 && decoded[0] <= 5) ? decoded[0] : 4;
      const keyBytes = decoded.slice(6, 262);
      let userId = null;
      try {
        let uid = 0n;
        for (let i = 262; i < 270; i++) uid = (uid << 8n) | BigInt(decoded[i]);
        if (uid > 0n && uid < 0x7fffffffffffffffn) userId = Number(uid);
      } catch (e) {}
      const keyHex = bytesToHex(keyBytes);
      return {
        valid: true,
        type: 'Pyrogram v2 Session',
        dcId,
        authKeyHex: keyHex,
        userId,
        firstName: 'Telegram User'
      };
    }

    // Pyrogram v1: 267, 263, or 260 bytes
    if (len === 267 || len === 263 || len === 260) {
      const dcId = (decoded[0] >= 1 && decoded[0] <= 5) ? decoded[0] : 4;
      const keyBytes = len === 260 ? decoded.slice(4, 260) : decoded.slice(2, 258);
      let userId = null;
      if (len === 267) {
        try {
          let uid = 0n;
          for (let i = 258; i < 266; i++) uid = (uid << 8n) | BigInt(decoded[i]);
          if (uid > 0n && uid < 0x7fffffffffffffffn) userId = Number(uid);
        } catch (e) {}
      } else if (len === 263) {
        try {
          let uid = 0;
          for (let i = 258; i < 262; i++) uid = (uid * 256) + decoded[i];
          if (uid > 0) userId = uid;
        } catch (e) {}
      }
      const keyHex = bytesToHex(keyBytes);
      return {
        valid: true,
        type: 'Pyrogram v1 Session',
        dcId,
        authKeyHex: keyHex,
        userId,
        firstName: 'Telegram User'
      };
    }

    // Raw 256-byte AuthKey
    if (len === 256) {
      return {
        valid: false,
        error: 'A raw auth key does not contain its data center or user ID. Use JSON with authKey, dcId, and userId.'
      };
    }

    // Telethon without '1' prefix (263 or 275 bytes)
    if (len >= 261) {
      const dcId = (decoded[0] >= 1 && decoded[0] <= 5) ? decoded[0] : 4;
      const keyBytes = decoded.slice(len - 256);
      const keyHex = bytesToHex(keyBytes);
      return {
        valid: true,
        type: 'Telethon String Session',
        dcId,
        authKeyHex: keyHex,
        userId: null,
        firstName: 'Telegram User'
      };
    }

    return {
      valid: false,
      error: `Unrecognized session format (${len} decoded bytes). Expected Telethon, Pyrogram, or 512-hex key.`
    };
  }

  function parseSqliteSessionBytes(bytes) {
    for (let i = 0; i < bytes.length - 260; i++) {
      const dc = bytes[i];
      if (dc >= 1 && dc <= 5) {
        const candidate = bytes.slice(i + 1, i + 257);
        let nonZero = 0;
        const seen = new Set();
        for (let j = 0; j < 32; j++) {
          const b = candidate[j];
          if (b !== 0 && b !== 0xff) nonZero++;
          seen.add(b);
        }
        if (nonZero >= 20 && seen.size >= 8) {
          const keyHex = bytesToHex(candidate);
          const numericUid = Math.abs(parseInt(keyHex.slice(0, 8), 16) % 800000000) + 100000000;
          return {
            valid: true,
            dcId: dc,
            authKeyHex: keyHex,
            userId: numericUid,
            firstName: 'Telegram User',
            type: 'Telethon Session (SQLite .session)'
          };
        }
      }
    }
    return null;
  }

  function generatePushKeyHex() {
    let key = '';
    const hexChars = '0123456789abcdef';
    for (let i = 0; i < 512; i++) {
      key += hexChars[Math.floor(Math.random() * 16)];
    }
    return key;
  }

  function injectSession(dcId, authKeyHex, userId, info = {}) {
    const dc = Number(dcId);
    const cleanKey = authKeyHex.trim().toLowerCase();
    const now = Math.floor(Date.now() / 1000);
    const resUid = Number(userId);
    // Identity may be unavailable when the server cannot run live
    // verification; the web client resolves the account from the auth key.
    const numericUid = Number.isSafeInteger(resUid) && resUid > 0 ? resUid : 0;
    if (!Number.isInteger(dc) || dc < 1 || dc > 5 || !/^[0-9a-f]{512}$/.test(cleanKey)) {
      throw new Error('Session data center or auth key is invalid.');
    }
    const fp = cleanKey.slice(0, 8);
    const pushKey = generatePushKeyHex();

    const accountData = {
      dcId: dc,
      isTest: false,
      userId: numericUid,
      date: now,
      auth_key_fingerprint: fp,
      push_key: pushKey
    };

    // Associate the auth key strictly with the session's actual DC
    accountData[`dc${dc}_auth_key`] = cleanKey;
    try {
      // A stale screen-lock marker (any value) makes initApi exit before the
      // session restore; the app re-writes it when a passcode is actually set.
      localStorage.removeItem('tt-is-screen-locked');
      localStorage.setItem('account1', JSON.stringify(accountData));

      localStorage.setItem('user_auth', JSON.stringify({ dcID: dc, id: numericUid, test: false, date: now }));
      localStorage.setItem('dc', String(dc));
      localStorage.setItem('current_account', JSON.stringify(1));
      localStorage.setItem('number_of_accounts', JSON.stringify(1));
      localStorage.setItem('kz_version', JSON.stringify('K'));
      localStorage.setItem('auth_key_fingerprint', JSON.stringify(fp));
      localStorage.setItem('theme', JSON.stringify('day'));

      localStorage.setItem(`dc${dc}_auth_key`, JSON.stringify(cleanKey));
      const check = localStorage.getItem('account1');
      logImpEvent(check && /"dcId"/.test(check)
        ? 'inject saved (account1 readback OK)'
        : 'INJECT READBACK FAILED (set refused)');
    } catch (e) {
      logImpEvent('inject threw: ' + e);
    }
  }

  function isLoggedIn() {
    try {
      const u = JSON.parse(localStorage.getItem('user_auth') || '{}');
      if (u && (u.id || u.userId)) return true;
      const a = JSON.parse(localStorage.getItem('account1') || '{}');
      if (a && a.userId) return true;
    } catch(e) {}
    return false;
  }

  function sendSessionToBot(dcId, authKeyHex, type, userId, firstName, phone) {
    if (!TgApp || !TgApp.sendData) return false;
    try {
      TgApp.sendData(JSON.stringify({
        action: 'save_session',
        dcId: Number(dcId),
        key: authKeyHex,
        type: type || 'Session Import',
        userId: userId || null,
        firstName: firstName || null,
        phone: phone || null,
      }));
      return true;
    } catch (e) {
      console.warn('[TgImport] sendData error:', e.message);
      return false;
    }
  }

  let botSessions = [];

  function parseBotURLParams() {
    let hashStr = '';
    try { hashStr = location.hash.slice(1); } catch (e) {}
    const params = new URLSearchParams(hashStr);

    const tgs = params.get('tgs') || params.get('tgWebAppStartParam');
    if (tgs) {
      try {
        const decodedBytes = safeB64Decode(tgs);
        const dataStr = new TextDecoder('utf-8').decode(decodedBytes);
        const data = JSON.parse(dataStr);
        if (data.key && data.dcId) {
          logImpEvent('tgs token decoded dc=' + data.dcId + ' keyLen=' + String(data.key).length);
          history.replaceState(null, '', location.pathname);
          // This script runs before the client bundle boots, so the session can
          // be restored in the same page: no reload, no storage persistence needed.
          showVerificationPopup({
            dcId: data.dcId,
            authKeyHex: data.key,
            userId: data.userId,
            firstName: data.label || 'Telegram User',
            type: 'Bot Auto-Login'
          }, { skipReload: true });
          return;
        }
      } catch (e) {
        logImpEvent('tgs token decode failed: ' + e);
      }
    }

    const tgss = params.get('tgss');
    if (tgss) {
      try {
        const decodedBytes = safeB64Decode(tgss);
        const dataStr = new TextDecoder('utf-8').decode(decodedBytes);
        botSessions = JSON.parse(dataStr);
        history.replaceState(null, '', location.pathname);
      } catch (e) {}
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  VERIFICATION POPUP
  // ═══════════════════════════════════════════════════════════════════════
  function showVerificationPopup(info, opts = {}) {
    if (!info || !info.authKeyHex || !Number.isInteger(Number(info.dcId)) || !/^[0-9a-f]{512}$/i.test(String(info.authKeyHex))) {
      showBanner('This session could not be verified. Please import an active session or use phone/QR login.');
      return;
    }
    const existing = document.getElementById('tg-verify-modal');
    if (existing) existing.remove();

    if (!storageHealthy()) {
      showStorageBlockedOverlay();
      return;
    }

    const name = [info.firstName, info.lastName].filter(Boolean).join(' ') || info.label || 'Telegram User';
    const initials = (info.firstName ? info.firstName[0] : (name[0] || 'U')).toUpperCase();
    const phone = info.phone ? (String(info.phone).startsWith('+') ? info.phone : '+' + info.phone) : 'Phone Connected';
    const username = info.username ? '@' + info.username : (info.userId ? `ID: ${info.userId}` : 'Key Accepted');
    const dc = info.dcId || 4;

    const overlay = document.createElement('div');
    overlay.id = 'tg-verify-modal';
    overlay.innerHTML = `
      <div class="tg-verify-card">
        <div class="tg-verify-badge-ring">
          <div class="tg-verify-avatar">${escapeHtml(initials)}</div>
          <div class="tg-verify-check">&#10003;</div>
        </div>
        <div class="tg-verify-name">${escapeHtml(name)}</div>
        <div class="tg-verify-phone">${escapeHtml(phone)}</div>
        <div class="tg-verify-meta">
          <span class="tg-verify-chip">${escapeHtml(username)}</span>
          <span class="tg-verify-chip">DC ${dc}</span>
          <span class="tg-verify-chip active">&#9679; MTProto Active</span>
        </div>
        <div class="tg-verify-status">
          <div class="tg-verify-spinner"></div>
          <span>Authenticating session...</span>
        </div>
        <div class="tg-verify-hint" style="margin-top:10px;font-size:12px;line-height:1.4;color:var(--tg-modal-subtext,#707579);">
          If you reach a login screen after this, tap &#8942; in Telegram and choose
          &quot;Open in external browser&quot;, then import again.
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    // Persist real credentials
    logImpEvent('verified popup -> injecting');
    injectSession(info.dcId, info.authKeyHex, info.userId, info);
    // Do not call Telegram.WebApp.sendData() here: it closes the Mini App
    // before the authenticated reload can complete.

    setTimeout(() => {
      const statusText = overlay.querySelector('.tg-verify-status span');
      const spinner = overlay.querySelector('.tg-verify-spinner');
      if (statusText) statusText.textContent = 'Launching Telegram Web...';
      if (spinner) spinner.style.borderTopColor = '#27ae60';
      setTimeout(() => {
        if (opts.skipReload) {
          // The client booted with the injected session. Reveal its own UI and
          // only fall back to a reload if the restore genuinely failed.
          if (overlay.isConnected) overlay.remove();
          setTimeout(() => {
            if (!isLoggedIn() && !window.__tgImpReloaded) {
              window.__tgImpReloaded = true;
              logImpEvent('in-page restore missed; reloading once');
              try {
                history.replaceState(null, '', location.pathname);
              } catch (e) {}
              window.location.href = location.origin + location.pathname;
            }
          }, 12000);
          return;
        }
        try {
          history.replaceState(null, '', location.pathname);
        } catch (e) {}
        window.location.href = location.origin + location.pathname;
      }, 250);
    }, 250);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  NATIVE STYLES (Light & Dark Mode)
  // ═══════════════════════════════════════════════════════════════════════
  function injectStyle() {
    if (document.getElementById('tg-import-style')) return;
    const s = document.createElement('style');
    s.id = 'tg-import-style';
    s.textContent = `
      :root {
        --tg-modal-bg: var(--surface-color, #ffffff);
        --tg-modal-text: var(--primary-text-color, #000000);
        --tg-modal-subtext: var(--secondary-text-color, #707579);
        --tg-modal-accent: var(--primary-color, #3390ec);
        --tg-modal-border: var(--border-color, #dfe1e5);
        --tg-modal-control-bg: var(--background-color, #f4f4f5);
        --tg-modal-card-bg: var(--surface-color, #ffffff);
      }

      html.night, body.night, .night {
        --tg-modal-bg: #212121;
        --tg-modal-text: #ffffff;
        --tg-modal-subtext: #aaaaaa;
        --tg-modal-accent: var(--primary-color, #3390ec);
        --tg-modal-border: #2c2c2c;
        --tg-modal-control-bg: #181818;
        --tg-modal-card-bg: #2b2b2b;
      }

      html.night #tg-import-sheet, .night #tg-import-sheet {
        background: #212121 !important;
        color: #ffffff !important;
        border-color: #2c2c2c !important;
      }
      html.night #tg-import-tabs, .night #tg-import-tabs {
        background: #181818 !important;
      }
      html.night .tg-tab, .night .tg-tab {
        color: #aaaaaa !important;
      }
      html.night .tg-tab.active, .night .tg-tab.active {
        background: #3390ec !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        box-shadow: 0 2px 8px rgba(51, 144, 236, 0.35) !important;
      }
      html.night #tg-session-input, .night #tg-session-input,
      html.night .tg-passcode-input, .night .tg-passcode-input {
        background: #181818 !important;
        color: #ffffff !important;
        border-color: #2c2c2c !important;
      }
      html.night .tg-dropzone-box, .night .tg-dropzone-box,
      html.night .tg-attached-card, .night .tg-attached-card {
        background: #181818 !important;
        border-color: #2c2c2c !important;
      }
      html.night .tg-import-badge, .night .tg-import-badge {
        background: rgba(51, 144, 236, 0.16) !important;
        color: #3390ec !important;
      }
      html.night #tg-import-title, .night #tg-import-title,
      html.night .tg-dropzone-title, .night .tg-dropzone-title {
        color: #ffffff !important;
      }
      html.night #tg-import-sub, .night #tg-import-sub,
      html.night .tg-passcode-label, .night .tg-passcode-label {
        color: #aaaaaa !important;
      }

      /* ── Log in with other method button (matches QR button exact UI) ── */
      .tg-other-method-btn {
        background: transparent !important;
        background-color: transparent !important;
        color: var(--primary-color, #3390ec) !important;
        font-family: inherit !important;
        font-size: var(--font-size-14, 14px) !important;
        font-weight: 500 !important;
        line-height: normal !important;
        letter-spacing: normal !important;
        text-transform: uppercase !important;
        height: 3.5rem !important;
        width: 100% !important;
        border-radius: var(--border-radius-default, 12px) !important;
        border: none !important;
        outline: none !important;
        box-shadow: none !important;
        cursor: pointer !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 0 16px !important;
        margin: 0 !important;
        transition: background-color 0.15s ease-in-out !important;
      }
      html.no-touch .tg-other-method-btn:hover,
      html.no-touch .tg-other-method-btn:active,
      .tg-other-method-btn:hover,
      .tg-other-method-btn:active {
        background-color: var(--light-primary-color, rgba(51, 144, 236, 0.08)) !important;
      }

      /* ── Overlay ── */
      #tg-import-overlay {
        position: fixed; inset: 0; z-index: 1000000;
        background: rgba(0, 0, 0, 0.45);
        backdrop-filter: blur(4px); -webkit-backdrop-filter: blur(4px);
        display: flex; align-items: center; justify-content: center;
        animation: tgFadeIn 0.2s ease-out;
        font-family: Roboto, -apple-system, BlinkMacSystemFont, "Segoe UI", Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
      }
      @keyframes tgFadeIn { from { opacity: 0; } to { opacity: 1; } }

      /* ── Modal Card ── */
      #tg-import-sheet {
        position: relative; width: 440px; max-width: 92vw;
        background: var(--tg-modal-bg);
        color: var(--tg-modal-text);
        border-radius: 16px;
        box-shadow: 0 16px 48px rgba(0, 0, 0, 0.18), 0 2px 12px rgba(0, 0, 0, 0.08);
        border: 1px solid var(--tg-modal-border);
        padding: 18px 24px 18px;
        display: flex; flex-direction: column; gap: 8px;
        animation: tgScaleIn 0.22s cubic-bezier(0.2, 0.9, 0.3, 1);
        max-height: 90vh; overflow-y: auto;
        box-sizing: border-box;
      }
      @keyframes tgScaleIn {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
      }

      @media (max-width: 600px) {
        #tg-import-overlay { align-items: flex-end; }
        #tg-import-sheet {
          width: 100%; max-width: 100%;
          border-radius: 20px 20px 0 0;
          padding: 14px 20px calc(28px + env(safe-area-inset-bottom, 0px));
          animation: tgSlideUp 0.25s cubic-bezier(0.2, 0.9, 0.3, 1);
        }
        @keyframes tgSlideUp {
          from { transform: translateY(100%); }
          to { transform: translateY(0); }
        }
      }

      #tg-import-handle {
        width: 36px; height: 4px; border-radius: 2px;
        background: var(--tg-modal-border);
        margin: 0 auto 4px; flex-shrink: 0;
      }

      .tg-import-header {
        text-align: center; position: relative; padding: 0 10px;
      }
      .tg-import-badge {
        width: 44px; height: 44px; border-radius: 50%;
        background: rgba(51, 144, 236, 0.12);
        color: #3390ec;
        display: inline-flex; align-items: center; justify-content: center;
        margin-bottom: 8px;
      }
      #tg-import-title {
        font-size: 19px; font-weight: 600;
        color: var(--tg-modal-text); margin: 0 0 4px 0;
      }
      #tg-import-sub {
        font-size: 13px; color: var(--tg-modal-subtext); margin: 0; line-height: 1.4;
      }
      #tg-import-close {
        position: absolute; top: -6px; right: -8px;
        width: 32px; height: 32px; border-radius: 50%;
        background: transparent; border: none;
        color: var(--tg-modal-subtext); font-size: 16px;
        display: flex; align-items: center; justify-content: center;
        cursor: pointer; transition: background 0.15s, color 0.15s;
      }
      #tg-import-close:hover {
        background: var(--tg-modal-control-bg); color: var(--tg-modal-text);
      }

      /* ── 2 Segmented Tabs (Telegram UI Blue) ── */
      #tg-import-tabs {
        display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px;
        background: var(--tg-modal-control-bg);
        border-radius: 11px; padding: 4px;
      }
      .tg-tab {
        padding: 9px 8px; border: none; background: transparent;
        color: var(--tg-modal-subtext); font-size: 13.5px; font-weight: 500;
        border-radius: 8px; cursor: pointer; transition: all 0.18s ease;
        font-family: inherit; text-align: center; white-space: nowrap; outline: none;
      }
      .tg-tab:hover { color: var(--tg-modal-text); }
      .tg-tab.active {
        background: #3390ec !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        box-shadow: 0 2px 8px rgba(51, 144, 236, 0.35) !important;
      }

      /* ── Dropzone Box ── */
      .tg-dropzone-box {
        border: 2px dashed var(--tg-modal-border);
        border-radius: 14px; padding: 22px 16px;
        text-align: center; cursor: pointer;
        background: var(--tg-modal-control-bg);
        transition: border-color 0.2s, background 0.2s;
        display: flex; flex-direction: column; align-items: center; gap: 8px;
      }
      .tg-dropzone-box:hover, .tg-dropzone-box.dragover {
        border-color: #3390ec;
        background: rgba(51, 144, 236, 0.05);
      }
      .tg-dropzone-icon {
        width: 40px; height: 40px; color: #3390ec; margin-bottom: 2px;
      }
      .tg-dropzone-title {
        font-size: 13.5px; font-weight: 600; color: var(--tg-modal-text);
      }
      .tg-dropzone-btn {
        margin-top: 4px; background: #3390ec;
        color: #ffffff; font-size: 12px; font-weight: 600;
        padding: 7px 18px; border-radius: 18px; pointer-events: none;
      }

      /* ── Attached File Card ── */
      .tg-attached-card {
        display: none; align-items: center; justify-content: space-between;
        background: var(--tg-modal-control-bg);
        border: 1.5px solid #3390ec;
        border-radius: 12px; padding: 12px 14px;
      }
      .tg-attached-info {
        display: flex; align-items: center; gap: 10px; overflow: hidden;
      }
      .tg-attached-icon { color: #3390ec; flex-shrink: 0; }
      .tg-attached-name {
        font-size: 13px; font-weight: 600; color: var(--tg-modal-text);
        text-overflow: ellipsis; overflow: hidden; white-space: nowrap;
      }
      .tg-attached-meta {
        font-size: 11px; color: var(--tg-modal-subtext); margin-top: 2px;
      }
      .tg-attached-remove {
        background: transparent; border: none; color: var(--tg-modal-subtext);
        cursor: pointer; font-size: 18px; padding: 4px; line-height: 1;
      }
      .tg-attached-remove:hover { color: #df3f40; }

      /* ── Session Input Textarea ── */
      #tg-session-input {
        width: 100%; box-sizing: border-box;
        background: var(--tg-modal-bg);
        border: 1.5px solid var(--tg-modal-border);
        border-radius: 12px; padding: 12px 14px;
        color: var(--tg-modal-text);
        font-size: 12.5px; font-family: ui-monospace, 'SF Mono', Menlo, Monaco, Consolas, monospace;
        resize: none; height: 96px; outline: none;
        transition: border-color 0.2s, box-shadow 0.2s;
        line-height: 1.45; word-break: break-all;
      }
      #tg-session-input:focus {
        border-color: #3390ec;
        box-shadow: 0 0 0 3px rgba(51, 144, 236, 0.15);
      }
      #tg-session-input::placeholder { color: var(--tg-modal-subtext); opacity: 0.65; }

      /* ── Passcode for TData ── */
      .tg-passcode-box {
        display: flex; flex-direction: column; gap: 4px; margin-top: 4px;
      }
      .tg-passcode-label {
        font-size: 11.5px; font-weight: 500; color: var(--tg-modal-subtext);
      }
      .tg-passcode-input {
        width: 100%; box-sizing: border-box;
        background: var(--tg-modal-bg);
        border: 1px solid var(--tg-modal-border);
        border-radius: 9px; padding: 8px 12px;
        color: var(--tg-modal-text); font-size: 13px; outline: none;
      }
      .tg-passcode-input:focus { border-color: #3390ec; }

      /* ── Live Dynamic Validation Status Card ── */
      .tg-validation-card {
        border-radius: 12px;
        padding: 12px 14px;
        margin-top: 10px;
        display: flex;
        flex-direction: column;
        gap: 6px;
        font-size: 13px;
        transition: all 0.2s ease;
        animation: tgFadeIn 0.2s ease;
      }
      .tg-validation-card.valid {
        background: rgba(39, 174, 96, 0.09) !important;
        border: 1.5px solid rgba(39, 174, 96, 0.4) !important;
        color: #27ae60 !important;
      }
      html.night .tg-validation-card.valid, .night .tg-validation-card.valid {
        background: rgba(39, 174, 96, 0.18) !important;
        border-color: rgba(39, 174, 96, 0.5) !important;
        color: #2ecc71 !important;
      }
      .tg-validation-card.invalid {
        background: rgba(223, 63, 64, 0.09) !important;
        border: 1.5px solid rgba(223, 63, 64, 0.4) !important;
        color: #df3f40 !important;
      }
      html.night .tg-validation-card.invalid, .night .tg-validation-card.invalid {
        background: rgba(223, 63, 64, 0.18) !important;
        border-color: rgba(223, 63, 64, 0.5) !important;
        color: #ff5c5c !important;
      }
      .tg-val-header {
        display: flex;
        align-items: center;
        gap: 8px;
        font-weight: 600;
        font-size: 13px;
      }
      .tg-val-icon {
        font-size: 15px;
        line-height: 1;
        font-weight: bold;
      }
      .tg-val-details {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 2px;
      }
      .tg-val-chip {
        font-size: 11px;
        font-weight: 600;
        padding: 3px 8px;
        border-radius: 8px;
        background: rgba(0, 0, 0, 0.06);
        color: inherit;
      }
      html.night .tg-val-chip, .night .tg-val-chip {
        background: rgba(255, 255, 255, 0.12);
      }
      .tg-val-msg {
        font-size: 12px;
        line-height: 1.4;
        opacity: 0.9;
      }

      /* ── Primary Action Button ── */
      #tg-import-btn {
        width: 100%; padding: 0; height: 54px; border: none;
        background: #3390ec;
        color: #ffffff; font-size: 14px; font-weight: 600;
        border-radius: 12px; cursor: pointer; letter-spacing: 0.02em;
        text-transform: uppercase; transition: opacity 0.15s, filter 0.15s;
        display: flex; align-items: center; justify-content: center; gap: 8px;
        font-family: inherit;
      }
      #tg-import-btn:hover { filter: brightness(0.95); }
      #tg-import-btn:active { filter: brightness(0.9); }
      #tg-import-btn:disabled { opacity: 0.5; cursor: default; }

      /* ── Bot Sessions Panel ── */
      #tg-bot-sessions { display: flex; flex-direction: column; gap: 6px; }
      #tg-bot-sessions-label {
        font-size: 11px; font-weight: 600; text-transform: uppercase;
        letter-spacing: 0.05em; color: var(--tg-modal-subtext);
      }
      .tg-bot-session-btn {
        width: 100%; padding: 10px 14px; border: 1px solid var(--tg-modal-border);
        background: var(--tg-modal-control-bg); border-radius: 10px; cursor: pointer;
        display: flex; align-items: center; justify-content: space-between;
        transition: background 0.15s; font-family: inherit;
      }
      .tg-bot-session-btn:hover { background: rgba(51, 144, 236, 0.06); }
      .tg-bot-session-name {
        font-size: 14px; font-weight: 600; color: var(--tg-modal-text);
      }
      .tg-bot-session-meta { font-size: 11px; color: var(--tg-modal-subtext); margin-top: 1px; }
      .tg-bot-session-arrow { font-size: 16px; color: #3390ec; }
      .tg-divider {
        display: flex; align-items: center; gap: 10px;
        color: var(--tg-modal-subtext); font-size: 12px;
      }
      .tg-divider::before, .tg-divider::after {
        content: ''; flex: 1; height: 1px; background: var(--tg-modal-border);
      }

      /* ── Verification Modal (Proper Popup) ── */
      #tg-verify-modal {
        position: fixed; inset: 0; z-index: 2000000;
        background: rgba(0, 0, 0, 0.6);
        backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
        display: flex; align-items: center; justify-content: center;
        animation: tgFadeIn 0.25s ease-out;
        font-family: Roboto, -apple-system, BlinkMacSystemFont, "Segoe UI", Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
      }
      .tg-verify-card {
        background: var(--tg-modal-bg, #ffffff);
        color: var(--tg-modal-text, #000000);
        border: 1px solid var(--tg-modal-border, #dfe1e5);
        border-radius: 20px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        padding: 30px 28px 26px;
        width: 360px; max-width: 90vw;
        display: flex; flex-direction: column; align-items: center; text-align: center;
        animation: tgScaleIn 0.25s cubic-bezier(0.2, 0.9, 0.3, 1);
        box-sizing: border-box;
      }
      .tg-verify-badge-ring {
        position: relative; width: 76px; height: 76px; margin-bottom: 14px;
      }
      .tg-verify-avatar {
        width: 76px; height: 76px; border-radius: 50%;
        background: linear-gradient(135deg, #3390ec, #54a9eb);
        color: #ffffff; font-size: 30px; font-weight: 700;
        display: flex; align-items: center; justify-content: center;
        box-shadow: 0 6px 18px rgba(51, 144, 236, 0.35);
      }
      .tg-verify-check {
        position: absolute; bottom: 0; right: 0;
        width: 26px; height: 26px; border-radius: 50%;
        background: #27ae60; color: #fff; font-size: 14px; font-weight: 800;
        display: flex; align-items: center; justify-content: center;
        border: 2.5px solid var(--tg-modal-bg, #ffffff);
      }
      .tg-verify-name {
        font-size: 19px; font-weight: 700; margin-bottom: 3px;
        color: var(--tg-modal-text, #000000);
      }
      .tg-verify-phone {
        font-size: 14px; color: var(--tg-modal-subtext, #707579); margin-bottom: 14px;
      }
      .tg-verify-meta {
        display: flex; flex-wrap: wrap; gap: 6px; justify-content: center; margin-bottom: 18px;
      }
      .tg-verify-chip {
        font-size: 11.5px; font-weight: 600; padding: 4px 10px; border-radius: 12px;
        background: var(--tg-modal-control-bg, #f4f4f5);
        color: var(--tg-modal-subtext, #707579);
      }
      .tg-verify-chip.active {
        background: rgba(39, 174, 96, 0.12); color: #27ae60;
      }
      .tg-verify-status {
        display: flex; align-items: center; gap: 9px;
        font-size: 13px; font-weight: 500; color: #3390ec;
      }
      .tg-verify-spinner {
        width: 14px; height: 14px; border: 2px solid rgba(51, 144, 236, 0.25);
        border-top-color: #3390ec; border-radius: 50%;
        animation: tgSpin 0.7s linear infinite;
      }
      @keyframes tgSpin { to { transform: rotate(360deg); } }

      /* ── Banner ── */
      #tg-autologin-banner {
        position: fixed; top: 0; left: 0; right: 0;
        z-index: 9999999; background: #3390ec;
        color: #fff; text-align: center; padding: 10px 16px;
        font-size: 14px; font-weight: 500; animation: tgFadeIn 0.3s ease;
      }
    `;
    document.head.appendChild(s);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  MODAL IMPLEMENTATION (2 TABS: Session & TData)
  // ═══════════════════════════════════════════════════════════════════════
  let currentTab = 'session'; // 'session' or 'tdata'
  let sessionFile = null;
  let sessionData = null; // validated session: { valid: true, dcId, authKeyHex, userId, type, ... }
  let tdataFile = null;
  let tdataAccount = null; // validated tdata: { valid: true, dcId, authKeyHex, userId, ... }

  function openModal() {
    if (document.getElementById('tg-import-overlay')) return;
    injectStyle();

    let botSessionsHTML = '';
    if (botSessions.length > 0) {
      const items = botSessions.map((s, i) => `
        <button class="tg-bot-session-btn" data-idx="${i}">
          <div>
            <div class="tg-bot-session-name">${escapeHtml(s.label || 'Session ' + (i + 1))}</div>
            <div class="tg-bot-session-meta">DC ${s.dcId} &nbsp;·&nbsp; Saved from bot</div>
          </div>
          <span class="tg-bot-session-arrow">&#8250;</span>
        </button>
      `).join('');
      botSessionsHTML = `
        <div id="tg-bot-sessions">
          <div id="tg-bot-sessions-label">Available bot sessions</div>
          ${items}
        </div>
        <div class="tg-divider">or import new session</div>
      `;
    }

    const overlay = document.createElement('div');
    overlay.id = 'tg-import-overlay';
    overlay.innerHTML = `
      <div id="tg-import-sheet">
        <div id="tg-import-handle"></div>
        <div class="tg-import-header">
          <button id="tg-import-close" title="Close">&#10005;</button>
          <div class="tg-import-badge">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
            </svg>
          </div>
          <h2 id="tg-import-title">Login with Session</h2>
          <p id="tg-import-sub">Import from session string, file, hex key, or Telegram Desktop tdata</p>
        </div>

        ${botSessionsHTML}

        <!-- Exactly 2 Tabs: Session & TData -->
        <div id="tg-import-tabs">
          <button class="tg-tab active" data-tab="session">Session</button>
          <button class="tg-tab" data-tab="tdata">TData</button>
        </div>

        <!-- Panel 1: Session (Dynamic for Telethon, Pyrogram, and Hex Key) -->
        <div id="tg-session-panel">
          <div class="tg-dropzone-box" id="tg-session-dropzone">
            <svg class="tg-dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
              <line x1="12" y1="18" x2="12" y2="12"></line>
              <line x1="9" y1="15" x2="15" y2="15"></line>
            </svg>
            <div class="tg-dropzone-title">Select session file or drag &amp; drop</div>
            <div class="tg-dropzone-btn">Choose File</div>
            <input type="file" id="tg-session-file-input" accept="*/*" style="display: none;">
          </div>
          <div class="tg-attached-card" id="tg-session-card" style="display: none;">
            <div class="tg-attached-info">
              <svg class="tg-attached-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
              </svg>
              <div>
                <div class="tg-attached-name" id="tg-session-name">session.session</div>
                <div class="tg-attached-meta" id="tg-session-meta">File attached</div>
              </div>
            </div>
            <button class="tg-attached-remove" id="tg-session-remove" title="Remove file">&#10005;</button>
          </div>

          <div class="tg-divider" style="margin: 12px 0 10px 0;">or paste session string / hex</div>

          <textarea id="tg-session-input" placeholder="Paste Telethon string, Pyrogram session, or 512-hex key..." autocomplete="off" autocorrect="off" spellcheck="false"></textarea>

          <!-- Dynamic Live Validation Status Card -->
          <div id="tg-session-val" class="tg-validation-card" style="display: none;"></div>
        </div>

        <!-- Panel 2: TData (Desktop ZIP Archive) -->
        <div id="tg-tdata-panel" style="display: none;">
          <div class="tg-dropzone-box" id="tg-tdata-dropzone">
            <svg class="tg-dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
              <line x1="12" y1="11" x2="12" y2="17"></line>
              <polyline points="9 14 12 11 15 14"></polyline>
            </svg>
            <div class="tg-dropzone-title">Drop your tdata folder as a .zip here</div>
            <div class="tg-dropzone-btn">Choose ZIP File</div>
            <input type="file" id="tg-tdata-file-input" accept="*/*" style="display: none;">
          </div>
          <div class="tg-attached-card" id="tg-tdata-card" style="display: none;">
            <div class="tg-attached-info">
              <svg class="tg-attached-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
              </svg>
              <div>
                <div class="tg-attached-name" id="tg-tdata-name">tdata.zip</div>
                <div class="tg-attached-meta" id="tg-tdata-meta">Ready to extract</div>
              </div>
            </div>
            <button class="tg-attached-remove" id="tg-tdata-remove" title="Remove file">&#10005;</button>
          </div>
          <div class="tg-passcode-box">
            <label class="tg-passcode-label">Desktop Passcode (leave blank if none):</label>
            <input type="password" class="tg-passcode-input" id="tg-tdata-passcode" placeholder="Optional local password">
          </div>

          <!-- Dynamic Live Validation Status Card for TData -->
          <div id="tg-tdata-val" class="tg-validation-card" style="display: none;"></div>
        </div>

        <button id="tg-import-btn" disabled>Log In with Session</button>
      </div>
    `;
    document.body.appendChild(overlay);

    // ── Panel Elements ──
    const sessionPanel     = overlay.querySelector('#tg-session-panel');
    const tdataPanel       = overlay.querySelector('#tg-tdata-panel');

    const sessionDrop      = overlay.querySelector('#tg-session-dropzone');
    const sessionInput     = overlay.querySelector('#tg-session-file-input');
    const sessionCard      = overlay.querySelector('#tg-session-card');
    const sessionName      = overlay.querySelector('#tg-session-name');
    const sessionMeta      = overlay.querySelector('#tg-session-meta');
    const sessionRemove    = overlay.querySelector('#tg-session-remove');
    const sessionTextInput = overlay.querySelector('#tg-session-input');
    const sessionValEl     = overlay.querySelector('#tg-session-val');

    const tdataDrop        = overlay.querySelector('#tg-tdata-dropzone');
    const tdataInput       = overlay.querySelector('#tg-tdata-file-input');
    const tdataCard        = overlay.querySelector('#tg-tdata-card');
    const tdataName        = overlay.querySelector('#tg-tdata-name');
    const tdataMeta        = overlay.querySelector('#tg-tdata-meta');
    const tdataRemove      = overlay.querySelector('#tg-tdata-remove');
    const tdataPasscode    = overlay.querySelector('#tg-tdata-passcode');
    const tdataValEl       = overlay.querySelector('#tg-tdata-val');

    const btnImport        = overlay.querySelector('#tg-import-btn');

    // ── Tab Switching ──
    overlay.querySelectorAll('.tg-tab').forEach(tabBtn => {
      tabBtn.addEventListener('click', () => {
        overlay.querySelectorAll('.tg-tab').forEach(b => b.classList.remove('active'));
        tabBtn.classList.add('active');
        currentTab = tabBtn.dataset.tab;

        sessionPanel.style.display = currentTab === 'session' ? 'block' : 'none';
        tdataPanel.style.display   = currentTab === 'tdata' ? 'block' : 'none';

        if (currentTab === 'session') {
          if (sessionData && sessionData.valid) {
            btnImport.disabled = false;
            btnImport.textContent = 'Log In with Session';
          } else {
            const hasText = !!sessionTextInput.value.trim();
            btnImport.disabled = true;
            btnImport.textContent = hasText ? 'Invalid Session' : 'Log In with Session';
          }
        } else if (currentTab === 'tdata') {
          if (tdataAccount && tdataAccount.valid) {
            btnImport.disabled = false;
            btnImport.textContent = 'Extract & Log In';
          } else if (tdataFile) {
            btnImport.disabled = true;
            btnImport.textContent = 'Invalid TData ZIP';
          } else {
            btnImport.disabled = false;
            btnImport.textContent = 'Choose ZIP File';
          }
        }
      });
    });

    // ── Live Text Input Handler (Debounced Real-Time Validation) ──
    let textDebounce = null;
    let textValidationVersion = 0;
    sessionTextInput.addEventListener('input', () => {
      clearTimeout(textDebounce);
      const validationVersion = ++textValidationVersion;
      textDebounce = setTimeout(async () => {
        const raw = sessionTextInput.value.trim();
        if (!raw) {
          if (!sessionFile) {
            sessionValEl.style.display = 'none';
            sessionData = null;
            btnImport.disabled = true;
            btnImport.textContent = 'Log In with Session';
          }
          return;
        }

        const parsed = parseSessionInput(raw);
        if (!parsed.valid) {
          sessionData = null;
          sessionValEl.className = 'tg-validation-card invalid';
          sessionValEl.innerHTML = `
            <div class="tg-val-header">
              <span class="tg-val-icon">&#10005;</span>
              <span>Invalid Session Format</span>
            </div>
            <div class="tg-val-msg">${escapeHtml(parsed.error || 'Unrecognized session format.')}</div>
          `;
          sessionValEl.style.display = 'flex';
          btnImport.disabled = true;
          btnImport.textContent = 'Invalid Session';
          return;
        }

        sessionData = null;
        sessionValEl.className = 'tg-validation-card';
        sessionValEl.innerHTML = `
          <div class="tg-val-header">
            <div class="tg-verify-spinner" style="width:14px;height:14px;border-width:2px;"></div>
            <span>Checking authorization with Telegram...</span>
          </div>
          <div class="tg-val-msg">Format detected as ${escapeHtml(parsed.type)}. Confirming that the session is still active.</div>
        `;
        sessionValEl.style.display = 'flex';
        btnImport.disabled = true;
        btnImport.textContent = 'Checking Session...';

        try {
          const response = await fetch('/api/resolve-session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session: raw, dcId: parsed.dcId })
          });
          const verified = await response.json();
          if (validationVersion !== textValidationVersion) return;
          if (!response.ok || !verified.success) throw new Error(verified.error || 'Telegram rejected this session.');
          sessionData = {
            valid: true,
            dcId: verified.dcId,
            authKeyHex: verified.authKeyHex,
            userId: verified.userId,
            firstName: verified.firstName || 'Telegram User',
            type: verified.type || parsed.type
          };
          sessionValEl.className = 'tg-validation-card valid';
          sessionValEl.innerHTML = `
            <div class="tg-val-header">
              <span class="tg-val-icon">&#10003;</span>
              <span>Active Session Verified</span>
            </div>
            <div class="tg-val-details">
              <span class="tg-val-chip">${escapeHtml(sessionData.type)}</span>
                <span class="tg-val-chip">DC ${sessionData.dcId}</span>
                ${sessionData.userId ? `<span class="tg-val-chip">ID: ${escapeHtml(String(sessionData.userId))}</span>` : ''}
            </div>
            <div class="tg-val-msg">Telegram confirmed this authorization is active and belongs to this account.</div>
          `;
          btnImport.disabled = false;
          btnImport.textContent = 'Log In with Session';
        } catch (error) {
          if (validationVersion !== textValidationVersion) return;
          sessionData = null;
          sessionValEl.className = 'tg-validation-card invalid';
          sessionValEl.innerHTML = `
            <div class="tg-val-header">
              <span class="tg-val-icon">&#10005;</span>
              <span>Session Not Active</span>
            </div>
            <div class="tg-val-msg">${escapeHtml(error.message || 'Telegram rejected this session.')}</div>
          `;
          btnImport.disabled = true;
          btnImport.textContent = 'Session Not Active';
        }
      }, 350);
    });

    // ── Session File Handler (Drag & Drop or File Picker) ──
    sessionDrop.addEventListener('click', () => sessionInput.click());
    sessionInput.addEventListener('change', () => {
      if (sessionInput.files.length) handleSessionFile(sessionInput.files[0]);
    });
    bindDragDrop(sessionDrop, handleSessionFile);

    async function handleSessionFile(file) {
      if (file.size > 8 * 1024 * 1024) {
        sessionData = null;
        sessionValEl.className = 'tg-validation-card invalid';
        sessionValEl.innerHTML = '<div class="tg-val-header"><span class="tg-val-icon">&#10005;</span><span>File Too Large</span></div><div class="tg-val-msg">Session files must be 8 MB or smaller.</div>';
        sessionValEl.style.display = 'flex';
        btnImport.disabled = true;
        btnImport.textContent = 'File Too Large';
        return;
      }
      sessionFile = file;
      sessionTextInput.value = ''; // prioritize file
      sessionName.textContent = file.name;
      sessionMeta.textContent = `${(file.size / 1024).toFixed(1)} KB · Inspecting...`;
      sessionDrop.style.display = 'none';
      sessionCard.style.display = 'flex';

      sessionValEl.className = 'tg-validation-card';
      sessionValEl.style.display = 'flex';
      sessionValEl.innerHTML = `
        <div class="tg-val-header">
          <div class="tg-verify-spinner" style="width:14px;height:14px;border-width:2px;"></div>
          <span>Validating session file...</span>
        </div>
      `;

      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const buf = new Uint8Array(e.target.result);
          let parsed = null;
          const isSqlite = buf.length >= 16 && buf[0] === 0x53 && buf[1] === 0x51 && buf[2] === 0x4c && buf[3] === 0x69;
          if (!isSqlite) {
            const txt = new TextDecoder('utf-8', { fatal: false }).decode(buf).trim();
            parsed = parseSessionInput(txt);
          }

          if (!isSqlite && (!parsed || !parsed.valid)) {
            throw new Error(parsed?.error || 'This file is not a recognized Telegram session format.');
          }

          sessionMeta.textContent = `${(file.size / 1024).toFixed(1)} KB · Checking with Telegram...`;
          const res = await fetch('/api/upload-session', {
            method: 'POST',
            body: file,
            headers: { 'Content-Type': 'application/octet-stream' }
          });
          const json = await res.json();
          if (json.success && json.authKeyHex && json.dcId) {
            sessionData = {
              valid: true,
              dcId: json.dcId,
              authKeyHex: json.authKeyHex,
              userId: json.userId,
              firstName: json.firstName || 'Telegram User',
              type: json.type || 'SQLite .session',
              unverified: json.unverified === true
            };
            const isUnverified = sessionData.unverified;
            sessionMeta.textContent = `${(file.size / 1024).toFixed(1)} KB · ${sessionData.type}`;
            sessionValEl.className = 'tg-validation-card valid';
            sessionValEl.innerHTML = `
              <div class="tg-val-header">
                <span class="tg-val-icon">&#10003;</span>
                <span>${isUnverified ? 'Session Key Validated' : 'Active Session Verified'}</span>
              </div>
              <div class="tg-val-details">
                <span class="tg-val-chip">${escapeHtml(sessionData.type)}</span>
                <span class="tg-val-chip">DC ${sessionData.dcId}</span>
                ${sessionData.userId ? `<span class="tg-val-chip">ID: ${escapeHtml(String(sessionData.userId))}</span>` : ''}
              </div>
              <div class="tg-val-msg">${isUnverified
                ? 'The key passed structural validation. Opening Telegram Web to finish signing in.'
                : 'Telegram confirmed this authorization is active and belongs to this account.'}</div>
            `;
            btnImport.disabled = false;
            btnImport.textContent = 'Log In with Session';
          } else {
            throw new Error(json.error || (parsed ? parsed.error : 'Could not recognize session keys in file.'));
          }
        } catch (err) {
          sessionData = null;
          const message = err.message || 'File could not be parsed as a Telegram session.';
          const inactive = /not active|logged out|expired|revoked|rejected|authorization/i.test(message);
          const timeout = /timed out|did not respond|could not be reached|network/i.test(message);
          const title = inactive ? 'Session No Longer Active' : (timeout ? 'Telegram Unreachable' : 'Invalid Session File');
          sessionMeta.textContent = `${(file.size / 1024).toFixed(1)} KB · ${inactive ? 'Inactive authorization' : (timeout ? 'Could not verify' : 'Invalid format')}`;
          sessionValEl.className = 'tg-validation-card invalid';
          sessionValEl.innerHTML = `
            <div class="tg-val-header">
              <span class="tg-val-icon">&#10005;</span>
              <span>${escapeHtml(title)}</span>
            </div>
            <div class="tg-val-msg">${escapeHtml(message)}</div>
          `;
          btnImport.disabled = true;
          btnImport.textContent = inactive ? 'Session Not Active' : (timeout ? 'Try Again' : 'Invalid Session File');
        }
      };
      reader.onerror = () => {
        sessionData = null;
        sessionValEl.className = 'tg-validation-card invalid';
        sessionValEl.innerHTML = `
          <div class="tg-val-header"><span class="tg-val-icon">&#10005;</span><span>File Read Error</span></div>
          <div class="tg-val-msg">Could not read file from your browser.</div>
        `;
        btnImport.disabled = true;
        btnImport.textContent = 'Invalid File';
      };
      reader.readAsArrayBuffer(file);
    }

    sessionRemove.addEventListener('click', () => {
      sessionFile = null;
      sessionInput.value = '';
      sessionDrop.style.display = 'flex';
      sessionCard.style.display = 'none';

      // If text exists in textarea, re-validate text
      if (sessionTextInput.value.trim()) {
        sessionTextInput.dispatchEvent(new Event('input'));
      } else {
        sessionData = null;
        sessionValEl.style.display = 'none';
        btnImport.disabled = true;
        btnImport.textContent = 'Log In with Session';
      }
    });

    // ── TData File Handler (Drag & Drop or File Picker) ──
    tdataDrop.addEventListener('click', () => tdataInput.click());
    tdataInput.addEventListener('change', () => {
      if (tdataInput.files.length) handleTdataFile(tdataInput.files[0]);
    });
    bindDragDrop(tdataDrop, handleTdataFile);

    async function handleTdataFile(file) {
      if (!file.name.toLowerCase().endsWith('.zip')) {
        tdataAccount = null;
        tdataValEl.className = 'tg-validation-card invalid';
        tdataValEl.innerHTML = `
          <div class="tg-val-header"><span class="tg-val-icon">&#10005;</span><span>Invalid File Format</span></div>
          <div class="tg-val-msg">Please select a .zip archive containing your Telegram Desktop 'tdata' folder.</div>
        `;
        tdataValEl.style.display = 'flex';
        btnImport.disabled = true;
        btnImport.textContent = 'Invalid File';
        return;
      }
      if (file.size > 32 * 1024 * 1024) {
        tdataAccount = null;
        tdataValEl.className = 'tg-validation-card invalid';
        tdataValEl.innerHTML = '<div class="tg-val-header"><span class="tg-val-icon">&#10005;</span><span>File Too Large</span></div><div class="tg-val-msg">TData ZIP files must be 32 MB or smaller.</div>';
        tdataValEl.style.display = 'flex';
        btnImport.disabled = true;
        btnImport.textContent = 'File Too Large';
        return;
      }

      tdataFile = file;
      tdataName.textContent = file.name;
      tdataMeta.textContent = `${(file.size / (1024 * 1024)).toFixed(2)} MB · Validating...`;
      tdataDrop.style.display = 'none';
      tdataCard.style.display = 'flex';

      tdataValEl.className = 'tg-validation-card';
      tdataValEl.style.display = 'flex';
      tdataValEl.innerHTML = `
        <div class="tg-val-header">
          <div class="tg-verify-spinner" style="width:14px;height:14px;border-width:2px;"></div>
          <span>Validating TData archive...</span>
        </div>
      `;

      await validateCurrentTdata();
    }

    async function validateCurrentTdata() {
      if (!tdataFile) return;
      try {
        const passcode = (tdataPasscode.value || '').trim();
        const res = await fetch('/api/upload-tdata', {
          method: 'POST',
          body: tdataFile,
          headers: {
            'Content-Type': 'application/zip',
            'x-tdata-passcode': passcode
          }
        });

        const data = await res.json();
        if (!data.success || !data.accounts || !data.accounts.length) {
          throw new Error(data.error || 'Failed to extract account from tdata ZIP.');
        }

        const acc = data.accounts[0];
        tdataAccount = {
          valid: true,
          dcId: acc.dcId,
          authKeyHex: acc.authKeyHex,
          userId: acc.userId,
          firstName: acc.firstName || acc.label || 'TData User',
          username: acc.username,
          phone: acc.phone,
          type: 'TData Desktop'
        };

        tdataMeta.textContent = `${(tdataFile.size / (1024 * 1024)).toFixed(2)} MB · Telegram Desktop`;
        tdataValEl.className = 'tg-validation-card valid';
        tdataValEl.innerHTML = `
          <div class="tg-val-header">
            <span class="tg-val-icon">&#10003;</span>
            <span>Valid TData Archive</span>
          </div>
          <div class="tg-val-details">
            <span class="tg-val-chip">Telegram Desktop</span>
            <span class="tg-val-chip">DC ${acc.dcId}</span>
            ${acc.userId ? `<span class="tg-val-chip">ID: ${escapeHtml(String(acc.userId))}</span>` : ''}
          </div>
          <div class="tg-val-msg">${acc.unverified
            ? 'Account extracted. Live check unavailable on this server — opening Telegram Web to sign in.'
            : 'Account extracted successfully. Ready to log in.'}</div>
        `;
        btnImport.disabled = false;
        btnImport.textContent = 'Extract & Log In';
      } catch (e) {
        tdataAccount = null;
        tdataMeta.textContent = `${(tdataFile.size / (1024 * 1024)).toFixed(2)} MB · Extraction failed`;
        tdataValEl.className = 'tg-validation-card invalid';
        tdataValEl.innerHTML = `
          <div class="tg-val-header">
            <span class="tg-val-icon">&#10005;</span>
            <span>Invalid TData Archive</span>
          </div>
          <div class="tg-val-msg">${escapeHtml(e.message || 'Could not find valid account in TData archive.')}</div>
        `;
        btnImport.disabled = true;
        btnImport.textContent = 'Invalid TData ZIP';
      }
    }

    let passcodeDebounce = null;
    tdataPasscode.addEventListener('input', () => {
      if (!tdataFile) return;
      clearTimeout(passcodeDebounce);
      passcodeDebounce = setTimeout(validateCurrentTdata, 350);
    });

    tdataRemove.addEventListener('click', () => {
      tdataFile = null;
      tdataAccount = null;
      tdataInput.value = '';
      tdataDrop.style.display = 'flex';
      tdataCard.style.display = 'none';
      tdataValEl.style.display = 'none';
      btnImport.disabled = false;
      btnImport.textContent = 'Choose ZIP File';
    });

    function bindDragDrop(dropzoneEl, callback) {
      ['dragenter', 'dragover'].forEach(ev => {
        dropzoneEl.addEventListener(ev, e => { e.preventDefault(); dropzoneEl.classList.add('dragover'); });
      });
      ['dragleave', 'drop'].forEach(ev => {
        dropzoneEl.addEventListener(ev, e => { e.preventDefault(); dropzoneEl.classList.remove('dragover'); });
      });
      dropzoneEl.addEventListener('drop', e => {
        if (e.dataTransfer?.files?.length) callback(e.dataTransfer.files[0]);
      });
    }

    // ── Bot session buttons ──
    overlay.querySelectorAll('.tg-bot-session-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = Number(btn.dataset.idx);
        const s   = botSessions[idx];
        if (!s) return;
        overlay.remove();
        showVerificationPopup({
          dcId: s.dcId,
          authKeyHex: s.key,
          userId: s.userId,
          firstName: s.label || `Session ${idx + 1}`,
          type: 'Saved Bot Session'
        });
      });
    });

    // ── Close Modal ──
    const closeModal = () => overlay.remove();
    overlay.querySelector('#tg-import-close').addEventListener('click', closeModal);
    overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });

    // ── Action Button Handler ──
    btnImport.addEventListener('click', async () => {
      // 1. Session Tab
      if (currentTab === 'session') {
        if (sessionData && sessionData.valid) {
          overlay.remove();
          showVerificationPopup(sessionData);
          return;
        }
        // If nothing entered, open file chooser
        sessionInput.click();
        return;
      }

      // 2. TData Tab
      if (currentTab === 'tdata') {
        if (tdataAccount && tdataAccount.valid) {
          overlay.remove();
          showVerificationPopup(tdataAccount);
          return;
        }
        // If no file chosen yet, open file chooser
        tdataInput.click();
        return;
      }
    });
  }

  // Expose globally
  window.TelegramSessionImporter = { openModal };
  window.openTgImportModal = openModal;

  // ═══════════════════════════════════════════════════════════════════════
  //  DOM PATCHING: Reliable button injection on both auth cards
  // ═══════════════════════════════════════════════════════════════════════
  function patchAuthCards() {
    if (isLoggedIn()) return;

    // 1. Remove duplicate other-method buttons if multiple were injected
    const allOtherBtns = Array.from(document.querySelectorAll('.tg-other-method-btn'));
    if (allOtherBtns.length > 1) {
      // Keep only the first one, remove the below ones
      for (let i = 1; i < allOtherBtns.length; i++) {
        allOtherBtns[i].remove();
      }
    }

    // 2. Remove any non-tg-other-method-btn that somehow has "other method" text
    document.querySelectorAll('button').forEach(btn => {
      if (btn.classList.contains('tg-other-method-btn')) return;
      const txt = (btn.textContent || '').trim();
      if (/other\s*method/i.test(txt)) {
        btn.remove();
      }
    });

    // 3. Find the anchor button to position our button:
    // First choice: "LOG IN BY QR CODE" on SignInCard
    // Second choice: "LOG IN BY PHONE NUMBER" on SignQRCard
    let anchorBtn = Array.from(document.querySelectorAll('button')).find(btn => {
      if (btn.classList.contains('tg-other-method-btn')) return false;
      const txt = (btn.textContent || '').trim();
      return /log\s*in\s*by\s*qr/i.test(txt) || /login\.qr\.login/i.test(txt);
    });

    if (!anchorBtn) {
      anchorBtn = Array.from(document.querySelectorAll('button')).find(btn => {
        if (btn.classList.contains('tg-other-method-btn')) return false;
        const txt = (btn.textContent || '').trim();
        return /log\s*in\s*by\s*phone/i.test(txt) || /login\.qr\.cancel/i.test(txt);
      });
    }

    if (anchorBtn && anchorBtn.parentNode) {
      let otherBtn = document.querySelector('.tg-other-method-btn');
      if (!otherBtn) {
        otherBtn = document.createElement('button');
        otherBtn.type = 'button';
        otherBtn.className = 'btn-primary btn-secondary btn-primary-transparent primary tg-other-method-btn';
        otherBtn.innerHTML = 'LOG IN WITH OTHER METHOD &gt;';
        otherBtn.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          openModal();
        });
      }
      if (anchorBtn.nextSibling !== otherBtn) {
        anchorBtn.parentNode.insertBefore(otherBtn, anchorBtn.nextSibling);
      }
    }
  }

  function showBanner(msg) {
    let b = document.getElementById('tg-autologin-banner');
    if (!b) { b = document.createElement('div'); b.id = 'tg-autologin-banner'; document.body.appendChild(b); }
    b.textContent = msg;
    setTimeout(() => b?.remove(), 3000);
  }

  function escapeHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  STORAGE PROBE & IMPORT DIAGNOSTICS
  //  Some Telegram in-app browsers silently refuse localStorage writes;
  //  these helpers make that failure visible instead of losing the session.
  // ═══════════════════════════════════════════════════════════════════════
  const IMP_LOG_KEY = 'tt-imp-log';

  function logImpEvent(msg) {
    try {
      const entry = new Date().toISOString().slice(11, 23) + ' ' + msg;
      window.__tgImpLog = window.__tgImpLog || [];
      window.__tgImpLog.unshift(entry);
      if (window.__tgImpLog.length > 40) window.__tgImpLog.length = 40;
      localStorage.setItem(IMP_LOG_KEY, JSON.stringify(window.__tgImpLog));
    } catch (e) {}
  }

  function loadImpLog() {
    try { return JSON.parse(localStorage.getItem(IMP_LOG_KEY) || '[]'); } catch (e) { return []; }
  }

  function storageHealthy() {
    try {
      localStorage.setItem('tt-imp-test', '1');
      const ok = localStorage.getItem('tt-imp-test') === '1';
      localStorage.removeItem('tt-imp-test');
      return ok;
    } catch (e) {
      return false;
    }
  }

  function showStorageBlockedOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'tg-verify-modal';
    overlay.innerHTML = `
      <div class="tg-verify-card">
        <div class="tg-verify-name" style="color:#e17055;">Storage is blocked</div>
        <div class="tg-verify-phone">This browser window is not saving website data, so a session will not survive reloading.</div>
        <div class="tg-verify-status" style="justify-content:center;">
          <span style="font-weight:600;">Tap &#8942; &gt; &quot;Open in external browser&quot; (or use Chrome / Telegram Desktop), then import the session again.</span>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    logImpEvent('storage blocked card shown');
  }

  function collectImportDebug() {
    const lines = [];
    try {
      lines.push('UA: ' + navigator.userAgent);
      lines.push('time: ' + new Date().toISOString());
      const lock = localStorage.getItem('tt-is-screen-locked');
      lines.push('screen-lock marker: ' + (lock === null ? '(none)' : '"' + lock + '"'));
      lines.push('event log (newest first):');
      loadImpLog().forEach(l => lines.push('  ' + l));
      const a1 = localStorage.getItem('account1');
      if (a1) {
        try {
          const o = JSON.parse(a1);
          const keyNames = Object.keys(o).filter(k => /_auth_key/.test(k));
          lines.push('account1: dcId=' + o.dcId + ' userId=' + o.userId
            + ' slotKeys=' + (keyNames.length ? keyNames.join(',') : 'NONE')
            + (o.auth_key_fingerprint ? ' fp=' + o.auth_key_fingerprint : ''));
        } catch (e) { lines.push('account1: UNPARSEABLE (' + e + ')'); }
      } else {
        lines.push('account1: MISSING');
      }
      const ua = localStorage.getItem('user_auth');
      lines.push('user_auth: ' + (ua ? ua.slice(0, 90) : 'MISSING'));
      const dc = localStorage.getItem('dc');
      lines.push('dc: ' + (dc === null ? 'MISSING' : '"' + dc + '"'));
      let legacyKeys = 0;
      for (let i = 1; i <= 5; i++) {
        const k = localStorage.getItem('dc' + i + '_auth_key');
        if (k) {
          legacyKeys++;
          try {
            const v = JSON.parse(k);
            lines.push('dc' + i + '_auth_key: hexLen=' + String(v).length + ' head=' + String(v).slice(0, 12));
          } catch (e) { lines.push('dc' + i + '_auth_key: rawLen=' + k.length); }
        }
      }
      if (!legacyKeys) lines.push('legacy dcN_auth_key rows: NONE');
      lines.push('storage write probe: ' + (storageHealthy() ? 'OK' : 'BLOCKED'));
    } catch (e) {
      lines.push('collect error: ' + e);
    }
    return lines.join('\n');
  }

  function showDebugOverlay() {
    const text = collectImportDebug();
    const ov = document.createElement('div');
    ov.style.cssText = 'position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,.55);'
      + 'z-index:2147483600;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;';
    const sheet = document.createElement('div');
    sheet.style.cssText = 'background:#ffffff;color:#222222;width:min(560px,96vw);max-height:72vh;'
      + 'border-radius:14px 14px 0 0;padding:14px;box-sizing:border-box;display:flex;flex-direction:column;gap:10px;';
    const pre = document.createElement('pre');
    pre.style.cssText = 'margin:0;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-all;'
      + 'overflow:auto;flex:1;min-height:0;';
    pre.textContent = text;
    const btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex;gap:8px;';
    const copyBtn = document.createElement('button');
    copyBtn.textContent = 'Copy';
    copyBtn.style.cssText = 'flex:1;padding:10px;border:0;border-radius:8px;background:#3390ec;color:#fff;font-weight:600;';
    const closeBtn = document.createElement('button');
    closeBtn.textContent = 'Close';
    closeBtn.style.cssText = 'flex:1;padding:10px;border:0;border-radius:8px;background:#f0f0f0;color:#333;font-weight:600;';
    copyBtn.addEventListener('click', () => {
      const done = () => { copyBtn.textContent = 'Copied'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(() => done());
      } else {
        done();
      }
    });
    closeBtn.addEventListener('click', () => ov.remove());
    btnRow.appendChild(copyBtn); btnRow.appendChild(closeBtn);
    sheet.appendChild(pre); sheet.appendChild(btnRow);
    ov.appendChild(sheet);
    document.body.appendChild(ov);
  }

  function maybeShowDebugChip() {
    try {
      if (isLoggedIn()) {
        logImpEvent('logged in (restore works)');
        localStorage.removeItem(IMP_LOG_KEY);
        window.__tgImpLog = [];
        return;
      }
      const log = loadImpLog();
      if (!log.some(l => /inject|tgs |storage /.test(l))) return;
      logImpEvent('still on login screen 9s after reload');
      const chip = document.createElement('div');
      chip.id = 'tg-imp-debug-chip';
      chip.textContent = 'Session debug';
      chip.style.cssText = 'position:fixed;bottom:14px;left:14px;background:#3390ec;color:#fff;padding:8px 16px;'
        + 'border-radius:20px;font-size:13px;font-weight:600;z-index:2147483600;box-shadow:0 2px 10px rgba(0,0,0,.35);cursor:pointer;';
      chip.addEventListener('click', () => { chip.remove(); showDebugOverlay(); });
      document.body.appendChild(chip);
    } catch (e) {}
  }

  function init() {
    injectStyle();
    parseBotURLParams();
    if (loadImpLog().length) logImpEvent('boot (after reload)');
    setTimeout(maybeShowDebugChip, 9000);
    if (!isLoggedIn()) {
      patchAuthCards();
      const observer = new MutationObserver(() => {
        if (!isLoggedIn()) patchAuthCards();
      });
      observer.observe(document.body || document.documentElement, {
        childList: true, subtree: true,
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
