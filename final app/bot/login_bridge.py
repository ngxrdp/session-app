#!/usr/bin/env python3
"""Persistent Telegram login worker for the interactive OTP login flow.

The bot process starts this worker once per login attempt and talks to it
over two JSON-lines pipes:

  stdin  : {"cmd": "start",    "phone": "+15551234567"}
           {"cmd": "code",     "code": "12345"}
           {"cmd": "password", "password": "s3cr3t"}
           {"cmd": "cancel"}
  stdout : {"event": "code_sent", "phone_code_hash": "...", "hint": "..."}
           {"event": "password_required"}
           {"event": "authorized", "success": true, "userId": "...", ...}
           {"event": "error", "message": "..."}
           {"event": "expired"} / {"event": "done"}

One Telegram connection stays alive for the whole attempt, because the
phone_code_hash returned by send_code_request only works on the client that
created it. The worker exits on "cancel", on stdin EOF (the bot killed it),
and after 5 minutes without any request.
"""

import asyncio
import json
import os
import re
import sys
import threading
from pathlib import Path

try:
    from telethon import TelegramClient, errors
    from telethon.sessions import StringSession
except ImportError:
    msg = {
        "event": "error",
        "message": "The Python Telethon package is not installed on this server."
                   " The bot admin must run: pip install telethon",
    }
    print(json.dumps(msg), flush=True)
    sys.exit(0)

IDLE_TIMEOUT_SECONDS = 300
PHONE_RE = re.compile(r"^\+\d{7,15}$")

# Telegram public client credentials + the operator pair. Match the pairs
# used by telegram_session_bridge.py so sessions stay interchangeable.
def _api_pairs():
    pairs = []
    configured_id = os.environ.get("TELEGRAM_API_ID", "").strip()
    configured_hash = os.environ.get("TELEGRAM_API_HASH", "").strip()
    if configured_id.isdigit() and configured_hash:
        pairs.append((int(configured_id), configured_hash))
    pairs.extend(
        [
            (38785545, "d5ad8c7bd2b01e837e2deb0b41dee770"),
            (2040, "b18441a1ff607e10a989891a5462e627"),
            (4, "014b35b6184100b085b0d0572f9b5103"),
            (6, "eb06d4abfb49dc3eeb1aeb98ae0f581e"),
        ]
    )
    unique = []
    seen = set()
    for pair in pairs:
        if pair in seen:
            continue
        seen.add(pair)
        unique.append(pair)
    return unique


def _emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _delivery_hint(sent):
    type_name = str(getattr(getattr(sent, "type", None), "name", "") or getattr(sent, "type", "") or "")
    if "app" in type_name.lower():
        return "Delivery: Telegram app"
    if "sms" in type_name.lower():
        return "Delivery: SMS"
    if "call" in type_name.lower():
        return "Delivery: Phone call"
    if "email" in type_name.lower():
        return "Delivery: Email"
    return ""


class LoginAttempt:
    """Holds the live Telegram client across the phone -> code -> 2FA steps."""

    def __init__(self):
        self.client = None
        self.phone = ""
        self.phone_code_hash = ""

    def _client_kwargs(self):
        return {"connection_retries": 3, "request_retries": 2}

    async def _authorized_result(self):
        me = await self.client.get_me()
        if me is None or not getattr(me, "id", None):
            raise ValueError("Telegram did not return the logged-in account.")
        session_string = StringSession.save(self.client.session)
        session = StringSession(session_string)
        auth_key = getattr(session, "auth_key", None)
        key_bytes = getattr(auth_key, "key", None)
        dc_id = int(getattr(session, "dc_id", 0) or 0)
        if dc_id not in range(1, 6) or not key_bytes or len(key_bytes) != 256:
            raise ValueError("Telegram returned an incomplete session.")
        first = getattr(me, "first_name", None) or ""
        last = getattr(me, "last_name", None) or ""
        return {
            "event": "authorized",
            "success": True,
            "userId": str(me.id),
            "firstName": (f"{first} {last}".strip() or "Telegram User"),
            "phone": getattr(me, "phone", None) or self.phone,
            "dcId": dc_id,
            "authKeyHex": bytes(key_bytes).hex(),
            "telethon": session_string,
        }

    def _stop(self):
        client = self.client
        self.client = None

        async def _disconnect():
            if client is not None:
                try:
                    await client.disconnect()
                except Exception:
                    pass

        asyncio.ensure_future(_disconnect())

    async def start(self, phone):
        phone = phone.strip()
        if self.client is not None:
            self._stop()
        if not PHONE_RE.match(phone):
            _emit({"event": "error", "message": "Invalid phone number. Use the format +15551234567."})
            return
        pair = _api_pairs()[0]
        api_id, api_hash = pair
        client = TelegramClient(StringSession(), api_id, api_hash, **self._client_kwargs())
        try:
            await client.connect()
            sent = await client.send_code_request(phone)
        except errors.FloodWaitError as exc:
            try:
                await client.disconnect()
            except Exception:
                pass
            _emit({"event": "error", "message": f"Telegram flood limit. Wait {exc.seconds} seconds and try again."})
            return
        except errors.PhoneNumberInvalidError:
            try:
                await client.disconnect()
            except Exception:
                pass
            _emit({"event": "error", "message": "Invalid phone number. Include the country code."})
            return
        except errors.PhoneNumberBannedError:
            try:
                await client.disconnect()
            except Exception:
                pass
            _emit({"event": "error", "message": "This phone number is banned on Telegram."})
            return
        except Exception as exc:
            try:
                await client.disconnect()
            except Exception:
                pass
            _emit({"event": "error", "message": f"Telegram could not send a code: {exc}"})
            return
        self.client = client
        self.phone = phone
        self.phone_code_hash = sent.phone_code_hash
        _emit({
            "event": "code_sent",
            "phone_code_hash": sent.phone_code_hash,
            "hint": _delivery_hint(sent),
        })

    async def code(self, code):
        if self.client is None:
            _emit({"event": "error", "message": "No login in progress. Start a new OTP login from the menu."})
            return
        code = code.strip()
        try:
            await self.client.sign_in(phone=self.phone, code=code, phone_code_hash=self.phone_code_hash)
            result = await self._authorized_result()
            _emit(result)
            self._stop()
        except errors.SessionPasswordNeededError:
            _emit({"event": "password_required", "message": "A 2FA password is required for this account."})
        except errors.PhoneCodeInvalidError:
            _emit({"event": "error", "message": "Wrong code. Try again:"})
        except errors.PhoneCodeExpiredError:
            self._stop()
            _emit({"event": "error", "message": "The code expired. Start a new login from the menu."})
        except errors.FloodWaitError as exc:
            self._stop()
            _emit({"event": "error", "message": f"Telegram flood limit. Wait {exc.seconds} seconds and try again."})
        except Exception as exc:
            self._stop()
            _emit({"event": "error", "message": f"Login failed: {exc}"})

    async def password(self, password):
        if self.client is None:
            _emit({"event": "error", "message": "No login in progress. Start a new OTP login from the menu."})
            return
        try:
            await self.client.sign_in(password=password)
            result = await self._authorized_result()
            _emit(result)
            self._stop()
        except errors.PasswordHashInvalidError:
            _emit({"event": "error", "message": "Wrong 2FA password. Try again:"})
        except Exception as exc:
            self._stop()
            _emit({"event": "error", "message": f"Login failed: {exc}"})


async def _main():
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()

    def _pump_stdin():
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    loop.call_soon_threadsafe(queue.put_nowait, line)
        except Exception:
            pass
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=_pump_stdin, daemon=True).start()

    attempt = LoginAttempt()
    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=IDLE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            attempt._stop()
            _emit({"event": "expired", "message": "Login timed out. Start again from the menu."})
            break
        if item is None:
            break
        try:
            payload = json.loads(item)
        except json.JSONDecodeError:
            _emit({"event": "error", "message": "Bad request."})
            continue
        cmd = str(payload.get("cmd", ""))
        if cmd == "cancel":
            attempt._stop()
            _emit({"event": "done"})
            break
        if cmd == "start":
            await attempt.start(str(payload.get("phone", "")))
        elif cmd == "code":
            await attempt.code(str(payload.get("code", "")))
        elif cmd == "password":
            await attempt.password(str(payload.get("password", "")))
        else:
            _emit({"event": "error", "message": f"Unknown command: {cmd or '(empty)'}"})

    if attempt.client is not None:
        try:
            await attempt.client.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
