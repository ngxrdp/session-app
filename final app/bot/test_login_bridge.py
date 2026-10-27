#!/usr/bin/env python3
"""Deterministic stub for login_bridge.py used by the automated tests.

Protocol (JSON lines on stdin -> stdout):
  {"cmd": "start", "phone": "+9876500"}    -> {"event": "code_sent", ...}
  {"cmd": "code", "code": "11111"}         -> {"event": "error", ...}        (wrong code)
  {"cmd": "code", "code": "22222"}         -> {"event": "password_required"}
  {"cmd": "code", "code": "33333"}         -> {"event": "authorized", ...}   (no 2FA)
  {"cmd": "password", "password": "..."}   -> authorized for "SecretPass1", else error
  {"cmd": "cancel"}                        -> {"event": "done"} (then exit)

The authorized payload uses a fixed 512-hex auth key so the tests can assert
exact record contents. The phone in the response mirrors the "start" request.
"""

import json
import sys

STUB_KEY = "ab" * 256
STUB_TELETHON = "1BQANOTEuMTA0LjAu"  # shape only; tests never dial Telegram


def authorized(stub_phone):
    return {
        "event": "authorized",
        "success": True,
        "userId": "998877",
        "firstName": "Stub User",
        "phone": stub_phone,
        "dcId": 4,
        "authKeyHex": STUB_KEY,
        "telethon": STUB_TELETHON,
    }


def respond(payload):
    cmd = payload.get("cmd")

    if cmd == "start":
        phone = str(payload.get("phone", ""))
        if not phone.startswith("+") or not phone[1:].isdigit():
            return {"event": "error", "message": "Invalid phone number. Use the format +15551234567."}
        return {
            "event": "code_sent",
            "phone_code_hash": "stub-hash-0001",
            "hint": "Delivery: Stub",
            "phone": phone,
        }

    if cmd == "code":
        code = str(payload.get("code", ""))
        if code == "22222":
            return {"event": "password_required", "message": "A 2FA password is required for this account."}
        if code == "33333":
            return authorized(str(payload.get("phone", "") or ""))
        return {"event": "error", "message": "Wrong code. Try again:"}

    if cmd == "password":
        if str(payload.get("password", "")) == "SecretPass1":
            return authorized(str(payload.get("phone", "") or ""))
        return {"event": "error", "message": "Wrong 2FA password. Try again:"}

    if cmd == "cancel":
        return {"event": "done"}

    return {"event": "error", "message": "Unknown command."}


for _line in sys.stdin:
    _line = _line.strip()
    if not _line:
        continue
    try:
        _payload = json.loads(_line)
    except json.JSONDecodeError:
        print(json.dumps({"event": "error", "message": "Bad request."}), flush=True)
        continue
    _response = respond(_payload)
    print(json.dumps(_response), flush=True)
    if _response.get("event") == "done":
        break
