"""Validate imported Telegram sessions against Telegram with Telethon.

The Node server sends one JSON object on stdin containing either base64 encoded
session-file bytes or a Telethon StringSession.  Only a small JSON result is
written to stdout.  No session material is logged.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
from pathlib import Path

from telethon import TelegramClient
from telethon.sessions import StringSession


def _raise_validation_failure(error_names: list[str]) -> None:
    names = " ".join(error_names).lower()
    if "authkeyduplicated" in names:
        raise ValueError(
            "Telegram revoked this session because its authorization key was used from different IP addresses. Create a new session."
        )
    if any(value in names for value in (
        "authkeyunregistered", "sessionrevoked", "sessionexpired",
        "unauthorized", "userdeactivated",
    )):
        raise ValueError(
            "This session is no longer active on Telegram. It was logged out, expired, or revoked. Create a new session or use phone/QR login."
        )
    if any(value in names for value in ("timeout", "connection", "oserror")):
        raise ValueError("Telegram could not be reached to verify this session. Check the server connection and try again.")
    raise ValueError("Telegram rejected this session authorization. Create a new session or use phone/QR login.")


def _api_pairs() -> list[tuple[int, str]]:
    pairs: list[tuple[int, str]] = []
    configured_id = os.environ.get("TELEGRAM_API_ID", "").strip()
    configured_hash = os.environ.get("TELEGRAM_API_HASH", "").strip()
    if configured_id.isdigit() and configured_hash:
        pairs.append((int(configured_id), configured_hash))

    # The first pair is from the user's supplied working Python core.  The
    # remaining pairs are Telegram's public client credentials and are useful
    # for sessions originally created by those official clients.
    pairs.extend(
        [
            (38785545, "d5ad8c7bd2b01e837e2deb0b41dee770"),
            (2040, "b18441a1ff607e10a989891a5462e627"),
            (4, "014b35b6184100b085b0d0572f9b5103"),
            (6, "eb06d4abfb49dc3eeb1aeb98ae0f581e"),
        ]
    )

    unique: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique


async def _inspect_client(client: TelegramClient) -> dict | None:
    await client.connect()
    try:
        if not await client.is_user_authorized():
            return None
        me = await client.get_me()
        if me is None or not getattr(me, "id", None):
            return None
        session_string = StringSession.save(client.session)
        session = StringSession(session_string)
        auth_key = getattr(session, "auth_key", None)
        key_bytes = getattr(auth_key, "key", None)
        dc_id = int(getattr(session, "dc_id", 0) or 0)
        if dc_id not in range(1, 6) or not key_bytes or len(key_bytes) != 256:
            raise ValueError("Telegram returned an incomplete session.")
        first = getattr(me, "first_name", None) or ""
        last = getattr(me, "last_name", None) or ""
        return {
            "success": True,
            "userId": str(me.id),
            "firstName": (f"{first} {last}".strip() or "Telegram User"),
            "phone": getattr(me, "phone", None) or "",
            "dcId": dc_id,
            "authKeyHex": bytes(key_bytes).hex(),
            "telethon": session_string,
        }
    finally:
        await client.disconnect()


async def _from_string(value: str) -> dict | None:
    # Fail malformed strings before attempting any network connection.
    StringSession(value)
    failures: list[str] = []
    for api_id, api_hash in _api_pairs():
        client = TelegramClient(
            StringSession(value), api_id, api_hash,
            timeout=10, connection_retries=1, request_retries=1,
        )
        try:
            result = await _inspect_client(client)
            if result:
                return result
            failures.append("Unauthorized")
        except Exception as exc:
            failures.append(exc.__class__.__name__)
            try:
                await client.disconnect()
            except Exception:
                pass
    _raise_validation_failure(failures)


async def _from_sqlite(raw: bytes) -> dict | None:
    handle = tempfile.NamedTemporaryFile(suffix=".session", delete=False)
    path = Path(handle.name)
    try:
        handle.write(raw)
        handle.close()
        failures: list[str] = []
        for api_id, api_hash in _api_pairs():
            client = TelegramClient(
                str(path), api_id, api_hash,
                timeout=10, connection_retries=1, request_retries=1,
            )
            try:
                result = await _inspect_client(client)
                if result:
                    return result
                failures.append("Unauthorized")
            except Exception as exc:
                failures.append(exc.__class__.__name__)
                try:
                    await client.disconnect()
                except Exception:
                    pass
        _raise_validation_failure(failures)
    finally:
        try:
            handle.close()
        except Exception:
            pass
        for candidate in (path, Path(f"{path}-journal"), Path(f"{path}-wal"), Path(f"{path}-shm")):
            try:
                candidate.unlink(missing_ok=True)
            except Exception:
                pass


async def _main() -> dict:
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    if payload.get("session"):
        result = await _from_string(str(payload["session"]).strip())
    else:
        raw = base64.b64decode(str(payload.get("data", "")), validate=True)
        if not raw:
            raise ValueError("The session file is empty.")
        if raw.startswith(b"SQLite format 3\x00"):
            result = await _from_sqlite(raw)
        else:
            try:
                result = await _from_string(raw.decode("utf-8").strip())
            except UnicodeDecodeError:
                result = None

    if not result:
        return {
            "success": False,
            "error": "Telegram rejected this session. It may be expired, revoked, incomplete, or from an unsupported format.",
        }
    return result


if __name__ == "__main__":
    try:
        output = asyncio.run(asyncio.wait_for(_main(), timeout=45))
    except asyncio.TimeoutError:
        output = {"success": False, "error": "Telegram did not respond in time. Please try again."}
    except Exception as exc:
        output = {"success": False, "error": str(exc) or "Session validation failed."}
    sys.stdout.write(json.dumps(output, separators=(",", ":")))
