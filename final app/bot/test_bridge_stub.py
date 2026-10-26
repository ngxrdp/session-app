import base64
import json
import sys


def main() -> None:
    try:
        stdin_bytes = sys.stdin.buffer.read()
        payload = json.loads(stdin_bytes.decode("utf-8"))
    except Exception:
        sys.stdout.write(json.dumps({"success": False, "error": "Stub rejected this session."}))
        return
    result = {"success": False, "error": "Stub rejected this session."}
    session = str(payload.get("session", "")).strip()
    if session.startswith("1"):
        try:
            b64 = session[1:].replace("-", "+").replace("_", "/")
            raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
            dc_id = raw[0] if len(raw) >= 7 else 4
            key = raw[-256:]
            if any(b != 0 for b in key):
                result = {
                    "success": True,
                    "userId": "9988776655",
                    "firstName": "Test User",
                    "phone": "",
                    "dcId": dc_id,
                    "authKeyHex": key.hex(),
                    "telethon": session,
                }
        except Exception:
            pass
    sys.stdout.write(json.dumps(result, separators=(",", ":")))


main()
