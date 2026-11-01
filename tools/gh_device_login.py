"""GitHub device-flow login without a browser dependency.

Prints a one-time code and polls until the user authorises the app, then writes
the token to ``.ghconfig/token`` (gitignored). Used by the maintainer tooling;
not imported by the test suite.

Run:  python tools/gh_device_login.py
"""

from __future__ import annotations

import json
import pathlib
import sys
import time
import urllib.parse
import urllib.request

CLIENT_ID = "Iv1.b507a08c87ecfe98"  # GitHub CLI OAuth app, public client id
SCOPE = "repo"
ROOT = pathlib.Path(__file__).resolve().parents[1]
TOKEN_PATH = ROOT / ".ghconfig" / "token"


def post(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "7702-safety-device-login",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main() -> int:
    code = post("https://github.com/login/device/code",
                {"client_id": CLIENT_ID, "scope": SCOPE})
    if "user_code" not in code:
        print(f"ERROR=no_code {code}", flush=True)
        return 1

    print(f"USER_CODE={code['user_code']}", flush=True)
    print(f"URL={code['verification_uri']}", flush=True)

    interval = int(code.get("interval", 5))
    deadline = time.time() + int(code.get("expires_in", 900))

    while time.time() < deadline:
        time.sleep(interval)
        try:
            result = post(
                "https://github.com/login/oauth/access_token",
                {
                    "client_id": CLIENT_ID,
                    "device_code": code["device_code"],
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            )
        except Exception as exc:  # transient network error: keep polling
            print(f"POLL_ERROR={exc}", flush=True)
            continue

        error = result.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error:
            print(f"ERROR={error}", flush=True)
            return 2

        token = result["access_token"]
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_PATH.write_text(token, encoding="utf-8")
        print("TOKEN_SAVED", flush=True)
        return 0

    print("ERROR=expired", flush=True)
    return 3


if __name__ == "__main__":
    sys.exit(main())
