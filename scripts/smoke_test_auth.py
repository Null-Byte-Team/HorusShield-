#!/usr/bin/env python3
"""One-shot smoke test: boot the server, register, login, verify auth
enforcement actually works, then shut down. Run within a single blocking
call since this sandbox doesn't persist background processes across tool
calls."""

import os
import signal
import subprocess
import sys
import time

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
HOST = "127.0.0.1"
PORT = "5097"
BASE = f"http://{HOST}:{PORT}"


def main():
    env = os.environ.copy()
    env.update(
        {
            "HORUS_HEADLESS": "true",
            "HORUS_ENV": "development",
            "HORUS_HOST": HOST,
            "HORUS_PORT": PORT,
            "HORUS_SECRET_KEY": "smoke-test-secret",
            "HORUS_DB_PATH": "/tmp/smoke_test2.db",
        }
    )
    for f in ("/tmp/smoke_test2.db", "/tmp/smoke_test2.db-wal", "/tmp/smoke_test2.db-shm"):
        if os.path.exists(f):
            os.remove(f)

    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=BACKEND_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    results = []

    def check(label, cond, extra=""):
        results.append((label, cond, extra))
        print(f"  {'PASS' if cond else 'FAIL'}: {label} {extra}")

    try:
        # wait for boot
        deadline = time.time() + 30
        healthy = False
        while time.time() < deadline:
            try:
                r = requests.get(f"{BASE}/api/health", timeout=2)
                if r.status_code == 200:
                    healthy = True
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)
        check("server boots and /api/health responds", healthy)
        if not healthy:
            print(proc.stdout.read())
            return 1

        # 1. Protected endpoint with NO token -> 401
        r = requests.get(f"{BASE}/api/devices/", timeout=5)
        check(
            "GET /api/devices/ with no token -> 401", r.status_code == 401, f"(got {r.status_code})"
        )

        # 2. Terminal with NO token -> 401
        r = requests.post(f"{BASE}/api/terminal/run", json={"operation": "whoami"}, timeout=5)
        check(
            "POST /api/terminal/run with no token -> 401",
            r.status_code == 401,
            f"(got {r.status_code})",
        )

        # 3. Register a user
        email = "smoketest@example.com"
        r = requests.post(
            f"{BASE}/api/auth/register",
            json={"email": email, "password": "SmokeTest123!", "name": "Smoke Test"},
            timeout=5,
        )
        check(
            "register returns 2xx",
            200 <= r.status_code < 300,
            f"(got {r.status_code}: {r.text[:200]})",
        )
        dev_code = r.json().get("dev_code") if r.status_code == 200 else None

        # SMTP isn't configured in this test env, so the app falls back to
        # returning the verification code directly in the response
        # (dev_code) instead of emailing it — expected behavior, not a bug.
        # Complete verification with it before attempting login.
        if dev_code:
            r = requests.post(
                f"{BASE}/api/auth/verify", json={"email": email, "code": dev_code}, timeout=5
            )
            check(
                "email verification with dev_code succeeds",
                r.status_code == 200,
                f"(got {r.status_code}: {r.text[:200]})",
            )

        r = requests.post(
            f"{BASE}/api/auth/login", json={"email": email, "password": "SmokeTest123!"}, timeout=5
        )
        token = None
        if r.status_code == 200 and "token" in r.json():
            token = r.json()["token"]
            check("login succeeds and returns a token", True)
        else:
            check(
                "login succeeds and returns a token",
                False,
                f"(got {r.status_code}: {r.text[:150]} -- may need email verification)",
            )

        if token:
            # 4. Protected endpoint WITH token -> 200
            r = requests.get(
                f"{BASE}/api/devices/", headers={"Authorization": f"Bearer {token}"}, timeout=5
            )
            check(
                "GET /api/devices/ with valid token -> 200",
                r.status_code == 200,
                f"(got {r.status_code})",
            )

            # 5. Terminal allowlist works with valid (admin-role-by-default) token
            r = requests.post(
                f"{BASE}/api/terminal/run",
                json={"operation": "whoami"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            check(
                "POST /api/terminal/run 'whoami' with token -> 200",
                r.status_code == 200,
                f"(got {r.status_code}: {r.text[:200]})",
            )

            # 6. Terminal rejects a non-allowlisted operation
            r = requests.post(
                f"{BASE}/api/terminal/run",
                json={"operation": "format C:"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            check(
                "POST /api/terminal/run with disallowed op -> 400",
                r.status_code == 400,
                f"(got {r.status_code})",
            )

            # 7. Terminal rejects shell-injection-shaped target for ping
            r = requests.post(
                f"{BASE}/api/terminal/run",
                json={"operation": "ping", "target": "8.8.8.8; rm -rf /"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            check(
                "POST /api/terminal/run ping with injection payload -> 400",
                r.status_code == 400,
                f"(got {r.status_code})",
            )

            # 8. Rate limiting on login (5/min) — hit it 7 times rapidly
            codes = []
            for _ in range(7):
                rr = requests.post(
                    f"{BASE}/api/auth/login",
                    json={"email": "x@x.com", "password": "wrong"},
                    timeout=5,
                )
                codes.append(rr.status_code)
            check(
                "rate limiting kicks in on login (429 appears within 7 rapid attempts)",
                429 in codes,
                f"(codes: {codes})",
            )

            # 9. Audit log recorded the terminal command
            r = requests.get(
                f"{BASE}/api/audit/?action=terminal_command&limit=5",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            has_entry = r.status_code == 200 and len(r.json()) > 0
            check(
                "audit log recorded terminal_command entries",
                has_entry,
                f"(got {r.status_code}, {len(r.json()) if r.status_code == 200 else 0} entries)",
            )

            # 10. V-8 Scanner manager is actually reachable via the new
            # app.extensions DI (not "Scanner not initialized" 500) —
            # verifies the Phase 7 DI-unification fix didn't break it.
            # Uses a malformed target so it fails validation (400) rather
            # than actually spidering a real host — we're testing wiring,
            # not running a live scan.
            r = requests.post(
                f"{BASE}/api/vscanner/scan/start",
                json={"target_url": ""},
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            check(
                "V-8 Scanner manager reachable via app.extensions DI (not 500)",
                r.status_code != 500,
                f"(got {r.status_code}: {r.text[:150]})",
            )

    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("\n" + "=" * 60)
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"RESULT: {passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
