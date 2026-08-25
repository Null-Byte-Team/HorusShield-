#!/usr/bin/env python3
"""
CI helper: actually boot the Flask/Socket.IO server (headless, as Docker
does) in a subprocess, poll /api/health, and confirm it comes up cleanly —
then shut it down. This exercises the real app.py entry point end-to-end,
which importing modules individually (check_imports.py) does not cover.
"""

import os
import signal
import subprocess
import sys
import time

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

HOST = os.environ.get("HORUS_HOST", "127.0.0.1")
PORT = os.environ.get("HORUS_PORT", "5099")
HEALTH_URL = f"http://{HOST}:{PORT}/api/health"
STARTUP_TIMEOUT_S = 30


def main():
    env = os.environ.copy()
    env.setdefault("HORUS_HEADLESS", "true")
    env.setdefault("HORUS_ENV", "development")

    print(f"Starting `python app.py` in {BACKEND_DIR} (headless) ...")
    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=BACKEND_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        deadline = time.time() + STARTUP_TIMEOUT_S
        healthy = False
        while time.time() < deadline:
            if proc.poll() is not None:
                print("❌ Process exited early — output:")
                print(proc.stdout.read())
                sys.exit(1)
            try:
                r = requests.get(HEALTH_URL, timeout=2)
                if r.status_code == 200 and r.json().get("status") == "online":
                    healthy = True
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)

        if not healthy:
            print(f"❌ {HEALTH_URL} never became healthy within {STARTUP_TIMEOUT_S}s")
            proc.terminate()
            print(proc.stdout.read())
            sys.exit(1)

        print(f"✅ Flask server booted and {HEALTH_URL} responded healthy")
    finally:
        print("Shutting down test server ...")
        if os.name == "nt":
            proc.terminate()
        else:
            proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
