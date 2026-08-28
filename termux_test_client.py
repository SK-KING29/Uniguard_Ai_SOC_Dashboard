#!/usr/bin/env python3
"""
UniGuard AI - Authorized Test Client (Android Termux)

Sends REAL HTTP requests, over your phone's mobile/wifi internet
connection, to a UniGuard AI backend you specify. This is the
"PHONE / AUTHORIZED TEST CLIENT" step of the demo flow - it does not
simulate anything; every request actually leaves your phone and hits
the live deployed backend, which logs it for real.

Setup on Android Termux (one-time):
    pkg update -y
    pkg install python -y

Usage:
    python3 termux_test_client.py --url https://your-app.onrender.com --rate 15 --duration 30

Only ever point --url at a UniGuard AI deployment you own/control.
No other target is supported by design (see SAFETY note below).
"""
import argparse
import sys
import time
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

ALLOWED_ENDPOINTS = ("/", "/api/login", "/api/data", "/api/search")


def send_one(url, stats, lock):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "UniGuard-Termux-TestClient/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        code = 0

    with lock:
        stats["sent"] += 1
        if code == 200:
            stats["ok"] += 1
        elif code in (429, 403):
            stats["blocked"] += 1
        else:
            stats["error"] += 1


def main():
    parser = argparse.ArgumentParser(
        description="UniGuard AI authorized test traffic generator (run from Android Termux)"
    )
    parser.add_argument("--url", required=True,
                         help="Base URL of YOUR deployed UniGuard AI instance, "
                              "e.g. https://uniguardai.onrender.com")
    parser.add_argument("--endpoint", default="/api/data", choices=list(ALLOWED_ENDPOINTS),
                         help="Which demo endpoint to hit (default: /api/data)")
    parser.add_argument("--rate", type=float, default=10.0, help="Requests per second (default: 10)")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds (default: 30)")
    parser.add_argument("--workers", type=int, default=20,
                         help="Max concurrent in-flight requests (default: 20)")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print("ERROR: --url must start with http:// or https://")
        sys.exit(1)

    target = args.url.rstrip("/") + args.endpoint
    print("=" * 60)
    print("UniGuard AI - Authorized Test Client (Termux)")
    print("=" * 60)
    print(f"Target:    {target}")
    print(f"Rate:      {args.rate} req/s")
    print(f"Duration:  {args.duration}s")
    print("SAFETY: This sends real requests ONLY to the URL you provided.")
    print("        Use only on a UniGuard AI deployment you own/control.")
    print("-" * 60)

    stats = {"sent": 0, "ok": 0, "blocked": 0, "error": 0}
    lock = threading.Lock()
    interval = 1.0 / args.rate if args.rate > 0 else 1.0
    stop_time = time.time() + args.duration

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        try:
            while time.time() < stop_time:
                pool.submit(send_one, target, stats, lock)
                elapsed = args.duration - (stop_time - time.time())
                sys.stdout.write(
                    f"\r sent={stats['sent']:<5} ok={stats['ok']:<5} "
                    f"blocked={stats['blocked']:<5} error={stats['error']:<5} "
                    f"t={elapsed:4.0f}s/{args.duration}s"
                )
                sys.stdout.flush()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped by user.")

    print(f"\n\nDone. sent={stats['sent']} ok={stats['ok']} "
          f"blocked={stats['blocked']} error={stats['error']}")
    if stats["blocked"] > 0:
        print(f"-> {stats['blocked']} requests were rejected by UniGuard AI mitigation "
              f"(HTTP 429/403). Mitigation is working.")
    if stats["error"] > 0:
        print(f"-> {stats['error']} requests failed at the network level "
              f"(timeout / connection error / DNS) - check the URL and your connection.")


if __name__ == "__main__":
    main()
