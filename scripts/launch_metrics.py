#!/usr/bin/env python3
"""gate.cat launch metrics — PyPI downloads + REAL paying customers vs target.

Goal (2026-07-15): 4000 downloads + 10 paying customers.

Paying customers are counted from the Lemon Squeezy activation path
(`/opt/bgml/gatecat-cloud/accounts.jsonl`), NOT Stripe — the landing checkout
is Lemon Squeezy. Internal e2e/wire/debug test accounts are filtered out.
"""
import json, subprocess, datetime, os

TARGET_DOWNLOADS = 4000
TARGET_CUSTOMERS = 10
VPS = "root@204.168.129.200"
SSH_KEY = os.path.expanduser("~/.ssh/vps/id_ed25519")


def pypi_downloads():
    """PyPI recent downloads (1h cache to dodge 429). Package normalizes to gate-cat."""
    import time, pathlib, urllib.request
    cache = pathlib.Path("/tmp/gatecat_pypi_cache.json")
    if cache.exists() and time.time() - cache.stat().st_mtime < 3600:
        return json.loads(cache.read_text())
    try:
        url = "https://pypistats.org/api/packages/gate-cat/recent"
        req = urllib.request.Request(url, headers={"User-Agent": "gatecat-launch-metrics"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read())["data"]
            cache.write_text(json.dumps(d))
            return d
    except Exception as e:
        if cache.exists():
            return json.loads(cache.read_text())
        return {"error": str(e)}


def paid_customers():
    """REAL paying customers = provisioned accounts in accounts.jsonl minus the
    internal test accounts (e2e/wire/dbg/ship-retry/etc). Lemon Squeezy path."""
    remote = (
        "python3 - <<'EOF'\n"
        "import json, re\n"
        "test = re.compile(r'e2e|wire|test|dbg|debug|ship-retry|ts-bug|final-ship|cf-|reporter|retry|@test', re.I)\n"
        "real = 0; total = 0; tiers = {}\n"
        "try:\n"
        "    for line in open('/opt/bgml/gatecat-cloud/accounts.jsonl'):\n"
        "        line = line.strip()\n"
        "        if not line:\n"
        "            continue\n"
        "        total += 1\n"
        "        d = json.loads(line)\n"
        "        acct = str(d.get('account', ''))\n"
        "        if not test.search(acct):\n"
        "            real += 1\n"
        "            t = d.get('tier', '?')\n"
        "            tiers[t] = tiers.get(t, 0) + 1\n"
        "except FileNotFoundError:\n"
        "    pass\n"
        "print(json.dumps({'real_customers': real, 'total_accounts': total, 'by_tier': tiers}))\n"
        "EOF"
    )
    try:
        cmd = ["ssh", "-i", SSH_KEY, "-o", "ConnectTimeout=8", VPS, remote]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = r.stdout.strip().splitlines()
        return json.loads(out[-1]) if out else {"error": "no output"}
    except Exception as e:
        return {"error": str(e)}


def real_funnel():
    """REAL human funnel from the nginx events log (JS-fired events = humans with a
    browser), NOT bot-inflated PyPI. Counts page_view / install_copy / checkout_click."""
    remote = (
        "L=/var/log/nginx/gate.cat.events.log; "
        "if [ -f \"$L\" ]; then "
        "for e in page_view install_copy checkout_click pypi_click github_click; do "
        "n=$(grep -oE \"e=$e\\b\" \"$L\" 2>/dev/null | wc -l); echo \"$e=$n\"; done; "
        "else echo 'no_events_log'; fi"
    )
    try:
        cmd = ["ssh", "-i", SSH_KEY, "-o", "ConnectTimeout=8", VPS, remote]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = {}
        for line in r.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = int(v) if v.isdigit() else v
        return out
    except Exception as e:
        return {"error": str(e)}


def disk_check():
    try:
        cmd = ["ssh", "-i", SSH_KEY, "-o", "ConnectTimeout=5", VPS, "df -h / | tail -1"]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return "unavailable"


def main():
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    print(f"=== gate.cat LAUNCH METRICS - {now} ===")
    print(f"    goal: {TARGET_DOWNLOADS} downloads + {TARGET_CUSTOMERS} paying customers\n")

    dl = pypi_downloads()
    if "error" in dl:
        print(f"PyPI downloads: ERROR ({dl['error']})")
        month = 0
    else:
        month = dl.get("last_month", 0) or 0
        pct = month / TARGET_DOWNLOADS * 100 if month else 0
        print("PyPI downloads (recent):")
        print(f"  day={dl.get('last_day','?')}  week={dl.get('last_week','?')}  month={dl.get('last_month','?')}")
        print(f"  -> {month}/{TARGET_DOWNLOADS} ({pct:.0f}% of goal)\n")

    pc = paid_customers()
    if "error" in pc:
        print(f"Paying customers: ERROR ({pc['error']})")
        real = 0
    else:
        real = pc.get("real_customers", 0)
        print("Paying customers (Lemon Squeezy activations, test accounts excluded):")
        print(f"  real={real}  (total account rows incl. test={pc.get('total_accounts','?')}, by_tier={pc.get('by_tier',{})})")
        print(f"  -> {real}/{TARGET_CUSTOMERS} paying\n")

    rf = real_funnel()
    if "error" not in rf and "no_events_log" not in rf:
        print("REAL human funnel (nginx events, NOT bot PyPI):")
        print(f"  page_views={rf.get('page_view','?')}  install_copy={rf.get('install_copy','?')}  "
              f"checkout_click={rf.get('checkout_click','?')}  pypi_click={rf.get('pypi_click','?')}  "
              f"github_click={rf.get('github_click','?')}")
        print(f"  ^ THIS is real traction; PyPI 'downloads' above are bot/mirror/CI inflated.\n")
    else:
        print(f"REAL funnel: {rf}\n")

    print(f"VPS disk: {disk_check()}\n")

    log_path = os.path.expanduser("~/gate.cat/docs/launch_metrics.log")
    with open(log_path, "a") as f:
        f.write(f"[{now}] downloads={month}/{TARGET_DOWNLOADS} customers={real}/{TARGET_CUSTOMERS}\n")
    print(f"Logged to {log_path}")


if __name__ == "__main__":
    main()
