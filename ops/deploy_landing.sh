#!/usr/bin/env bash
# Deploy the static site (docs/) to the VPS and verify the funnel pages the
# 0.4.17 post-veto nudge points at. Run from the repo root, on a machine that
# holds the VPS key (the sandboxed agent does NOT — this script is for the
# owner; see docs/AUTOPILOT-LOOP.md USER-2).
#
#   ops/deploy_landing.sh            # deploy docs/ + verify + restart fulfill
#   DRY_RUN=1 ops/deploy_landing.sh  # print what would happen
#
# Conventions match scripts/launch_metrics.py.
set -euo pipefail

VPS="${VPS:-root@204.168.129.200}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/vps/id_ed25519}"
DOCROOT="${DOCROOT:-/opt/bgml/static/gatecat}"
SITE_DIR="$(cd "$(dirname "$0")/.." && pwd)/docs"
PAGES=(teams.html partners.html packs.html sitemap.xml)
SSH=(ssh -i "$SSH_KEY" -o ConnectTimeout=8 "$VPS")

run() { if [ "${DRY_RUN:-0}" = "1" ]; then echo "DRY: $*"; else "$@"; fi }

echo "== 1/4 rsync docs/ -> $VPS:$DOCROOT"
# --delete is deliberately NOT used: the docroot also serves files that do not
# live in docs/ (e.g. veto-demo.html from site/). Additive deploy only.
# Excludes (W1, 2026-07-23): internal loop state, launch kits and research
# dossiers must NEVER reach the public docroot — AUTOPILOT-LOOP.md was found
# LIVE (HTTP 200) with third-party contact data and full internal strategy.
run rsync -av \
  --exclude 'AUTOPILOT-LOOP.md' \
  --exclude 'LAUNCH_KIT_2026-07-14.md' \
  --exclude 'LAUNCH_0.4.16.md' \
  --exclude 'research/' \
  -e "ssh -i $SSH_KEY -o ConnectTimeout=8" "$SITE_DIR/" "$VPS:$DOCROOT/"

echo "== 2/4 sha256 verify the funnel pages"
for f in "${PAGES[@]}"; do
  local_sum=$(sha256sum "$SITE_DIR/$f" | cut -d' ' -f1)
  if [ "${DRY_RUN:-0}" = "1" ]; then echo "DRY: verify $f ($local_sum)"; continue; fi
  remote_sum=$("${SSH[@]}" "sha256sum $DOCROOT/$f" | cut -d' ' -f1)
  if [ "$local_sum" != "$remote_sum" ]; then
    echo "MISMATCH on $f: local=$local_sum remote=$remote_sum" >&2; exit 1
  fi
  echo "ok  $f  $local_sum"
done

echo "== 3/4 live 200 check (the nudge in 0.4.17 hits these URLs)"
for url in https://gate.cat/teams.html https://gate.cat/partners.html https://gate.cat/packs.html; do
  if [ "${DRY_RUN:-0}" = "1" ]; then echo "DRY: curl $url"; continue; fi
  code=$(curl -s -o /dev/null -w '%{http_code}' "$url")
  echo "$code  $url"
  [ "$code" = "200" ] || { echo "FAIL: $url returned $code" >&2; exit 1; }
done

echo "== 4/4 restart pack fulfillment (port 8791) so template changes load"
run "${SSH[@]}" "systemctl restart gatecat-fulfill && systemctl is-active gatecat-fulfill"

echo
echo "Done. Post-deploy checklist (from docs/LAUNCH_0.4.16.md): smoke-test a"
echo "pack checkout link, confirm /cloud/health returns ok, and spot-check"
echo "https://gate.cat/ renders after the cache-control revalidation."
