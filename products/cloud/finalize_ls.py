#!/usr/bin/env python3
"""Finalize Lemon Squeezy wiring once the 3 subscription products exist.

Reads the LS API key from the vault, lists products+variants, maps
Solo/Team/Business -> variant id (by product name, price sanity-check),
and writes LEMONSQUEEZY_VARIANT_{SOLO,TEAM,BUSINESS} into the vault. Also
prints the env block to paste into the VPS deploy. Read-only against LS
(GET only) apart from writing the local vault file. Never prints the API key.

Run:  python3 finalize_ls.py
"""
import json, os, urllib.request, urllib.error

VAULT = "/home/bgml/bogum-backup/.env.lemonsqueezy"
EXPECT = {"solo": 1900, "team": 14900, "business": 39900}  # EUR cents


def vault():
    d = {}
    for l in open(VAULT).read().splitlines():
        if "=" in l and not l.startswith("#"):
            k, v = l.split("=", 1)
            d[k] = v
    return d


def get(path, key):
    req = urllib.request.Request(
        "https://api.lemonsqueezy.com/v1/" + path,
        headers={"Authorization": "Bearer " + key, "Accept": "application/vnd.api+json"},
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.load(r)


def main():
    env = vault()
    key = env.get("LEMONSQUEEZY_API_KEY")
    store = env.get("LEMONSQUEEZY_STORE_ID", "429443")
    if not key:
        print("BRAK LEMONSQUEEZY_API_KEY w vault:", VAULT); return 1

    prods = {p["id"]: p["attributes"].get("name", "") for p in get(f"products?filter[store_id]={store}&page[size]=100", key)["data"]}
    variants = get("variants?page[size]=100", key)["data"]
    if not variants:
        print("Wariantów 0 — najpierw utwórz 3 produkty w panelu LS (Solo €19 / Team €149 / Business €399).")
        return 2

    tiers = {}
    print("Znalezione warianty:")
    for v in variants:
        a = v["attributes"]
        pid = str(a.get("product_id") or (v.get("relationships", {}).get("product", {}).get("data", {}) or {}).get("id"))
        pname = prods.get(pid, "")
        price = a.get("price")
        label = (pname + " " + a.get("name", "")).lower()
        print(f"  variant_id={v['id']} product={pname!r} variant={a.get('name')!r} price={price} interval={a.get('interval')}")
        for tier in ("business", "team", "solo"):  # business before team so 'team' substring doesn't shadow
            if tier in label or price == EXPECT[tier]:
                tiers.setdefault(tier, v["id"])
                break

    print("\nMapowanie tier -> variant_id:", tiers)
    missing = [t for t in EXPECT if t not in tiers]
    if missing:
        print("⚠️ Nie zmapowano:", missing, "— sprawdź nazwy produktów (mają zawierać Solo/Team/Business) lub ceny.")

    lines = [l for l in open(VAULT).read().splitlines()
             if not l.startswith(("LEMONSQUEEZY_VARIANT_SOLO=", "LEMONSQUEEZY_VARIANT_TEAM=", "LEMONSQUEEZY_VARIANT_BUSINESS="))]
    for tier, vid in tiers.items():
        lines.append(f"LEMONSQUEEZY_VARIANT_{tier.upper()}={vid}")
    open(VAULT, "w").write("\n".join(lines) + "\n")
    os.chmod(VAULT, 0o600)
    print(f"\n✅ Zapisano LEMONSQUEEZY_VARIANT_* do {VAULT}")

    print("\n--- ENV BLOCK do deployu na VPS (systemd env / .env cloud-activate) ---")
    print(f"GATECAT_PAYMENT_CHANNEL=lemonsqueezy")
    print(f"LEMONSQUEEZY_WEBHOOK_SECRET={env.get('LEMONSQUEEZY_WEBHOOK_SECRET','<w vault>')}")
    for tier in ("solo", "team", "business"):
        print(f"LEMONSQUEEZY_VARIANT_{tier.upper()}={tiers.get(tier,'?')}")
    return 0 if not missing else 3


if __name__ == "__main__":
    raise SystemExit(main())
