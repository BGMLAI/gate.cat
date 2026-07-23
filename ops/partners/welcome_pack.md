# Partner welcome pack — odpowiedź na pierwsze mailto z partners.html w minutę

**Cel:** partners.html (LIVE) kończy się na mailto. Gdy przyjdzie pierwszy
mail od twórcy, NIE komponujemy odpowiedzi od zera — wklejamy stąd.
Onboarding do produkcyjnej bazy i wysyłka maila = **wyłącznie [USER]**.

Mechanika (źródło prawdy: `products/cloud/affiliate.py` + skrypt
`gc-affiliate-ref` na stronach): link `gate.cat/?ref=CODE` → cookie
`gc_ref` (90 dni, SameSite=Lax) → każdy checkout Stripe niesie
`client_reference_id=CODE` → webhook przypina subskrypcję do kodu na ZAWSZE
(`subscription_id → ref`), więc prowizja jest lifetime-recurring; refund =
ujemna prowizja (clawback), ledger zawsze nettuje. Stawka: **30% każdej
płatności** (RATE=0.30) — i to KAŻDEJ płatnej: subskrypcje Cloud
(Solo/Team/Business) akruują od każdego odnowienia, a one-time packi €29
akruują jednorazowo (kod: "any paid entitlement counts";
test_thirty_percent_accrual_one_time_pack to asertuje). [KOREKTA 2026-07-23,
przebieg #27 — wcześniejsza wersja tego pliku twierdziła odwrotnie.]

---

## 1. Welcome mail (EN, paste-ready)

Subject: `your gate.cat partner link — CODE inside`

> Hey NAME,
>
> Welcome aboard — here's everything, short:
>
> **Your link:** `https://gate.cat/?ref=CODE`
> It sets a 90-day cookie; any paid Cloud plan started from it (Solo EUR
> 19/mo, Team EUR 149/mo flat, Business EUR 399/mo) pays you **30% of every
> payment, for the lifetime of the subscription** — not just the first
> invoice. One-time EUR 29 policy packs earn the same 30% (once, at purchase).
>
> **Honest mechanics, so there are no surprises:**
> - Attribution rides Stripe's `client_reference_id`, pinned to the
>   subscription forever — renewals keep paying you even if the cookie dies.
> - Refunds claw back the matching commission (we run a 30-day no-questions
>   refund, so the ledger nets out truthfully).
> - Payouts are manual for now (solo founder): monthly, after the refund
>   window on the underlying payment clears. You'll get the per-code ledger
>   on request, any time.
>
> **One requirement:** disclose the affiliate relationship wherever you use
> the link (description line like "affiliate link — I earn a commission" is
> enough). The core tool is free forever and open source (Apache-2.0), so
> you're recommending real value either way — that's the whole point.
>
> **What you can honestly say** (every number is pinned in
> https://github.com/BGMLAI/gate.cat/blob/master/FACTS.md):
> - blocks an AI coding agent's catastrophic shell commands BEFORE they run;
>   deterministic, no model call in the veto path
> - 0 real recall misses across 1,085,159 unique real agent commands through
>   the full gate
> - the reproducible bypass suite catches 178/178 danger shapes it claims —
>   and prints its own edges (one named gap, one benign false-block in 129)
> - 71 default policy walls in the free core; 0.4.18 installable from PyPI
> - please DON'T say "100% safe" / "unbypassable" — we publish our gaps
>
> Assets: 30-sec demo https://gate.cat/veto-demo.html · what's in the paid
> packs https://gate.cat/packs.html · team page https://gate.cat/teams.html
>
> Reply with the name/handle you want on the ledger and you're live.
> — Bogumił

## 2. Warianty kodu (sanitizer: `[A-Za-z0-9_.-]`, max 120 znaków)

| Typ twórcy | Format kodu | Przykład |
|---|---|---|
| kanał YouTube | `yt-<handle>` | `yt-aiprofitlab` |
| newsletter | `nl-<nazwa>` | `nl-agentweekly` |
| kurs / edukator | `edu-<nazwa>` | `edu-shipfast` |

Zasada: kod czytelny na głos (twórca dyktuje go w wideo), bez wielkich
liter (mniej literówek), unikalny per KANAŁ, nie per osoba.

## 3. Onboarding — komendy [USER] (na VPS, gdzie żyje produkcyjna baza)

```bash
ssh -i ~/.ssh/vps/id_ed25519 root@204.168.129.200
cd /opt/bgml/gatecat-cloud   # katalog z affiliate.py + bazą
python -m affiliate add-affiliate CODE "Imię/Kanał" email@twórcy
# wypisze: added affiliate: CODE  link: gate.cat/?ref=CODE
python -m affiliate ledger   # per-code net owed (JSON) — do wypłat i na życzenie partnera
```

Po onboardingu: wiersz do LEDGER w docs/AUTOPILOT-LOOP.md (kod, kanał,
data), żeby pętla pilnowała follow-upów i wypłat.

## 4. Czego NIE obiecujemy (dopóki nieprawdziwe)

- Żadnych "typowych zarobków" ani projekcji — zero danych (revenue day-zero,
  mówimy to wprost jak w wątku Return on Security).
- Żadnego dashboardu partnera "wkrótce" — jest ledger na życzenie, tyle.
- Żadnej ekskluzywności kategorii/regionu.
