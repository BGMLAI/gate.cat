# OWNER RUNBOOK — 20 minut do odblokowania

Jeden przebieg, zero decyzji: każdy krok to jedna komenda albo jeden paste.
Kolejność jest twarda (publish PyPI **przed** deployem docs/ — llms.txt w tym
release reklamuje 0.4.18 i nie może wyprzedzić PyPI). Kroki 1–3 wykonaj razem;
4–6 mogą pójść tego samego dnia albo następnego — ale 4 (HN) najlepiej PO 2,
żeby packs.html i sitemap były już live, kiedy przyjdzie ruch.

Stan wykonania odnotuj w `docs/AUTOPILOT-LOOP.md` (sekcja [USER] v2 wskazuje
na ten plik) — pętla sama zauważy publish/deploy przy następnym przebiegu.

---

## 0. Prereq (1 min) — merge PR pętli

Merge **PR #27** (draft → ready → merge; CI musi być zielone na ostatnim
commicie). Bez tego deploy w kroku 2 nie ma packs.html w docs/.

## 1. Publish 0.4.18 na PyPI (5 min)

Z katalogu repo, na masterze po merge (pełne gates i re-piny FACTS:
[`release_0.4.18_checklist.md`](release_0.4.18_checklist.md)):

```bash
git checkout master && git pull
python -m pytest -q                      # release-gate: musi być zielony
python -m build && twine upload dist/*
pip install --no-cache-dir gate-cat==0.4.18 && gate.cat --help
```

Potem GitHub release `v0.4.18` (tag na commicie merge'a).

## 2. Deploy docs/ na VPS (3 min)

Z maszyny z kluczem VPS, z katalogu repo:

```bash
ops/deploy_landing.sh
```

Skrypt sam robi rsync (additive), weryfikuje sha256 + HTTP 200 na
teams/partners/**packs** i restartuje fulfillment (port 8791).

## 3. Snapshot funnela — jeden paste, wynik na czat (2 min)

```bash
ssh -i ~/.ssh/vps/id_ed25519 root@204.168.129.200 \
    'cat /var/log/nginx/gatecat-events.log' \
  | python3 scripts/daily_funnel.py - --date "$(date -u +%F)"
```

Wklej JSON-linię na czat sesji pętli. To tani test hipotezy packs:
czy ktokolwiek klika `checkout_click` i z jakiego `source`.

## 4. Show HN (3 min)

Tytuł + tekst + plan pierwszego komentarza: gotowe do wklejenia w
[`show_hn_ready.md`](show_hn_ready.md). Po publikacji dopisz live URL
do issue #9 (timestamp + owner).

## 5. Dystrybucja: Reddit / X / awesome-PRs (4 min)

Posty w kolejności z pliku (NIE wszystko naraz):
[`distribution_kit_2026-07-22.md`](distribution_kit_2026-07-22.md).
Każdy live URL → issue #9.

## 6. Batch kampanii affiliate — ≤15/dzień (2 min na setup)

Szablony per tier (YouTube / newsletter / mega-kanał) dostarczone na czacie
sesji 2026-07-22 (T14); lista 27 celów w pliku dostarczonym poza repo
(zasada: żadnych adresów osób trzecich w publicznym repo). Po **każdej**
wysyłce dopisz wiersz adresat+data do LEDGER w `docs/AUTOPILOT-LOOP.md` —
od tej daty liczą się follow-upy day-3/day-7 (U8). Wysłane dotąd: 1/27.

---

**Suma: ~20 min.** Jeśli coś się wywali (mismatch sha256, brak 200, failed
twine): przerwij i wrzuć błąd na czat sesji pętli — agent zdiagnozuje przy
najbliższym przebiegu, nic nie forsuj ręcznie.
