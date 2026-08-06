# Release 0.4.18 — checklist dla Bogumiła (agent nie może publikować)

Zawartość release'u: T5 (PyPI listing jako landing) + T6 (CLI Solo nudge) +
T7 (pack hint). Wersja i CHANGELOG już podbite w PR #26.

## Przed publikacją

> **UWAGA (2026-07-23):** PR #27 niesie niewydany kod 0.4.19 (pack hint v2).
> 0.4.18 buduj z mastera SPRZED merge'a PR #27 — commit `8ce3592` (merge
> PR #26). Jeśli PR #27 już zmergowany: `git checkout 8ce3592` przed buildem.
> Kolejność całości: `ops/launch/OWNER_RUNBOOK.md`.

- [x] Merge PR #26 do master (zmergowany 2026-07-22 21:53, commit `8ce3592`).
- [ ] Lokalnie z master: `python -m pytest -q` — pełny suite zielony
      (release-gate z FACTS.md F3; przy okazji re-pin F3 na nowy wynik).
- [ ] `python -m gatecat.integrations.bypass_suite` — re-pin F4 jeśli liczby
      się zmieniły (nie powinny: zero zmian w policy/recall/bypass).

## Publikacja

- [ ] `python -m build` + `twine upload` (albo Twój dotychczasowy flow).
- [ ] GitHub release v0.4.18 (tag na commicie merge'a).
- [ ] Clean install check: `pip install --no-cache-dir gate-cat==0.4.18`
      → `gate.cat --help` działa; F9 w FACTS.md re-pin na 0.4.18.
- [ ] KOLEJNOŚĆ: najpierw publish na PyPI, DOPIERO POTEM deploy docs/ na VPS —
      llms.txt w tym release reklamuje 0.4.18, nie może wyprzedzić PyPI.

## Publication gate (z docs/LAUNCH_0.4.16.md — nadal obowiązuje)

- [ ] gate.cat serwuje aktualny landing (teams/partners live — zweryfikowane
      2026-07-22) i dwustopniowy installer.
- [ ] Public PyPI clean install zwraca 0.4.18.
- [ ] `curl https://gate.cat/cloud/health` → 200.
- [ ] Stripe live-mode webhook aktywny (checkout completion, subscription
      updates, cancellation).
- [ ] Każdy live post URL dopisany do issue #9 (timestamp + owner).

## Po publikacji

- [ ] Post Show HN (`ops/launch/show_hn_ready.md`) — jeśli jeszcze nie wisi;
      stary post z 2026-07-15 miał 2 punkty, repost innego tytułu jest OK.
- [ ] METRICS.log: obserwuj pypi_downloads przez 3 dni (Action robi to sam).
