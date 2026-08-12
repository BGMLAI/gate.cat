# HANDOFF 2026-08-12 — release 0.4.19 PRZERWANY na release-gate (12 failed)

Sesja: fable-gatecat (powrót po przerwie 31.07→12.08). User przerwał: „kończymy, rób handoff".
**Release 0.4.19 NIE został opublikowany. Tag nie istnieje, PyPI bez zmian (latest = 0.4.18).**

## Co jest ZROBIONE (zweryfikowane)

1. **PR #30 MERGED do master** (`59be75b`, 2026-08-12 10:26Z) — fix driftu
   `gatecat.__version__` 0.4.17 → 0.4.18 (FACTS F9). 11 testów wersji pass przed merge.
2. **Gałąź `release/0.4.19`** (wypchnięta, NIE zmergowana) — bump 0.4.18 → 0.4.19 w:
   `pyproject.toml`, `gatecat/__init__.py` (`__version__`), nowa sekcja w `CHANGELOG.md`.
3. **Audyt po przerwie** (szczegóły: issue #9, komentarz 2026-08-12): skrzynka bez maili
   gate.cat (skan 773 od 24.07); wątki zewnętrzne pozamykane same; 3 awesome-listy MERGED;
   CI master zielony; czysta instalacja z PyPI = 0.4.18, 71/73 polityk — działa.

## Dlaczego przerwano publikację: release gate F3 = 12 failed / 1933 passed (Windows, 213 s)

```
tests/integrations/test_gatecat_shell.py — 9 testów (allow_benign_execs_real_shell,
  exit_code, lc_combined_flags, positional_args, warn_class, shadow_mode,
  install_bash_emits_trap, script_file_passthrough, dash_s_benign_stream)
tests/integrations/test_repro_autogen_7770.py::test_repro_runs_and_blocks_the_incident_action
tests/test_cloud_e2ee.py::test_key_is_32_bytes_and_stable
tests/test_marketing_consistency.py::test_llms_txt_tracks_current_package_and_offer
```

**Hipotezy (NIEZWERYFIKOWANE — do potwierdzenia przed publikacją):**
- 9× `test_gatecat_shell` + repro_autogen: integracyjne, odpalają realny shell — F3 zawsze
  było mierzone na `.venv/bin/python` (Linux). Prawdopodobnie środowiskowe (Windows), nie
  regresja. **Dowód wymagany: pełny `pytest -q` na Linuksie (VPS/WSL/CI).**
- `test_llms_txt_tracks_current_package_and_offer`: najpewniej REALNY fail wywołany bumpem —
  `docs/llms.txt` (albo site) nadal mówi 0.4.18. Naprawić treść llms.txt w ramach release PR.
- `test_cloud_e2ee` key stable: nieznane, możliwe env (brak klucza na tej maszynie). Sprawdzić.

## Następne kroki (kolejność z ops/launch/release_0.4.18_checklist.md — analogicznie dla 0.4.19)

1. Na gałęzi `release/0.4.19`: naprawić llms.txt (i ewent. inne odwołania do 0.4.18 w site/docs);
   sprawdzić `test_cloud_e2ee` lokalnie na Linuksie.
2. Pełny suite na Linuksie zielony → PR do master → CI zielony → merge.
3. `python -m build` + `twine upload` (flow Bogumiła — checklist 0.4.18 zastrzegał publikację
   dla właściciela), tag `v0.4.19` na commicie merge, GitHub release.
4. Clean install check `pip install --no-cache-dir gate-cat==0.4.19`; re-pin FACTS F9 + F3
   (+F4 bypass_suite — NIE uruchomiono w tej sesji).
5. KOLEJNOŚĆ z checklisty: najpierw PyPI, POTEM deploy docs/ na VPS (llms.txt nie może
   wyprzedzić PyPI).

## BLIND / nie ruszone

- bypass_suite (F4) nie uruchomiony.
- pypistats 429 (rate limit) — F13a nie re-pinowany; METRICS.log ostatni odczyt 1319 (2026-08-09).
- Spam/foldery poza INBOX nie skanowane; skrzynka po 12.08 rano nie sprawdzana ponownie.
- VPS: stan gatecat-cloud nie weryfikowany w tej sesji (`/cloud/health` nie odpytany).
