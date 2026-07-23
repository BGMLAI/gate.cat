# Release 0.4.19 — checklist (agent nie może publikować; Ty = 2 komendy)

Zawartość: `gate.cat setup claude-code` + `doctor` (W3), pack hint v2 →
packs.html (U3), fix desyncu `__version__` (0.4.18 drukował 0.4.17), sweep
konwersji W4 (nudge-veto tag, report-URL, tracking teams). Wersja podbita w
PIĘCIU miejscach (pyproject, `gatecat/__init__`, plugin.json,
marketplace.json, llms.txt) — pilnuje tego `tests/test_version_sync.py`.

## KOLEJNOŚĆ TWARDA (inna niż przy 0.4.18!)

1. **Merge PR #27** (CI zielone).
2. **Deploy docs/ NAJPIERW**: `ops/deploy_landing.sh` (+ jednorazowe `rm`
   z W1 w tym samym SSH — patrz OWNER_RUNBOOK krok 2). Powód kolejności:
   pack hint v2 i llms.txt w 0.4.19 linkują `gate.cat/packs.html`, które na
   produkcji jest dziś soft-404 — hinty nie mogą linkować w pustkę, więc
   strona idzie live PRZED wheelem, który ją reklamuje.
3. **Publish** (z mastera po merge — build i smoke są już zweryfikowane
   na branchu: twine check PASSED, czysty venv: `__version__==0.4.19`,
   entry-pointy gate.cat/gatecat-hook/gatecat-shell, hint→packs.html):

```bash
git checkout master && git pull
python -m pytest -q                      # release-gate
python -m build && twine upload dist/*
pip install --no-cache-dir gate-cat==0.4.19 && gate.cat doctor
```

4. **GitHub release v0.4.19** (tag na commicie merge'a; body z CHANGELOG
   sekcji [0.4.19]).
5. Po publikacji: re-pin FACTS F9 (0.4.19) i F3 (wynik release-gate) —
   zrobi to pętla przy następnym przebiegu, wystarczy że publish się wydarzy.

## Gates (bez zmian z 0.4.16/0.4.18)

- [ ] Pełny pytest zielony na masterze przed `twine upload`.
- [ ] `gate.cat doctor` z czystej instalacji pokazuje 0.4.19.
- [ ] `curl -s https://gate.cat/packs.html | grep -c 'id="fintech"'` ≥ 1
      (strona live PRZED publish — patrz kolejność).
- [ ] `curl https://gate.cat/cloud/health` → 200.
