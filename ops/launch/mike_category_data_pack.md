# Mike Privette (Return on Security) — category data pack

**Cel:** kiedy Mike odpowie na mail z 2026-07-22 17:11 (wątek
`19f669c061fe1503`), odpowiedź składamy w MINUTY, nie godziny — wszystko
obiecane w tamtym mailu jest tu, paste-ready. **Gmail draft powstaje DOPIERO
po jego odpowiedzi** (reguła dedupe #7 pętli); ten plik to amunicja, nie
wiadomość.

Kontekst: Mike nazywa kategorię **"Agent Runtime Security"** i mapuje firmy
w niej. Obiecaliśmy mu: (1) surowe dane za każdą liczbą, (2) redacted sample
raportu z własnego dogfood logu, (3) notatki porównawcze o sąsiednich
narzędziach.

**Zasady twarde tego pakietu** (fix sędziów panelu v2): zero twierdzeń o
konkurentach poza tym, co już stoi w publicznym COMPARISON.md; zero nazwisk
osób trzecich; incydenty WYŁĄCZNIE po numerach issue (np.
`microsoft/autogen#7770`). Liczby WYŁĄCZNIE z FACTS.md (stan po re-pinie U5,
2026-07-23).

---

## 1. Manifest assetów (linki wklejalne do maila)

| Obiecane | Asset | Link |
|---|---|---|
| "raw data behind any number above" | wyniki miliona komend (JSON) | https://github.com/BGMLAI/gate.cat/blob/master/results/million_recall_2026-07-08.json |
| — metoda + adjudykacja 4 allows | RECALL.md | https://github.com/BGMLAI/gate.cat/blob/master/RECALL.md |
| — rejestr wszystkich liczb | FACTS.md (claim → źródło → dozwolone brzmienie) | https://github.com/BGMLAI/gate.cat/blob/master/FACTS.md |
| "redacted sample of the monthly report" | SAMPLE_REPORT.md (z własnego dogfood logu, kawety red-team w środku) | https://github.com/BGMLAI/gate.cat/blob/master/docs/SAMPLE_REPORT.md |
| "comparison notes we keep on adjacent tools" | COMPARISON.md (public, uczciwe pozycjonowanie vs LangGraph `interrupt`, HumanLayer, Lakera, Guardrails AI — tylko to, co już publiczne) | https://github.com/BGMLAI/gate.cat/blob/master/COMPARISON.md |
| samodzielna reprodukcja | `pip install gate-cat && python -m gatecat.integrations.bypass_suite` | (komenda w treści) |

## 2. Liczby — dozwolone brzmienia (FACTS.md po U5, nie parafrazować)

- **F1b:** "0 real recall misses across 1.085M unique real agent commands
  through the full gate (the 4 catalog-flagged allows are disposable-artifact
  cleanups the gate correctly permits — same shape blocks on a real target)"
- **F4:** "the reproducible bypass suite catches 178/178 danger shapes it
  claims, with one published runtime-assembly gap and one benign false-block
  in 129 cases"
- **F13 (świeży pin 2026-07-23):** "2,529 PyPI downloads excluding known
  mirrors across the full daily series through 2026-07-22"
- **F9:** "0.4.17 is installable from PyPI and pinned by GitHub release
  v0.4.17"
- **F10:** 71 default policy walls / 73 presets.
- Incydent kosztowy: runaway loop `microsoft/autogen#7770` (~$106k;
  reprodukcja jako block-verdict: `examples/veto_integrations/repro_autogen_7770.py`).

**Nota korekcyjna (podać tylko gdy poprosi o dane):** mail 07-22 podawał
"2,528 trailing month" z żywego pypistats; świeży pin metodą pełnej serii
dziennej to 2,529 (07-03→07-22). Różnica kosmetyczna, metoda odnotowana w F13.

## 3. Szkielety odpowiedzi — 3 gałęzie

### A) Poprosi o dane / drąży liczby

> Here's everything, self-contained:
>
> - Raw results for the 1,085,159-command replay: [million_recall JSON] —
>   method and the adjudication of the 4 catalog-flagged allows in
>   [RECALL.md]. Headline, stated precisely: 0 real recall misses across
>   1.085M unique real agent commands through the full gate; the 4 allows are
>   disposable-artifact cleanups the gate correctly permits.
> - Every public number we use, with source artifact and allowed wording:
>   [FACTS.md]. Fresh pin as of Jul 23: 2,529 PyPI downloads excluding known
>   mirrors across the full daily series (the Jul 22 mail said 2,528 from a
>   live read — same curve, method now pinned in the register).
> - Reproduce the bypass numbers yourself, no datasets:
>   `pip install gate-cat && python -m gatecat.integrations.bypass_suite`
>   — prints 178/178 caught plus its own edges: one named runtime-assembly
>   gap and one benign false-block in 129 cases. We publish the gaps louder
>   than our critics do.
>
> If any number doesn't reproduce on your end, that's a bug report I want.

### B) Zaproponuje mention w newsletterze

> That'd be great — two asks to keep it honest:
>
> 1. If you cite numbers, these are the exact wordings the evidence supports:
>    [wklej z sekcji 2 — F1b i F4 zawsze z kawetami; nigdy "100% safe"].
> 2. Please keep the limit in: it's a deterministic wall in front of
>    known-dangerous shapes, not a proof of safety — the bypass suite prints
>    its own gaps.
>
> Assets if useful: 30-sec demo https://gate.cat/veto-demo.html · redacted
> sample report [SAMPLE_REPORT.md] · category-relevant detail: the free core
> (Apache-2.0) deliberately carries everything safety-critical; the paid
> layer (EUR 19/149/399) is the off-machine, append-only veto history — the
> log the agent can't rewrite.

### C) Zaproponuje wspólny content / dane do mapy kategorii

> Happy to. The dataset I'd bring: 1,085,159 real agent commands (5 public
> datasets), replayed through the full 6-stage gate, with a 43-class danger
> catalog and per-class verdicts — plus the honest economics: intervention
> rate ~0.6% on real traffic, and the incident class that anchors pricing
> (runaway loop microsoft/autogen#7770, ~$106k).
>
> Angle that fits Return on Security: "what a million real agent commands
> say about where the Agent Runtime Security budget actually goes" — every
> number reproducible from the public repo, method in RECALL.md. I'll draft;
> you edit ruthlessly.

## 4. Czego NIE robimy (żeby nie spalić wątku)

- Nie wysyłamy follow-upu zanim Mike nie odpowie (day-3/day-7 dla tego wątku
  NIE obowiązuje — on już odpowiedział raz i dostał odpowiedź; piłka u niego).
- Zero ocen firm z jego mapy — jeśli spyta o konkretną firmę: "we keep our
  comparison notes to what's public and verifiable — COMPARISON.md is the
  honest version" i tyle.
- Revenue: day-zero, mówimy wprost (już powiedzieliśmy w mailu 07-22 — nie
  wycofywać się z tego framingu).
