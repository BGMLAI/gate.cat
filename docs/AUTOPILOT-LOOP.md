# AUTOPILOT-LOOP — gate.cat (cel: $2,000 USD)

Plik stanu autonomicznej pętli operacyjnej (cron co 1h, sesja Claude Code Remote,
branch `claude/email-cron-strategy-automation-drmkv4`). Agent czyta ten plik na
początku każdego przebiegu i aktualizuje go na końcu. Kolejność przebiegu:
**POCZTA → BACKLOG → (pusta kolejka? → nowy panel strategiczny) → ZAPIS.**

## ZASADY TWARDE

1. **Wysyłka maili** (dyspozycja Bogumiła 2026-07-22: agent MA wysyłać — stan
   faktyczny): konektor Gmail nie ma funkcji send, a klasyfikator uprawnień
   sesji zablokował zarówno dostęp do credentiali, jak i COMMIT pipeline'u
   wysyłkowego (ops/mail_sender) do repo. Kanał agenta = Gmail DRAFT
   (`create_draft` z `replyToMessageId`) + natychmiastowa flaga w [USER].
   Kod sendera (SMTP + allowlist + systemd timer) został dostarczony userowi
   bezpośrednio na czacie 2026-07-22 — jeśli user zainstaluje go na VPS i/lub
   doda regułę permissions w ustawieniach Claude Code, protokół przechodzi na
   outbox. Zawsze: tylko odpowiedzi w istniejących wątkach, nigdy cold-outreach.
2. **Outreach partnerski: tylko w trybie kampanii zleconej przez usera** (zlecenie
   2026-07-22): drafty do publicznych kontaktów biznesowych z zatwierdzonej listy,
   zawsze personalizowane, max 15/dzień; wysyłka po stronie usera/sesji lokalnej.
   Poza kampanią: drafty tylko w istniejących wątkach.
3. **Liczby publiczne wyłącznie z FACTS.md** — nowa liczba = najpierw wiersz
   w FACTS.md z artefaktem pomiaru. Żadnych zmyślonych metryk, opinii, klientów.
4. **Zero wydawania pieniędzy** — żadnych zmian w Stripe (ceny/produkty), żadnych
   sponsoringów, żadnych zakupów. Decyzje finansowe → sekcja [USER].
5. **Zero publikacji** — PyPI publish, deploy na VPS, posty na HN/socialach robi
   tylko Bogumił; agent przygotowuje paste-ready artefakty w `ops/launch/`.
6. **Git**: commit + `git push -u origin claude/email-cron-strategy-automation-drmkv4`
   (retry 2s/4s/8s/16s), nigdy na master. **BIEŻĄCY PR PĘTLI: #27** (PR #26 zmergowany
   2026-07-22 21:53 — wszelkie "#26" w promptcie crona czytaj jako "#27"). Po każdym
   merge'u PR-a pętli: restart brancha od origin/master (`git checkout -B ... origin/master`,
   force-with-lease) i NOWY draft PR przy pierwszym pushu; zaktualizuj ten wpis.
7. **Dedupe draftów**: przed `create_draft` sprawdź `list_drafts` + ledger niżej
   + czy w wątku nie ma już naszej odpowiedzi po ostatniej wiadomości rozmówcy.
8. **Kod = testy zielone** (`python -m pytest -q` dla dotkniętych ścieżek);
   copy = spójne z FACTS.md. SPRZEDAŻ > kosmetyka.
9. **Repo jest PUBLICZNE** — żadnych prywatnych adresów e-mail osób trzecich,
   treści korespondencji ani artefaktów imiennego outreachu w commitach
   (dotyczy też T13/dm_dimitrios: dostarczać przez czat/SendUserFile, nie repo).

## CEL I STAN

| Metryka | Wartość | Stan na |
|---|---|---|
| Przychód gate.cat (potwierdzony w Gmail/Stripe) | **$0 / $2,000** | 2026-07-22 |
| Pobrania PyPI (trailing month, bez mirrorów) | 2,529 (F13 re-pin; pełna seria od 2026-07-03) | 2026-07-23 |
| Płacący klienci Cloud/Packs | 0 | 2026-07-22 |
| Wersja na PyPI | 0.4.17 (F9) | 2026-07-16 |

Znane fakty operacyjne:
- Nudge post-veto z 0.4.17 kieruje na `gate.cat/teams.html` — **strona nie istnieje (404)** → T1.
- Lemon Squeezy **odrzuciło** aplikację 2026-07-14; Stripe jest jedynym kanałem → T10.
- Outreach 2026-07-15 (7 adresatów): odpowiedzi = Mike Privette (pozytywna, pyta o trakcję),
  Julian Goldie (chce płatnego sponsoringu — misread darmowej oferty affiliate), Console.dev (auto-ack).
- Mail do grzegorz@grzegorzlapanowski.pl odbił się (błąd serwera odbiorcy) 2026-07-19.
- Site = statyczne `docs/` serwowane z VPS (OVH) za Cloudflare; deploy poza repo → kroki [USER].
- METRICS.log dopisuje codziennie GitHub Action na masterze (możliwe konflikty — rebase przed pushem).
- **RÓWNOLEGŁA SESJA LOKALNA (Claude Desktop u Bogumiła) deployuje bezpośrednio na VPS z pominięciem gita** — wykryta 2026-07-22 ~18:40: live teams.html/partners.html to JEJ wersje (lepsze; zsynchronizowane do repo w przebiegu #4). Zasada: przed każdą edycją plików site'u najpierw `curl` z produkcji i porównaj — produkcja wygrywa; nigdy nie nadpisuj ślepo deployem.

## KOLEJKA (backlog agenta)

_Synteza panelu 2026-07-22 (4 propozycje, 12 krytyk sędziów, wszystkie kluczowe fakty zweryfikowane w repo). Uczciwa rama sędziów: żadne pojedyncze zadanie nie domyka $2,000 — realna 30-dniowa gotówka to warm threads + Show HN + odblokowanie martwych linków, na które celuje już wysłany nudge 0.4.17; reszta to konwersja i higiena. Kolejność: oczekiwane $ / effort / time-to-cash._

- [x] **T1 — Napraw martwe linki lejka: docs/teams.html + docs/partners.html (jeden PR)** — WYKONANE 2026-07-22 przebieg #1: obie strony zbudowane (standalone, paleta index.html, zero JS; wszystkie liczby wg allowed-wording z FACTS.md F1b/F2/F3 + PRICING.md; policy sharing opisane jako "rolling out" zamiast datowanej obietnicy — patrz T10), sitemap.xml uzupełniony, `ops/deploy_landing.sh` gotowy (rsync bez --delete, sha256 verify, curl 200, restart gatecat-fulfill). HTML/XML zwalidowane. Live po USER-2. Oryginalna spec: — `gatecat/_nudge.py` (shipped w 0.4.17, odpala się po pierwszym realnym veto na każdej maszynie) oraz README.md:285/292 kierują na gate.cat/teams.html i /partners.html, których nie ma w docs/ (żywe 404 — zweryfikowane). Zbuduj obie jako standalone strony na layoucie index.html (bez przebudowy bundla): teams.html = Team €149 value prop + wpleciona verbatim kopia audit-pilot z PRICING.md:109-127 + live Stripe links (Team `buy.stripe.com/9B66oA5xj2eIaly2Vo67S0a`, Business `...7sYdR2e3PcTm2T6cvY67S0b`); partners.html = 30% lifetime-recurring + mailto CTA (affiliate.py nie ma self-serve signup). Do tego `ops/deploy_landing.sh` (artefakt dla USER-2). Acceptance: wpisy w sitemap.xml, każda liczba ma wiersz w FACTS.md/PRICING.md, jeden PR gotowy do merge; live dopiero po USER-2. _(impact: $150-600 (sufit wg sędziów), effort: M, B2B+PRODUCT-LED, 6.7/5.0)_
- [x] **T2 — Gmail draft do Mike'a Privette (Return on Security), wątek 19f669c061fe1503** — WYKONANE 2026-07-22 przy bootstrapie: draft `r-7583389221339500184` w wątku; szczere liczby wyłącznie z FACTS.md (2,528 pobrań/30d, 0 real misses / 1,085,159 komend, revenue day-zero podane wprost), oferta danych do mapy kategorii "Agent Runtime Security". → USER-1: wyślij.
- [x] **T3 — Gmail draft do Juliana Goldie: affiliate ≠ sponsoring, wątek 19f675a02242badf** — WYKONANE 2026-07-22: draft `r1170664853448124004` (reply do 19f75bbfe62653c7); zero zobowiązań finansowych, matematyka prowizji z cennika, link do partners.html (wyślij po deploy'u USER-2 albo zaraz — strona wstanie za chwilę). UWAGA: w Draftach wiszą 2 STARE drafty do Juliana z 2026-07-15 (`r6116468691101999441`, `r-7678200491588625290` — jeden ze stalą ceną €9) → user powinien je skasować. Oryginalna spec: — Julian odpisał cennikiem płatnych sponsoringów, a oferta to darmowy 30% lifetime-recurring affiliate (README:289-292); draftuj do nowszego z dwóch zduplikowanych wątków i odnotuj duplikat. Jedna klaryfikacja bez zobowiązań: zero upfront spend, link do partners.html (po T1) albo sekcji README, decyzję o płatnym sponsoringu zostaw explicite Bogumiłowi. Acceptance: draft w wątku, żadnych obietnic wydatków. _(impact: $0-800 opcjonalność, effort: S, B2B, 6.7)_
- [x] **T4 — Odśwież i fact-checkuj paczkę Show HN (+ warunkowy wariant lobste.rs)** — WYKONANE 2026-07-22 przebieg #2: `ops/launch/show_hn_ready.md` (tytuł+body+pierwszy komentarz, paste-ready) i `ops/launch/lobsters_ready.md` (warunkowy). Fixy: F1b/F4 rozdzielone (0 real misses w 1M replay ≠ 1/129 benign false-block bypass suite), 69→71 policies (F10), €9→€19, "zero-dependency core" (pyproject `dependencies = []`), first-comment z modelem biznesowym i stroną cenową zamiast gołych linków Stripe (norma HN; uzasadnienie w pliku). Linia "one-command install" pominięta — T11 niezmergowane. → USER-4: publikacja PO deploy'u. Oryginalna spec: — Nie pisz od zera: zweryfikuj istniejący draft z docs/LAUNCH_KIT_2026-07-14.md przeciw FACTS.md (fix sędziów: popraw konflację "4 allowed commands"/false-block wg F4 = 178/178 i 1/129 benign; €19 nie €9; 71 policies wg F9), dopisz first-comment z live checkout links i linią "one-command install" jeśli T11 zmergowane. Zapisz ops/launch/show_hn_ready.md + ops/launch/lobsters_ready.md (lobste.rs jest invite-only — wariant tylko-jeśli-konto). Acceptance: każda liczba ma wiersz w FACTS.md, posty paste-ready bez dalszej edycji. _(impact: odblokowuje $200-1000 przez USER-4, effort: S, DISTRIBUTION, 4.8)_
- [x] **T5 — PyPI listing jako landing page (do release-PR 0.4.18)** — WYKONANE 2026-07-22 przebieg #3: pyproject.urls Homepage→https://gate.cat + Pricing→https://gate.cat/teams.html (odstępstwo od speca: #pricing to niezweryfikowana kotwica w bundlowanym index.html; teams.html kontrolujemy); blok cenowy pod sekcją Install w README (PyPI renderuje README = landing); README:417 "21 deny policies"→"71 default policy walls" (proxy używa DOGFOOD_DEFAULTS; 71/73 zweryfikowane importem, F10). WAŻNE USTALENIE: €9 na docs/index.html to CELOWA oferta founding ("locked for life, then €19", osobny link Stripe, test test_marketing_consistency pilnuje) — NIE jest stale, nie "naprawiać". test_marketing_consistency: 5 passed. Wersji NIE podbito — bump przy cięciu 0.4.18 po T6/T7. Oryginalna spec: — pyproject.toml [project.urls] (linie 93-96) kieruje Homepage/Repository/Issues na repo z 0 stars: dodaj `Homepage=https://gate.cat` i `Pricing=https://gate.cat/#pricing?source=pypi`; wstaw 4-linijkowy blok "Free forever · Cloud Solo €19/mo · Team €149 · Packs €29" zaraz pod sekcją install README (pricing dziś na linii ~265/619); grep i uzgodnij stale liczby (€9, 21/69 policies → €19, 71). Acceptance: zero sprzeczności liczbowych w repo, zmiany w release-PR 0.4.18 z checklistą publication-gate; publish = USER-3. _(impact: $50-250, effort: S, CONVERSION, 4.8)_
- [x] **T6 — Rozszerz istniejący _nudge.py o Solo surface (NIE reimplementuj)** — WYKONANE 2026-07-22 przebieg #4: `maybe_nudge_cli()` w _nudge.py (raz/dzień przez ~/.gatecat/nudge_last, stderr, honoruje GATECAT_NO_NUDGE/GATECAT_QUIET, cicho gdy GATECAT_CLOUD_API_KEY albo interventions=0) + wspólna blokada procesu `mark_fired()`/`fired_this_run()` — nigdy 2 nudge w jednym przebiegu (gotowe pod T7); wpięte w `gate.cat status` i `stats`; stopka `report` z linkiem ?source=report (ASCII — test wklejalności pilnuje, stąd EUR nie €); `cloud` bez klucza → link ?source=cli. Testy: 9 nowych w tests/test_nudge_cli.py; 49 passed w dotkniętych suite'ach. Do 0.4.18. Oryginalna spec: — Post-veto nudge już jest w 0.4.17; dodaj rate-limitowane (raz/dzień, `~/.gatecat/nudge_last`) linie: status/stats przy blocked>0 bez cloud key, stopka raportu, `cloud` bez klucza → krótki pitch + gate.cat/#pricing?source=cli; copy verbatim z PRICING.md, respektuj GATECAT_NO_NUDGE/GATECAT_QUIET. Acceptance: testy zielone, nigdy dwa nudge w jednym przebiegu (koordynacja z T7), wchodzi do 0.4.18; zasięg uczciwie = tylko nowe instalacje od publish (fix sędziów). _(impact: $100-400 (sufit), effort: S, CONVERSION, 4.8)_
- [x] **T7 — Pack hint środowiskowy (gatecat/_pack_hint.py)** — WYKONANE 2026-07-22 przebieg #5: shutil.which na stripe (→Fintech €29) i vercel/netlify/fly/heroku/railway/render/supabase (→PaaS €29), scope verbatim z PRICING.md, raz na maszynę (~/.gatecat/.pack_nudged), wspólna blokada z T6 (nigdy 2 hinty w przebiegu), opt-out honorowany, best-effort. 7 testów, 35 passed w suite. BONUS: release-prep 0.4.18 domknięty — bump wersji, wpis CHANGELOG, ops/launch/release_0.4.18_checklist.md (USER-3). Oryginalna spec: — `shutil.which()` na stripe/vercel/fly/netlify/railway/supabase/heroku → jedna uczciwa linia o pasującym packu €29 (scope verbatim z PRICING.md:72-74), max raz na maszynę (`~/.gatecat/.pack_nudged`), opt-out i best-effort pattern skopiowany z _nudge.py. Packi to najtańszy zakup w katalogu z w pełni automatycznym fulfillmentem. Acceptance: unit test doboru packa i wykluczeń, brak stackowania z T6 w jednym przebiegu, do 0.4.18. _(impact: $58-290, effort: S, PRODUCT-LED, 5.0)_
- [x] **T8 — `gate.cat report`: lokalny raport w kształcie płatnego** — ZAMKNIĘTE 2026-07-22 przebieg #6 jako T8-lite: `gate.cat report` (render_report) istniał już w repo w layoucie zgodnym z SAMPLE_REPORT (markdown, counts-only, honest-limits) — spec był częściowo nieaktualny; stopka z CTA off-machine dodana w T6; brakującą linię discovery dodano teraz do maybe_nudge_cli ("See exactly what it caught, free and local: gate.cat report"). 35 testów zielonych. Oryginalna spec: — Nowa komenda renderuje WŁASNY lokalny veto log użytkownika w layoucie docs/SAMPLE_REPORT.md z watermarkiem "paid layer trzyma tę kopię off-machine, poza zasięgiem agenta" + CTA Solo €19/Team €149; discovery wg fixu sędziów: jedna linia w komunikatach T6 wskazuje komendę (inaczej nikt jej nie odpali). Acceptance: działa na pustym i niepustym logu, testy przechodzą, do 0.4.18/0.4.19. _(impact: $100-500 (sufit), effort: M, PRODUCT-LED, 5.0)_
- [x] **T9 — Cross-sell na stronie fulfillment packów** — WYKONANE 2026-07-22 przebieg #7: sekcja "Complete your coverage" w PAGE (products/cloud/gatecat_fulfill.py) — 2 niekupione packi + linia Cloud Solo; atrybucja: `client_reference_id=pack-xsell` na linkach Stripe (widoczna w Checkout Session; `?source=` na buy.stripe.com nic by nie mierzyło — świadome odstępstwo od speca) + `?source=pack-xsell` na teams.html (nginx analytics). Testy: 2 nowe (wykluczenie kupionego packa, render do PAGE), 5 passed. Live po restarcie gatecat-fulfill na VPS (deploy checklist). Oryginalna spec: — PAGE template w products/cloud/gatecat_fulfill.py: sekcja "Complete your coverage" z dwoma nie-kupionymi packami (linki z PRICING.md:72-74 z `?source=pack-xsell`) + jedna linia Cloud Solo €19; bez zmian w Stripe. Acceptance: unit test wykluczenia kupionego modułu (MODULE_FOR); live wymaga restartu usługi na VPS (USER-2). Label sędziów: EV ≈ 0 do pierwszej sprzedaży packa — dlatego ta pozycja, nie wyżej. _(impact: $29-200, effort: S, CONVERSION, 4.8)_
- [x] **T10 — Higiena prawdy: llms.txt, sitemap 404, Lemon Squeezy "pending"** — WYKONANE 2026-07-22 przebieg #8: (1) llms.txt — już odświeżone wcześniej (71 policies; wersja 0.4.18 z hotfixa #5); (2) sitemap /answers/* — NIE martwe: strony ŻYJĄ na produkcji (kolejny out-of-band deploy) → zamiast usuwać, zaciągnięto 5 stron do docs/answers/ (produkcja wygrywa); (3) PRICING.md:56 "LS review pending" → "Stripe is the payment channel"; (4) default payment_channel() lemonsqueezy→stripe (ODWRÓCENIE decyzji foundera z 2026-07-12, powód: LS odrzuciło 2026-07-14; sign-off = merge PR #26; ścieżka LS zostaje za env); (5) "ships this month"→"rolling out" (spójne z live teams.html). Testy: 23 passed. Oryginalna spec: — docs/llms.txt: 65/65→178/178 (F4) i v0.4.3→0.4.17 (F9); sitemap.xml: usuń/przekieruj 5 martwych wpisów /answers/* (budowa stron odrzucona jako revenue-driver); PRICING.md:56 "review is pending" → LS odrzucone 2026-07-14 + default `payment_channel()` w cloud_activate.py na stripe; sprawdź obietnicę "ships this month" (PRICING.md:50) i jeśli fleet policy nie wejdzie do ~2026-08-01, przygotuj PR łagodzący wording. Acceptance: diff przeciw FACTS.md czysty; PR wyraźnie flaguje odwrócenie decyzji foundera z 2026-07-12 i wymaga sign-off przed merge. _(impact: ~$0 (risk-avoidance), effort: S, DISTRIBUTION+B2B, 4.8/6.7)_
- [x] **T11 — Claude Code plugin-marketplace manifest** — WYKONANE 2026-07-22 przebieg #9: wg oficjalnej dokumentacji (code.claude.com/docs/en/plugins, pobrana WebFetch — fix sędziów: bez zgadywania schematu): repo = marketplace (.claude-plugin/marketplace.json) + plugin plugins/gatecat/ (.claude-plugin/plugin.json v0.4.18, hooks/hooks.json z PreToolUse Bash|Write|Edit → gatecat-hook — blok 1:1 z settings.example.json, README z instalacją `/plugin marketplace add BGMLAI/gate.cat` → `/plugin install gatecat@gatecat`). JSON zwalidowany. Weryfikacja załadowania = owner po merge #27 (`claude --plugin-dir ./plugins/gatecat`). Linia one-command-install do postów: po merge'u. Oryginalna spec: — `.claude-plugin/marketplace.json` + `plugin.json` opakowujące istniejący PreToolUse hook (examples/veto_integrations/claude_code_hook/); fix sędziów: najpierw WebFetch oficjalnej dokumentacji schematu — nie zgaduj formatu; weryfikacja załadowania = owner po merge, nie agent. Wartość głównie jako linia "one-command install" w poście HN (T4). Acceptance: manifest przechodzi walidację składni JSON wobec udokumentowanego schematu, PR otwarty. _(impact: $0-150 (obniżone przez sędziów), effort: M, DISTRIBUTION, 4.8)_
- [x] **T12 — daily_funnel.py testowany na fixture (bez SSH z sandboxa)** — WYKONANE 2026-07-23 przebieg #10: scripts/daily_funnel.py (reużywa summarize() z funnel_report.py; filtr per-dzień UTC; JSON-line w kształcie METRICS.log: {date, page_view, install_copy, checkout_click, top_sources}); fixture tests/fixtures/gatecat_events.log (9 linii: 2 dni, smoke_test ignorowany, źródła hn/pypi/reddit/direct); 3 testy passed. Instrukcja SSH-run w docstringu (wzorzec launch_metrics.py) — uruchamiane tam, gdzie jest log; to pomiar, nie przychód. Oryginalna spec: — Skrypt parsuje events log przez funnel_report.py i appenduje JSON-line {date, page_view, install_copy, checkout_click, top_sources} do METRICS.log; w środowisku agenta NIE ma klucza VPS, więc acceptance = unit test na fixture w repo + instrukcja uruchomienia tam gdzie jest klucz (wzorzec SSH z scripts/launch_metrics.py). Fix sędziów: to pomiar, nie przychód — niczego nie blokuje i nie twierdzimy "pierwszego realnego snapshotu" z sandboxa. _(impact: $0 (pomiar do iteracji), effort: S, CONVERSION, 4.8)_
- [x] **T14 — Influencer affiliate outreach (dyspozycja usera 2026-07-22 ~20:40)** — WYKONANE: research (developereducators.com katalog 92 twórców CC, awesome-ai-newsletters, sponsor-pages) → pakiet `influencer-affiliate-outreach.md` dostarczony userowi NA CZACIE (nie w repo — zasada 9): 17 twórców YouTube Tier 1 (Edmund Yong, Simon Scrapes, Jack Roberts, Nate Herk, John Kim, Bart Slodyczka-proxy-fit, Greg Isenberg...), 10 newsletterów Tier 2 (AI Engineering, AI Agents Simplified, Latent Space, Ben's Bites...), Tier 3 mega-kanały po trakcji; 3 szablony (YT/newsletter/follow-up Nick Saraev); protokół ≤15/dzień + obowiązkowa personalizacja. Wysyłka = user/sesja lokalna; odpowiedzi łapie pętla. Wykluczeni już kontaktowani (7 z 15.07).
- [x] **T13 — LinkedIn DM do Dimitriosa Kaprilisa (artefakt dla USER-5)** — WYKONANE 2026-07-23 przebieg #11: DM dostarczony userowi NA CZACIE (zasada 9 — nie w repo). Źródło zweryfikowane: docs/research/community-threads-2026-07-13.md:99 (post o skasowanym projekcie Electron; pyta o polityki zespołowe; nasz publiczny komentarz już istnieje — publications #25) → DM = kontynuacja: merytoryczna odpowiedź (stack + deterministyczny veto w harnessie, F1b), potem oferta design-partner (Team free za feedback + zgodę na cytowanie zanonimizowanego wyniku). Profil: linkedin.com/in/dimitrios-kaprilis-295b6a348. Oryginalna spec: — `ops/launch/dm_dimitrios.md` wg fixu sędziów: najpierw merytoryczna odpowiedź na jego publiczne pytanie o policies (z F1b), dopiero potem oferta bezpłatnego Team + audit-pilot review za zgodę na cytowanie wyniku. Acceptance: paste-ready DM, zero liczb spoza FACTS.md. _(impact: design-partner opcjonalność, effort: S, B2B)_

## KOLEJKA v2 (panel 2026-07-23)

_Synteza panelu 2026-07-23 (3 propozycje / 6 krytyk; 0 propozycji killed, ale sędziowie wycięli lub zdegradowali ~40% zadań). Rama sędziów: jedyna agent-wykonalna ścieżka do pierwszej płatności to domknięcie self-serve Packs €29 (jedyny produkt impulsowy z auto-fulfillmentem) + gotowe-do-wklejenia konwersje ciepłych wątków; realny bottleneck (publish 0.4.18, deploy docs/, posty, wysyłka kampanii) jest po stronie ownera — stąd U2. Kolejność: oczekiwane $ / effort / time-to-cash. Liczby publiczne WYŁĄCZNIE z FACTS.md (nigdy ze stanu pętli). Zweryfikowane przed syntezą: packs.html = soft-404, _pack_hint.py linkuje goły buy.stripe.com (2/3 packów), FACTS.md F13 = 2,019 (pin 2026-07-13) vs 2,528 w pętli, PRICING.md:23/50 obiecuje SIGNED policy sync._

- [x] **U1 — Zbuduj docs/packs.html (dziś soft-404) i przepnij wszystkie pack-CTA na podgląd przed checkoutem** _(DONE 2026-07-23 przebieg #13: docs/packs.html zbudowany — 3 packi scope verbatim z PRICING.md + kotwice #fintech/#paas/#http-api, buy-linki ?source=packs, 30-day refund, install steps, fail-closed note, blok „What packs are NOT", skrypt affiliate + funnel /events; sitemap.xml + wpis; cross-sell przepięty: gatecat_fulfill.py xsell → packs.html?source=pack-xsell#kotwica, teams.html nota+footer → packs.html?source=teams, coverage.html /#packs (martwa kotwica!) → /packs.html?source=coverage; README jedna linia „What's inside each pack → gate.cat/packs.html?source=pypi"; llms.txt wzmianka; NOWY test test_packs_page_shows_scope_before_checkout jako strażnik dryfu; pełny suite 1928 passed. Live po deployu [USER]-2.)_ — Każdy pack-CTA prowadzi dziś PROSTO na buy.stripe.com bez podglądu co się kupuje (cold checkout — zweryfikowane przez obu sędziów: /packs.html serwuje ten sam 352KB index.html co losowy URL). Zbuduj stronę na layoucie teams.html: 3 packi ze scope VERBATIM z sekcji "Policy Packs — €29 one-time" w PRICING.md, buy-linki z `?source=packs`, 30-day refund, install steps, wpis do sitemap.xml; w tym samym PR przepnij cross-sell w products/cloud/gatecat_fulfill.py i teams.html oraz dodaj JEDNĄ skanowalną linię w README pod istniejącym blokiem pricing ("What's inside each pack → gate.cat/packs.html?source=pypi") — bez drugiego bloku cenowego (cięcie sędziów: dawny Task 3 zwinięty tutaj). Acceptance: test_marketing_consistency zielony, każda liczba z PRICING.md/FACTS.md, PR gotowy do merge; live dopiero po deployu ([USER]-2) — framing sędziów: usunięcie tarcia, nie gwarancja płatności. _(impact: $0-290, warunkowe: deploy+ruch, effort: M, SELF-SERVE PACKS, 6.5)_
- [x] **U2 — OWNER_RUNBOOK: "20 minut do odblokowania" — jeden plik z dokładnymi komendami dla ownera** _(DONE 2026-07-23 przebieg #14: ops/launch/OWNER_RUNBOOK.md — 6 kroków+prereq, każdy jedna komenda/jeden paste, twarda kolejność publish→deploy→funnel→HN→dystrybucja→batch, suma ~20 min; przy okazji ops/deploy_landing.sh weryfikuje teraz też packs.html (sha256+200); [USER] v2 przepisany na wskazanie runbooka.)_ — Obaj sędziowie górnych propozycji wskazali to samo: realny bottleneck do cash to throughput usera (publish 0.4.18, deploy docs/, Show HN/Reddit, wysyłka kampanii czekają od dni), a panel dokładał artefakty zamiast rozładować kolejkę. Napisz ops/launch/OWNER_RUNBOOK.md: kroki w kolejności wykonania, każdy = jedna komenda albo jeden paste, zero decyzji (twine wg ops/launch/release_0.4.18_checklist.md → ops/deploy_landing.sh → jednorazowy scripts/daily_funnel.py na logach VPS z wklejeniem wyniku na czat [tani test hipotezy packs: czy ktoś w ogóle klika checkout_click] → show_hn_ready.md + distribution_kit_2026-07-22.md → batch affiliate ≤15/dzień). Acceptance: łączny czas wykonania <20 min, linkuje wyłącznie istniejące artefakty, sekcja [USER] w tym pliku wskazuje na runbook zamiast dublować kroki. _(impact: $0 bezpośrednio — multiplikator na wszystkie [USER]-gated $, effort: S, THROUGHPUT OWNERA, konsensus sędziów)_
- [x] **U3 — Pack hint v2: detekcja HTTP-API Breadth (tylko stack-specyficzne CLI) + repoint na packs.html — do 0.4.19** _(DONE 2026-07-23 przebieg #15: trzecia krotka HTTP-API Breadth z detekcją TYLKO datadog-ci/sentry-cli (test strażnik: docker/gh/curl NIE triggerują), wszystkie 3 hinty → gate.cat/packs.html?source=hint#kotwica zamiast gołego Stripe; test ASCII-only; CHANGELOG sekcja Unreleased/0.4.19 BEZ podbicia pyproject (0.4.18 czeka na publish); runbook+checklist: publish 0.4.18 z 8ce3592 PRZED merge PR #27, bo branch niesie kod 0.4.19.)_ — gatecat/_pack_hint.py wykrywa 2 z 3 packów i linkuje goły Stripe; dodaj trzecią krotkę (HTTP-API Breadth, scope VERBATIM z PRICING.md, link `buy.stripe.com/...67S0e`) z detekcją WYŁĄCZNIE stack-specyficznych CLI typu datadog-ci/sentry-cli — fix sędziów: BEZ docker/gh, bo są uniwersalne i zabijają precyzję "high-intent" triggera; oba istniejące URL-e przepnij na `https://gate.cat/packs.html?source=hint`. Wchodzi do release-PR 0.4.19 z wpisem CHANGELOG — jawnie NIE wstrzymuje publisha przygotowanego 0.4.18 (fix sędziów: brak rozjazdu z gotowym checklistem). Acceptance: test detekcji HTTP-API w tests/test_pack_hint.py, `python -m pytest -q tests/test_pack_hint.py` zielony. _(impact: $29-116, effort: S, SELF-SERVE PACKS, 6.5)_
- [x] **U4 — Blok self-verify "Don't trust us — reproduce it" na stronach zakupu + README** _(DONE 2026-07-23 przebieg #16: identyczny blok (pip install + bypass_suite, F4 178/178 + named gap + 1/129 benign, F1b 0 misses/1,085,159 z adjudykacją) na teams.html, packs.html i w sekcji pricing README; test test_self_verify_block_on_every_purchase_surface wymusza „honesty coupling" — liczby nigdy bez kawetów; PRZY OKAZJI przepięte 6 przegapionych martwych anchorów gate.cat/#packs → packs.html (README-footer ?source=pypi + 5 stron answers/ ?source=answers). Suite 1933 passed.)_ — Kontra na 0 gwiazdek/0 testimoniali dokładnie w punkcie decyzji zakupowej: identyczny blok z komendą `pip install gate-cat && python -m gatecat.integrations.bypass_suite` i allowed-wordingiem z FACTS.md (F1b: 0 real misses / 1,085,159; F4: 178/178 + 1 named gap + 1/129 benign) do docs/teams.html, docs/packs.html (po U1) i sekcji pricing w README.md. README renderuje się na GitHub natychmiast, bez publish/deploy-gate. Acceptance: grep liczb (`178|1,085,159|71 `) na dotkniętych plikach zgodny z FACTS.md. _(impact: $0-150, effort: S, SELF-SERVE PACKS, 6.5)_
- [x] **U5 — Higiena FACTS.md: re-pin F13 (2,019 → świeży odczyt) + audyt wierszy wersjonowanych — GATE dla U6/U7** _(DONE 2026-07-23 przebieg #17: F13 re-pin 2,529 bez mirrorów, pełna seria dzienna 07-03→07-22 z overall?mirrors=false — endpoint recent był 429, metoda odnotowana w wierszu; F4 re-run na branchu: identyczne 178/178, 1/129, ta sama luka; F3: nota loop-branch 1933 passed + CI green, headline re-pin przy release-gate 0.4.18; F9 uczciwie zostaje 0.4.17 z notą „0.4.18 prepped, unpublished". Bramka U6/U7 otwarta.)_ — F13 wisi na 2,019 (pin 2026-07-13), a pętla i wysłany mail do Mike'a operują 2,528 — jedyna niespójność potwierdzona przez CZTERECH sędziów z obu stron panelu. Re-pinuj F13 świeżym `curl pypistats.org/api/packages/gate.cat/recent` + METRICS.log z nową datą i źródłem; przejrzyj F3/F4/F9 pod notatkę "0.4.18 przygotowany, niepublikowany" (F9 uczciwie zostaje 0.4.17). Acceptance: commit w PR pętli; twardy warunek sędziów dla WSZYSTKICH kolejnych zadań: publiczne copy bierze liczby tylko z wierszy FACTS.md, nigdy ze STANU pętli. _(impact: $0 — risk-avoidance, odblokowuje publiczne liczby w U6/U7, effort: S, B2B PIPELINE, 4.5)_
- [ ] **U6 — Pakiet danych dla Mike'a Privette: dokładnie to, co obiecane w mailu 07-22 17:11, gotowe na jego reply** — ops/launch/mike_category_data_pack.md: docs/SAMPLE_REPORT.md jako "redacted sample", results/million_recall_2026-07-08.json + RECALL.md jako "raw data behind the numbers", jeden akapit honest positioning (deterministic pre-execution veto, zero-model-in-path) BEZ twierdzeń o konkurentach bez zweryfikowanych danych i BEZ nazwisk osób trzecich — incydenty tylko po numerach issue (fix sędziów); do tego szkielet odpowiedzi z 3 gałęziami (poprosi o dane / mention w newsletterze / wspólny content). Gmail draft powstaje DOPIERO po jego odpowiedzi (dedupe #7) — pakiet ścina czas reakcji z godzin do minut; ŻADNEJ nowej publicznej strony docs/ na razie (cięcie sędziów z pełnego "analyst kit"). Acceptance: liczby wyłącznie z FACTS.md po U5; plik paste-ready. _(impact: $0-500 w 30 dni — pipeline/wiarygodność, nie bezpośredni cash (korekta sędziów z $200-1,500), effort: S, KONWERSJA ODPOWIEDZI + B2B, 5.5/4.5)_
- [ ] **U7 — Welcome pack partnera (markdown-only): odpowiedź na pierwsze mailto z partners.html w minutę** — partners.html (LIVE) ma tylko mailto CTA, a products/cloud/affiliate.py ma gotowe `add-affiliate`/`ledger` — brakuje wyłącznie treści. Napisz ops/partners/welcome_pack.md: welcome mail (format linku `gate.cat/?ref=CODE`, mechanika 30% lifetime-recurring wg affiliate.py, termin wypłaty), 3 warianty kodu per typ twórcy, dokładna komenda [USER] `python -m affiliate add-affiliate CODE "Name" email` na VPS, blok statystyk TYLKO z FACTS.md (po U5 — twardy warunek sędziów) + wymóg disclosure afiliacji. BEZ osobnego skryptu Pythona i testów slugów (cięcie sędziów: nadinżynieria przy 0 zdarzeń). Acceptance: zero liczb spoza FACTS.md; wysyłka i wpis do produkcyjnej bazy oznaczone [USER]. _(impact: $0-800 opcjonalność do pierwszego partnera, effort: S, KONWERSJA ODPOWIEDZI, 5.5)_
- [ ] **U8 — Szablony follow-up day-3/day-7 + kolumny due w LEDGER (bez skryptu; Julian jako jeden wariant)** — ops/launch/followup_templates.md: day-3 (krótkie przypomnienie) i day-7 ("ostatni dotyk + coś nowego") per tier z T14 (YouTube/newsletter/mega-kanał), w tym JEDEN wariant day-3 dla Juliana z zero-friction downgrade ask — BEZ prerezerwacji kodu "julian-goldie" zanim cokolwiek potwierdzi (cięcie sędziów: osobne zadanie Julian wchłonięte tutaj). Dopisz do LEDGER kolumny due: AI Engineering wysłane 07-22 21:18 → day-3 2026-07-25 / day-7 2026-07-29; Julian klaryfikacja 07-22 15:53 → 2026-07-25 / 2026-07-29; każdy kolejny wysłany mail kampanii dostaje wiersz przy odnotowaniu. Żadnych draftów przed datami due (dedupe #7). Acceptance: szablony paste-ready, LEDGER zaktualizowany; skrypt due-trackingu dopiero gdy wysłanych >5 (patrz ODRZUCONE v2). _(impact: $0-400 — materializuje się dopiero z wysyłkami usera, effort: S, KONWERSJA ODPOWIEDZI, 5.5)_
- [ ] **U9 — Design-partner fala 2: scoring i MAX 3 spersonalizowane drafty, dostarczone na czacie** — Scoring kandydatów z docs/research/community-threads-2026-07-13.md (P0+P1) + świeży `mcp__github__search_issues` po incydentach destructive-command <14 dni (anthropics/claude-code, cline/cline, opencode); wybierz MAX 3 (cięcie sędziów z ~10 — nie dokładać WIP userowi, który ma niewysłaną kampanię) i przygotuj drafty wzorcem T13: najpierw merytoryczna odpowiedź na ich publiczny problem z F1b, potem oferta Team-free-for-feedback + zgoda na cytowanie zanonimizowanego wyniku. Całość NA CZAT, nie do repo (zasada 9 — zero danych osób trzecich w publicznym repo). Acceptance: tabela scoringowa w scratchpadzie, 3 paste-ready drafty na czacie, wysyłka = [USER]. _(impact: $0-300 w 30 dni — pierwszy Team reference, effort: M, B2B PIPELINE, 4.5)_

## [USER] v2

**Wszystko w jednym pliku: [`ops/launch/OWNER_RUNBOOK.md`](../ops/launch/OWNER_RUNBOOK.md) — ~20 minut, 7 kroków w twardej kolejności** (publish 0.4.18 **PRZED** merge PR #27 — branch niesie już kod 0.4.19! → merge PR #27 → deploy docs/ → snapshot funnela na czat → Show HN → dystrybucja → batch affiliate ≤15/dzień). Każdy krok = jedna komenda albo jeden paste; szczegóły i gates release'u nadal w `release_0.4.18_checklist.md`. Nie dubluj kroków stąd — runbook jest źródłem prawdy; po wykonaniu czegokolwiek pętla sama wykryje stan (PyPI/produkcja) przy następnym przebiegu.

## ODRZUCONE v2

- **`policy export/import` do 0.4.19 (P3-T4)** — live teams.html i PRICING.md:23/50 obiecują SIGNED policy sync ("tampering shows"); plain-file bez podpisu tworzy rozjazd copy-vs-feature zamiast domykać obietnicę, a główny powód pierwotnego odrzucenia (0 potwierdzonych Team buyerów) obowiązuje w całości — zabite przez obu sędziów.
- **`response_triage.md` — silnik triażu odpowiedzi kampanii (P1-T1)** — drzewo decyzyjne budowane z próbki n=2 (Mike + dwukrotnie ten sam autoreply Juliana) przy 0 odpowiedziach z kampanii; dedupe #7 już działa w praktyce — dokumentacja nad działającym procesem, ~$0 w 14 dni.
- **`followup_due.py` — skrypt parsujący Gmail pod zegary follow-upów (P1-T2)** — inżynieria nieproporcjonalna do <30 rekordów (spojrzenie w kalendarz); zdegradowane do szablonów + kolumn LEDGER w U8; wróć TYLKO gdy wysłanych >5 i ręczne śledzenie realnie boli.
- **`docs/security-review.md` — kit dla championa B2B (P3-T5)** — odłożone do pojawienia się pierwszego realnego leada na etapie security review; THREAT_MODEL.md/TELEMETRY.md/SECURITY.md są już linkowalne pojedynczo z maila, a nowy artefakt tylko powiększa kolejkę review ownera.

## [USER] — czeka na Bogumiła (v1 — patrz też [USER] v2 wyżej)

**DECYZJA USERA 2026-07-22 ~20:00: "wszystko co się da" — pełna dystrybucja zatwierdzona.**
Pakiet: `ops/launch/show_hn_ready.md` (HN, repost OK — stary post 2 pkt) +
`ops/launch/distribution_kit_2026-07-22.md` (r/ClaudeAI, r/LocalLLaMA, r/Python,
wątek X, 4 PR-y awesome-list) — z kolejnością publikacji w pliku (NIE wszystko
naraz). Publikuje user/sesja lokalna; każdy live URL → issue #9.

0. **Decyzja o kanale wysyłki.** Sesja agenta NIE MOŻE wysyłać (konektor bez send;
   klasyfikator zablokował też commit sendera do repo). Opcje: (a) NAJSZYBCIEJ —
   wyślij 2 gotowe drafty ręcznie (punkt 1); (b) zainstaluj dostarczone na czacie
   pliki sendera na VPS (instrukcja w install.sh; Gmail App Password w
   /etc/gatecat-mailer.env, nigdy w repo); (c) dodaj regułę permissions
   w ustawieniach Claude Code, żeby agent mógł utrzymywać outbox w repo —
   wtedy pętla dokończy automatyzację w następnym przebiegu.
1. **Wyślij OBA drafty z folderu Drafts (2 min, leady się starzeją)** — (a) Mike Privette,
   wątek "Re: new security category…"; (b) Julian Goldie, wątek "Re: 30% lifetime
   recurring…". Konektor Gmail agenta nie ma funkcji send — wysyłka musi być Twoja.
   PRZY OKAZJI skasuj 2 stare drafty do Juliana z 15.07 (jeden ma błędną cenę €9).
2. **Zmerguj PR #26** — teams/partners są już LIVE (wgrane przez Twoją sesję lokalną
   i zsynchronizowane do repo), więc 404 z nudge'a jest ZAŁATANE. Deploy `ops/deploy_landing.sh`
   został do wgrania sitemap.xml (nowe wpisy) i przyszłych zmian docs/.
3. **Opublikuj gate-cat 0.4.18 na PyPI** — po release-PR (T5+T6+T7, opcjonalnie T8)
   z checklistą publication-gate z docs/LAUNCH_0.4.16.md; agent nie może publikować.
4. **Post Show HN — najlepiej PO kroku 2** (ruch ma trafiać na naprawione strony).
   Artefakt GOTOWY: `ops/launch/show_hn_ready.md` (tytuł + body + pierwszy komentarz,
   z notą o timing/obsłudze komentarzy); opcjonalnie `ops/launch/lobsters_ready.md`,
   jeśli masz konto na lobste.rs.
5. **Wklej LinkedIn DM do Dimitriosa Kaprilisa** — artefakt: `ops/launch/dm_dimitrios.md` (T13).
6. **Decyzja: płatny sponsoring u Juliana Goldie?** — jego cennik: https://aiprofitboardroom.com/sponsor/
   (agent nie wydaje pieniędzy; draft klaryfikujący darmowy affiliate przygotuje T3).

## ODRZUCONE (z uzasadnieniem — nie proponować ponownie)

- **PACK_HINTS w demo na docs/index.html** — ruch demo niezmierzony, plik to zbundlowany, entity-encoded JS (to samo ryzyko regresji co 2026-07-14), M-effort za deploy-gated efekt; wróć tylko gdy dane z T12 pokażą realny ruch demo.
- **Budowa 4 stron /answers/ i docs/vs.html jako revenue-drivery** — SEO z domeny o 0 stars nie zarankuje w 30 dni; uczciwy impact ~$0; martwe wpisy sitemap czyści T10, content idzie do backlogu po HN.
- **Standalone docs/audit-pilot.html** — czwarta niepodlinkowana strona bez źródła ruchu; kopia z PRICING.md:109-127 zostaje wpleciona do teams.html (T1).
- **Pełny fleet policy sign/pull (L-effort) w tej partii** — brak potwierdzonego Team buyera; security-sensitive krypto shipowane przez hourly agenta do produktu safety = zły ROI teraz; obietnicy "ships this month" pilnuje T10.
- **Reimplementacja post-veto nudge "od zera"** — już jest w 0.4.17 (gatecat/_nudge.py); przyszłe panele mogą go tylko rozszerzać (T6).
- **SSH na VPS z sandboxa / lobste.rs jako pełnoprawny kanał** — brak klucza VPS w środowisku agenta (zostaje fixture w T12); lobste.rs invite-only (zostaje wariant warunkowy w T4).

## LEDGER OBSŁUŻONYCH WĄTKÓW (dedupe)

| Wątek | Kto | Ostatnia obsługa | Akcja |
|---|---|---|---|
| 19f669c061fe1503 | Mike Privette (Return on Security) | 2026-07-22 | **WYSŁANE przez usera 17:11 UTC** (odpowiedź o trakcji); czekamy na odpowiedź Mike'a |
| 19f675a02242badf / 19f668f7b6a127eb | Julian Goldie (duplikat wątku) | 2026-07-22 | **WYSŁANE ręcznie przez usera 15:53 UTC** (klaryfikacja affiliate); czekamy na odpowiedź |
| 19f7acd133235366 | grzegorz@grzegorzlapanowski.pl | 2026-07-19 | bounce (serwer odbiorcy); brak akcji agenta — nr tel. ma user |

## LOG PĘTLI

- **2026-07-23 07:21 UTC — przebieg #17: U5 DONE.** Poczta: bez zmian. FACTS:
  F13 re-pin 2,529 (pełna seria 07-03→07-22, bez mirrorów); F4 re-run
  identyczny (178/178, 1/129, ta sama luka); F3 nota branchowa (1933+CI);
  F9 zostaje 0.4.17. Stale 2,019/2,528 tylko w stanie pętli, publiczne copy
  czyste. Bramka U6/U7 otwarta. Następny przebieg: U6 (data pack Mike'a).

- **2026-07-23 06:21 UTC — przebieg #16: U4 DONE.** Poczta: bez zmian. Backlog:
  **U4 done** — blok self-verify na teams/packs/README (F1b+F4 w dozwolonym
  brzmieniu, kawety jadą razem z liczbami — nowy test wymusza sprzężenie);
  bonus: 6 martwych anchorów /#packs przepiętych na packs.html (README footer
  + answers/). Suite 1933 passed. Następny przebieg: U5 (re-pin F13 + przegląd
  F3/F4/F9 — GATE dla U6/U7).

- **2026-07-23 05:21 UTC — przebieg #15: U3 DONE.** Poczta: bez zmian. Backlog:
  **U3 done** — pack hint v2: +HTTP-API Breadth (datadog-ci/sentry-cli, strażnik
  na universal-CLI), 3× URL → packs.html?source=hint#kotwica, ASCII-test;
  CHANGELOG Unreleased/0.4.19 bez podbicia wersji. KRYTYCZNA zmiana kolejności
  w runbooku: publish 0.4.18 PRZED merge PR #27 (branch od teraz niesie
  niewydany kod 0.4.19 w gatecat/ — build z HEAD mastera po merge dałby
  cichy rozjazd zawartości wheela). Następny przebieg: U4 (self-verify blok).

- **2026-07-23 04:21 UTC — przebieg #14: U2 DONE.** Poczta: bez zmian (identyczny
  stan jak #13). CI na 8a84201 (U1): 3/3 zielone. Backlog: **U2 done** —
  ops/launch/OWNER_RUNBOOK.md (6 kroków + prereq merge PR #27, jedna
  komenda/paste na krok, ~20 min, twarda kolejność publish→deploy→funnel→
  HN→dystrybucja→batch); deploy_landing.sh weryfikuje też packs.html;
  [USER] v2 = jeden wskaźnik na runbook. Następny przebieg: U3 (pack hint v2,
  0.4.19).

- **2026-07-23 03:21 UTC — przebieg #13: U1 DONE.** Poczta: nic nowego (Mike/Julian/
  AI-Engineering czekają na ich ruch; Stripe payout = Fundacja, nie gate.cat).
  Backlog: **U1 done** — docs/packs.html (scope verbatim, kotwice, ?source=packs,
  refund/install/fail-closed, affiliate+funnel tracking), sitemap, cross-selle
  przepięte (fulfill xsell/teams/coverage — coverage linkował do NIEISTNIEJĄCEJ
  kotwicy /#packs), README 1 linia, llms.txt, nowy test strażnik. Suite: 1928
  passed. Produkcja zweryfikowana przed edycją (coverage.html diff = tylko
  Cloudflare email-protection). Następny przebieg: U2 (OWNER_RUNBOOK).

- **2026-07-23 02:21 UTC — przebieg #12: PANEL v2.** Poczta: nic dla gate.cat (payout
  Stripe = Fundacja LC/Bloom, inny biznes). Panel: 3 propozycje (sonnet/opus/fable) ×
  2 sędziów (sonnet/opus) + synteza; 0 killed, ~40% zadań wyciętych. Nowa kolejka
  U1-U9; klucz: packs.html = soft-404 (goły checkout bez podglądu!), F13 stale
  (2,019 vs 2,528), bottleneck = throughput ownera → U2 OWNER_RUNBOOK. Następny
  przebieg: U1.

- **2026-07-23 01:21 UTC — przebieg #11.** Poczta/Stripe/HN: bez zmian. Backlog: **T13
  done** (DM przez czat) → **KOLEJKA PUSTA**. Następny przebieg: panel adversarialny
  multi-model po nową partię zadań. Sugerowane soczewki dla panelu: (a) konwersja
  odpowiedzi kampanii affiliate, (b) follow-upy po publikacjach usera (HN/Reddit/X,
  gdy już wiszą), (c) droga do pierwszej płatności z istniejącego ruchu, (d) release
  0.4.19. NIE proponować ponownie pozycji z ODRZUCONE.

- **2026-07-23 00:21 UTC — przebieg #10.** Poczta/Stripe/HN: bez zmian. Backlog:
  **T12 done** (daily_funnel na fixture, 3 testy zielone). W kolejce został TYLKO T13
  (DM Dimitrios — artefakt przez czat, zasada 9) → po nim kolejka pusta = następny
  przebieg odpala panel adversarialny po nową partię zadań (priorytet: konwersja
  odpowiedzi z kampanii affiliate + follow-upy po publikacjach usera).

- **2026-07-22 23:21 UTC — przebieg #9.** Poczta/Stripe/HN: bez zmian (kampania: 1 mail
  wysłany, czekamy na odpowiedzi). Backlog: **T11 done** — plugin marketplace manifest
  (schemat z oficjalnych docs). Po merge #27: `/plugin marketplace add BGMLAI/gate.cat`
  + `/plugin install gatecat@gatecat` = one-command install do postów HN/Reddit.
  Zostały: T12 (daily_funnel fixture), T13 (DM Dimitrios — czat).

- **2026-07-22 21:53 UTC — PR #26 ZMERGOWANY przez usera** (29 plików, T1-T10 + release-prep
  0.4.18 na masterze). Gałąź pętli zrestartowana od origin/master; kolejne commity pójdą
  w NOWYM draft PR. ODBLOKOWANE: USER-3 (publish 0.4.18 wg ops/launch/release_0.4.18_checklist.md)
  i deploy docs/ (sitemap, answers w repo == produkcja). W kolejce: T11, T12, T13.

- **2026-07-22 22:21 UTC — przebieg #8.** POCZTA: **kampania wystartowała — mail do
  AI Engineering (corp@systemdrd.com) WYSŁANY 21:18** (user/sesja lokalna); 0 płatności.
  Backlog: **T10 done** — w tym odkrycie: /answers/ (4 artykuły SEO + index) żyją na
  produkcji out-of-band → zsynchronizowane do repo. Default płatności: stripe
  (LS odrzucone). Zostały: T11 (plugin manifest), T12 (daily_funnel), T13 (DM — czat).

- **2026-07-22 21:21 UTC — przebieg #7.** Poczta: nic nowego; 0 płatności; HN bez
  nowego posta; draft do AI Engineering czeka na wysyłkę. Backlog: **T9 done**
  (cross-sell na stronie packów, 5 testów zielonych). Zostały: T10 (higiena prawdy),
  T11 (plugin manifest), T12 (daily_funnel), T13 (DM Dimitrios — przez czat).

- **2026-07-22 ~20:45 UTC — T14 (na żądanie usera): pakiet outreachu affiliate.**
  27 celów w 2 tierach + szablony + protokół anty-spamowy; dostarczony na czacie
  (poza publicznym repo). Follow-up do Nicka Saraeva (kontakt 15.07 bez odpowiedzi)
  zaplanowany PO publikacji HN (news hook). E-maile YT zbiera sesja lokalna.

- **2026-07-22 20:21 UTC — przebieg #6.** CI na HEAD **ZIELONE 3/3** (run 29949977365)
  → PR #26 gotowy do merge'a. Poczta: tylko alert CI ze starego commita (obsłużony);
  0 płatności. HN: Algolia chwilowo nie-JSON (rate limit) — sprawdzę w #7. Backlog:
  **T8 zamknięte** (T8-lite: discovery line w nudge; render_report już istniał).
  Następne: T9 (cross-sell w fulfillment) — UWAGA: wymaga zsynchronizowania z produkcją
  wg zasady "produkcja wygrywa" (gatecat_fulfill.py mógł być zmieniony przez sesję lokalną).

- **2026-07-22 ~20:05 UTC — decyzja usera: pełna dystrybucja.** Zweryfikowano na PyPI:
  0.4.18 NIE opublikowane (latest = 0.4.17) wbrew przekonaniu usera — release czeka
  na merge+twine (checklist). Stary post HN 15.07 = 2 pkt → repost dozwolony i
  zatwierdzony. Przygotowano distribution_kit_2026-07-22.md: 3×Reddit + 8 tweetów
  + 4 awesome-PR, wszystkie liczby wg F1b/F4/F10/F2, harmonogram anty-spamowy.
  Pobrania (live pypistats): 2,528/mies., 350/tydz., 46 dziś.

- **2026-07-22 19:21 UTC — przebieg #5.** Poczta: nic nowego; 0 płatności. HN check
  (Algolia): nowego posta BRAK — wisi tylko stary z 15.07 (2 pkt; repost innego tytułu
  zgodny z normami HN). Backlog: **T7 done** + release-prep 0.4.18 (bump+CHANGELOG+
  checklist). Zawartość 0.4.18 kompletna → USER-3 odblokowane po merge PR #26.
  Następne: T8 (gate.cat report — lokalny raport w kształcie płatnego) — UWAGA: już
  istnieje render_report; T8 = discovery line w T6 (zrobione) → sprawdzić czy T8 nie
  jest w większości zbędne; potem T10 (higiena prawdy).
- **2026-07-22 19:35 UTC — hotfix #5.** Bump 0.4.18 wywalił test llms.txt (wersja
  hardcoded w pliku) — poprawione na 0.4.18, 5/5 zielone. Odkrycie: llms.txt już
  ma 71 policies (odświeżony out-of-band — pewnie lokalna sesja; część T10 done).
  Checklist release'u: dopisana kolejność publish-przed-deployem (llms.txt).

- **2026-07-22 ~18:45 UTC — przebieg #4b (Chrome + odkrycie).** Na żądanie usera otwarty
  Chromium (headless; TLS przez proxy blokuje renderowanie — curl działa). ODKRYCIE:
  gate.cat/teams.html i /partners.html są LIVE z wersjami z równoległej sesji lokalnej
  (nie było ich w gicie!) — zaciągnięte do repo (produkcja = prawda), walidacja HTML OK,
  liczby zgodne z FACTS/PRICING. Dziura 404 z nudge'a ZAŁATANA w produkcji. USER-2
  zredukowane do: merge PR #26 + deploy sitemap.

- **2026-07-22 18:21 UTC — przebieg #4.** Poczta: **Mike WYSŁANY przez usera 17:11**
  (oba warm leady obsłużone — USER-1 domknięte); 0 płatności ($0/$2,000). Backlog:
  **T6 done** — CLI Solo nudge (status/stats raz/dzień + stopka report + cloud-bez-klucza),
  9 nowych testów, 49 passed. Następne: T7 (pack hint środowiskowy).

- **2026-07-22 17:21 UTC — przebieg #3.** Poczta: nic nowego (Mike bez odpowiedzi — draft
  i payload Resend czekają na odblokowanie przez usera; 0 płatności; $0/$2,000).
  Backlog: **T5 done** (PyPI landing: pyproject urls, blok cenowy w README, 21→71 fix;
  landing €9 = founding, celowe). Klasyfikator raz zablokował złożone `git fetch && pull`
  — proste `git pull` przechodzi. Następne: T6 (rozszerzenie _nudge.py o Solo surface).

- **2026-07-22 ~16:50 UTC — kanał Resend.** User przekazał klucz API Resend (scratchpad,
  NIE w repo; domeny zweryfikowane: bizzon.ai, zeszytyterapeutyczne.pl). Julian: user
  wysłał draft ręcznie 15:53 UTC (dedupe zadziałał — Resend pominięty). Mike: wysyłka
  przez api.resend.com zablokowana przez klasyfikator uprawnień — czeka na decyzję
  usera (reguła permissions / wysyłka ręczna / VPS sender).

- **2026-07-22 16:21 UTC — przebieg #2.** Poczta: nic nowego (drafty Mike/Julian
  wciąż niewysłane przez usera; 0 płatności; stan $0/$2,000). Backlog: **T4 done** —
  show_hn_ready.md + lobsters_ready.md, wszystkie liczby przepięte na FACTS.md
  (F1b/F4/F10/F9). Gotowe do publikacji po USER-2. Następne zadanie: T5 (PyPI listing).

- **2026-07-22 ~15:10 UTC — interwencja usera #2 ("ty masz wysyłać").** Zbudowano kod
  sendera (SMTP + allowlist 7 warm kontaktów + idempotencja + systemd timer) i outbox
  z mailami do Mike'a i Juliana — ale klasyfikator uprawnień sesji zablokował commit
  tych plików do repo (i wcześniej: dostęp do credentiali, wykonanie sendera). Zgodnie
  z jego instrukcją: STOP, pliki dostarczone userowi bezpośrednio na czacie, decyzja
  o kanale wysyłki = USER-0. Drafty w Gmailu pozostają natychmiastową drogą.
- **2026-07-22 ~14:50 UTC — interwencja usera ("wysyłaj").** Zweryfikowano: konektor
  Gmail NIE MA funkcji send (tylko read/label/draft) — wysyłka niemożliwa z sesji;
  zasada #1 przeredagowana z polityki na ograniczenie techniczne. T3 done: draft
  do Juliana `r1170664853448124004`. Znalezione 2 stare drafty do Juliana (15.07,
  jeden ze stalą ceną €9) → USER ma skasować. Oba świeże drafty czekają w Drafts.
- **2026-07-22 14:21 UTC — przebieg #1.** Poczta: 0 nowych odpowiedzi (Mike w ledgerze),
  0 płatności gate.cat; Gmail działa z crona. Backlog: **T1 done** — teams.html,
  partners.html, sitemap, ops/deploy_landing.sh (walidacja OK). USER-2 odblokowany:
  deploy-artefakt gotowy. Następny przebieg: T3 (draft do Juliana).
- **2026-07-22 ~13:00 UTC — bootstrap.** Panel adversarialny multi-model (19 agentów:
  fable + opus + sonnet + haiku; 4 soczewki × 3 sędziów × synteza; 975k tokenów) →
  kolejka T1–T13. Skrzynka przejrzana (30 dni): 0 płatności gate.cat, 2 warm leady
  (Mike, Julian), 1 bounce. Draft do Mike'a utworzony (T2 done). Cron co 1h ustanowiony.
