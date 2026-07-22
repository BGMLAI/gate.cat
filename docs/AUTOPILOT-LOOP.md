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
2. **Zero cold-outreach** — drafty tylko w istniejących wątkach (odpowiedzi na
   odpowiedzi) lub do adresów, z którymi Bogumił już korespondował.
3. **Liczby publiczne wyłącznie z FACTS.md** — nowa liczba = najpierw wiersz
   w FACTS.md z artefaktem pomiaru. Żadnych zmyślonych metryk, opinii, klientów.
4. **Zero wydawania pieniędzy** — żadnych zmian w Stripe (ceny/produkty), żadnych
   sponsoringów, żadnych zakupów. Decyzje finansowe → sekcja [USER].
5. **Zero publikacji** — PyPI publish, deploy na VPS, posty na HN/socialach robi
   tylko Bogumił; agent przygotowuje paste-ready artefakty w `ops/launch/`.
6. **Git**: commit + `git push -u origin claude/email-cron-strategy-automation-drmkv4`
   (retry 2s/4s/8s/16s), nigdy na master; draft PR utrzymywany na bieżąco.
7. **Dedupe draftów**: przed `create_draft` sprawdź `list_drafts` + ledger niżej
   + czy w wątku nie ma już naszej odpowiedzi po ostatniej wiadomości rozmówcy.
8. **Kod = testy zielone** (`python -m pytest -q` dla dotkniętych ścieżek);
   copy = spójne z FACTS.md. SPRZEDAŻ > kosmetyka.

## CEL I STAN

| Metryka | Wartość | Stan na |
|---|---|---|
| Przychód gate.cat (potwierdzony w Gmail/Stripe) | **$0 / $2,000** | 2026-07-22 |
| Pobrania PyPI (trailing month, bez mirrorów) | 2,528 (F13; 1,588 → 2,528 w 11 dni) | 2026-07-22 |
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

## KOLEJKA (backlog agenta)

_Synteza panelu 2026-07-22 (4 propozycje, 12 krytyk sędziów, wszystkie kluczowe fakty zweryfikowane w repo). Uczciwa rama sędziów: żadne pojedyncze zadanie nie domyka $2,000 — realna 30-dniowa gotówka to warm threads + Show HN + odblokowanie martwych linków, na które celuje już wysłany nudge 0.4.17; reszta to konwersja i higiena. Kolejność: oczekiwane $ / effort / time-to-cash._

- [x] **T1 — Napraw martwe linki lejka: docs/teams.html + docs/partners.html (jeden PR)** — WYKONANE 2026-07-22 przebieg #1: obie strony zbudowane (standalone, paleta index.html, zero JS; wszystkie liczby wg allowed-wording z FACTS.md F1b/F2/F3 + PRICING.md; policy sharing opisane jako "rolling out" zamiast datowanej obietnicy — patrz T10), sitemap.xml uzupełniony, `ops/deploy_landing.sh` gotowy (rsync bez --delete, sha256 verify, curl 200, restart gatecat-fulfill). HTML/XML zwalidowane. Live po USER-2. Oryginalna spec: — `gatecat/_nudge.py` (shipped w 0.4.17, odpala się po pierwszym realnym veto na każdej maszynie) oraz README.md:285/292 kierują na gate.cat/teams.html i /partners.html, których nie ma w docs/ (żywe 404 — zweryfikowane). Zbuduj obie jako standalone strony na layoucie index.html (bez przebudowy bundla): teams.html = Team €149 value prop + wpleciona verbatim kopia audit-pilot z PRICING.md:109-127 + live Stripe links (Team `buy.stripe.com/9B66oA5xj2eIaly2Vo67S0a`, Business `...7sYdR2e3PcTm2T6cvY67S0b`); partners.html = 30% lifetime-recurring + mailto CTA (affiliate.py nie ma self-serve signup). Do tego `ops/deploy_landing.sh` (artefakt dla USER-2). Acceptance: wpisy w sitemap.xml, każda liczba ma wiersz w FACTS.md/PRICING.md, jeden PR gotowy do merge; live dopiero po USER-2. _(impact: $150-600 (sufit wg sędziów), effort: M, B2B+PRODUCT-LED, 6.7/5.0)_
- [x] **T2 — Gmail draft do Mike'a Privette (Return on Security), wątek 19f669c061fe1503** — WYKONANE 2026-07-22 przy bootstrapie: draft `r-7583389221339500184` w wątku; szczere liczby wyłącznie z FACTS.md (2,528 pobrań/30d, 0 real misses / 1,085,159 komend, revenue day-zero podane wprost), oferta danych do mapy kategorii "Agent Runtime Security". → USER-1: wyślij.
- [x] **T3 — Gmail draft do Juliana Goldie: affiliate ≠ sponsoring, wątek 19f675a02242badf** — WYKONANE 2026-07-22: draft `r1170664853448124004` (reply do 19f75bbfe62653c7); zero zobowiązań finansowych, matematyka prowizji z cennika, link do partners.html (wyślij po deploy'u USER-2 albo zaraz — strona wstanie za chwilę). UWAGA: w Draftach wiszą 2 STARE drafty do Juliana z 2026-07-15 (`r6116468691101999441`, `r-7678200491588625290` — jeden ze stalą ceną €9) → user powinien je skasować. Oryginalna spec: — Julian odpisał cennikiem płatnych sponsoringów, a oferta to darmowy 30% lifetime-recurring affiliate (README:289-292); draftuj do nowszego z dwóch zduplikowanych wątków i odnotuj duplikat. Jedna klaryfikacja bez zobowiązań: zero upfront spend, link do partners.html (po T1) albo sekcji README, decyzję o płatnym sponsoringu zostaw explicite Bogumiłowi. Acceptance: draft w wątku, żadnych obietnic wydatków. _(impact: $0-800 opcjonalność, effort: S, B2B, 6.7)_
- [ ] **T4 — Odśwież i fact-checkuj paczkę Show HN (+ warunkowy wariant lobste.rs)** — Nie pisz od zera: zweryfikuj istniejący draft z docs/LAUNCH_KIT_2026-07-14.md przeciw FACTS.md (fix sędziów: popraw konflację "4 allowed commands"/false-block wg F4 = 178/178 i 1/129 benign; €19 nie €9; 71 policies wg F9), dopisz first-comment z live checkout links i linią "one-command install" jeśli T11 zmergowane. Zapisz ops/launch/show_hn_ready.md + ops/launch/lobsters_ready.md (lobste.rs jest invite-only — wariant tylko-jeśli-konto). Acceptance: każda liczba ma wiersz w FACTS.md, posty paste-ready bez dalszej edycji. _(impact: odblokowuje $200-1000 przez USER-4, effort: S, DISTRIBUTION, 4.8)_
- [ ] **T5 — PyPI listing jako landing page (do release-PR 0.4.18)** — pyproject.toml [project.urls] (linie 93-96) kieruje Homepage/Repository/Issues na repo z 0 stars: dodaj `Homepage=https://gate.cat` i `Pricing=https://gate.cat/#pricing?source=pypi`; wstaw 4-linijkowy blok "Free forever · Cloud Solo €19/mo · Team €149 · Packs €29" zaraz pod sekcją install README (pricing dziś na linii ~265/619); grep i uzgodnij stale liczby (€9, 21/69 policies → €19, 71). Acceptance: zero sprzeczności liczbowych w repo, zmiany w release-PR 0.4.18 z checklistą publication-gate; publish = USER-3. _(impact: $50-250, effort: S, CONVERSION, 4.8)_
- [ ] **T6 — Rozszerz istniejący _nudge.py o Solo surface (NIE reimplementuj)** — Post-veto nudge już jest w 0.4.17; dodaj rate-limitowane (raz/dzień, `~/.gatecat/nudge_last`) linie: status/stats przy blocked>0 bez cloud key, stopka raportu, `cloud` bez klucza → krótki pitch + gate.cat/#pricing?source=cli; copy verbatim z PRICING.md, respektuj GATECAT_NO_NUDGE/GATECAT_QUIET. Acceptance: testy zielone, nigdy dwa nudge w jednym przebiegu (koordynacja z T7), wchodzi do 0.4.18; zasięg uczciwie = tylko nowe instalacje od publish (fix sędziów). _(impact: $100-400 (sufit), effort: S, CONVERSION, 4.8)_
- [ ] **T7 — Pack hint środowiskowy (gatecat/_pack_hint.py)** — `shutil.which()` na stripe/vercel/fly/netlify/railway/supabase/heroku → jedna uczciwa linia o pasującym packu €29 (scope verbatim z PRICING.md:72-74), max raz na maszynę (`~/.gatecat/.pack_nudged`), opt-out i best-effort pattern skopiowany z _nudge.py. Packi to najtańszy zakup w katalogu z w pełni automatycznym fulfillmentem. Acceptance: unit test doboru packa i wykluczeń, brak stackowania z T6 w jednym przebiegu, do 0.4.18. _(impact: $58-290, effort: S, PRODUCT-LED, 5.0)_
- [ ] **T8 — `gate.cat report`: lokalny raport w kształcie płatnego** — Nowa komenda renderuje WŁASNY lokalny veto log użytkownika w layoucie docs/SAMPLE_REPORT.md z watermarkiem "paid layer trzyma tę kopię off-machine, poza zasięgiem agenta" + CTA Solo €19/Team €149; discovery wg fixu sędziów: jedna linia w komunikatach T6 wskazuje komendę (inaczej nikt jej nie odpali). Acceptance: działa na pustym i niepustym logu, testy przechodzą, do 0.4.18/0.4.19. _(impact: $100-500 (sufit), effort: M, PRODUCT-LED, 5.0)_
- [ ] **T9 — Cross-sell na stronie fulfillment packów** — PAGE template w products/cloud/gatecat_fulfill.py: sekcja "Complete your coverage" z dwoma nie-kupionymi packami (linki z PRICING.md:72-74 z `?source=pack-xsell`) + jedna linia Cloud Solo €19; bez zmian w Stripe. Acceptance: unit test wykluczenia kupionego modułu (MODULE_FOR); live wymaga restartu usługi na VPS (USER-2). Label sędziów: EV ≈ 0 do pierwszej sprzedaży packa — dlatego ta pozycja, nie wyżej. _(impact: $29-200, effort: S, CONVERSION, 4.8)_
- [ ] **T10 — Higiena prawdy: llms.txt, sitemap 404, Lemon Squeezy "pending"** — docs/llms.txt: 65/65→178/178 (F4) i v0.4.3→0.4.17 (F9); sitemap.xml: usuń/przekieruj 5 martwych wpisów /answers/* (budowa stron odrzucona jako revenue-driver); PRICING.md:56 "review is pending" → LS odrzucone 2026-07-14 + default `payment_channel()` w cloud_activate.py na stripe; sprawdź obietnicę "ships this month" (PRICING.md:50) i jeśli fleet policy nie wejdzie do ~2026-08-01, przygotuj PR łagodzący wording. Acceptance: diff przeciw FACTS.md czysty; PR wyraźnie flaguje odwrócenie decyzji foundera z 2026-07-12 i wymaga sign-off przed merge. _(impact: ~$0 (risk-avoidance), effort: S, DISTRIBUTION+B2B, 4.8/6.7)_
- [ ] **T11 — Claude Code plugin-marketplace manifest** — `.claude-plugin/marketplace.json` + `plugin.json` opakowujące istniejący PreToolUse hook (examples/veto_integrations/claude_code_hook/); fix sędziów: najpierw WebFetch oficjalnej dokumentacji schematu — nie zgaduj formatu; weryfikacja załadowania = owner po merge, nie agent. Wartość głównie jako linia "one-command install" w poście HN (T4). Acceptance: manifest przechodzi walidację składni JSON wobec udokumentowanego schematu, PR otwarty. _(impact: $0-150 (obniżone przez sędziów), effort: M, DISTRIBUTION, 4.8)_
- [ ] **T12 — daily_funnel.py testowany na fixture (bez SSH z sandboxa)** — Skrypt parsuje events log przez funnel_report.py i appenduje JSON-line {date, page_view, install_copy, checkout_click, top_sources} do METRICS.log; w środowisku agenta NIE ma klucza VPS, więc acceptance = unit test na fixture w repo + instrukcja uruchomienia tam gdzie jest klucz (wzorzec SSH z scripts/launch_metrics.py). Fix sędziów: to pomiar, nie przychód — niczego nie blokuje i nie twierdzimy "pierwszego realnego snapshotu" z sandboxa. _(impact: $0 (pomiar do iteracji), effort: S, CONVERSION, 4.8)_
- [ ] **T13 — LinkedIn DM do Dimitriosa Kaprilisa (artefakt dla USER-5)** — `ops/launch/dm_dimitrios.md` wg fixu sędziów: najpierw merytoryczna odpowiedź na jego publiczne pytanie o policies (z F1b), dopiero potem oferta bezpłatnego Team + audit-pilot review za zgodę na cytowanie wyniku. Acceptance: paste-ready DM, zero liczb spoza FACTS.md. _(impact: design-partner opcjonalność, effort: S, B2B)_

## [USER] — czeka na Bogumiła

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
2. **Zmerguj PR #26 i wgraj site na VPS** — bez tego nudge z 0.4.17 codziennie
   strzela w 404, a T1/T9/T10 zarabiają $0. Artefakt GOTOWY: `ops/deploy_landing.sh`
   (uruchom z maszyny z kluczem VPS; `DRY_RUN=1` na próbę).
3. **Opublikuj gate-cat 0.4.18 na PyPI** — po release-PR (T5+T6+T7, opcjonalnie T8)
   z checklistą publication-gate z docs/LAUNCH_0.4.16.md; agent nie może publikować.
4. **Post Show HN — najlepiej PO kroku 2** (ruch ma trafiać na naprawione strony).
   Artefakt: `ops/launch/show_hn_ready.md` (T4); opcjonalnie lobste.rs, jeśli masz konto.
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
| 19f669c061fe1503 | Mike Privette (Return on Security) | 2026-07-22 | draft `r-7583389221339500184` utworzony (T2); czeka na wysyłkę → USER-1 |
| 19f675a02242badf / 19f668f7b6a127eb | Julian Goldie (duplikat wątku) | 2026-07-22 | draft `r1170664853448124004` w nowszym wątku (T3); czeka na wysyłkę → USER-1 |
| 19f7acd133235366 | grzegorz@grzegorzlapanowski.pl | 2026-07-19 | bounce (serwer odbiorcy); brak akcji agenta — nr tel. ma user |

## LOG PĘTLI

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
