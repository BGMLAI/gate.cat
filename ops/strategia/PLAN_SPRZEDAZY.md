# PLAN SPRZEDAŻY gate.cat — jedno źródło prawdy

**Pinned 2026-07-31.** Zastępuje operacyjnie sześć dokumentów `.docx` z 30.07
(00–05) oraz rozjazd między dwoma równoległymi celami ($2 000 w
`docs/AUTOPILOT-LOOP.md` vs €2 000 „Próg 0" rady). Dokumenty 00–05 zostają jako
**zapis diagnozy** — ich §diagnoza i §werdykty są nadal ważne i nie są tu
powtarzane. Ten plik jest tym, co się **robi**.

Kiedy ten plik i `.docx` się nie zgadzają — wygrywa ten plik.
Kiedy ten plik i `FACTS.md` na masterze się nie zgadzają w liczbie publicznej —
**wygrywa FACTS.md, zawsze, bez wyjątku.**

---

## 0. Jedno zdanie

Produkt jest gotowy, kanał dowozi ludzi, którzy z definicji nie kupują, a cena
jest ustawiona tak, że nawet pełny sukces obecnego planu daje 2% celu — więc
kolejność jest: **naprawić cenę → zmierzyć ból u klienta → sprzedać
osiemnastu, nie trzystu sześćdziesięciu ośmiu.**

---

## 1. Stan faktyczny na 31.07 (uzgodniony z repo, nie z .docx)

Dokumenty 00–05 opisują 30.07. Poniżej różnice, które zaszły przez jeden dzień
i które zmieniają listę zadań:

| Pozycja | Stan wg .docx (30.07) | Stan faktyczny (31.07) |
|---|---|---|
| CI na masterze | 🔴 czerwone od 29.07, „logów nie odczytam — przeglądarka niezalogowana" | Awaria z 29.07 minęła. Ostatnia czerwień (`7eb5596`) miała inną przyczynę: `test_marketing_consistency` wykrył martwy JS Lemon Squeezy na landingu. Commit `5b46e90` to naprawił i **CI na masterze jest zielone** (run 30658644573, wszystkie trzy joby 3.11/3.12/3.13). Czyli `FACTS.md` F3 „CI green on Python 3.11–3.13" jest znów prawdziwe i wolno go cytować. **`gh` jest zalogowane jako BGMLAI — logi CI są czytelne z terminala, blokada „nie mam dostępu" nie istnieje.** |
| Landing: „69 policies", „V0.4.11" | 🔴 do naprawy przez człowieka, wymaga deployu | ✅ Naprawione w repo (`073ae27`): 71 polityk, 826 644, stary token wersji usunięty. **Zostaje sam deploy na VPS.** |
| `ops/tools/gatecat_retroscan.py` | ✅ „ZBUDOWANE 29.07, 45/45 testów" | ❌ **Nie istnieje w tym repo.** Powstało na maszynie Windows i nigdy nie trafiło do gita. Odbudowane 31.07 (patrz §7). |
| `ops/machine/`, `ops/strategia/` | „zsynchronizowane dziś" | Nie istniały tutaj do 31.07. Ten plik zakłada `ops/strategia/`. |
| Pobrania PyPI | 2 652 | 2 725 (`docs/launch_metrics.log`, 31.07 19:08) |
| GitHub stars | 3 | 2 — **jedna gwiazdka ubyła** (`METRICS.log` 31.07) |
| Pętla autopilota | nieopisana w .docx | Działa co godzinę na `claude/email-cron-strategy-automation-drmkv4`, ma **własny cel $2 000** i własny backlog. Od dziś jej cel = Próg 0 z §2.4. |

**Niezmienione i nadal prawdziwe:** 0 płacących klientów, 0 € MRR, 91
nieopłaconych checkoutów o wzorcu card-testingu, trzy konta Stripe z
wstrzymanymi payoutami, Workspace pada 4.08.

---

## 2. Cel: 10 000 instalacji + $10 000 MRR — arytmetyka, zanim cokolwiek zrobimy

### 2.1. „10 000 instalacji" — najpierw ustalmy, która to liczba

To nie jest jedna metryka, tylko trzy, różniące się o dwa rzędy wielkości:

| Metryka | Dziś | Do 10 000 | Uczciwa ocena |
|---|---|---|---|
| Pobrania PyPI bez znanych mirrorów | 2 725 | ×3,7 | **Osiągalne w 4–8 miesięcy.** Ale rada ma rację: dla świeżego pakietu 70–95% tego to mirrory, CI, dependabot i skanery. Baza 2 482 pobrań **sprzed** launchu to przesądza — pakiet był ściągany, zanim ktokolwiek o nim wiedział. |
| Realne ludzkie instalacje | 10–40 (szacunek rady) | ×250–1000 | Nierealne w horyzoncie roku bez audytorium. |
| **Aktywacje** — realnie zainstalowany hook Claude Code, który cokolwiek zawetował | nie mierzone | — | **To jest metryka, której nam brakuje i którą da się mieć uczciwie.** |

**Decyzja:** „10 000 instalacji" prowadzimy jako **pobrania PyPI bez mirrorów**
(bo taka jest metryka, którą już mamy i którą FACTS.md pozwala cytować —
zawsze jako *downloads*, nigdy jako *users*), a obok budujemy **licznik
aktywacji**, bo to on, a nie pobrania, koreluje z przychodem.

Twarda zasada, wprost z F13a: **nigdy „2 725 użytkowników" ani „2 725
instalacji".** Mirrory, CI i boty siedzą w tej liczbie.

### 2.2. $10 000 MRR — ilu klientów, po przepisaniu cennika

$10 000 ≈ **€9 200/mies.** (kurs zmienny — traktować jako rząd wielkości, nie
zobowiązanie).

| Ścieżka | Klientów do €9 200 | Realizm |
|---|---|---|
| Solo €19 | **484** | Wykluczone. To jest dokładnie ta arytmetyka, która dała 0 zł. |
| Team €299 | 31 | Trudne — 31 zespołów bez audytorium |
| Business €399 | **23** | Możliwe, długo |
| Compliance €1 100 | **9** | ✅ Najkrótsza droga self-serve |
| OEM/embed €7–15k | **1** | ✅ Najkrótsza droga w ogóle |
| Licencja korpusu €10–40k/rok | 1 = €830–3 300/mies. | Nie MRR, ale liczy się do progu |

**Realistyczny miks docelowy, nie jedna kolumna:**
2 × Compliance (€2 200) + 10 × Business (€3 990) + 8 × Team (€2 392) +
1 licencja korpusu €25k/rok (€2 083) = **€10 665/mies. ≈ $11 600.**
To **21 kont**, nie 484. Cała różnica siedzi w cenniku, nie w marketingu.

### 2.3. Wiążące ograniczenie to godziny, nie pomysły

Rada policzyła uczciwie i nie ma sensu tego negocjować: przy **1–2 h/dzień**
budżet czasowy wystarcza na €2–4k MRR w rok, nie na €12k. Prawdopodobieństwo
€7k MRR w 12 miesięcy: **<5% self-serve, 35–45% sales-led + usługi + korpus.**

Z tego wynika jedyny uczciwy warunkowy zapis celu:

> **$10k MRR jest osiągalne — ale nie na 1–2 h/dzień.** Do zamknięcia jednego
> kontraktu Compliance albo OEM trzeba rozmów sprzedażowych, a rozmowy
> sprzedażowej nie da się zdelegować agentowi. Wersja mieszcząca się w 1–2
> h/dzień to Próg 0 → Próg A. Wersja $10k wymaga albo (a) wyjścia powyżej 2
> h/dzień na 2–3 miesiące wokół kontraktu OEM, albo (b) jednej umowy
> korpusowej, która kupuje czas na resztę.

Wszystko, co poniżej, jest zaprojektowane pod to ograniczenie: **research,
listy, personalizacja, drafty i pomiary idą przez agenta; człowiek wchodzi
wyłącznie tam, gdzie jest nieusuwalny — rozmowa, decyzja cenowa, podpis,
płatność.** Każdy plan zakładający codzienną ludzką dyscyplinę outboundową
zostanie niewykonany — dane z sześciu dni to pokazały i nie jest to zarzut,
tylko parametr.

### 2.4. Kamienie milowe — i co je falsyfikuje

| Próg | Wartość | Termin | Co go falsyfikuje |
|---|---|---|---|
| **Próg −1** | pierwsza złotówka *czegokolwiek* (usługa retro-scan, nie subskrypcja) | tydzień 4–8 (do 25.09) | brak = kategoria nie kupuje od nas w tej formie |
| **Próg 0** | **€2 000 MRR** — ujednolicony cel pętli autopilota i rady | koniec 2026 | brak = model self-serve zamknięty, zostaje OEM albo koniec |
| **Próg A** | €7 000 MRR | mies. 11–15; mies. 8 przy jednym kontrakcie korpusowym | — |
| **Próg B — cel użytkownika** | **€9 200 ≈ $10 000 MRR** | mies. 20–30 *albo* mies. 6–9 przy jednym OEM | — |
| **Cel instalacji** | 10 000 pobrań PyPI bez mirrorów | ~4–8 mies. | — |

Próg −1 jest najważniejszy w tej tabeli. Wszystko powyżej niego to
ekstrapolacja z próby zerowej.

---

## 3. Dwa tory, których nie wolno mieszać

To jest błąd, który kosztował tydzień: **instalacje i przychód to dwa różne
lejki z dwoma różnymi ludźmi na końcu.** Darmowy rdzeń trafia przez PyPI do
solo-devów. Warstwa płatna ma wartość wyłącznie dla zespołu, audytora albo
kogoś z zobowiązaniem umownym. Solo-dev **nigdy** nie zapłaci za audit log
własnych komend — on jest jedynym audytorem.

| | **TOR I — instalacje** | **TOR II — przychód** |
|---|---|---|
| Cel | 10 000 pobrań | $10k MRR |
| Odbiorca | solo-dev, hobbysta, CI | właściciel/CTO software house'u 20–100 os. |
| Kanał | PyPI, GitHub, r/ClaudeCode, katalogi, wtyczka Claude Code | ciepły outbound 1:1, retro-scan, rekomendacja |
| Metryka | pobrania + aktywacje | rozmowy → oferty → podpisy |
| Kto robi | **agent, w całości** | **człowiek na ostatnim metrze** |
| Rola | dowód jakości i dystrybucja; **nie jest lejkiem sprzedażowym** | jedyne źródło pieniędzy |

Tor I **nie karmi** Toru II i przestajemy udawać, że karmi. Tor I ma sens jako
dowód („2 725 pobrań, 71 polityk, korpus 826 644") pokazywany w Torze II — i
tylko w tej roli.

---

## 4. Drabina działań — uporządkowana według „co blokuje co"

### 4.1. 🔴 STOPIEŃ 0 — egzystencjalne, tylko człowiek, przed czymkolwiek innym

Dopóki to nie jest zrobione, cała reszta jest teoretyczna, bo **nie mamy
zdolności przyjęcia pieniędzy.**

| # | Co | Dlaczego to jest stopień 0 | Czas |
|---|---|---|---|
| 0.1 | **Stripe KYC na trzech kontach** — dashboard.stripe.com → Account status | Payouty wstrzymane od 27.07. Przy 91 nieopłaconych checkoutach o wzorcu card-testingu Stripe zamyka konta. Ryzykujemy utratę zdolności przyjmowania pieniędzy **zanim** pojawi się pierwszy klient. | 1 posiedzenie |
| 0.2 | **Wyłączyć publiczne Payment Linki + włączyć Radar rules** | To jest źródło 91 checkoutów. Nie naprawia się tego copywritingiem. | 15 min |
| 0.3 | **Przetestować pełny checkout własną kartą** | Przy 0 subskrypcji **od zawsze** nie mamy żadnego dowodu, że pipeline płatności w ogóle działa. To 20 minut o najwyższej wartości w całym planie. | 20 min |
| 0.4 | **Opłacić Google Workspace** | Pada 4.08. Bez skrzynki pada cały silnik mailowy. | 10 min |
| 0.5 | **Deploy `docs/` na VPS** (`ops/deploy_landing.sh`) | Poprawki liczb siedzą w repo od 31.07 i nie są live. Zaprosiliśmy sześciu dziennikarzy do sprawdzania naszych liczb. | 3 min |

> ⚠️ 0.3 jest niezależne od 0.1 i nie czeka na nie. Jeśli pipeline płatności
> jest zepsuty, chcemy to wiedzieć **dziś**, a nie w dniu pierwszego klienta.

### 4.2. 🟠 STOPIEŃ 1 — odblokować możliwość sprzedaży B2B (agent robi, człowiek zatwierdza)

Rada: ~4 h roboty blokujące **100%** sprzedaży B2B. Software house nie kupi bez
faktury, a firma w trakcie SOC 2 nie kupi bez DPA.

| # | Co | Właściciel | Stan |
|---|---|---|---|
| 1.1 | Cennik wg rekomendacji rady — Solo jako kotwica, Team €299, Business €399, **Compliance €900–1200**, wdrożenie €1500–2500, packi → subskrypcja | agent pisze / człowiek decyduje i klika w Stripe | ✅ zatwierdzone 31.07 |
| 1.2 | DPA (wzór), lista subprocesorów, security one-pager, ścieżka „faktura + przelew + odwrotne obciążenie" | agent | ✅ 31.07 |
| 1.3 | **Produkty i ceny w Stripe + nowe Payment Linki** | ⚠️ **tylko człowiek** | czeka |
| 1.4 | Rozważyć Merchant of Record zamiast gołego Stripe'a | człowiek | decyzja odłożona — nie blokuje 1.3 |

### 4.3. 🟡 STOPIEŃ 2 — test E-6, jedyny zaplanowany eksperyment (start 3.08, odczyt 11.08)

**Hipoteza:** darmowy retro-scan na danych prospekta otwiera rozmowę, której
nie otwiera żaden komunikat marketingowy — bo strach pochodzi z jego liczb, nie
z naszych.

**ICP:** właściciel/CTO software house'u albo agencji **20–100 osób pracującej
na infrastrukturze klientów**, która dała zespołowi Claude Code lub Cursor.
Kupuje **odpowiedzialność kontraktową**, nie compliance. Decyzja jednoosobowa,
budżet uznaniowy, może przerzucić koszt na klienta jako pozycję w SOW. Bez
procurementu, bez sześciomiesięcznego cyklu.

**Próg: ≥2 z 20 prospektów przyjmuje skan I umawia rozmowę o wersji płatnej.**

> Wynik <2/20 znaczy **zmiana kierunku, a nie „popracujmy nad copy".**
> Ten zapis istnieje po to, żeby 11.08 nie dało się go zracjonalizować.

Nigdy: CISO w enterprise (jesteśmy za mali, poproszą o nasz SOC 2). Nigdy:
solo-dev, w żadnej cenie.

### 4.4. 🟢 STOPIEŃ 3 — tor lumpy revenue (równolegle, niski koszt czasu)

| # | Co | Dlaczego |
|---|---|---|
| 3.1 | **Licencja korpusu** — wydzielona spod Apache 2.0 31.07 ✅ | Naszego silnika ktoś odtworzy w weekend. Korpusu 826 644 nie odtworzy. Jedna umowa = 2–6 miesięcy celu, zero supportu, zero churnu. |
| 3.2 | Lista 10 kupujących korpus: dostawcy harnessów i sandboxów, zespoły budujące własne agenty, które muszą pokazać eval bezpieczeństwa | Rynek jest finansowany (CodeIntegrity zebrało rundę dokładnie na ten problem) |
| 3.3 | Płatny przebieg „przejedź swojego agenta przez nasz benchmark" | gotówka z usługi najpierw, MRR potem |
| 3.4 | Jeden kontrakt OEM/embed €7–15k/mies. | 6 klientów zamiast 368 — jedyna ścieżka do $10k mieszcząca się blisko budżetu czasu |

---

## 5. Kanały zamknięte — nie otwierać ponownie bez nowego dowodu

Wzorzec potwierdzony pięć razy w jednym tygodniu: **uwaga w tej kategorii jest
towarem na sprzedaż, a nie nagrodą za jakość zgłoszenia.**

| Kanał | Werdykt |
|---|---|
| Product Hunt | ❌ 5 upvote'ów, 0 wpływu na pobrania. Bez relaunchu. |
| Maile do YouTuberów | ❌ 45 maili → 2 odpowiedzi → 0 publikacji |
| AlphaSignal / Julian Goldie | ❌ tylko płatne placementy, brak ścieżki prowizyjnej |
| Nowe PR-y do awesome-list | ❌ 0/8 zmergowanych |
| Konta brandowe @gatecat | ❌ odłożone — 12–24 mies. budowy zasięgu od zera |
| Promowanie Solo €19 | ❌ wymaga 484 klientów do celu |
| **Hacker News** | ⛔ **konto `bgmlai` zbanowane. NIGDY drugie konto — ban evasion to ban domeny gate.cat na zawsze.** |
| Reddit jako *kanał wzrostu* | ⚠️ sufit ~75–100 kliknięć/mies. Odpowiadać, gdy ktoś pyta; przestać traktować jako dystrybucję. r/ClaudeCode zostaje — jedyny kanał z realną rozmową techniczną i najbliżej nowego ICP. |

**Czego wynik Product Hunta NIE dowodzi:** że produkt jest zły ani że nikt nie
zapłaci. Dowodzi, że PH nie konwertuje na B2B security tooling. Próba ma
rozmiar zero — cennik przepisujemy dlatego, że linia free/paid jest niezależnie
źle postawiona, a nie w panice po sygnale z próby zerowej.

---

## 6. Reguły nadrzędne — obowiązują bezwzględnie

1. **Żadna liczba nie wychodzi na zewnątrz, zanim nie zostanie odczytana z
   `FACTS.md` na masterze w TEJ SAMEJ turze.** Dotyczy też liczb
   „pamiętanych" — dokładnie tak w jeden dzień powstały trzy błędy (korpus,
   liczba obejść, pobrania PyPI), z czego jeden trafił do sześciu dziennikarzy
   i wymagał sprostowań. Pliki w `ops/launch/` to kopie robocze, **nie** źródło
   prawdy.
2. **Art. 50 EU AI Act NIGDY jako powód zakupu gate.cat.** Art. 50 dotyczy
   transparentności wobec ludzi, nie nakłada obowiązku logowania wewnętrznego
   agenta kodującego. U nas występuje wyłącznie jako obowiązek nałożony **na
   nas** (disclosure automatyzacji). Pierwszy kompetentny compliance buyer
   wyłapie nadużycie i wtedy stracimy wiarygodność wszystkich pozostałych
   liczb — a wiarygodność dowodowa to jedyne aktywo, jakie mamy.
   Prawdziwe haki: SOC 2 CC8.1 / CC6.1 / CC7.2, ISO 42001, ISO 27001 A.8.x,
   ankiety bezpieczeństwa, NIS2 art. 21. Trigger: audytor pyta „agenty piszą
   kod, wołają API i modyfikują środowisko — co autoryzowało te zmiany?",
   a odpowiedź brzmi „nic".
3. **Honest line w każdym materiale o skuteczności:** *the gate is certain only
   about what it blocks; an unmatched action is unchecked, not safe.* Luki
   nazywamy pierwsi — bypass map to feature.
4. **Szkic to nie jest wykonana praca.** Zostawianie gotowych maili w szkicach
   było głównym błędem operacyjnym pierwszego tygodnia (narosło 361 szkiców).
   Każdą wysyłkę weryfikować osobno przez `in:sent` — toast „wysłano" potrafi
   skłamać.
5. **Zakazy bezwzględne:** fałszywe persony, sieci kont, kupowanie
   zaangażowania, drugie konto na HN, automatyzacja przeglądarki na
   LinkedIn/Meta, drugi auto-post w tym samym wątku.
6. **Stop-loss:** 2 sygnały moderacyjne na kanale = pauza kanału + push.
7. **Zero wydawania pieniędzy przez agenta** — żadnych zmian cen w Stripe,
   sponsoringów, zakupów. Decyzje finansowe zawsze do człowieka.

---

## 7. Rejestr decyzji i wykonania — 31.07

| Decyzja | Kto | Stan |
|---|---|---|
| Cennik wg pełnej rekomendacji rady | człowiek 31.07 | wdrażane w repo, Stripe czeka |
| Korpus i benchmark spod Apache 2.0 | człowiek 31.07 | ✅ `LICENSE-CORPUS`, `NOTICE`, `LICENSING.md`, `results/LICENSE.md` |
| Retro-scan: budować, nie wysyłać samodzielnie | człowiek 31.07 | odbudowa w toku |
| Cel pętli autopilota ujednolicony z Progiem 0 (€2 000) | agent 31.07 | do naniesienia w `docs/AUTOPILOT-LOOP.md` |

**Ważne uściślenie do decyzji o licencji.** Rada napisała „korpus, **packi i
suite regresyjny** muszą wyjść spod Apache 2.0". Wykonane węziej i celowo:
`gatecat/integrations/policies.py` (71 ścian) i `bypass_suite.py` **zostają
Apache-2.0**, bo jadą w pakiecie pip i są tym „free forever, complete, nothing
held back", które jest całą dystrybucją i całym Torem I. Wyjęcie ich zabiłoby
cel 10 000 instalacji dla przychodu, którego jeszcze nie ma.
`scripts/recall_danger_axis.py` też zostaje Apache-2.0 — to on pozwala każdemu
odtworzyć naszą główną liczbę recall bez datasetów, a claim, którego nikt nie
może przebiec, jest plotką. Pod licencję komercyjną poszło to, co faktycznie
jest nie do odtworzenia w weekend: harness dużego korpusu i zaadjudykowane
artefakty wyników. Licencja **wprost** zachowuje prawo do czytania,
przebiegania i **publikowania wyników sprzecznych z naszymi**, za darmo i bez
pytania — bo dostawca bezpieczeństwa, którego liczb nie da się sprawdzić, nie
ma czego sprzedawać.

---

## 8. Gdzie ten plan może się mylić

- **„0 subskrypcji dowodzi, że nikt nie zapłaci" — nie dowodzi.** Dowodzi, że
  nikt nie widział. Próba ma rozmiar zero.
- **Retro-scan może nie zadziałać z powodu, którego E-6 nie zmierzy:** prospekt
  może odmówić uruchomienia czegokolwiek na swoich transkryptach niezależnie od
  wartości raportu. Dlatego narzędzie jest bezzależnościowe, bezsieciowe,
  read-only i redaguje sekrety — ale jeśli odmowy będą z tego powodu, wynik
  <2/20 znaczy co innego niż „ICP nie ma bólu". **Zapisać powód każdej odmowy.**
- **Metryka 10 000 pobrań może zostać osiągnięta bez żadnego wpływu na
  przychód** i to jest scenariusz bazowy, nie porażka pomiaru. §3 istnieje po
  to, żeby nikt nie odczytał tego jako postępu w Torze II.
- **Rekomendacja „sprzedaj aktywo / acqui-hire"** padła na radzie jako opcja o
  potencjalnie wyższej wartości oczekiwanej niż budowanie MRR przy tym budżecie
  czasu. Odnotowana, bo padła. To nie jest decyzja, którą podejmuje agent.
