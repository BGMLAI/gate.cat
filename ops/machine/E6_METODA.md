# E-6 — metoda, szablony, kryteria kwalifikacji

Start 03.08, odczyt 11.08. Próg: **≥2/20 przyjmuje skan I umawia rozmowę.**

> ⚠️ **Lista nazwanych firm i kontaktów NIE trafia do tego repo.** Repo jest
> publiczne, a reguła 9 playbooka zakazuje artefaktów imiennego outreachu w
> commitach. Lista żyje poza repo i jest dostarczana człowiekowi bezpośrednio.
> Ten plik zawiera **metodę**, którą można powtórzyć na dowolnej liście.

---

## 1. Kryteria kwalifikacji — twarde

Prospekt wchodzi na listę tylko z kompletem:

| Kryterium | Waga | Jak weryfikować |
|---|---|---|
| Software house / agencja **20–100 osób** | 0–10 | LinkedIn, strona „O nas", Clutch |
| **Pracuje na infrastrukturze klientów** | 0–35 | oferta DevOps/SRE/managed hosting, status partnera AWS/GCP, case study z przejęciem produkcji |
| **Zespół używa Claude Code albo Cursora** | 0–35 | patrz §1.1 — to jest najtrudniejsze do zweryfikowania i najważniejsze |
| **Nazwany decydent z publiczną drogą kontaktu** | 0–20 | founder/CTO/head of engineering; wyłącznie adresy firmowe i profile publiczne |

### 1.1. Jak weryfikować adopcję agentów — metoda z 31.07

Pierwsze podejście (szukanie wpisów na blogu i prelekcji) dało **zero
potwierdzeń na kilkanaście polskich software house'ów**. Nie dlatego, że nie
używają — dlatego, że nikt o tym nie pisze. Metoda, która zadziałała, jest
tańsza i twardsza, bo opiera się na artefakcie, a nie na deklaracji:

**Przeszukać publiczne repozytoria organizacji na GitHubie pod kątem:**

| Sygnał | Co znaczy | Siła |
|---|---|---|
| `CLAUDE.md` / `AGENTS.md` / `.cursorrules` **we własnym repo** (nie forku) | zespół skonfigurował agenta pod ten projekt | **30** |
| To samo + firma nazywa narzędzie własnym tekstem (README, opis skilla) | przyznana, świadoma adopcja | **35** |
| `Co-Authored-By: Claude` w historii commitów | agent faktycznie pisał kod, który poszedł na produkcję | wzmacnia powyższe |
| Katalog `.claude/` z `settings.json` w repo | uzgodniona polityka uprawnień w zespole — **najbliżej naszego ICP, jaki istnieje** | **35** |
| `AI-assisted development` bez nazwy narzędzia | coś jest, nie wiadomo co | 18 |
| brak | — | **0** |

Jak przeszukać, bez logowania i bez API:
`https://github.com/orgs/<org>/repositories?sort=updated` → dla każdego repo
`https://raw.githubusercontent.com/<org>/<repo>/HEAD/CLAUDE.md` (i `AGENTS.md`,
`.cursorrules`) → oraz `https://github.com/<org>/<repo>/commits` z grepem na
`Co-Authored-By: Claude`. Code search na GitHubie jest za loginem, a
nieuwierzytelnione REST API kończy się na 60 zapytaniach/h — HTML wystarcza.

⚠️ **Zawsze sprawdzić, czy repo nie jest forkiem.** `CLAUDE.md` w forku cudzego
projektu to plik *upstreamu*, nie dowód na tę firmę. Na kilkanaście trafień
cztery okazały się forkami i nie liczą się.

### 1.2. Ranking kanałów — zmierzony, nie zgadnięty

Na 20 zakwalifikowanych firm:

| Kanał | Ile potwierdzeń | Wniosek |
|---|---|---|
| Artefakt w publicznym repo | **~12/20** | najmocniejszy i najtańszy |
| **Ogłoszenia o pracę nazywające narzędzie** | **~4/20** | niedoceniony — trzeba nazwać narzędzie, żeby zrekrutować |
| Blog inżynierski | ~4/20 | słabszy, niż zakładaliśmy |
| **Prelekcje konferencyjne** | **0/20** | **kanał martwy — nie szukać tam ponownie** |

Wniosek, który jest jednocześnie argumentem sprzedażowym: **firmy, które
odpowiadają kontraktowo za produkcję klienta, nie piszą o tym, że dopuszczają
do niej agenta.** Ale `CLAUDE.md` muszą zacommitować, żeby agent działał, i
muszą nazwać narzędzie, żeby kogoś zatrudnić. Najostrzejszy przypadek: firma
prowadząca wyłącznie zarządzany AWS/K8s, milcząca o AI wszędzie, ma pięć
commitów Claude'a **wewnątrz modułów Terraform**.

To jest też dowód, że lista nie wybiera firm gadatliwych — patrz
`EXPERIMENTS.md`, „Wariant listy".

### 1.3. Zasada weryfikacji — po incydencie z 31.07

**Podsumowania wyszukiwarki sfabrykowały fakty co najmniej pięć razy w jednej
sesji researchu** — zmyślone nazwiska autorów, metryki jednej firmy przypisane
drugiej, nieistniejące ogłoszenie o pracę, wymyślona statystyka „85%".

Reguła: **hak i dowód adopcji muszą pochodzić z pobranej strony albo z pliku
odczytanego przez `gh`, nigdy ze streszczenia wyników wyszukiwania.** Przed
wysyłką hak sprawdzić jednym kliknięciem. Mail z halucynowanym hakiem
(„widziałem Waszą prelekcję o…", której nie było) kosztuje więcej niż brak
maila — i psuje E-6 w sposób, którego wynik nie pokaże.

**Dyskwalifikacja bezwzględna:** CISO w enterprise (poproszą o nasz SOC 2,
którego nie mamy), solo-dev i freelancer (jest własnym audytorem — nie kupi w
żadnej cenie), body-leasing bez odpowiedzialności za infrę, firma produktowa
utrzymująca wyłącznie własną infrę (brak elementu „cudza produkcja").

**Nie dopychać listy do 20.** Dwanaście prawdziwych bije dwadzieścia z
wypełniaczem, bo próg ≥2/20 jest bez sensu, jeśli mianownik jest fikcyjny.
Jeśli kwalifikuje się 14 — eksperyment ma próg ≥2/14 i to jest zapisane 3.08,
nie 11.08.

## 2. Sekwencja — 3 dotknięcia, potem stop

| Dzień | Co | Cel |
|---|---|---|
| 0 | Mail 1 — **hak + narzędzie, zero oferty** | zgoda na uruchomienie skanu |
| +3 | Mail 2 — jedna konkretna liczba z **naszego** raportu jako przykład | pokazać kształt wyniku |
| +7 | Mail 3 — „zamykam wątek" | zwolnić miejsce, zostawić drzwi |

Po trzecim: koniec. Bez czwartego maila, bez LinkedIna, bez telefonu. Każdy
mail personalizowany hakiem, który człowiek może sprawdzić w 30 sekund.
Generyczny hak psuje eksperyment w sposób, którego wynik nie pokaże.

## 3. Mail 1 — szablon

> **Temat:** `[HAK] — ile komend wykonały u was agenty?`
>
> Cześć [IMIĘ],
>
> [JEDNO ZDANIE O KONKRETNEJ, SPRAWDZALNEJ RZECZY — ich wpis, prelekcja, repo,
> usługa, którą reklamują. Nie „podoba mi się Wasza strona".]
>
> Piszę, bo [FIRMA] utrzymuje produkcję klientów, a wasi devowie pracują na
> [CLAUDE CODE / CURSOR]. Interesuje mnie jedna liczba, której prawie nikt nie
> ma: **ile komend wasze agenty faktycznie wykonały w ostatnich miesiącach i
> ile z nich należało do klas nieodwracalnych** (`rm -rf`, `terraform destroy`,
> `DROP TABLE`, force-push, `kubectl delete`).
>
> Transkrypty sesji leżą już na dyskach waszych devów. Napisałem narzędzie,
> które je czyta i robi z tego raport:
>
> * jeden plik Pythona, **zero zależności**, uruchamiasz `python3 retroscan.py`
> * **zero wywołań sieciowych** — sprawdzalne jednym grepem, komenda jest w README
> * read-only, nie dotyka transkryptów
> * sekrety (klucze AWS, tokeny, hasła) są redagowane, zanim trafią do raportu
> * raport zostaje u was — nie muszę go widzieć
>
> Chcesz go? Odsyłam plik, nic w zamian. Jeśli liczba wyjdzie nudna, to też
> jest odpowiedź i nie zawracam więcej głowy.
>
> [PODPIS]
> gate.cat — [github.com/BGMLAI/gate.cat](https://github.com/BGMLAI/gate.cat)

**Czego w tym mailu nie ma i ma nie być:** ceny, słowa „compliance", prośby o
rozmowę, linku do checkoutu, art. 50 AI Act. Sprzedajemy pomiar, nie ochronę —
nikt nie kupuje ochrony przed ryzykiem, którego nie zmierzył.

## 4. Mail 2 — po 3 dniach

Jedno zdanie z **naszego** raportu jako przykład kształtu wyniku (liczba z
FACTS.md, odczytana w tej samej turze), plus jedno pytanie zamknięte:
„uruchomić u was, czy odpuszczam?".

## 5. Mail 3 — po 7 dniach

Trzy zdania. „Zamykam wątek, gdyby kiedyś było potrzebne — tu jest narzędzie,
działa bez nas." Link do repo. Koniec.

## 6. Co się dzieje, gdy ktoś powie „tak"

1. Wysyłamy **plik**, nie link do instalatora. `ops/tools/gatecat_retroscan.py`
   plus trzy linijki instrukcji i grep, którym CTO sam sprawdza brak sieci.
2. Nie prosimy o raport. Jeśli sam go pokaże — dobrze. Jeśli nie — pytamy tylko
   o **dwie liczby**: ile komend, ile w klasach nieodwracalnych.
3. Rozmowa 20 minut, jeżeli sam zaproponuje albo jeżeli liczba go zaskoczy.
   Na rozmowie: **żadnej prezentacji.** Jedno pytanie — „co się dzieje u was
   dzisiaj, kiedy agent zrobi coś, czego nie powinien, na produkcji klienta?".
4. Cena pada dopiero, gdy on zapyta o cenę.

## 7. Reguły, które obowiązują też tutaj

- Maksymalnie **15 maili dziennie**, wyłącznie publiczne adresy firmowe.
- Żadna liczba nie wychodzi bez odczytu z `FACTS.md` na masterze w tej samej
  turze.
- Disclosure automatyzacji w stopce, jeśli mail wychodzi automatem
  (AI Act art. 50 — obowiązek **na nas**, nigdy argument sprzedażowy).
- Każda wysyłka weryfikowana przez `in:sent`. **Szkic to nie jest wykonana
  praca** — 361 szkiców z pierwszego tygodnia to jest ta lekcja.
- Wysyłkę odpala człowiek. Agent przygotowuje.
