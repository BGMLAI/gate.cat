# ops/ — maszyna sprzedażowa

Gdzie co leży. Zaczynaj od `strategia/PLAN_SPRZEDAZY.md`.

| Ścieżka | Co to jest | Kto pisze |
|---|---|---|
| `strategia/PLAN_SPRZEDAZY.md` | **jedno źródło prawdy** — cel, arytmetyka, drabina działań, reguły | człowiek + agent, przy zmianie strategii |
| `machine/QUEUE.md` | co następne, podzielone na „człowiek" i „agent" | agent |
| `machine/SCORECARD.md` | dzienny puls + postęp do progów | agent |
| `machine/EXPERIMENTS.md` | rejestr eksperymentów z progami zapisanymi **przed** odczytem | agent |
| `machine/E6_METODA.md` | protokół E-6: kwalifikacja, sekwencja, szablony | agent |
| `machine/PARTNERS.md` | pipeline; pusty jest informacją, nie wstydem | agent |
| `machine/SEEN.log` | append-only zapis decyzji z uzasadnieniem | agent |
| `launch/STRIPE_CENNIK_2026-07-31.md` | runbook przełączenia cennika w Stripe | człowiek wykonuje |
| `launch/*` | kity launchowe ⚠️ kopie robocze, **nie źródło prawdy dla liczb** | agent |
| `tools/` | narzędzia sprzedażowe (retro-scan) | agent |
| `deploy_landing.sh`, `nginx/` | deploy statyku na VPS | człowiek wykonuje |

## Trzy reguły, które obowiązują w całym tym katalogu

1. **Żadna liczba nie wychodzi na zewnątrz bez odczytu z `FACTS.md` na
   masterze w tej samej turze.** Dotyczy też liczb pamiętanych — tak powstały
   trzy błędy w jeden dzień, jeden trafił do sześciu dziennikarzy.
2. **Repo jest publiczne.** Żadnych adresów e-mail osób trzecich, treści
   korespondencji ani imiennych list outreachowych w commitach. Listy nazwane
   dostarczamy człowiekowi bezpośrednio.
3. **Szkic to nie jest wykonana praca.** Weryfikować wysyłkę przez `in:sent`.
