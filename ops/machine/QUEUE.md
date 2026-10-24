# QUEUE — co następne

Kolejność z `ops/strategia/PLAN_SPRZEDAZY.md` §4. Kolejka nie zawiera niczego,
czego nie da się zacząć dzisiaj.

## 🔴 Człowiek — blokuje wszystko inne

| # | Zadanie | Czas | Blokuje |
|---|---|---|---|
| 0.1 | Stripe KYC ×3 konta | 1 posiedzenie | przyjmowanie płatności w ogóle |
| 0.2 | Wyłączyć publiczne Payment Linki + Radar rules | 15 min | to samo (card-testing → zamknięcie konta) |
| 0.3 | **Test pełnego checkoutu własną kartą** | 20 min | nic — i dlatego można to zrobić teraz |
| 0.4 | Opłacić Google Workspace | 10 min | cały silnik mailowy, deadline 4.08 |
| 0.5 | Stripe: cennik wg `ops/launch/STRIPE_CENNIK_2026-07-31.md` | 25 min | merge brancha + deploy landingu |
| 0.6 | `ops/deploy_landing.sh` — **po 0.5** | 3 min | wiarygodność wobec 6 zaproszonych dziennikarzy |

## 🟠 Agent — gotowe do wykonania

| # | Zadanie | Stan |
|---|---|---|
| 1.1 | Plan sprzedaży, cennik, licencja korpusu | ✅ 31.07 |
| 1.2 | DPA, subprocesorzy, security one-pager, ścieżka fakturowa | ✅ 31.07 |
| 1.3 | Retro-scan + testy | 31.07 |
| 1.4 | E-6: metoda + lista prospektów | 31.07 |
| 1.5 | Ujednolicić cel pętli autopilota z Progiem 0 (€2 000) w `docs/AUTOPILOT-LOOP.md` | czeka |

## 🟡 Po E-6 (odczyt 11.08)

Nic tu nie wpisywać przed odczytem. Kolejka po E-6 zależy od wyniku i
wpisywanie jej teraz to planowanie pod wynik, którego nie znamy.

## Znalezione po drodze — do rozstrzygnięcia

| Co | Dlaczego to ma znaczenie |
|---|---|
| `docs/coverage.html` ładuje Google Fonts, `docs/index.html` robi `preconnect` mimo self-hostowania fontów | IP odwiedzających trafiają do Google, a sprzedajemy „cookieless". Ujawnione w `docs/legal/SUBPROCESSORS.md` §4 — do usunięcia, nie do opisania. |
| Lokalizacja VPS OVH nieustalona | decyduje, czy główny magazyn zdarzeń jest w EOG i czy potrzebne są SCC. Najważniejsza otwarta pozycja w pakiecie procurementowym. |
| Nagłówek machine-binding i feed alertów istnieją po stronie serwera, ale reporter 0.4.18 ich nie wysyła | „nic więcej nie wychodzi" jest dziś prawdą i przestaje nią być w dniu podpięcia |
