# Rejestr eksperymentów

Zasada: eksperyment ma **próg zapisany PRZED odczytem**. Wynik poniżej progu
znaczy zmianę kierunku, nie „popracujmy nad copy". Ten plik istnieje po to,
żeby w dniu odczytu nie dało się progu przenegocjować.

| ID | Hipoteza | Próg | Start → odczyt | Wynik |
|---|---|---|---|---|
| E-1 | Plan roczny podnosi konwersję | — | — | nieuruchomiony |
| E-2 | Repricing packów | — | — | zastąpiony przez zmianę cennika 31.07 |
| E-3 | `gatecat upgrade` w CLI | — | — | nieuruchomiony |
| E-4 | Trial z kartą | — | — | nieuruchomiony |
| E-5 | Product Hunt daje dystrybucję do B2B security tooling | wzrost pobrań | 29.07 → 30.07 | ❌ **NEGATYWNY.** 5 upvote'ów, 16 followersów, 0 komentarzy zewnętrznych, 0 przyrostu pobrań. Kanał zamknięty bez relaunchu. |
| **E-6** | **Darmowy retro-scan na danych prospekta otwiera rozmowę, której nie otwiera żaden komunikat marketingowy** | **≥2 z 20 prospektów przyjmuje skan I umawia rozmowę o wersji płatnej** | **03.08 → 11.08** | — |
| E-7 | Licencja korpusu ma kupca | ≥1 rozmowa handlowa z dostawcą harnessu/sandboxa | 15.08 → 15.09 | — |

## E-5 — czego ten wynik NIE dowodzi

Nie dowodzi, że produkt jest zły, ani że nikt nie zapłaci. Dowodzi, że Product
Hunt nie konwertuje na B2B security tooling. Próba na pytanie „czy ktoś
zapłaci" ma nadal rozmiar zero.

## E-6 — protokół odczytu

Odczyt 11.08 wypełnia **tę** tabelę, nie prozę:

| # | Wysłano | Otworzył | Uruchomił skan | Odesłał raport / pokazał | Umówił rozmowę | Powód odmowy (dosłownie) |
|---|---|---|---|---|---|---|

**Powód odmowy zapisujemy dosłownie, cytatem.** To jest najważniejsza kolumna w
całym eksperymencie i jedyne dane jakościowe, jakie z niego wyjdą.

Rozróżnienie, które decyduje o interpretacji wyniku <2/20:

- **Odmowa „nie mam tego problemu" / brak reakcji** → hipoteza o bólu ICP jest
  fałszywa. Zmiana kierunku: inne ICP albo inny produkt.
- **Odmowa „nie uruchomię obcego narzędzia na naszych transkryptach"** →
  hipoteza o bólu **nie została zmierzona**. Narzędzie jest bezzależnościowe,
  bezsieciowe, read-only i redaguje sekrety właśnie po to, żeby zdjąć tę
  obiekcję; jeśli mimo to blokuje, problemem jest sposób dostarczenia, nie
  oferta. Wtedy E-6 powtarzamy z inną formą (skan na ich maszynie przez
  screen-share, albo raport z **naszych** danych jako przykład).

Bez tego rozróżnienia wynik 0/20 jest nieinterpretowalny.
