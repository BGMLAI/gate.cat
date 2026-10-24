# Stripe — przełączenie cennika (runbook dla człowieka)

**Kontekst:** `PLAN_SPRZEDAZY.md` §4.2 poz. 1.3. Repo na branchu
`sales/ordering-2026-07-31` niesie **nowy cennik**. Stripe niesie **stary**.
Dopóki te dwa się nie zgadzają, **nie merge'ować do mastera i nie deployować
`docs/`** — landing obiecywałby cenę, której checkout nie policzy.

Czas: ~25 minut. Zero decyzji do podjęcia po drodze — wszystkie zapadły 31.07.

---

## 0. NAJPIERW to, co jest pilniejsze niż cennik (5 min)

Zanim dotkniesz cen — `PLAN_SPRZEDAZY.md` §4.1 stopień 0. W skrócie, bo to ta
sama zakładka przeglądarki:

- [ ] **Account status → dokończyć KYC na trzech kontach.** Payouty wstrzymane
      od 27.07.
- [ ] **Wyłączyć publiczne Payment Linki, które nie są w tabeli niżej.**
      91 nieopłaconych checkoutów o wzorcu card-testingu bierze się stąd.
- [ ] **Radar rules: włączyć blokowanie po liczbie nieudanych prób z jednego
      IP/karty.** Stripe zamyka konta za card-testing i przy trzech kontach z
      wstrzymanymi payoutami jesteśmy dokładnie w tej kolejce.

## 1. Co zostaje bez zmian (nie dotykać)

Te trzy linki są w repo i **są poprawne** — landing i README na nie wskazują:

| Tier | Cena | Link |
|---|---|---|
| Business | €399/mies. | `buy.stripe.com/7sYdR2e3PcTm2T6cvY67S0b` |
| Solo | €19/mies. | `buy.stripe.com/7sY6oAaRD5qU79m2Vo67S09` |
| Packi €29 jednorazowo ×3 | €29 | `…67S0c`, `…67S0d`, `…67S0e` |

## 2. Co wyłączyć

| Co | Dlaczego |
|---|---|
| **Team €149/mies.** — `buy.stripe.com/9B66oA5xj2eIaly2Vo67S0a` | zastąpiony przez €299. Deaktywować link, **nie kasować produktu** — historia i ewentualne subskrypcje muszą zostać. Subskrybentów: 0, więc nie ma kogo migrować. |
| **Solo „founding" €9/mies.** — `buy.stripe.com/14AaEQ6BncTmctGbrU67S0f` | promocja kończyła się 3.08, a Solo przestaje być tierem promowanym. Landing już na niego nie wskazuje. |

## 3. Co utworzyć

### 3.1. Team — €299/mies.
- Produkt: `gate.cat Cloud — Team`
- Cena: **€299/mies.**, recurring, EU VAT automatycznie
- Opis: „up to 25 seats, 3 protected environments, fleet policy sync, VAT
  invoice + DPA, priority support"
- **Włączyć fakturowanie (invoice) + przelew**, nie tylko kartę — to jest cały
  powód istnienia tego tieru dla software house'u.
- Payment Link → wstawić w miejsce `⟦STRIPE:team-299⟧` w `PRICING.md`.

### 3.2. Packi utrzymywane — €19/mies. za pack
- Produkt: `gate.cat Policy Pack — maintained` (jeden produkt, 3 warianty:
  Fintech / PaaS / HTTP-API)
- Cena: **€19/mies.** recurring
- Payment Link → w miejsce `⟦STRIPE:pack-sub⟧` w `PRICING.md`.
- Jednorazowe €29 **zostaje aktywne** — działa, ma automatyczny fulfillment
  (`products/cloud/gatecat_fulfill.py`), nie ma powodu psuć czegoś, co działa.

### 3.3. Czego **nie** tworzyć w Stripe
**Compliance (€900–1200) i wdrożenie (€1500–2500) nie dostają Payment Linku.**
To jest celowe: opłata wdrożeniowa jest filtrem na niepoważnych, a tier bez
gotowego „proof of enforcement" (patrz `PRICING.md`) sprzedaje się rozmową i
umową, nie przyciskiem. Faktura wystawiana ręcznie.

## 4. Po Stripe — w tej kolejności

1. [ ] Wstawić dwa linki w `PRICING.md` w miejsce `⟦STRIPE:…⟧`.
2. [ ] `python -m pytest tests/test_marketing_consistency.py -q` — musi być
       zielone. Test `test_unresolved_stripe_placeholders_never_reach_a_buyer`
       pilnuje, żeby placeholder nie wyjechał na landing.
3. [ ] Merge `sales/ordering-2026-07-31` → master, CI zielone.
4. [ ] `ops/deploy_landing.sh` — dopiero **teraz** landing może pójść live.
5. [ ] **Test checkoutu własną kartą na Business €399** (`PLAN_SPRZEDAZY.md`
       §4.1 poz. 0.3). Przy 0 subskrypcji od zawsze nie mamy żadnego dowodu, że
       pipeline płatności w ogóle działa. Zwrot potem — 20 minut o najwyższej
       wartości w całym planie.
6. [ ] Odnotować wykonanie w `docs/AUTOPILOT-LOOP.md`, żeby pętla to zobaczyła.

## 5. Znane ryzyko tej zmiany

Podnosimy ARPU przy próbie o rozmiarze zero. To nie jest optymalizacja
konwersji na podstawie danych — **danych nie ma i nie będzie ich, dopóki nie
porozmawiamy z kimś, kto ma budżet.** Uzasadnienie jest strukturalne, nie
statystyczne: przy €19 do celu trzeba 484 klientów, przy €399 — 23, a linia
free/paid była postawiona odwrotnie do rozkładu portfeli (solo-dev nigdy nie
zapłaci za audit log własnych komend, bo jest jedynym audytorem).

Jeśli po E-6 (odczyt 11.08) okaże się, że €299–399 wypada z budżetu uznaniowego
ICP — cofamy się do jednego tieru €149–199, a nie do €19. Zapisane, żeby 11.08
nie dało się tego przedyskutować od nowa.
