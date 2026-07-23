# Follow-up templates — day-3 / day-7 (kampania affiliate)

**Reguły twarde:**
- Follow-up TYLKO gdy zero odpowiedzi w wątku (dedupe #7: przed draftem
  sprawdź wątek + list_drafts + LEDGER). Żadnych draftów PRZED datą due.
- day-3 = jedno krótkie przypomnienie z JEDNĄ nową informacją. day-7 =
  ostatni dotyk, jawnie zamykający. Po day-7: cisza, wątek zamknięty w LEDGER.
- Wysyła wyłącznie user. Każda wysyłka = wiersz w LEDGER z datami due
  (day-3 = +3 dni, day-7 = +7 dni od PIERWSZEGO maila).
- Liczby wyłącznie z FACTS.md (stan 2026-07-23: 0.4.18 na PyPI, 2,529 pobrań
  bez mirrorów w pełnej serii, 0 real misses / 1,085,159, 178/178 z kawetami).
- Skrypt due-trackingu: dopiero gdy wysłanych >5 (ODRZUCONE v2).
- Zero adresów osób trzecich w tym pliku (publiczne repo) — adresaci są w
  LEDGER po ID wątku.

Placeholdery: `{NAME}` = imię/handle, `{HOOK}` = jednozdaniowe nawiązanie do
ich ostatniego materiału (obowiązkowe — bez tego nie wysyłamy).

---

## Day-3 — YouTube (kanał praktyczny, jak w T14 tier 1)

Subject: `Re:` (ten sam wątek — NIE nowy mail)

> Hey {NAME} — quick nudge in case this got buried.
>
> One thing that's new since I wrote: v0.4.18 just shipped on PyPI, and the
> packs now have a proper preview page (https://gate.cat/packs.html) — full
> blocking scope listed before any checkout, which makes an honest
> "here's exactly what it does" segment easy to film.
>
> The offer stands as-is: 30% of every payment, lifetime of the
> subscription, free core so you're recommending real value. One link, one
> disclosure line, done.
>
> If it's a no, a one-word "pass" saves us both the day-7 email :)
> — Bogumił

## Day-3 — newsletter

Subject: `Re:` (ten sam wątek)

> Hey {NAME} — one-line follow-up.
>
> Since my last mail: 0.4.18 is live on PyPI and every claim your readers
> might check now has a "reproduce it yourself" block next to it
> (`pip install gate-cat && python -m gatecat.integrations.bypass_suite` —
> prints its own edges, not just the wins). That's the kind of link that
> survives a skeptical dev audience.
>
> 30% lifetime-recurring, affiliate disclosure required, free core forever.
> Yes / no / "show me the numbers first" all fine.
> — Bogumił

## Day-3 — mega-kanał / duża publiczność

Subject: `Re:` (ten sam wątek)

> Hey {NAME} — I'll keep this to three lines.
>
> New since last mail: 0.4.18 on PyPI + a scope-before-checkout page for the
> paid packs. The pitch is unchanged: deterministic kill-switch for AI coding
> agents, free core (Apache-2.0), 30% of every payment for the lifetime of
> every subscription you send.
>
> If the format you'd want is different (short, integration, community post) —
> name it, I'll fit it.
> — Bogumił

## Day-3 — WARIANT JULIAN (wątek `19f675a02242badf`; due 2026-07-25)

Kontekst: odpowiedział cennikiem sponsorowanych wideo; klaryfikacja "to
affiliate, nie sponsoring" wysłana 07-22 15:53. Zero-friction downgrade ask;
**BEZ prerezerwacji kodu** — kod powstaje dopiero po jego "yes".

> Hey Julian — following up on the clarification from Tuesday.
>
> Totally understand if a dedicated video only happens on a sponsored basis —
> not asking for that. The zero-effort version: an affiliate link + one
> disclosure line in a description or a pinned comment of a video you're
> already making about AI coding agents. 30% of every payment, for the
> lifetime of each subscription — recurring, not one-off.
>
> If that's worth 60 seconds of your workflow, reply "set me up" and I'll
> send your link the same day. If not, no hard feelings — I'll stop here.
> — Bogumił

## Day-7 — wspólny (wszystkie tiery; ostatni dotyk)

Subject: `Re:` (ten sam wątek)

> Hey {NAME} — last one from me, promise.
>
> If agent-safety content isn't in your pipeline right now, that's a
> completely fine answer — I'd rather know than wonder. The offer doesn't
> expire: 30% lifetime-recurring, free core, evidence register in the repo
> (FACTS.md) so anything you say on camera can be checked by your audience.
>
> Whenever an "AI agent deleted my repo" story crosses your feed and you
> want the tool that stops it mid-command: gate.cat. Door's open.
> — Bogumił

---

## Mike Privette (Return on Security)

**BRAK follow-upu wg harmonogramu** — on odpowiedział, my odpowiedzieliśmy
(07-22 17:11), piłka u niego. Reakcja na jego odpowiedź:
`ops/launch/mike_category_data_pack.md`. Jeśli cisza >14 dni, decyzja
wraca do panelu (nie do tego pliku).

---

## Gałąź: „show me the numbers first" (V4, 2026-07-23)

Przewidziana w day-3 („Yes / no / show me the numbers first all fine") —
obsługa w 60 sekund:

1. **Liczby:** wklej blok „What you can honestly say" z
   `ops/partners/welcome_pack.md` (sekcja 1 welcome maila — NIE kopiuj go
   tutaj, jedno źródło prawdy) + link https://github.com/BGMLAI/gate.cat/blob/master/FACTS.md.
2. **Jedno uczciwe zdanie o trakcji** (frazowanie z wątku Return on Security —
   działa, bo uprzedza zarzut): *"Revenue is day-zero and I won't dress it
   up — downloads plus the evidence register ARE the traction story today,
   which is exactly why the deal is revenue-share, not a sponsorship
   invoice: it costs you nothing unless it converts."*
3. **Pre-yes demo:** *"30 seconds, no signup, watch it veto rm -rf live:
   https://gate.cat/veto-demo.html — if that demo wouldn't interest your
   audience, we're done and no hard feelings."*

Zero innych liczb. Jeśli spyta o zarobki innych partnerów: prawda —
program wystartował w tym tygodniu, jest zero danych i mówimy to wprost.
