# Buying gate.cat as a company

> **What this is:** the operational answer to "how do we actually pay you" —
> card, or invoice and bank transfer. **Who it is for:** a CTO, an engineering
> manager, or a procurement/finance contact. **Version:** 1.0 · **Date:**
> 2026-07-31.
>
> If you only want the free local gate, stop reading. `pip install gate.cat` is
> Apache-2.0, complete, and free forever. Nothing below applies to it.

---

## 1. What is being sold

**Tiers, prices and what each one contains live in
[PRICING.md](../../PRICING.md), which is the single source of truth.** They are
deliberately not repeated here — a price copied into a second file is a price
that goes stale. This page covers only *how* the money moves.

Constant across every paid tier: cancel at any time, and a **30-day full
refund, no questions asked**.

## 2. Two ways to pay

### Path A — card, self-serve (live today)

Stripe Checkout, links in [PRICING.md](../../PRICING.md). Add your EU VAT ID at
checkout and VAT is handled automatically. Receipt and invoice arrive by email
from Stripe. Fulfilment is automatic: payment → API key → encrypted off-machine
history. For policy packs: payment → instant download page.

This is the fastest path and needs nothing from us. Per PRICING.md it is the
channel for the self-serve tiers.

### Path B — invoice and bank transfer (for companies that cannot pay by card)

This is the channel for the tiers PRICING.md routes through a conversation, and
it is available on request for any tier. It is handled manually today — a human
reads your email and issues the invoice — so allow `[2]` business days rather
than expecting an instant portal.

Send one email to **`bogumil@bgml.ai`**, subject `gate.cat invoice request`,
containing the fields in §4. You get back a PDF invoice; you pay by transfer;
the API key is issued on receipt of funds (or on issue of the invoice, if we
have agreed payment terms — see §6).

## 3. VAT

Seller: a Polish company. `[CONFIRM: exact legal entity, and whether it is
registered for VAT and for EU VAT (VIES).]` Nothing below is tax advice; your
finance team owns the final treatment.

| You are | Treatment |
|---|---|
| **A business in another EU member state with a valid VAT number** | **Reverse charge.** No Polish VAT is charged. The invoice is issued net and carries the note *"Reverse charge — VAT to be accounted for by the recipient pursuant to Article 196 of Council Directive 2006/112/EC"*. Your VAT number is validated against **VIES** before the invoice is issued; if it does not validate, we cannot apply the reverse charge and will have to charge Polish VAT instead |
| **A business or consumer in Poland** | Polish VAT is charged at the applicable rate `[CONFIRM CURRENT RATE AND REGISTRATION STATUS]`, invoice in `[PLN / EUR — CONFIRM]` |
| **A business outside the EU** | The place of supply is where you are established, so no Polish VAT is charged. You may have a local reverse-charge, self-assessment or import-VAT obligation — that is on your side. See §7 on withholding tax |
| **A consumer (non-business) anywhere in the EU** | VAT of your member state applies. On the self-serve path Stripe calculates and collects it |

On the self-serve card path, Stripe performs VAT determination and collection.
On the invoice path we do it manually, which is why we need §4 before issuing
anything.

## 4. What to send us to get an invoice

Copy this block into your email and fill it in. Anything missing means a second
round-trip.

```
Legal entity name:
Registered address (street, city, postcode, country):
Company registration number:
VAT / EU VAT ID (with country prefix, e.g. DE123456789):
Billing contact name and email:
PO / reference to print on the invoice (if your AP system requires one):
Invoice delivery address (email or portal):
Plan and quantity:            e.g. Team, 1 subscription, up to 10 machines
Billing period:               monthly / annual prepay
Requested start date:
Any e-invoicing format you require (e.g. Peppol, KSeF, XRechnung):
```

If your AP system will reject an invoice without a PO, send the PO number in
the same email. We cannot add it retroactively without reissuing.

## 5. Currency and bank details

- **Currency: EUR.** `[CONFIRM whether PLN and USD invoices are also offered.]`
- Bank transfer to:

```
Account holder:   [LEGAL ENTITY NAME]
IBAN:             [IBAN]
BIC / SWIFT:      [BIC]
Bank:             [BANK NAME AND ADDRESS]
Payment reference: the invoice number, exactly
```

> `[These must be filled in by Bogumił. Nothing here is invented — do not
> publish this file with placeholder bank details still in place.]`

- Transfer fees: **`[SHA / OUR — CONFIRM]`**. If your bank deducts charges,
  the invoice is settled only when the full net amount arrives.
- We do not accept cheques, PayPal, or crypto. `[CONFIRM.]`

## 6. Payment terms

- Proposed: **net `[14]` days from invoice date**. `[BUSINESS DECISION —
  CONFIRM. Net 30 is the common corporate default and many AP systems will
  simply pay on their own cycle regardless of what the invoice says.]`
- Service starts `[on issue of the invoice / on receipt of funds — CONFIRM]`.
- Late payment: `[statutory interest under Polish law on late payment in
  commercial transactions — CONFIRM whether to state a rate]`.
- **Annual prepay:** available. `[CONFIRM the discount — a common shape is 12
  months for the price of 10. Do not quote a discount here until it is set,
  because a number in this file becomes a price.]`
- Mid-term upgrades are prorated; downgrades take effect at the next renewal.
  `[CONFIRM.]`
- Where [PRICING.md](../../PRICING.md) attaches a one-time onboarding fee to a
  tier, it is invoiced separately from the subscription, on the same terms.

## 7. Tax forms and residency

- We are a Polish entity with no US presence. For a US customer we can provide
  a completed **W-8BEN-E** on request (the entity equivalent of a W-8BEN),
  claiming treaty benefits under the Poland–US double taxation treaty.
  `[CONFIRM who prepares and signs it.]`
- For any customer that needs to justify not applying withholding tax, we can
  supply a **certificate of tax residency** (*certyfikat rezydencji*) issued by
  the Polish tax authority. Allow `[2–4]` weeks; the certificate is issued by
  the tax office, not by us. `[CONFIRM lead time.]`
- If your jurisdiction requires withholding on software or service payments,
  tell us **before** the invoice is issued so it can be handled correctly.

## 8. The procurement pack

Everything a security or legal review normally asks for, already written:

| Document | What it is |
|---|---|
| [DPA](../legal/DPA.md) | GDPR Art. 28 processor agreement, template. You are the controller; we are the processor. Includes Annex I (processing details), Annex II (technical and organisational measures, derived from what the product actually does), Annex III (sub-processors) and the SCC hook |
| [Sub-processors](../legal/SUBPROCESSORS.md) | Dated list, with what each one touches and where it sits. Entries we could not confirm are marked as unconfirmed rather than filled in |
| [Security one-pager](SECURITY_ONEPAGER.md) | The document to forward to your security reviewer. Data flow, crypto, tenancy, supply chain, a Limitations section that names our gaps first, and a control mapping to SOC 2 / ISO 27001 / ISO 42001 |
| [Threat model](../THREAT_MODEL.md) and [Cloud threat model](../../THREAT_MODEL_CLOUD.md) | The boundary, both directions — what a hostile agent can do, what it cannot, and what *we* cannot do |
| [FACTS.md](../../FACTS.md) | The claims register. Every public number, with its measurement artifact and date, and a list of numbers we have retired and will not reuse |
| [RECALL.md](../../RECALL.md) | How the coverage claim is measured, and its explicit scope limits |
| [Sample report](../SAMPLE_REPORT.md) | A redacted monthly report, generated from our own real dogfood log, red-team caveats included |

**Security questionnaires.** Send yours. We answer in writing within `[15]`
business days, at no charge. If a question is answered by the one-pager we will
point at the section rather than paraphrase it.

**Certifications.** We do not hold SOC 2 or ISO 27001 and do not claim to. If
your policy requires a certified vendor for hosted data, the **Business** tier
keeps the evidence log in your own infrastructure — we never hold the only
copy — which is usually the shape that clears the review.

**Insurance and liability.** `[BUSINESS DECISION — CONFIRM. State whether
professional indemnity / cyber liability cover is in place, with insurer and
limit, or state plainly that none is currently held. Do not leave this blank in
a document a procurement team reads, and do not agree to an uncapped liability
clause without cover. The liability position is set in the main agreement and
referenced from DPA clause 9.]`

## 9. The one email

If you have read this far, this is all you need to send to
**`bogumil@bgml.ai`**:

```
Subject: gate.cat invoice request — [YOUR COMPANY]

We want [Team / Business], billed [monthly / annual prepay], starting [DATE].

[paste the filled-in block from §4]

Please also send: DPA for signature, sub-processor list, security one-pager.
Our security questionnaire is attached / will follow.
Notice address for sub-processor changes: [EMAIL]
```

You will get back: the invoice, the DPA as a document for review, and the
procurement pack. Questions about the technology go to the same address.
