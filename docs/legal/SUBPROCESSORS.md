# Sub-processors

> **What this is:** the list of third parties that may process personal data in
> connection with gate.cat, with what each one touches and where it sits.
> **Who it is for:** a customer's DPO, security reviewer or procurement team,
> and anyone assessing the DPA. **Version:** 1.0-draft · **Date:** 2026-07-31.

This list is referenced by Annex III of
[`docs/legal/DPA.md`](DPA.md) and forms part of it.

**The starting point:** if you use only the free `pip install gate.cat`
package, **there are no sub-processors at all.** The package phones nowhere.
Nothing on this page touches your data unless you enable the paid Cloud layer
or buy something.

Entries marked ⟦UNCONFIRMED — verify with Bogumił⟧ could not be established
from the repository. They are listed rather than omitted, because a gap a
reviewer discovers is worse than a gap we flag ourselves. They must be resolved
before this document is presented as final.

---

## 1. Sub-processors for the Cloud service (paid, opt-in)

| Name | Role | Data it touches | Location / region | Transfer mechanism | DPA |
|---|---|---|---|---|---|
| **OVH** (`[EXACT LEGAL ENTITY — OVH SAS / OVH Hosting? CONFIRM]`) | VPS hosting for the Cloud API, the event store and the static site | Everything at rest: the encrypted event blobs, cleartext event timestamps, account email addresses, API-key hashes. **OVH cannot read event content** — it is ciphertext encrypted with a key that never leaves the customer's machine | ⟦UNCONFIRMED — verify with Bogumił⟧ The datacentre region is not recorded anywhere in the repository. The host is `204.168.129.200`. **This must be confirmed before the DPA is signed**: it decides whether the primary event store is inside the EEA and therefore whether SCCs are required for the main storage location | `[NONE NEEDED IF EEA / SCCs MODULE 3 IF NOT]` | [ovhcloud.com/en/personal-data-protection/](https://www.ovhcloud.com/en/personal-data-protection/) — `[CONFIRM the DPA URL for the contracting entity]` |
| **Cloudflare, Inc.** | Reverse proxy, TLS termination at the edge, DDoS protection and DNS for `gate.cat` | Connection metadata for every request to the Cloud API and the website: source IP, User-Agent, requested path, TLS metadata. Request bodies transit Cloudflare; event bodies are ciphertext, so Cloudflare sees no event content. The `Authorization` bearer token transits Cloudflare inside TLS | Global anycast network, US-headquartered | EU SCCs / Cloudflare Data Processing Addendum | [cloudflare.com/cloudflare-customer-dpa/](https://www.cloudflare.com/cloudflare-customer-dpa/) |
| **Stripe** (`[Stripe Payments Europe, Ltd. — CONFIRM the contracting entity on the account]`) | Payment processing, checkout, subscription billing, tax calculation, receipts and invoices | Billing contact name and email, billing address, VAT ID, card data (never touches our systems), subscription state. **The checkout email becomes the Cloud account identifier**, so it also lands in our account store | Ireland / EU, with US parent | Stripe DPA + SCCs | [stripe.com/legal/dpa](https://stripe.com/legal/dpa) |

### Not sub-processors, but in the path

| Name | Role | Data | Why it is not a sub-processor |
|---|---|---|---|
| **Let's Encrypt** (ISRG) | TLS certificate issuance for `gate.cat` | Domain name only | No personal data. Certificate transparency logs are public and contain only the domain |

---

## 2. Sub-processors for the free package

**None.** `pip install gate.cat` performs no network call to us, sends no
telemetry, and has no analytics. The only third party involved is the one you
chose yourself:

| Name | Role | Data | Notes |
|---|---|---|---|
| **PyPI** (Python Software Foundation) / **GitHub** (Microsoft) | Distribution of the package and the installer script | Your IP address and User-Agent at download time, as with any package install | You are the one contacting them. We receive only aggregate download counts through the public `pypistats.org` API |

---

## 3. Optional integrations the customer switches on itself

These are **not** our sub-processors. They are third parties the customer
chooses, configures and contracts with directly, using its own API keys. They
are listed so that nobody discovers them during a code review and assumes they
were hidden.

| Name | When it is contacted | Data | Default |
|---|---|---|---|
| **Brave Search API** | Only if the customer sets `BRAVE_API_KEY` **and** `GATECAT_WEB_ENABLED=1` — the web arbiter branch of the verification stack | Query text sent to Brave | **Off** |
| **OpenRouter / OpenAI / a local model server** | Only if the customer configures cache-augmented synthesis (`[openai]` extra) and supplies a key | Prompt/response text the customer routes through it | **Off**; the veto gate itself calls no model |
| **Hugging Face Hub** | First use of an ML-backed optional extra, to fetch the embedding model file | Model download request | Only with the optional ML extras installed; the deterministic gate does not need them |

---

## 4. Business operations — where we act as controller, not processor

Listed for completeness. These do not process data *on a customer's behalf*,
but a reviewer will ask, and a customer's own personal data does reach some of
them.

| Name | Role | Data | Location | Notes |
|---|---|---|---|---|
| **GitHub (Microsoft)** | Public source repository, issue tracker, CI (GitHub Actions on `ubuntu-latest`), security reports filed as issues | Whatever a person voluntarily puts in a public issue. **No customer data and no production credentials** flow through CI: there is no automated deploy and no PyPI publish step in the workflows | US / global | Public repository; the CI job runs tests only |
| **Email provider for `bgml@bgml.ai`** | Support, security reports, sales correspondence, invoice requests | Names, email addresses and message content of anyone who writes to us | ⟦UNCONFIRMED — verify with Bogumił⟧ | ⟦UNCONFIRMED — verify with Bogumił⟧ The mailbox provider is not identified in the repository. Repository notes reference a Gmail connector for the founder's mail, which would make **Google** the provider, but that is not the same as confirming where `bgml@bgml.ai` is hosted. It must be named here, because procurement will ask where a support email containing customer data is stored |
| **Website analytics** | Traffic measurement | **Self-hosted.** A `/events` beacon on our own nginx, logged with a log format that deliberately omits client IPs, cookies and request bodies. The only cookie set anywhere on the site is the first-party affiliate referral cookie `gc_ref` | Same VPS as above | **No third-party analytics.** No Google Analytics, Plausible, Umami, Fathom, Matomo, Hotjar or equivalent — verified against the repository |
| **Google Fonts** | — | — | — | **None, as of 2026-07-31.** This row previously described a real disclosure: `coverage.html` loaded a stylesheet from `fonts.googleapis.com`, and `index.html` emitted `preconnect` hints to `fonts.googleapis.com` and `fonts.gstatic.com` — enough on its own to hand a visitor's IP and User-Agent to Google. Both were removed the same day they were found (the pages fall back to the system font stacks their CSS variables already declare). Kept as a dated row rather than deleted, because "we never had one" and "we had one and removed it on 2026-07-31" are different answers to a procurement question, and only one of them is true |
| **Error tracking / APM** | — | — | — | **None.** No Sentry, Rollbar, Bugsnag, Datadog or New Relic integration exists. Where "Sentry" or "Datadog" appear in the codebase they are targets of destructive-API policies, not services we use |
| **Support desk / CRM / booking** | — | — | — | **None.** No Zendesk, Intercom, Crisp, HubSpot, Salesforce, Calendly or Typeform |
| **Object storage / managed database** | — | — | — | **None.** All state is flat JSONL and one SQLite file on the VPS disk |

---

## 5. Retired and non-live entries

| Name | Status |
|---|---|
| **Lemon Squeezy** | **Not in use.** Application declined 2026-07-14. Webhook routes and a historical finalisation script remain in the repository but are inactive; Stripe is the payment channel. Listed here so a code reviewer who finds the dead routes does not report an undisclosed processor |
| **Resend** | ⟦UNCONFIRMED — verify with Bogumił⟧ Repository notes record that a Resend API key exists, but for domains unrelated to gate.cat, and that no send ever went through it for this product. **Confirm it is not, and will not be, used for gate.cat mail.** If it is adopted — for the Cloud email alerts promised on the pricing page — it becomes a sub-processor and this list must be updated *before* the first send |

---

## 6. Open item: the alert email channel

⟦UNCONFIRMED — verify with Bogumił⟧
[PRICING.md](../../PRICING.md) offers **email alerts** on the Solo tier and
above. The repository contains an alert *feed* on the Cloud server
(`GET /v1/alerts`, `POST /v1/alert`) but **no mail-sending integration of any
kind** — no SMTP client, no transactional email provider. Either the alerts are
pull-only today, or a mail provider exists outside the repository. Whichever it
is, it must be stated here, because "we email you" and "we have no mail
sub-processor" cannot both be true.

---

## 7. Change notification

- We give **at least `[30]` days' notice** before adding or replacing a
  sub-processor that touches customer data, per clause 4.5(b) of the
  [DPA](DPA.md).
- Notice goes out by email to each customer's stated notice address, and this
  file is updated on the same day. The file is version-controlled in a public
  repository, so the change is diffable.
- **Subscribe to changes:** email `bgml@bgml.ai` with the subject
  `subprocessor-notices` and the account you want notices for.
  `[CONFIRM: whether a dedicated alias — e.g. subprocessors@gate.cat — should
  be published instead.]`
- Customers may object on reasonable data-protection grounds within `[15]` days
  of a notice; the consequences are in DPA clause 4.5(c).

---

*Every entry above was derived from the repository. Nothing on this page was
inferred from what a company of this shape usually uses — where the repository
was silent, the entry says so.*
