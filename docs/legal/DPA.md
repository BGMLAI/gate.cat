# Data Processing Agreement (template)

> **What this is:** a GDPR Article 28 processor agreement covering gate.cat
> Cloud — the optional, off-by-default off-machine copy of a customer's veto
> history. **Who it is for:** the customer's DPO, legal or procurement reviewer.
> **Version:** 1.0-draft · **Date:** 2026-07-31 · Applies to gate.cat 0.4.18.

> ⚠️ **This is a template, not an executed contract.** It has not been reviewed
> by counsel. Both parties must have it reviewed by their own lawyers before
> signature. Every `[SQUARE BRACKET]` is a field that the customer or the
> supplier must complete, and several bracketed items (breach window, liability
> cap, audit notice period) are commercial decisions, not legal boilerplate.

> **Scope note, up front:** the free `pip install gate.cat` package processes
> **no personal data on our behalf at all** — it phones nowhere and writes only
> to the local machine. This agreement is only needed if the customer enables
> the paid Cloud layer, or where the supplier processes personal data in the
> course of billing and support. If Cloud is off, there is nothing here to sign.

---

## Parties

This Data Processing Agreement ("**DPA**") is entered into between:

- **[CUSTOMER LEGAL NAME]**, `[REGISTERED ADDRESS]`, company number
  `[REGISTRATION NUMBER]`, VAT ID `[VAT ID]` (the "**Controller**"); and
- **[SUPPLIER LEGAL ENTITY NAME — the Polish entity trading as gate.cat]**,
  `[REGISTERED ADDRESS, POLAND]`, company number `[KRS / CEIDG NUMBER]`,
  VAT ID `[NIP / EU VAT ID]` (the "**Processor**").

and forms part of the `[MAIN AGREEMENT / TERMS OF SERVICE, dated …]` (the
"**Principal Agreement**").

Contact for data protection matters: `bgml@bgml.ai`.
`[CONFIRM: whether a dedicated privacy@ alias should be used instead.]`

---

## 1. Definitions

"GDPR" means Regulation (EU) 2016/679. "Personal Data", "Processing",
"Controller", "Processor", "Sub-processor", "Data Subject", "Personal Data
Breach" and "Supervisory Authority" have the meanings given in the GDPR.
"Services" means the gate.cat Cloud service described in Annex I.
"Veto Event" means one record written by the gate when it blocks, warns on, or
otherwise adjudicates an action attempted by an AI agent on a Controller
machine.

## 2. Roles and scope

2.1 The Controller is the controller and the Processor is the processor in
respect of the Personal Data described in Annex I.

2.2 The Processor processes Personal Data only to provide the Services.

2.3 **Architectural constraint (load-bearing).** Veto Events are encrypted on
the Controller's machine with AES-256-GCM using a key generated on and never
transmitted from that machine. The Processor stores ciphertext plus a cleartext
timestamp. The Processor therefore **cannot read** the content of Veto Events —
not the command, not the policy id, not the reason — and cannot be instructed
to. This is a property of the system, not a promise about the Processor's
behaviour, and it can be verified in the public source
(`gatecat/cloud_crypto.py`, `gatecat/cloud_reporter.py`,
`products/cloud/cloud_server.py`). Where this DPA imposes an obligation the
Processor cannot technically perform on encrypted content (for example
rectification of a specific record's content), clause 8.3 applies.

## 3. Subject-matter, duration, nature and purpose

3.1 **Subject-matter:** provision of an off-machine, append-only copy of the
Controller's Veto Event history, together with the credentials and account
records needed to authenticate the Controller to it.

3.2 **Duration:** from the effective date of the Principal Agreement until
termination or expiry of the Controller's subscription, plus the deletion
window in clause 11.

3.3 **Nature of processing:** receipt, authentication, storage, ordering,
retention-windowing, retrieval and deletion of encrypted event records. No
content analysis, profiling or automated decision-making is performed on the
data — the Processor is technically incapable of it.

3.4 **Purpose:** to give the Controller a copy of its own agent-veto history
that lives outside the blast radius of the AI agent whose actions it records,
and to detect tampering with the Controller's local log.

3.5 Full details are in **Annex I**.

## 4. Processor obligations

The Processor shall:

4.1 **Documented instructions.** Process Personal Data only on documented
instructions from the Controller, including as to international transfers,
unless required to do otherwise by Union or Member State law; in that case the
Processor shall inform the Controller of that legal requirement before
processing, unless that law prohibits such information on important grounds of
public interest. This DPA, the Principal Agreement, and the Controller's own
configuration of the client (notably whether raw command text is enabled — see
Annex I §3) constitute the Controller's complete documented instructions.

4.2 **Immediate notification of unlawful instructions.** Inform the Controller
without delay if, in the Processor's opinion, an instruction infringes the GDPR
or other Union or Member State data protection provisions.

4.3 **Confidentiality.** Ensure that persons authorised to process the Personal
Data are bound by confidentiality obligations. Today that population is
`[NUMBER — currently one: the founder]` natural person(s); see Annex II §6.

4.4 **Security.** Implement the technical and organisational measures set out in
**Annex II**, as required by Article 32.

4.5 **Sub-processors.**
  (a) The Controller grants general written authorisation for the engagement of
      sub-processors. The sub-processors approved at the date of this DPA are
      listed in **Annex III** and maintained publicly at
      [`docs/legal/SUBPROCESSORS.md`](SUBPROCESSORS.md).
  (b) The Processor shall give the Controller at least **`[30]` days' prior
      notice** of the addition or replacement of a sub-processor, by email to
      the Controller's notice address and by update of the public list.
  (c) The Controller may object on reasonable data-protection grounds within
      **`[15]` days** of that notice. If the objection is not resolved, the
      Controller may terminate the affected Services without penalty and
      receive a pro-rata refund of prepaid fees.
  (d) The Processor shall impose on each sub-processor data protection
      obligations no less protective than those in this DPA, and remains fully
      liable to the Controller for the performance of each sub-processor.

4.6 **Assistance with data-subject rights.** Taking into account the nature of
the processing, assist the Controller by appropriate technical and
organisational measures, insofar as possible, in fulfilling the Controller's
obligation to respond to requests under Chapter III GDPR. In practice the
Controller can satisfy access, portability and erasure requests itself:
`gate.cat cloud report` exports the full decrypted history in JSON, and account
deletion is a hard delete (clause 11). The Processor shall forward to the
Controller, without responding to it, any request received directly from a Data
Subject, within **`[5]` business days**.

4.7 **Assistance with Articles 32–36.** Assist the Controller in ensuring
compliance with the obligations in Articles 32 to 36 GDPR (security of
processing, breach notification to the Supervisory Authority and to Data
Subjects, data protection impact assessment, and prior consultation), taking
into account the nature of processing and the information available to the
Processor. The published threat models
([`docs/THREAT_MODEL.md`](../THREAT_MODEL.md),
[`THREAT_MODEL_CLOUD.md`](../../THREAT_MODEL_CLOUD.md)) and the security
one-pager ([`docs/sales/SECURITY_ONEPAGER.md`](../sales/SECURITY_ONEPAGER.md))
are provided as standing input to the Controller's DPIA.

4.8 **Records.** Maintain a record of processing carried out on behalf of the
Controller in accordance with Article 30(2), and make it available on request.

4.9 **Audit and information.** Make available to the Controller all information
necessary to demonstrate compliance with Article 28 and allow for and
contribute to audits, including inspections, conducted by the Controller or an
auditor mandated by the Controller. Given the size of the Processor's
operation, the parties agree the following order of preference:
  (a) the public artefacts first — source code, threat models, test and
      coverage output, the claims register ([`FACTS.md`](../../FACTS.md)) and
      the security one-pager;
  (b) a written security questionnaire, answered within **`[15]` business
      days**, at no charge, up to `[2]` times per 12 months;
  (c) a remote audit interview on **`[30]`** days' notice, once per 12 months;
  (d) an on-site inspection where (a)–(c) are demonstrably insufficient, on
      **`[30]`** days' notice, during business hours, subject to
      confidentiality undertakings, at the Controller's cost, and not more than
      once per 12 months unless a Personal Data Breach has occurred.
  The Processor does **not** hold a SOC 2 or ISO 27001 certification and does
  not claim one; see Annex II §7.

## 5. Personal Data Breach

5.1 The Processor shall notify the Controller of a Personal Data Breach
affecting the Controller's Personal Data **without undue delay and in any event
within `[24] hours`** of becoming aware of it.

> `[BUSINESS DECISION — CONFIRM.]` 24 hours is proposed because it leaves the
> Controller the remaining 48 of its own 72-hour Article 33 window. 48 or 72
> hours are also defensible; a shorter window than 24 hours is not realistic
> for a single-operator vendor and should not be promised.

5.2 The notification shall include, to the extent known: the nature of the
breach, the categories and approximate number of records concerned, the likely
consequences, the measures taken or proposed, and the contact point for further
information. Where the information cannot be provided at once, it shall be
provided in phases without further undue delay.

5.3 The Processor shall not notify a Supervisory Authority or Data Subjects on
the Controller's behalf unless legally required or expressly instructed.

5.4 **Honest scope of a breach here.** A full compromise of the Processor's
server yields event ciphertext, cleartext event timestamps, event counts,
account identifiers (email addresses), and API-key hashes. It does not yield
command text, policy ids, reasons, code, credentials or environment data,
because the Processor never holds the decryption key. This does not remove the
notification duty; it defines what would actually be in scope.

## 6. International transfers

6.1 The Processor shall not transfer Personal Data to a country outside the
European Economic Area, or to an international organisation, except in
accordance with this clause and Annex III.

6.2 Where a transfer to a third country occurs, it shall be governed by:
  (a) an adequacy decision under Article 45; or
  (b) the Standard Contractual Clauses adopted by Commission Implementing
      Decision (EU) 2021/914, **Module Two (controller to processor)** or, as
      between the Processor and a sub-processor, **Module Three (processor to
      processor)**, which are hereby incorporated into this DPA by reference and
      completed as follows:
      - Clause 7 (docking clause): `[INCLUDED / NOT INCLUDED]`
      - Clause 9 (sub-processors): **Option 2 (general written authorisation)**,
        notice period as in clause 4.5(b) of this DPA
      - Clause 11 (redress): optional independent dispute-resolution body
        `[INCLUDED / NOT INCLUDED]`
      - Clause 17 (governing law): the law of `[MEMBER STATE — proposed: Poland]`
      - Clause 18(b) (forum): the courts of `[MEMBER STATE — proposed: Poland]`
      - Annexes I, II and III of the SCCs are populated by Annexes I, II and III
        of this DPA
  (c) supplemented, where required, by the transfer impact assessment at
      `[REFERENCE — TO BE PREPARED IF A NON-EEA SUB-PROCESSOR IS ENGAGED]`.

6.3 Where the Controller is established in the United Kingdom, the UK
International Data Transfer Addendum to the SCCs (version B1.0) applies:
`[APPLICABLE / NOT APPLICABLE]`.

## 7. Rights and obligations of the Controller

7.1 The Controller warrants that it has a lawful basis for the processing it
instructs, that it has provided any required transparency information to its
own personnel, and that it is entitled to transfer the Personal Data to the
Processor.

7.2 **The raw-command setting is the Controller's decision.** By default the
client transmits only a SHA-256 hash of the matched command. If the Controller
sets `GATECAT_CLOUD_SEND_RAW=1`, raw command text (truncated to 4096
characters) is placed inside the encrypted payload. The Controller is
responsible for assessing whether its agents' command lines can contain
personal data or secrets before enabling that setting. The Processor's
recommendation, stated in the product documentation, is to leave it off.

7.3 The Controller is responsible for custody of its encryption key
(`~/.gatecat/cloud.key`). **If the key is lost, the off-machine history is
unreadable by anyone, including the Processor.** That is a design property, not
a defect, and it is the reason the Processor cannot restore access.

## 8. Limits of what the Processor can do

8.1 The Processor cannot search, filter, redact or selectively correct the
content of stored events, because it cannot decrypt them.

8.2 The event store is **append-only by construction**: the server exposes no
update and no delete route for individual events. Correction of an individual
record is therefore not technically available.

8.3 Where the Controller requires rectification or erasure of specific content,
the available remedies are (i) the Controller's own local export and
re-ingestion, or (ii) deletion of the account store in whole, per clause 11.
The parties acknowledge these constraints as a deliberate integrity property of
the Services, disclosed before contracting.

## 9. Liability

9.1 Each party's liability under or in connection with this DPA is subject to
the exclusions and limitations of liability set out in the Principal Agreement.
Nothing in this DPA limits liability that cannot be limited under applicable
law, including under Article 82 GDPR as between a party and a Data Subject.

9.2 The aggregate liability cap applicable to this DPA is
`[AS SET OUT IN THE PRINCIPAL AGREEMENT / STATE AMOUNT]`.

> `[BUSINESS DECISION — CONFIRM.]` No cap figure is stated here because none has
> been agreed. A common position for a subscription at this price point is the
> fees paid in the preceding 12 months; enterprise buyers frequently ask for a
> super-cap or an uncapped carve-out for data-protection breaches. Do not agree
> to an uncapped position without insurance in place — see
> [`docs/sales/BUYING.md`](../sales/BUYING.md) for the current insurance
> position.

## 10. Term

This DPA takes effect on the effective date of the Principal Agreement and
continues for as long as the Processor processes Personal Data on behalf of the
Controller.

## 11. Deletion or return on termination

11.1 On termination or expiry of the Services, and at the Controller's choice,
the Processor shall delete or return all Personal Data processed on behalf of
the Controller and delete existing copies, unless Union or Member State law
requires storage.

11.2 The Controller can export at any time during the term
(`gate.cat cloud report`, JSON) and should do so before termination.

11.3 Default behaviour absent a contrary instruction: **hard delete of the
account's event store within `[30]` days of termination.** Billing records are
retained separately for the statutory period under Polish accounting and tax
law (`[5]` years from the end of the tax year — `[CONFIRM WITH ACCOUNTANT]`);
those records are held by the Processor as a controller, not under this DPA.

11.4 Backups: `[CONFIRM — state the backup regime and the maximum lag before a
deleted account disappears from backup media. Do not sign a "deleted
immediately everywhere" clause the backup schedule cannot honour.]`

## 12. Order of precedence, severability, governing law

12.1 In the event of conflict between this DPA and the Principal Agreement, this
DPA prevails on data protection matters. Where the SCCs apply, the SCCs prevail
over both.

12.2 If any provision is held invalid, the remainder continues in effect.

12.3 This DPA is governed by the law of `[POLAND / OTHER]`, and the courts of
`[CITY, POLAND / OTHER]` have exclusive jurisdiction, without prejudice to
clause 6.2(b).

---

**Signatures**

| | Controller | Processor |
|---|---|---|
| Name | `[NAME]` | `[NAME]` |
| Title | `[TITLE]` | `[TITLE]` |
| Entity | `[CUSTOMER LEGAL NAME]` | `[SUPPLIER LEGAL ENTITY NAME]` |
| Date | `[DATE]` | `[DATE]` |
| Signature | | |

---

# Annex I — Description of the processing

## 1. List of parties

**Data exporter / Controller:** `[CUSTOMER LEGAL NAME]`, `[ADDRESS]`.
Contact: `[NAME, ROLE, EMAIL]`. Activities relevant to the transfer: operating
AI coding agents on developer workstations and build infrastructure, and
retaining an off-machine record of the actions those agents attempted.
Role: **Controller**.

**Data importer / Processor:** `[SUPPLIER LEGAL ENTITY NAME]`, `[ADDRESS,
POLAND]`. Contact: `bgml@bgml.ai`. Activities relevant to the transfer:
operating the gate.cat Cloud endpoint that receives, stores and serves back
encrypted veto-event records. Role: **Processor**.

## 2. Categories of Data Subjects

- The Controller's employees, contractors and other personnel who operate a
  machine on which gate.cat is installed with Cloud enabled (typically software
  engineers; the identifying element is the machine and the account, not the
  person).
- The Controller's administrative and billing contacts.

No other category of Data Subject is expected. The Services do not process data
about the Controller's own customers or end users, unless the Controller
enables raw command text and its agents' command lines contain such data — see
§3 below and clause 7.2.

## 3. Categories of Personal Data

Stated at the level of what is actually transmitted. The exhaustive list of
fields is visible in `gatecat/cloud_reporter.py` (function `_redact`) and
`products/cloud/cloud_server.py` (function `_store`).

### 3.1 Visible to the Processor (cleartext)

| Field | Content | Personal data? |
|---|---|---|
| Account identifier | the email address supplied at checkout; also the storage partition key | Yes — a business email address |
| API-key hash | SHA-256 of the account API key. The plaintext key is never stored | Pseudonymous credential material |
| Event timestamp | epoch seconds, per event, needed for ordering and retention | Indirectly, in combination |
| Event sequence number | integer, per account | Indirectly |
| Record class tag | the literal string `ledger` on gate-toggle / override records, or absent. No other value is accepted from the client | No |
| Ciphertext blob | AES-256-GCM, base64, ≤ 64 KiB per event | Opaque to the Processor |
| Client version string | `gatecat-cloud/<version>` in the User-Agent header | No |
| Source IP address | presented by the reverse proxy for rate limiting. Held in an in-memory counter for a `[10]`-second window; the Cloud service writes no HTTP request log (`Handler.log_message` is a no-op) | Yes, transiently |

### 3.2 Inside the ciphertext — the Processor cannot read these

Present because the Controller can read them after local decryption, and
because they define what the Controller has entrusted to the encrypted store:

- event timestamp and source (`hook`, `shell`, adapter name)
- policy id (e.g. `RM_RF`, `DB_DESTRUCTIVE`) and verdict (`block` / `warn` /
  `allow` / gate-state transition)
- reason string, truncated to 256 characters
- **SHA-256 hash of the matched command** — the default; the command text
  itself does not leave the machine
- gate version and the redaction mode in force (`hash` or `raw`)
- for ledger records: the two 16-hex hash-chain tips that let the client verify
  the chain has not been cut

### 3.3 Only on explicit opt-in by the Controller

- **Raw matched command text**, truncated to 4096 characters, when
  `GATECAT_CLOUD_SEND_RAW=1` is set on the Controller's machine. Still inside
  the ciphertext. A command line may incidentally contain a filesystem path
  including a username, a hostname, or — if the Controller's engineers do this
  — a credential typed on a command line. This setting is off by default and
  the documentation advises against it.

### 3.4 Only if the Controller enables the optional fleet / alert features

- **Machine identifier** (`X-Gatecat-Machine` header, ≤ 200 characters,
  Controller-chosen) — stored in the clear, used to enforce the per-plan
  machine cap.
- **Alert records** — `kind` (≤ 64 chars), `machine` (≤ 200 chars) and a
  `reason` string (≤ 400 chars), stored in the clear so that an out-of-band
  notification can be sent without breaking event encryption. These carry
  operational metadata, not command text.

> As of gate.cat 0.4.18 the shipped reporter client sends neither a machine
> identifier nor alert records; both are server-side capabilities. If the
> Controller starts using them, §3.4 becomes live and the Controller should
> re-read this Annex.

## 4. Data that is never processed

File contents, environment variables, API keys, tokens or other secrets, source
code, prompts, model outputs, browsing or usage telemetry, analytics of any
kind, special categories of personal data under Article 9, criminal-offence
data under Article 10, and data of children.

The Processor does not intend to receive special-category data. The Controller
must not enable raw command text in an environment where command lines
routinely embed such data.

## 5. Frequency of the transfer

Continuous while enabled, in batches of up to 200 events per request from the
client (server ceiling 500 per request), on the Controller's own schedule —
typically a cron job or systemd timer. Zero transfers when Cloud is off, which
is the default.

## 6. Nature and purpose of the processing

Receipt over TLS, bearer-token authentication against a stored key hash,
append to a per-account event file, retention-windowed read-back, and hard
deletion on request. Purpose: to hold a copy of the Controller's veto history
outside the reach of the AI agent whose actions it records, and to make local
tampering detectable (`gate.cat cloud verify`).

## 7. Retention

The published retention is **12 months** of event history
([PRICING.md](../../PRICING.md)). The server additionally enforces a per-plan
retention window on read-back; the window applicable to this Controller is
`[STATE THE WINDOW FOR THE CONTRACTED PLAN — CONFIRM against the server's tier
table before signature]`. On termination, clause 11 applies.

## 8. Competent Supervisory Authority

For the Processor: the Polish supervisory authority, **Prezes Urzędu Ochrony
Danych Osobowych (UODO)**, Warsaw, Poland.
For the Controller: `[SUPERVISORY AUTHORITY]`.

---

# Annex II — Technical and organisational measures

These are the measures the product actually implements. Each is verifiable in
the public repository; file references are given so a reviewer can check rather
than believe. Measures the Processor does **not** have are listed in §7, first,
because that is more useful to a reviewer than a longer list of the ones it
does.

## 1. Pseudonymisation and encryption (Art. 32(1)(a))

- **Client-side end-to-end encryption.** Every event is encrypted with
  **AES-256-GCM** on the Controller's machine before transmission
  (`gatecat/cloud_crypto.py`). Key: 32 random bytes in `~/.gatecat/cloud.key`,
  file mode `0600`, generated locally, never transmitted. A fleet may instead
  derive a shared key from a passphrase via **scrypt** (N=2^15, r=8, p=1,
  32-byte output). The server never participates in key exchange.
- **Authenticated encryption with associated data.** The AAD is a fixed version
  label; any tampering with a stored blob fails authentication on decrypt.
- **Minimisation before encryption.** The default payload carries a **SHA-256
  hash of the matched command**, not the command. Raw text requires an explicit
  opt-in environment variable.
- **Credential storage.** API keys are stored as **SHA-256 hashes only**
  (`products/cloud/cloud_server.py`, `issue_key`). A leak of the accounts file
  does not expose usable keys.
- **Encryption in transit.** TLS to the public endpoint (certificates issued by
  Let's Encrypt; the endpoint is fronted by a CDN/WAF — see Annex III).
- **Encryption at rest.** Application-layer: every event body is ciphertext, so
  the at-rest store is encrypted regardless of the disk. Full-disk encryption on
  the host: `[CONFIRM WITH BOGUMIŁ]`.

## 2. Confidentiality and access control (Art. 32(1)(b))

- Bearer-token authentication on every Cloud request; an unknown or revoked key
  returns `401` before any data is touched.
- **Tenant isolation by construction:** every read and write is scoped to the
  account resolved from the presented key. Account identifiers are sanitised to
  a filename-safe character set before use in a path, guarding path traversal.
- The Cloud service binds to `127.0.0.1` and is reachable only through the
  reverse proxy.
- Key revocation is an append-only account record (`revoke_key`), so revocation
  is durable and auditable and does not rewrite history.
- Administrative access to the host is by SSH key only, from the founder's
  machine. Number of persons with production access: `[NUMBER — currently 1]`.
  Multi-factor authentication on the hosting, DNS, code-hosting and payment
  accounts: `[CONFIRM WITH BOGUMIŁ]`.

## 3. Integrity (Art. 32(1)(b))

- **Append-only by construction.** The server exposes no update and no delete
  route for individual events. This is a design property, not a permission
  setting.
- **Per-account write serialisation.** A per-account lock serialises the
  read-sequence-then-append path, so concurrent writers cannot produce duplicate
  sequence numbers or interleaved records.
- **Tamper detection at the Controller's end.** `gate.cat cloud verify` fetches
  the off-machine copy, decrypts locally, and diffs it against the local log:
  entries an agent deleted locally but that already shipped surface as an alarm.
- **Hash-chained ledger.** Gate on/off flips and override grants are written as
  hash-chained records; the chain tips ride inside the encrypted payload and the
  chain is verified **on the client**, so the Processor is not trusted to
  validate its own storage.

## 4. Availability and resilience (Art. 32(1)(b), (c))

- **The safety function does not depend on this service.** Cloud is a reporter
  beside the gate, never in its execution path. If Cloud is down, unreachable or
  cancelled, the gate blocks exactly as before. Loss of availability of the
  Processor's service therefore does not create a safety incident for the
  Controller — it creates a gap in the record, which is itself visible.
- The client is fail-silent and cursor-based: it advances its read cursor only
  after a successful ship, so an outage delays but does not lose events, as long
  as the local log is intact.
- Abuse and denial-of-service controls: per-IP fixed-window rate limit
  (`[200]` requests / `[10]` s), per-request body ceiling (8 MiB), per-event
  blob ceiling (64 KiB), per-batch ceiling (500 events). Unhandled exceptions
  are converted to a clean `500` rather than dropping the connection.
- Backup and restore regime: `[CONFIRM WITH BOGUMIŁ — frequency, location,
  retention, restore test date]`.
- Uptime commitment: `[NONE CONTRACTED / STATE SLA]` — see §7.

## 5. Testing and evaluation of effectiveness (Art. 32(1)(d))

- **1,956 tests collected with 0 failures on 0.4.18, and the CI matrix is green
  on Python 3.11–3.13** (FACTS F3). CI runs on every push and pull request.
- **73% statement coverage, printed by CI on every run** (FACTS F12). Proxy and
  CI/CLI paths are the least covered.
- A dedicated adversarial suite for the Cloud path is in the repository
  (`tests/test_cloud_e2ee.py`, `tests/test_cloud_reporter.py`,
  `tests/test_cloud_server_hardening.py`).
- **The reproducible bypass suite catches 178/178 danger shapes it claims, with
  one benign false-block in 129 cases and 3 published regex-wall gaps — 2 of
  them (a Unicode homoglyph and a printf-hex assembled `rm`) slip the whole
  product, the 3rd the delete-analyzer still blocks** (FACTS F4). The Processor
  publishes its own gaps rather than asserting there are none.
- Independent penetration test: `[NONE COMMISSIONED — CONFIRM WHETHER TO
  COMMISSION ONE BEFORE ENTERPRISE SALES]`.

## 6. Personnel

- The Processor is a single-operator business. All persons with access to
  Personal Data: `[NUMBER — currently 1]`.
- Confidentiality obligations: `[STATE — for the founder, by operation of the
  Principal Agreement; for any future contractor, by written NDA before
  access]`.
- Security awareness training: `[CONFIRM APPROACH]`.

## 7. What these measures do **not** include

Stated first in any conversation with a security reviewer, because a list of
strengths without this section is not evidence:

- **No SOC 2 report and no ISO 27001 certificate.** The Processor is a
  solo-founder vendor. The compensating position is that the trust model does
  not require believing the Processor: the client is Apache-2.0, the reporter
  and the crypto are readable Python, and the Business tier can host the
  evidence log in the Controller's own infrastructure.
- **The Processor sees metadata.** Event counts and cleartext timestamps per
  account are visible, and are the deliberate, disclosed cost of storing an
  ordered append-only timeline server-side. So is the account email address.
- **No 24/7 on-call.** Incident response is best-effort during
  `[BUSINESS HOURS / TIMEZONE — CONFIRM]`.
- **No formal, tested disaster-recovery plan** beyond the backup regime in §4.
- **Key loss is unrecoverable.** If the Controller loses its encryption key, the
  Processor cannot restore access. This is intentional.
- **The alert feed, if enabled, is cleartext metadata** (Annex I §3.4) and does
  not enjoy the end-to-end encryption property.
- **No attestation that the gate was armed.** The stored history is evidence of
  what the gate saw, not proof that it was running: a client with the hook
  removed produces an empty log for the same reason it produces no protection.
  Signed heartbeat and configuration attestation are designed but not shipped as
  at 2026-07-31. A Controller relying on this record for assurance should
  operate its own check that the hook is installed on each machine.

---

# Annex III — Approved sub-processors

The authoritative, dated list is maintained at
[`docs/legal/SUBPROCESSORS.md`](SUBPROCESSORS.md) and is incorporated into this
DPA by reference. The list as at **2026-07-31** is reproduced there in full,
including for each entry the role, the categories of data touched, the
processing location, and the transfer mechanism where applicable.

Changes are notified per clause 4.5(b); the Controller may subscribe to change
notices at the address given in that file.

`[CONFIRM: paste the table into this Annex as a point-in-time snapshot at
signature, so the executed document is self-contained.]`
