# Security Policy

## Reporting

Found a bypass, a false negative, or any security issue? **That is the most valuable
contribution this project can receive.** Report it:

- Preferred: [open a veto-story issue](https://github.com/BGMLAI/gate.cat/issues/new?template=veto-story.yml)
  (public is fine for deny-list gaps — the bypass suite already prints its known gaps).
- For anything sensitive (e.g. a vulnerability in the hook itself, not just a pattern gap):
  email **bgml@bgml.ai**. You'll get a reply within 72 hours.

Reported gaps get fixed and credited in the CHANGELOG.

## Scope — what a report means here

gate.cat's own doctrine applies to itself: the gate is certain only about what it **blocks**.
An action it does not match is *unchecked*, not *safe*. A new unmatched-but-dangerous shape is
an expected finding, not an embarrassment — please send it.

- In scope: deny-list gaps, analyzer false negatives, fail-open behaviors (anything where an
  error path ALLOWS instead of blocking), hook-integration bypasses, false-positive classes.
- Known, documented gaps (printed by `bypass_suite`): base64-assembled payloads, deletes via a
  language runtime, `curl|sh` obfuscation variants — improvements welcome, reports not needed.

## Supported versions

Only the latest release on PyPI receives fixes.

## Disclosure

No bounty program (solo, pre-revenue). If you plan to publish a working bypass, a 14-day heads-up
before publication is appreciated — most pattern fixes ship in days.
