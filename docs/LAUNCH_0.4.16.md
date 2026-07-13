# gate.cat 0.4.16 launch kit

Canonical links:

- Product: https://gate.cat
- Repository: https://github.com/BGMLAI/gate.cat
- Release: https://github.com/BGMLAI/gate.cat/releases/tag/v0.4.16
- PyPI: https://pypi.org/project/gate.cat/0.4.16/
- Method and evidence: https://gate.cat/blog/1m-agent-commands.html

Every post must preserve the product boundary: gate.cat is certain only about
what it blocks. An unmatched action is unchecked, not verified safe. The local
gate is free and Apache-2.0; Cloud is optional.

## Show HN

**Title:** Show HN: gate.cat – a local veto layer for AI coding agents

I built gate.cat because an agent deciding to run a command and the system
deciding whether that command may run should be separate decisions.

It is a local, open-source veto layer for coding agents. The Claude Code hook
can refuse destructive shell, cloud, database, identity, billing and
secret-handling actions before execution. The current release ships 71 default
policy walls; the policies are plain text and the local product needs no
account or API key.

I tried to make the evidence unusually reproducible: 1,863 local tests pass,
CI is green on Python 3.11–3.13, the known-danger recall script neutralizes
43/43 catalog classes with 0/13 benign twins hard-blocked, and the bypass suite
prints its own known gap and false-block instead of hiding them.

The honest limit: unmatched does not mean safe. Regex/policy walls cannot prove
arbitrary programs harmless, and the framework adapters are weaker than an
out-of-process hook. The free gate is Apache-2.0; optional Cloud stores an
encrypted off-machine evidence copy.

Install with the reviewed two-step user-local installer (it creates a private
venv and works on PEP 668 systems):

```bash
curl -fsSL https://raw.githubusercontent.com/BGMLAI/gate.cat/master/install.sh -o /tmp/gatecat-install.sh
sh /tmp/gatecat-install.sh
```

I would especially value adversarial examples that bypass a named policy or
benign commands that get blocked. Those become regression tests.

## X / Bluesky / Mastodon

I shipped gate.cat 0.4.16: a free, local veto layer for AI coding agents.

71 default policy walls. 1,863 tests. CI on Python 3.11–3.13. The bypass suite
publishes its own gap.

Safe two-step installer (download, inspect, then run): https://gate.cat

Unmatched means unchecked — not “safe.”

https://gate.cat

## LinkedIn

AI coding agents should not be the final authority on whether their own shell
commands are allowed to run.

Today I released gate.cat 0.4.16, an open-source local veto layer. It puts a
separate policy decision between an agent proposal and execution, covering 71
default destructive-action policies across shell, cloud, databases, identity,
billing and secrets.

The release gate is reproducible: 1,863 local tests, green CI on Python
3.11–3.13, 43/43 known danger classes neutralized, and a bypass suite that
explicitly prints its known gap and benign false-block.

The boundary matters: gate.cat is certain only about what it blocks. An
unmatched action is unchecked, not verified safe. The local gate is free,
Apache-2.0 and needs no account; Cloud is optional.

Product: https://gate.cat
Source: https://github.com/BGMLAI/gate.cat

## Reddit / community post

**Title:** I built a local veto layer that can stop destructive AI-agent commands before execution

gate.cat 0.4.16 is an Apache-2.0 policy gate for coding agents. The main use case
is simple: the model proposes an action, but a separate local hook decides
whether a known destructive shape may execute.

It ships 71 default policies and requires no account for local use. The release
has 1,863 passing local tests, a green Python 3.11–3.13 CI matrix, and public
recall/bypass scripts. I am explicitly not claiming that an unmatched command
is safe; the suite publishes one runtime-assembly bypass and one benign
false-block.

Install with the reviewed two-step user-local installer:

```bash
curl -fsSL https://raw.githubusercontent.com/BGMLAI/gate.cat/master/install.sh -o /tmp/gatecat-install.sh
sh /tmp/gatecat-install.sh
```

Repo: https://github.com/BGMLAI/gate.cat

I am looking for concrete bypasses and false positives, especially commands
from real coding-agent sessions. Please redact secrets before sharing.

## Publication gate

Before posting beyond owned channels, verify all of the following:

- `gate.cat` serves the reviewed 0.4.16 landing and two-step installer command.
- Public PyPI clean install returns 0.4.16.
- Cloud health returns 200.
- Stripe has a live-mode webhook for checkout completion, subscription updates
  and cancellation while Lemon Squeezy account review is pending.
- Production rejects an invalid Stripe signature and accepts a correctly signed
  non-mutating event; automated tests cover idempotent provisioning and revocation.
- Each live post URL is added to GitHub issue #9 with timestamp and owner.
