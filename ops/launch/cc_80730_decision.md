# claude-code #80730 — decision record: NO-GO (do NOT post)

**Decision (2026-07-24, loop run #43): NO-GO.** This is a decision record, not
a paste-ready comment. We are deliberately NOT preparing a promotional reply.

## Why NO-GO (verified, not inferred)

The thread has escalated to **legal**: the reporter (`duquedotdev`) sent emails
to `legal@anthropic.com` and `support@anthropic.com` and it's part of a
coordinated incident report (#80728/#80729). The panel's own GO/NO-GO gate said
do not post if the thread turns into a pile-on or legal escalation — that
condition is objectively met.

Posting an adjacent product on a data-loss thread that someone has taken to
legal — even with full disclosure and even foregrounding our own non-catch —
reads as exploiting a stranger's crisis, and carries real reputational/legal
risk. Not worth a $0–20 variance shot. If the thread's legal framing clears and
it becomes a normal technical permission-system discussion, revisit.

## The genuinely useful part: a verified product gap

Replaying the incident commands through the gate today (sandbox, verbatim
verdicts) shows gate.cat catches 3 of 5 — but **misses the exact command that
caused the loss**:

| Command (from the incident) | gate.cat verdict |
|---|---|
| `npm create vite@latest pluto -- --template react --typescript` | **ALLOW** — the command that destroyed a populated dir |
| `rm -rf /Users/felipeduque/www/pluto` | BLOCK [DELETE_ANALYZER] |
| `git reset --hard HEAD` | BLOCK [GIT_DESTRUCTIVE] |
| `git clean -fd` | BLOCK [DELETE_ANALYZER] |
| `git checkout -- .` | ALLOW (deliberate — pinned in tests/test_v0413_gaps.py::DELIBERATELY_ALLOW) |

**Uncaught danger class surfaced: scaffold-overwrite.** A scaffolder
(`npm create` / `pnpm create` / `yarn create` / `degit` / `create-*`) run with
a target that is an EXISTING non-empty directory can overwrite/destroy its
contents, and no current policy sees it (it's not a delete verb, not a git
destructive op). This is a real, honest gap — the kind the bypass suite exists
to surface. It is NOT a marketing line; it's a candidate for a future policy
(with the usual danger/benign-twin test: overwrite of a populated dir vs.
scaffold into a fresh/empty dir), only after PR #27 lands and the queue reopens.

## Recorded, not actioned

- No comment drafted, nothing to post.
- Scaffold-overwrite gap logged here as a future-policy candidate (needs owner
  product call on the danger/benign boundary — do not ship silently, it changes
  the coverage surface).
