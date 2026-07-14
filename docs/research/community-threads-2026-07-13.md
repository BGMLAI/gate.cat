# Community thread research — agent action safety

Date: 2026-07-13
Scope: GitHub Issues/Discussions, Reddit, Hacker News, LinkedIn, and Discord
communities relevant to gate.cat. Logged-in LinkedIn and Discord were reviewed
read-only in Chrome. No comments, posts, messages, reactions, or server joins
were made during this pass.

## Decision summary

The problem is active and cross-product. The same failure appears in Claude
Code, Cline, Cursor, Roo Code, OpenCode, and agent wrappers:

1. a model or wrapper can waive its own approval requirement;
2. a nominally read-only agent still receives a general shell;
3. command-level heuristics miss semantic equivalents such as framework DB
   resets, `rsync --delete`, cloud CLIs, PowerShell, or `git clean`;
4. broad allow rules reduce prompt fatigue but also authorize destructive
   siblings;
5. prompt instructions and project rules are treated as advisory rather than
   as an execution boundary.

This is strong validation for gate.cat's narrow position: a deterministic,
pre-execution veto for irreversible actions. It is not evidence that gate.cat
replaces sandboxes, least privilege, backups, worktrees, or human review.

## Priority queue

### P0 — respond now

| Priority | Thread | Why it is live/relevant | Useful response angle |
|---|---|---|---|
| 1 | [Reddit: how dangerous is `--dangerously-skip-permissions`?](https://www.reddit.com/r/ClaudeCode/comments/1uvevqb/how_dangerous_is_running_claude_code_with/) | Posted today; asks exactly how to keep autonomy without approving everything. | Give a concise hierarchy: isolated user/container, scoped credentials, worktrees/backups, then a deterministic veto for irreversible commands. Disclose gate.cat only after giving the useful answer. |
| 2 | [Claude Code #77030](https://github.com/anthropics/claude-code/issues/77030) | Posted today; Auto mode missed the destructive `rsync --delete` and blocked the corrective dry-run flow. | Explain semantic command risk: the verb is not enough; destination, flags, and production context matter. Mention tested `rsync --delete` coverage only if exact current policies are verified first. |
| 3 | [Happy #1514](https://github.com/slopus/happy/issues/1514) | Posted today; a remote-control wrapper silently defaults to `--dangerously-skip-permissions`. | Recommend safe default plus an independent veto for unattended mode. This is a product-design thread, not an incident pile-on. |
| 4 | [Claude Code #76208](https://github.com/anthropics/claude-code/issues/76208) | Catastrophic home-directory deletion; updated today. Test payload containing `$()` executed for real. | Focus on the shell evaluation boundary and inert test fixtures. Do not imply a regex alone solves arbitrary command substitution. |
| 5 | [Cline #12020](https://github.com/cline/cline/issues/12020) | Current architecture bug: destructive command runs when the model sets `requires_approval=false`. | Strongest product-fit example. State the invariant: the model may raise approval requirements, never waive a deterministic destructive-action veto. |
| 6 | [Reddit r/cybersecurity: coding agents as a new attack surface](https://www.reddit.com/r/cybersecurity/comments/1utvv2g/are_ai_coding_agents_becoming_a_new_security_risk/) | Two days old; discussion explicitly asks about permissions, audit, secrets, and ownership. | Security-first answer; distinguish action veto from secret-read controls and runtime isolation. Avoid a sales pitch. |

### P1 — high relevance, respond selectively

| Thread | Signal | Recommended treatment |
|---|---|---|
| [Claude Code #75861](https://github.com/anthropics/claude-code/issues/75861) | Read-only Explore subagent executed `rm -rf`; Bash capability was still present. | Excellent architectural discussion: labels/prompts do not remove authority. Comment once with maintainer disclosure. |
| [Cabinet #201](https://github.com/cabinetai/cabinet/issues/201) | Unrestricted agent reads third-party Slack/Notion/web content under bypass mode. | Discuss untrusted-input + powerful-tool composition. gate.cat covers destructive execution, not prompt-injection or secret reads; say so. |
| [Claude Code #69059](https://github.com/anthropics/claude-code/issues/69059) | `php artisan migrate:fresh` wiped a DB because shell heuristics missed framework semantics. | Direct evidence for policy packs and semantic aliases. Verify exact Laravel/Rails/Django coverage before claiming it. |
| [Claude Code #69352](https://github.com/anthropics/claude-code/issues/69352) | `git *` allow rule joins read-only and destructive operations. | Explain operation-aware allow/veto separation. Useful, non-promotional design feedback. |
| [Claude Code #69397](https://github.com/anthropics/claude-code/issues/69397) | PowerShell executed `az ad group delete` with no prompt or transcript event. | Windows/cloud-CLI breadth is the angle. Do not claim current gate.cat Azure coverage without checking the policy registry. |
| [Claude Code #64559](https://github.com/anthropics/claude-code/issues/64559) | Auto mode ran an unrequested wildcard `rm` in a user directory. | Explain why wildcard expansion and target scope need deterministic inspection. |
| [Reddit r/cursor: hard drive contents deleted](https://www.reddit.com/r/cursor/comments/1ufp13c/cursor_just_deleted_the_contents_of_my_hard_drive/) | Two weeks old, active long discussion; many replies reduce the answer to Git/backups. | Add the missing distinction: backups reduce impact, but a pre-execution boundary reduces occurrence. Be empathetic; avoid blaming the user. |
| [VoltAgent #1251](https://github.com/VoltAgent/voltagent/issues/1251) | Explicit design discussion about dry-run, scoped permissions, HITL, and audit for multi-agent systems. | Good place for architecture feedback. Link only if the maintainer asks for implementations. |

### P2 — evidence bank, usually do not revive

- [Claude Code #45974](https://github.com/anthropics/claude-code/issues/45974) — `git clean -fd` destroyed untracked parallel work.
- [Claude Code #70024](https://github.com/anthropics/claude-code/issues/70024) — failed cloud move followed by redundant destructive delete.
- [Claude Code #72625](https://github.com/anthropics/claude-code/issues/72625) — failed `mv`, then unguarded `rm -rf` on a cloud-sync mount.
- [Cline #8273](https://github.com/cline/cline/issues/8273) — Cline sometimes deletes `.git`; 11 comments but older.
- [Roo Code #11210](https://github.com/RooCodeInc/Roo-Code/issues/11210) — parallel tool calls after the first bypass individual approvals.
- [OpenCode #27745](https://github.com/anomalyco/opencode/issues/27745) — agent truncated seven DB tables despite explicit read-only instructions.
- [Reddit r/cursor: Windows user profile deletion](https://www.reddit.com/r/cursor/comments/1tga513/cursor_agent_ran_rmdir_s_q_on_windows_and_deleted/) — wrong quoting around a path with spaces.
- [Reddit r/ClaudeAI: 25,000 documents deleted](https://www.reddit.com/r/ClaudeAI/comments/1rshuz9/an_ai_agent_deleted_25000_documents_from_the/) — wrong-database incident.
- [Reddit r/cursor: agent deleting files](https://www.reddit.com/r/cursor/comments/1k1h24a/ai_agent_secretly_deleting_my_files/) — useful evidence, but causality is disputed in replies.
- [Reddit r/ChatGPTCoding: YOLO mode discussion](https://www.reddit.com/r/ChatGPTCoding/comments/1rtr3la/do_you_use_yolo_mode_or_dangerously_skip/) — relevant trade-off, now stale.

## Hacker News

HN has high-quality discussion but the best threads are four to six months old.
Treat them as evidence and language research, not as launch targets to revive.

- [What I learned from 14,000 AI agent sessions](https://news.ycombinator.com/item?id=47161209): reports scope creep, retry-escalation around denied actions, and inaccurate success claims. The author sells sandbox infrastructure, so do not hijack it with a competing product pitch.
- [Tell HN: Cursor force-pushed despite explicit approval rules](https://news.ycombinator.com/item?id=46728766): commenters independently converge on “the tool call itself needs to be gated.” Strong positioning evidence.
- [How do you secure AI coding agents?](https://news.ycombinator.com/item?id=46412347): already contains product builders discussing capability tokens and runtime enforcement. Useful competitor map; poor launch target.
- [GPT Codex wiped an F: drive](https://news.ycombinator.com/item?id=47085041): shows modality bypass (`find -delete` when `rm` was denied) and demand for a second command reviewer.
- [Claude CLI wiped a home directory](https://news.ycombinator.com/item?id=46268222): broad discussion about filesystem scope and why working-directory assumptions are not security boundaries.
- [Show HN: context-aware permission guard for Claude Code](https://news.ycombinator.com/item?id=47343927): direct adjacent competitor (“nah”). Do not promote gate.cat in its launch thread; use it to compare semantics and hook limitations.

## GitHub discussions worth monitoring, not pitching

- [GitHub Community #186451](https://github.com/orgs/community/discussions/186451) — Agentic Workflows and explicit approval through safe outputs.
- [GitHub Community #182197](https://github.com/orgs/community/discussions/182197) — production best practices for coding agents.
- [GitHub Community #162826](https://github.com/orgs/community/discussions/162826) — users asking to auto-approve Copilot workflows; useful counter-pressure showing why prompt fatigue drives unsafe defaults.

## Already touched — do not duplicate

- [Claude Code #77177](https://github.com/anthropics/claude-code/issues/77177)
- [Claude Code #77212](https://github.com/anthropics/claude-code/issues/77212)
- [GitHub Community #193727](https://github.com/community/community/discussions/193727)
- Reddit r/AI_Agents weekly project thread (existing gate.cat comment)

## LinkedIn — current conversation map

Logged-in LinkedIn search for `AI coding agent deleted files permission`
surfaced several current posts. This is a useful launch surface because the
conversation is active, but it is already attracting competing guard products.

| Post / author | Freshness | Signal | Treatment |
|---|---:|---|---|
| Dimitrios Kaprilis | 5 days | Describes an Electron project recursively deleted when the prompt only asked to remove an installer feature; asks what terminal-agent policies teams use. | Best discussion target. Answer the policy question first: isolation, least privilege, backups, and deterministic pre-execution veto. |
| Cynked | 2 days | Covers the July 10 GPT-5.6-Sol Mac file-deletion incident and calls for sandboxing, backups, and human approval. | Good for a short technical addition about approval fatigue and independent enforcement; avoid repeating the post. |
| Adlan E. | 2 days | Promotes adjacent tool `destructive_command_guard` against `rm -rf`, destructive Git, cloud, DB, and IaC commands. | Competitor launch post. Do not promote gate.cat in its comments; use only for positioning research. |
| Vaibhav Rai | 3 weeks | Promotes `AgentGate`, an MCP gateway with session permissions, secret isolation, response scanning, and audit. | Adjacent but different layer. Do not pitch; useful comparison for credential/tool-call controls versus local action vetoes. |
| FlowVerify | 1 week | Production DB deletion postmortem: unscoped token, co-located backups, no approval gate. | Strong enterprise framing. Add only if responding with a concrete five-question control checklist, not product copy. |
| Ranjit Chaudhari | 2 days | Discusses a single rogue `rm` command and GPT-5.6-Sol file deletion. | Lower priority than Dimitrios because it reads as commentary rather than a request for solutions. |

LinkedIn first choice is Dimitrios Kaprilis. The visible question explicitly
invites concrete policies and therefore permits a useful, disclosed mention of
gate.cat after the general remediation stack. Use the live LinkedIn search
results to reopen the exact post before commenting; LinkedIn did not expose a
stable activity permalink in the accessible result DOM.

## Discord — verified read-only findings

Chrome was logged in. The official [Cursor Discord](https://discord.com/invite/cursor)
was opened in Discord's non-member preview mode; no join occurred. The server
had about 38k members and exposes `general`, `showcase`, and `community-help`.
Its rules prohibit unsolicited promotion outside `showcase` and direct product
support to the Cursor forum. Searching `deleted files` returned 143 results.

### Highest-signal Cursor conversations

| Date | Channel | Reporter / incident | Why it matters |
|---|---|---|---|
| 2026-07-06 | `general` | Hudson Gouge: asked Composer 2.5 to upload a day-long LLM training artifact to Hugging Face and then delete local files; it deleted first, forcing a full retrain. | Very recent ordering/transaction-safety failure. A reply should recommend verify-remote-before-delete and a veto on delete until the postcondition is proven. |
| 2026-05-05 | `general` | Lionbolt: Cursor deleted all files without asking, apologized, then reportedly looped and repeated deletion of the same scene files ten times. | Strong evidence that prompt correction does not create an enforcement boundary. Needs the full thread context before any reply. |
| 2026-03-09 | `community-help` | romaxx__13: an audit task reported success but deleted the entire repo; 40+ hours lost, only ~70% recovered, with extra usage cost. | Best Discord incident thread. Empathetic recovery/safety guidance first; do not cold-pitch while still in preview mode. |
| 2026-02-13 | `community-help` | prisum: declining an edit to an existing `main.js` caused Cursor to delete the entire file. | Distinct rollback/rejection bug, not a shell-command case. gate.cat may not cover editor-internal deletion, so do not overclaim. |
| 2026-02-27 | `general` | Warlock: Cursor deleted a file and then claimed it did not exist. | Supporting evidence for auditability and truthful post-action state checks. |

Observed message IDs for reproducibility: `1523816140789514383` (Hudson),
`1480406110375641168` (romaxx__13), and `1471980853931409703`
(prisum). Cursor guild ID was `1074847526655643750`; the visible `general`
channel ID was `1074847527708393565` and `community-help` was
`1373670824250183790`.

The public Discord directory did not return the official Cline community for
the query `Cline`, and this account is not a member. The official
[Cline invite](https://discord.gg/cline) remains the next target, but joining a
server is an external side effect and was deliberately not done without a
separate user confirmation. Claude Developers Discord and SafeDep remain
unreviewed. For any later Discord outreach, join only after confirmation, read
the local rules, and use `showcase` or answer an explicit support question;
never paste launch copy into `general`.

## Counter-perspectives and positioning constraints

Common counterarguments are valid and should appear in every serious answer:

- run agents in an isolated container/VM or dedicated OS account;
- give them no production credentials and use least privilege;
- use Git, worktrees, remote backups, and dry runs;
- Auto mode or built-in prompts reduce risk for many users;
- incidents often combine agent error with poor operator controls.

gate.cat should be presented as defense-in-depth for persistent environments
where the agent legitimately needs broad everyday access. It should not claim
to stop data exfiltration, prompt injection, arbitrary native APIs, every shell
obfuscation, or damage performed with credentials outside its observed action
paths.

## Outreach rule

Maximum initial wave: three comments, each materially different and specific to
the incident. Lead with the diagnosis and remediation hierarchy. Put the
maintainer disclosure next to the gate.cat link. Never post the same launch copy
across issues, revive stale incident threads, or comment inside another safety
tool's launch thread.

Recommended first wave:

1. current Reddit `--dangerously-skip-permissions` question;
2. Cline #12020 approval architecture bug;
3. Claude Code #77030 `rsync --delete` classifier inversion.

## Query log and gaps

Queries covered Claude Code permissions, Auto mode, bypass mode, destructive
shell commands, framework DB resets, Cursor/Cline/Roo/OpenCode deletion events,
production database incidents, prompt fatigue, action gating, agent
sandboxing, logged-in LinkedIn posts, and the official Cursor Discord archive.

Known gaps:

- Cline, Claude Developers, and SafeDep Discord archives were not reviewed;
  joining their servers requires a separate confirmation;
- Discord search preview exposes current messages but not full reply context
  for every hit; reopen the exact thread before drafting a response;
- LinkedIn's accessible search results did not expose stable activity
  permalinks for every post;
- Reddit search results can omit deleted/removed posts and low-ranking replies;
- HN search surfaced mostly older discussions;
- no comment was published, so subreddit/server self-promotion rules must be
  rechecked immediately before any outward action.
