# Changelog

All notable changes to `gate.cat` will be documented in this file.

## [0.4.12] -- Cloud (E2EE), gated shell, +34 more gaps closed, uppercase-flag audit (2026-07-12)

### Added -- `gatecat-shell`, a third enforcement point for any agent that shells out

The hook only fires in Claude Code and the proxy only sees what an OpenAI-API
model layer emits, but almost every agent (Codex, Gemini CLI, aider, OpenClaw,
Hermes, Antigravity, a plain `subprocess`/`os.system` script) ultimately runs
`sh -c "<command>"`. `gatecat-shell` is a drop-in gate at that exec point: it
runs the same deterministic engine as the hook on the command, then **blocks
(exit 2, the real shell never runs it) or `execv`s the real shell** with the
byte-for-byte command. Modes: `-c "<cmd>"` (gate + exec, tolerates combined
flags like `-lc`), `--check "<cmd>"` (gate only, exit 0/2 — the primitive for
git hooks / CI wrappers / other agents, command via arg or stdin), and
`--install-bash` (an `extdebug` DEBUG-trap snippet to source into a bash
session). Fail-closed with hook parity: engine-import failure, a
`GATECAT_EXTRA_POLICIES` fault, an evaluation error, a hung engine (watchdog,
`GATECAT_SHELL_DEADLINE_S`), or a malformed `-c` all exit 2 without exec'ing;
`GATECAT_VETO_SHADOW=1` proceeds except on those config faults. Real shell is
`/bin/sh` (`GATECAT_SHELL_REAL` overrides). Honest trust class: as the agent's
shell binary it is out-of-band enforcement (hook class); the DEBUG trap is
weaker (a command can `trap - DEBUG`); either way it is a string gate, not a
sandbox. New `gatecat-shell` console script; 30 e2e/contract tests
(`tests/integrations/test_gatecat_shell.py`); full suite green.

### Added -- gate.cat Cloud (end-to-end encrypted off-machine veto history)

The council red line for subscriptions, built and deployed: the off-machine copy
of your veto history is stored by a server that **cannot read it**. Events are
AES-256-GCM encrypted on your machine with a key we never receive; the server
holds ciphertext + a timestamp. `gate.cat cloud verify` diffs the off-machine
copy against your local log and catches an agent that rewrote local history after
it shipped. `pip install gate-cat[cloud]`; the free gate never imports any of it.
Full boundary in `THREAT_MODEL_CLOUD.md`. Subscription activation issues an API
key on purchase (Stripe). Verified end-to-end over the wire. The store is
crowd-hardened for launch day: a per-account append lock (concurrent POSTs never
collide on `seq`), an 8 MB body cap (413 before the body is read — RAM-DoS
guard), an app-layer per-IP rate limit (429 on a flood; nginx does not front the
box with `limit_req`), a path-traversal-safe account id, and a `(mtime, size)`
accounts cache that stays O(1) per request yet shows a brand-new subscriber's key
immediately. 5 hardening contracts in `tests/test_cloud_server_hardening.py`.

### Added -- 12 gap-closer classes (adversarial hunt round 2)

34 more real irreversible shapes that still passed 0.4.11, now blocked/warned
(0 false-positives; benign twins validated). Extends CLOUD_STORAGE_WIPE
(gsutil `-a`/`rsync -d`, azcopy/mc/s3cmd wipes), STREAM_QUEUE_DESTROY (nats,
kafka-storage format, rabbitmq forget-node), DB_DESTRUCTIVE_EXTRA (`UPDATE`
without `WHERE`, flyway clean), DATASTORE_FLUSH_EXTRA (dropAllUsers, etcd restore
from /dev/null), GIT_FORCE_PUSH (`+refspec`; `--force-with-lease` deliberately
allowed as the safe form), GH_DESTRUCTIVE (glab), WINDOWS_DESTROY (vssadmin
delete shadows, Clear-Disk -RemoveData, manage-bde -off, wmic shadowcopy),
REGISTRY_IMAGE_DELETE (gem yank), SYSTEM_TAMPER (ip link/route, warn),
CONTAINER_DESTROY (prune -af/swarm/podman reset, warn); plus two new classes
CLOUD_PROTECTION_OFF (disable deletion-protection/backups) and IAC_STATE_DESTROY
(pulumi/cdk destroy --force). Core: 38 -> 40 policies. Full suite 1218 passed.

### Fixed

- `GIT_DESTRUCTIVE` false-blocked the benign `git branch -d merged-branch`. The
  walls run case-insensitively, so the `-D` (force-delete) pattern also matched
  the lowercase `-d` -- but git itself REFUSES `-d` on a branch that is not fully
  merged, making it the safe benign twin that the project rule says must pass.
  The `-D` is now pinned case-sensitively with `(?-i:-D)` (same precedent as
  `GIT_FORCE_PUSH`'s `(?-i:-f)`); the dangerous `-d --force` form is still caught
  by the second alternative.

### Fixed (audit of other uppercase short flags)

A full sweep of every uppercase short flag in the deny-list for the same
IGNORECASE-vs-benign-twin class turned up three more, now case-pinned:

- `DISK_DESTROY` -- `sgdisk` flag class narrowed to `(?-i:[Zzog])`. A plain
  `[Zog]` under IGNORECASE also matched the READ-ONLY `-O/--print-mbr` (and
  `-G/--randomize-guids`), false-blocking a partition-table print. The destructive
  `-Z/-z` (zap), `-o` (clear), `-g` (mbrtogpt) all still block -- this also makes
  the previously-incidental lowercase `-z` match explicit.
- `SYSTEM_TAMPER` -- `iptables (?-i:-F)`. Lowercase `-f/--fragment` is a benign
  rule matcher, not a firewall flush.
- `SECRET_READ` -- `curl (?-i:-T)`. Lowercase `-t/--telnet-option` is a different,
  benign flag, not a file upload.

Left case-insensitive on purpose (documented in-line): `PERMISSION_LOCKOUT`'s
`chmod/chown -R` (no benign lowercase `-r` flag -- lowercase `r` is a symbolic
mode bit, and the pattern also requires an octal mode / system path), and the
`-X DELETE` walls (`GH_DESTRUCTIVE`, `HTTP_API_*`, ES) -- those anchor on the
literal `DELETE` method token, which the benign `-x/--proxy` flag never takes.

## [0.4.11] -- +10 coverage classes, 67 real gaps closed (2026-07-11)

An adversarial fan-out generated 444 concrete irreversible commands across 16
surfaces (AWS/GCP/Azure/k8s/databases/streaming/disk/secrets/registries/
macOS/Windows/...) and replayed every one through the live 0.4.10 gate. 153
dangerous shapes passed. This release closes 67 of them with 10 new deny-list
classes, taking the core from 28 to 38 default policies. The remaining ~86 are
either obfuscation (runtime-assembled/env-indirection -- the honest deny-list
limit), paid-pack surfaces (Stripe/Vercel/etc.), or disposable-artifact cleanups
the gate deliberately allows.

### Added (10 policies, all block-level, benign-twin validated)

- `CLOUD_STORAGE_WIPE` -- recursive/forced object-storage deletion
  (`aws s3 rm --recursive`, `gsutil/gcloud storage rm -r`, `rclone purge/delete`,
  `azcopy remove --recursive`, `mc rm --recursive`). Spares disposable prefixes
  (tmp/cache/scratch/build) and additive sync, so CI cache cleanup still passes.
- `STREAM_QUEUE_DESTROY` -- `kafka-topics --delete`, `kafka-delete-records`,
  consumer-group offset reset `--execute`, `sqs purge-queue`, `pubsub … delete`,
  `rabbitmqctl reset/delete_queue/purge_queue`.
- `WINDOWS_DESTROY` -- PowerShell `Remove-Item -Recurse -Force` / `Clear-Content
  -Force`, cmd `rd /s`, `del /q /s`, `format X:`, `cipher /w:`, `reg delete /f`,
  `bcdedit /delete`. (Plain `rm` stays with `RM_RF` + the delete-analyzer so
  disposable-temp cleanup keeps passing.)
- `MACOS_DISK_DESTROY` -- `diskutil eraseDisk/deleteContainer/secureErase`,
  `tmutil deletelocalsnapshots`, `security delete-keychain`, `srm -rf`.
- `DB_DESTRUCTIVE_EXTRA` -- `dropdb`, `mysqladmin drop`, `DROP
  TABLESPACE/USER/COLUMN/KEYSPACE`, `RESET MASTER`, `TRUNCATE`, `pg_ctl stop -m
  immediate`, drop replication slot. (SQL in `-e/-c` args is matched; the engine
  does not scrub command-bearing quoted args.)
- `DATASTORE_FLUSH_EXTRA` -- `etcdctl del --prefix`, ES delete-by-query / delete
  index, `nodetool clearsnapshot`, `mongosh … .drop()/.dropDatabase()/
  .deleteMany({})`, redis scan-and-DEL. (Filtered `deleteMany({…})` still passes.)
- `DISK_DESTROY_EXTRA` -- `sfdisk --delete`, `cryptsetup
  luksRemoveKey/luksErase/erase`, `fdisk/gdisk` on a device, `wipe -rf`.
- `K8S_DESTROY_EXTRA` -- `kubectl delete -f/-k`, `drain`, `delete node`, `delete
  pvc --all` (dry-run spared).
- `REGISTRY_IMAGE_DELETE` -- `crane/skopeo delete`, `oras manifest delete`,
  `aws ecr batch-delete-image/delete-repository`, `npm dist-tag rm`.
- `SECRET_STORE_DELETE_EXTRA` -- `vault secrets disable`, `vault lease revoke
  -prefix`, `vault kv metadata delete`, `vault token revoke -mode=path`,
  `gcloud secrets delete`.

### Notes

- Every new pattern is structure-keyed (verb + flag + resource), validated to
  block the dangerous shapes AND pass a curated benign-twin corpus -- 0
  false-positives introduced (the low-false-positive contract is what keeps the
  gate installed). Full suite: 1194 passed. Tests: `tests/test_v0411_coverage.py`.
- Not a safety proof: the ~86 still-passing shapes stay disclosed. `pip install -U gate-cat`.

## [0.4.10] -- two disclosed gaps closed from an outside review (2026-07-11)

A user ran an independent multi-model gauntlet (GPT-4o + Grok + Gemini) against
gate.cat before deploying it on their own infra and reported five findings.
Verified each against the live code: two were already fixed (base64|sh and
curl|sh are caught by ENCODED_EXEC since 2026-07-05 -- their #1 RPN-100 finding
was stale), two are by-design honest limits ("unchecked != safe"; fail-closed
is a feature, not a deadlock), and two were real. These are the two.

### Fixed

- **Terraform/OpenTofu interactive-prompt bypass now blocked.** A bare
  `terraform destroy` stops for a human (`Enter a value: yes`), so it is left
  allowed -- but an autonomous agent defeats that prompt by piping the
  confirmation in (`yes | terraform destroy`, `echo yes | terraform destroy`,
  `printf 'yes\n' | tofu destroy`). That is an irreversible teardown with no
  human in the loop. `TERRAFORM_PROD` now blocks any pipe INTO a
  `terraform/tofu ... destroy` (keyed on the pipe target -- robust to the
  engine's quoted-data scrub, which inerts a source-side `'yes'`). Low
  false-positive preserved: the bare interactive destroy, `terraform plan`,
  `terraform destroy | tee log` (piping output onward), and `terraform plan |
  grep destroy` all still pass. (`-auto-approve`/`prod` forms were already
  blocked; the KNOWN_GAP note claiming the `-destroy` FLAG form "sidesteps the
  verb lookahead" was itself wrong -- `\bdestroy\b` matches `-destroy` -- and is
  corrected.)
- **Proxy enforcement is now observable, so a misconfigured proxy is
  detectable.** The #1 proxy failure is silent: an agent whose `base_url` points
  straight at the provider is never inspected, and a proxy that sees no traffic
  looks identical to one that works. `GET /health` now returns
  `action_veto: {mode, enforcing, policies}`, and startup logs the enforcement
  status loudly -- a WARNING when `tool_veto=off` (passthrough), an info banner
  otherwise naming the upstream it fronts. Does not (cannot) prove the agent
  routes through the proxy -- that stays the operator's `base_url`
  responsibility, stated in the banner -- but "200 OK" no longer implies
  "protected".

### Notes

- Bypass suite: `KNOWN_GAP` shrinks 2 -> 1 (the terraform pipe-yes gap closed;
  the runtime-assembled binary name `$'\x72m' -rf` remains, disclosed). Suite
  still 70/70 on claimed dangers, 1 disclosed false-block. Test floor lowered
  to `known_gaps >= 1` (never a zero-gap claim).
- Full suite: 1007 passed. New tests in `tests/test_v0410_gaps.py`.

## [0.4.9] -- two live-caught fixes: RM_RF filename FP; block outranks warn (2026-07-09)

### Fixed

- **RM_RF no longer false-blocks filenames that look like flags.** Caught live
  during the 0.4.8 release: `rm /tmp/pypirc-fresh` was vetoed because the old
  whole-rest-of-line lookahead matched `-fre` inside the FILENAME as an `-fr`
  flag. Flags are now matched as TOKENS (`-` preceded by start/whitespace/quote
  -- `rm "-rf" /` still blocks), and the match stays inside one command segment,
  so `rm x && tar -rf a.tar y` is no longer blamed on `rm`. All dangerous
  spellings stay caught: `-rf`, `-fr`, `-Rf`, `-rfv`, `-vrf`, `-Rfi`, split
  `-r -f` / `-f -r`. Bypass suite gains the filename-substring benign class
  (70/70 dangers, benign corpus 44 -> 52).
- **Block-level policy outranks warn-level in attribution, order-independent.**
  Caught live productizing the policy packs: hit attribution was
  first-match-in-list-order, and `check_action` downgrades to a warn when the
  attributed policy is level="warn" -- so the core generic net
  `HTTP_API_DELETE_GENERIC` (warn), sitting earlier in the list, silently
  DOWNGRADED a hard danger that an operator pack's block rule (appended by
  `GATECAT_EXTRA_POLICIES` after the built-ins) also matched. Attribution is
  now two-pass -- block-level policies first, then warn-level -- so a hard
  match is never degraded by list order; a warn-only match still warns. This
  also makes the core's own block-before-warn ordering redundant instead of
  load-bearing.

## [0.4.8] -- policy packs plug into the hook; 28 core defaults (2026-07-09)

### Added

- **`GATECAT_EXTRA_POLICIES` loader -- operator policy packs now reach the
  hook and the proxy** (`gatecat/integrations/extra_policies.py`). The Claude
  Code hook and the proxy hard-coded `DOGFOOD_DEFAULTS`, so a pack the operator
  installed (e.g. `gatecat_packs.fintech`) only worked through the SDK -- never
  in the strongest enforcement point (the PreToolUse block that runs BEFORE the
  command executes). Set a comma-separated module list
  (`GATECAT_EXTRA_POLICIES=gatecat_packs.fintech,mycompany.policies`); each
  module's `POLICIES` list and every `*_PACK` attribute are folded in after the
  built-ins. FAIL-CLOSED contract: an unimportable module, a non-Policy object,
  or a named-but-empty module raises `ExtraPolicyError` -- the hook exits 2
  (`EXTRA_POLICIES`, even in shadow mode: a config fault is not an action
  decision) and the proxy refuses to start, rather than silently running
  without a policy the operator believes is enforced. 19 tests
  (`tests/integrations/test_extra_policies.py`), including subprocess
  end-to-end: pack blocks its danger, allows the benign twin, the same danger
  passes with NO pack configured (proving the pack is what blocks it), broken
  pack fails closed.
- **Coverage-audit promotion (2026-07-09): 5 new core default policies**
  (`DOGFOOD_DEFAULTS` **23 -> 28**, presets 25 -> 30). The 2026-07-09 coverage
  audit found three *universal + catastrophic* classes PASSING the default gate
  because `CLOUD_DESTROY` keys on the `delete-`/`terminate-`/`remove-` verbs and
  these are NON-delete shapes: **`IAM_PRIVILEGE_ESCALATION`** (block) + 
  **`IAM_IDENTITY_TAMPER`** (warn) -- attach/put admin-owner, add owner/editor
  binding, deactivate MFA; **`BACKUP_DESTROY`** (block) -- restic/borg
  `forget`/`prune`, `zfs destroy`, cloud snapshot delete, recursive S3 delete of a
  backup path; **`HTTP_API_IDENTITY_DNS_DESTROY`** (block) +
  **`HTTP_API_DELETE_GENERIC`** (warn) -- `curl -X DELETE` to an identity
  provider / DNS registrar / domain API, plus a universal external-DELETE net.
  Promoted from the opt-in packs per the binding business-model rule
  (universal + catastrophic -> free core), exactly as KMS/Vault were. Patterns
  ported verbatim from the tested packs; 0 benign false-blocks (attach ReadOnly,
  add `roles/viewer`, `restic snapshots`, `curl -X GET`, build-cache recursive
  delete all still pass). Bypass suite **65/65 -> 70/70** (`+5` block dangers,
  `+8` benign twins). Regression: `tests/integrations/test_iam_backup_http_defaults.py`.
  Stack-specific HTTP breadth (observability/SaaS/registry) stays an opt-in paid
  pack -- deliberately NOT promoted to core.
- **`gate.cat report [YYYY-MM]`** -- the free local monthly report promised in
  PRICING.md ("Local CLI dashboard + local reports"). Markdown, counts-only
  (no command text, so the output is safe to paste anywhere), four sections:
  the month in one line, verdicts, top policies that fired, timeline.
  Generated entirely from the local `~/.gatecat/veto_log.jsonl`; nothing
  leaves the machine.
- **`gatecat/cloud_reporter.py`** -- the optional client that ships veto events
  to gate.cat Cloud (`python -m gatecat.cloud_reporter`, cron-friendly;
  stdlib-only, zero-dep core intact). The PRICING.md architecture contracts
  are pinned by `tests/test_cloud_reporter.py` (10 tests, no network -- mock
  endpoint): OFF unless `GATECAT_CLOUD_API_KEY` is set; hash-by-default (raw
  command text only with explicit `GATECAT_CLOUD_SEND_RAW=1`); never in the
  gate's execution path (fail-silent on any error); per-log-file cursor --
  reruns idempotent, not advanced on failure, log rotation detected.

## [0.4.7] -- positioning fix: the veto is model-agnostic (2026-07-08)

### Changed

- **Dropped the inaccurate "built for cheap/local model agents" framing** from the
  package description, GitHub About, README, and llms.txt. The action-veto is
  **deterministic and model-agnostic** — it inspects the tool call at the
  boundary, so it protects any agent the same way, and the flagship integration
  is a Claude Code hook (a *frontier* model). Claiming it's "for cheap/local
  models" both contradicted that flagship use case and needlessly told
  frontier-agent users it wasn't for them. The 7-30B local-model strength is real
  but belongs specifically to the *uncertainty signal* (a secondary feature,
  AUC 0.77-0.90; FACTS F6/F7) — now scoped there, not applied to the whole
  product. No code change.

## [0.4.6] -- cache-path entry points honor the zero-dep-core contract (2026-07-08)

### Fixed

- **`gatecat-cli` no longer crashes with a raw `ModuleNotFoundError: numpy`** on a
  plain `pip install gate-cat`. The CLI manages the semantic cache (behind the
  optional `[cache]` extra), but imported it eagerly at module top level, so
  running `gatecat-cli` at all raised a bare traceback instead of the clear
  "install the extra" message the rest of the package already gives. Now guarded:
  cache commands print `install gate-cat[cache]` and exit 1, and — bonus —
  **`gatecat-cli audit` now works without the cache stack** (it runs against the
  user's endpoint and never needed the cache; the eager import used to block it).
- **`from gatecat import CachedOpenAI` / `CachedAnthropic`** without the deps now
  name the *right* extra. The lazy loader's error rewrite is content-aware: a
  missing numpy/hnswlib/onnxruntime → `[cache]`, a missing `openai` → `[openai]`,
  a missing `anthropic` → `[anthropic]` — instead of a raw `No module named`
  traceback (or a misleading `[cache]` when the SDK itself is what's absent).
- Regression coverage: `tests/test_cache_path_degradation.py` (6 cases) pins the
  message-vs-missing-dep mapping and that `audit` stays reachable cache-free.

The veto path (`gate.cat` dashboard, `gatecat-hook`, `check_action`, adapters)
was already clean and is unchanged; this only makes the cache-side entry points
degrade as gracefully as the core already promised.

## [0.4.5] -- the hook gets a home on the landing page (2026-07-08)

### Added

- **README now has a "The hook — the strongest mode" section** with the
  ready-to-paste `.claude/settings.json` `PreToolUse` config. The Claude Code
  hook is the product's #1 pitch (enforcement outside the model's control flow),
  but the landing README only *mentioned* it — there was nowhere to copy the
  config from. A reader who wanted the hero feature had to dig into
  `examples/` (which isn't shipped in the wheel). Now it's front and center,
  right after Install, with the exact block and a working first-run test.

### Fixed

- **`gate.cat` dashboard empty-state pointed at a path pip users don't have.**
  The first-run message said "Wire the hook
  (examples/veto_integrations/claude_code_hook/)", but `examples/` is excluded
  from the wheel/sdist — so a `pip install` user was sent to a nonexistent
  directory. It now names the actionable steps (add `gatecat-hook` to
  `.claude/settings.json`) and links the README's hook section.
- **README proxy section said "20 deny policies" — it is 21** (`DOGFOOD_DEFAULTS`
  since `AUTOEXEC_WRITE` in 0.4.0; pinned in FACTS.md F10).

## [0.4.4] -- adapter examples degrade cleanly; Beta + Security on PyPI (2026-07-08)

### Fixed

- **Framework adapter examples no longer crash with a raw traceback when the
  framework isn't installed.** `examples/veto_integrations/veto_crewai.py` and
  `veto_langgraph.py` ran the framework import inside `main()`, so a user who did
  `pip install gate-cat` (zero-dependency core) and ran the example to see how it
  works got a `ModuleNotFoundError` traceback. They now print a one-line "install
  `gate-cat[crewai]`/`[langgraph]` to run this adapter demo — the gate itself
  needs none of it" and exit cleanly. (`veto_autogen.py` was already
  framework-free.)
- **Claude Code hook example README** dropped the stale `>= 0.3.0` install note
  and the "fix the absolute path to `veto_hook.py`" step — which contradicted
  `settings.example.json`, that already calls the `gatecat-hook` console script
  by name (nothing to edit).

### Changed

- **PyPI metadata**: `Development Status` Alpha → **4 - Beta** (3 releases, 892
  CI tests, 73% coverage, 1.085M-command recall validation), added
  `Topic :: Security` and `Topic :: Software Development :: Quality Assurance`
  classifiers and security-oriented keywords so the package is discoverable as
  what it is — a guardrail, not an AI-research toy. No code change.

## [0.4.3] -- gh release delete-asset unblocked; recall harness (2026-07-08)

### Fixed

- **`GH_DESTRUCTIVE` no longer false-blocks `gh release delete-asset`.** Deleting
  a single release *asset* (a re-uploadable file) is not the same as deleting a
  release/repo/secret; the wall now scopes to the irreversible `gh` destructions.
- **`scripts/recall_danger_axis.py` runs with a bare `pip install gate-cat`.**
  The shared danger catalog (`scripts/corpus_recall.py`) imported the HuggingFace
  `datasets` package at module top — so the dataset-free recall check crashed with
  `ModuleNotFoundError: datasets`. That import is now lazy (only the streaming
  `run()` path needs it); the deterministic danger-axis check needs no extra deps.

### Added

- **`RECALL.md` + `scripts/recall_danger_axis.py`.** Two-axis recall measurement
  against the full 6-stage `ActionPipeline`: 43/43 known danger classes
  neutralized with 0 false-blocks on benign twins (deterministic, dataset-free),
  and 0 real misses across 1,085,159 unique real agent commands
  (`results/million_recall_2026-07-08.json`). Every number pinned in `FACTS.md`
  (F1a/F1b).

## [0.4.2] -- false-positive fix: git commit -F is not a force push (2026-07-08)

### Fixed

- **`GIT_FORCE_PUSH` no longer false-blocks `git commit -F file && git push`.**
  The short force flag `-f` is now matched case-sensitively (`(?-i:-f)`), so `-F`
  (commit message-from-file, a common benign op) no longer trips the force-push
  wall. Real `git push -f` / `--force` still block; `--force-with-lease` still
  allowed. Regression case added to the bypass suite's benign set. (This
  false-positive vetoed the launch assistant's own git command mid-prep — a real
  veto story.)

## [0.4.1] -- launch-blocker fixes: one import, one exception, English reasons (2026-07-08)

### Added

- **Top-level `check_action` export.** `from gatecat import check_action` now
  works (lazy re-export of `gatecat.integrations.guard.check_action`); the
  published hero snippet no longer needs the `gatecat.integrations` path.
- **CI workflow** (`.github/workflows/ci.yml`): pytest on ubuntu-latest,
  Python 3.11/3.12/3.13, full `[dev]` extra so the security-critical proxy
  tool-veto tests RUN instead of skipping. CI + PyPI badges in the README.

### Changed

- **One `ActionVetoed` class for the whole package.** The engine
  (`gatecat.veto`) and the integrations layer (hook/adapters) each raised their
  own `ActionVetoed`, so `except gatecat.ActionVetoed` silently missed a block
  raised by `check_action`. The unified class lives in `gatecat.exceptions`
  (stdlib-only, importable even when the engine is not) and accepts both a
  `VetoDecision` (engine) and a plain reason string (integrations).
  `from gatecat.veto import ActionVetoed` and
  `from gatecat.integrations import ActionVetoed` still work and are now the
  same object.
- **Veto reason strings are English.** The engine's runtime veto reasons were
  Polish ("akcja pasuje do zakazanego wzorca", "wszystkie mury przeszły", ...);
  every user-facing reason emitted by `ActionPolicy.classify` /
  `VetoGate.evaluate` is now plain-ASCII English. Wall identifiers
  (`policy-deny` / `koryto` / `human`) and the `mur` field name are unchanged --
  they are API, not prose.
- `gatecat.__version__` now matches the distribution version (was stale at
  `0.3.2` while pyproject said `0.4.0`).

## [0.4.0] -- Write/Edit content is data, not action (2026-07-08)

### Changed

- **The Claude Code hook no longer hard-blocks on Write/Edit FILE CONTENT.**
  Pre-0.4.0 the hook flattened the written content into the evaluated action,
  so authoring a comment, docstring, test, or doc that merely MENTIONED a
  dangerous command (`rm -rf`, `DROP TABLE`, `gh repo delete`, ...) was
  vetoed -- writing "rm -rf /" into a Python comment executes nothing. It was
  also inconsistent with the engine's own content-vs-command doctrine on the
  Bash side, where `echo "rm -rf /" > notes.md` has always been inert data
  (`tests/integrations/test_content_vs_command.py`). The evaluated action for
  Write/Edit is now `write <path>`: the target path is still gated, the
  content is not.
  - `GATECAT_HOOK_SCAN_FILE_CONTENT=1` in the hook environment restores the
    old paranoid behavior (opt-in).
  - **Bash gating is unchanged** -- enforcement lives at RUN time, and every
    command a file's content may mention still blocks when actually executed
    (pinned by `tests/integrations/test_write_content_data.py`).
  - Meta-note: this release's own regression tests had to be authored via a
    bash heredoc, because the 0.3.x hook kept vetoing the Write calls that
    mentioned the patterns under test. The bug blocked writing its own fix.

### Added

- **`AUTOEXEC_WRITE` (warn)** -- the one real risk content scanning used to
  catch incidentally, now covered deliberately and on BOTH pathways (the
  Write/Edit tool AND bash redirect/tee/cp): a write whose TARGET PATH is
  executed later without any visible Bash step -- `.git/hooks/`, shell rc
  files, `/etc/cron*` / `/var/spool/cron`, systemd units,
  `.claude/settings*.json` (editing that one can disarm this very gate), and
  `crontab <file>`. Warn, not block: authoring dotfiles and deploy units is
  legitimate, so the ambiguous class surfaces to the human instead of
  hard-stopping. This WIDENS coverage vs 0.3.x -- the bash-redirect variant
  (`echo ... >> ~/.bashrc`) was previously a silent allow.

## [0.3.2] -- proxy imports without the cache stack (2026-07-08)

### Fixed

- **`pip install gate-cat[proxy]` could not import the proxy** — it imported
  `gatecat.cache` (numpy/onnxruntime) at module load, but `[proxy]` doesn't
  include the cache stack, so `gatecat-proxy` crashed with `ModuleNotFoundError:
  numpy` (0.3.0/0.3.1). The cache import is now lazy: the proxy runs, and the
  action-veto works, WITHOUT numpy — only the semantic-cache tier is disabled
  (install `gate-cat[cache]` for it). Matches the zero-dep-core promise: a client
  who only wants to veto their agent needs no ML stack.

## [0.3.1] -- proxy action-veto on tool calls (2026-07-08)

Makes the proxy usable as a turnkey guard for ANY OpenAI-compatible provider
(Ollama, NIM, OpenRouter, vLLM, LM Studio) — the client changes one `base_url`,
writes no code.

### Added

- **`gatecat-proxy` now vetoes dangerous tool calls.** When the upstream model
  returns `tool_calls`, each is checked against the 20 DOGFOOD deny policies
  (recursive-force delete, prod infra teardown, destructive SQL, repo/registry
  deletion, disk wipe, ...) BEFORE it reaches the agent. A dangerous call is
  replaced with a refusal (no `tool_calls`), so a tool-calling agent on a local
  model cannot run `rm -rf`, `terraform destroy`, `DROP TABLE`, etc. Previously
  tool-call requests bypassed the proxy entirely.
  - Mode via `GATECAT_PROXY_TOOL_VETO`: `block` (default) / `flag` / `off`.
  - Works for streaming and non-streaming clients (the gate always sees the
    complete tool call; the result is re-emitted as SSE if the client streamed).
  - Fail-closed: an unparseable or engine-errored tool call is blocked.
- Proxy stack (`fastapi`, `uvicorn`, `pydantic`) added to the `[dev]` extra so
  the security-critical proxy tests run in CI instead of skipping.

### Notes

- The action-veto is applied to tool calls the model expresses through the API
  (the common tool-calling pattern). An agent that shells out directly, outside
  the API, still needs the harness-level hook (`gatecat-hook`).

## [0.3.0] -- import rename + hook hardening (2026-07-07)

Release-hardening pass. The engine and policies are unchanged from 0.2.1; this
release makes the shipped package match the "deterministic fail-closed" promise
and removes the legacy `cacheback` identity.

### Breaking

- **Import module renamed `cacheback` -> `gatecat`.** Update imports:
  `from gatecat.integrations import check_action`. No compatibility shim — the
  old top-level `cacheback` collided with an unrelated PyPI package (silent
  shadowing risk in a security tool). See `MIGRATION.md`.
- **Env vars renamed `CACHEBACK_*` -> `GATECAT_*`** (54 vars). A one-release
  compat shim maps any still-set `CACHEBACK_*` to its `GATECAT_*` name at import
  with a `DeprecationWarning` (new name wins); removed in 0.4. Log dir
  `~/.cacheback/` -> `~/.gatecat/`.
- **Response attributes** `response.cacheback_hit/_synthesized` ->
  `gatecat_hit/_synthesized`. **Exceptions** `CachebackError/Blocked` ->
  `GatecatError/Blocked`. **Console scripts** `cacheback`/`cacheback-proxy`
  dropped; use `gatecat-cli` / `gatecat-proxy`.

### Fixed (ship-blockers)

- **Claude Code hook failed OPEN.** The example hook imported the engine at
  module top-level outside `try/except`, so an unavailable engine exited 1 —
  which Claude Code treats as "proceed". Verified live: `wipefs -af /dev/sda`
  passed. Now the hook is **inside the package** (`gatecat/hooks/claude_code.py`,
  console script `gatecat-hook`), the import is guarded, and any failure,
  malformed input, engine error, or watchdog deadline exits **2 (block)**. 8 new
  contract tests lock the exit-code behavior.
- **Flagship hook was not pip-installable** (lived under `examples/`, excluded
  from the sdist). Now shipped in the wheel and sdist.
- **Release pipeline could not gate.** CI ran on `main` while the repo default is
  `master` (zero tests ran); publish on a tag ran no tests. Now CI runs on
  `master`, and publish depends on the full 3-OS x 3-Python suite plus a
  tag-equals-version guard and a wheel-contents check before the immutable
  upload.

### Added

- Hook watchdog: a hung engine self-blocks (exit 2) before the harness timeout
  can turn the hang into a silent proceed. Deadline via `GATECAT_HOOK_DEADLINE_S`
  (default 20s).

## [0.2.1] -- 7-stage hybrid guardrail + INGRESS (2026-07-06)

Wydanie skupione na jednym mechanizmie: deterministyczne **action-veto** rozszerzone
do pelnej bramy 7 warstw (6 EGRESS + 1 INGRESS). Rdzen pozostaje **zero-dependency**
(czysty stdlib) -- `pip install gate.cat` daje dzialajace veto bez numpy/ONNX.

### EGRESS -- ochrona przed destrukcyjna AKCJA agenta (`ActionPipeline`, 6 warstw)

- **6-warstwowa kaskada**: allow-list -> koryto [deny-walls + delete-analyzer] ->
  gate (disagreement) -> stagnacja -> arbiter -> czlowiek. Fail-closed: kazdy
  blad/niepewnosc -> BLOCK; `unchecked != safe`. (`cacheback/action_pipeline.py`)
- **Target-anchored delete-analyzer** -- klasyfikuje CEL kasowania, nie ksztalt komendy.
  (`cacheback/integrations/action_analysis.py`)
- **20 polityk DOGFOOD_DEFAULTS** -- RM_RF, SECRET_DELETE/READ, HISTORY_WIPE,
  DATASTORE_FLUSH, CLOUD/TERRAFORM/DB destroy, GIT/GH_DESTRUCTIVE, kubectl+helm,
  SYSTEM_TAMPER (warn), PACKAGE_PURGE (warn) i in. (`cacheback/integrations/policies.py`)
- **Windows-delete gap zamkniety** -- Remove-Item/del/rd + tokenizacja posix=False.
- **Dowody z zywego ruchu**: 100% recall na 1M komend (`corpus_million.py`); FBR
  (false-block rate) dogfood **92.1%** na 14.7k realnych komend; 30/30 recall na
  85k komend / 3 agenty; 0 crashow.

### INGRESS -- ochrona przed prompt-injection w tym, co agent CZYTA (warstwa 7)

- **`input_guard.scan(text)`** -> `clean | suspicious | injection`. Wykrywa override,
  fake-role, exfil-instruct, embedded-exec, persona-reset. Damper na tutoriale
  (dokument cytujacy injection bez payloadu -> suspicious, nie injection).
  (`cacheback/integrations/input_guard.py`)
- **Invisible-Unicode smuggling** -- skan po codepointach: Tags block U+E0000-E007F,
  zero-width, bidi, variation selectors (ZWJ/VS16 wewnatrz emoji zwolnione).
- **Recall zmierzony na realnych korpusach HF** (Lakera/gandalf, deepset, jackhhao):
  **36% -> 62% (regex-floor) -> 88% (regex+ML)** na HELD-OUT, FPR regex 0.8%.

### ML escalation (opt-in, `pip install gate.cat[ml]` + `CACHEBACK_ENABLE_ML_GUARD=1`)

- **MiniLM (ONNX) + LogReg head (~2.5KB `.npz`)** -- runtime **bez sklearn**
  (dot-embed + sigmoid). Eskaluje TYLKO clean->injection, nigdy nie downgraduje
  regex-hit. Off-default -> benign-contract nietkniety. (`cacheback/integrations/ml_guard.py`)
- Recall regex+ML **88.3%** / FPR 5.2% (prog = maks recall). Model shipuje w wheelu.

### Hybryda / feed (fundament auto-aktualizacji bazy regul)

- **Podpisane add-only Ed25519 rule-bundle** -- **pure-python** verify po stronie
  klienta (zero-dep), klucz PINNED w pakiecie, klucz prywatny OFFLINE. Add-only,
  anti-rollback, fail-last-good, zero-knowledge. (`cacheback/integrations/rules.py`,
  `scripts/sign_rules.py`)

### Compliance / UX

- **Split audit-log** (EU AI Act Art.12): hash-chained non-personal skeleton
  + redactable PII sidecar; `Decision.stages` = per-stage trace. (`_audit.py`)
- **Dashboard `gate.cat`** (zero ML): `status` / `stats` / `log N` / `why <cmd>`
  -- user widzi ze bramka pracuje. (`cacheback/integrations/dashboard.py`)

### Bezpieczenstwo wydania

- **sdist allowlist** -- NIE publikuje `REJESTR_PRAWD.md`/`GOTCHAS.md` (mapa wlasnych
  known-bypasses = prezent dla atakujacego); ship tylko tego, czego uzytkownik
  potrzebuje.

### Security-hardening (council review 2026-07-06 — 6 fail-open bypasses zamkniete)

Multimodel code council (5 soczewek, adwersaryjna weryfikacja) znalazl 15
potwierdzonych problemow; 6 under-block/fail-open bylo blokerami wydania dla
guardraila fail-closed. Wszystkie naprawione z przypietymi regression testami:

- **ReDoS w heredoc-strip** (crit) — 50KB nieterminowany `<<EOF` powodowal
  catastrophic backtracking ~30-100s -> hook zabity -> fail-OPEN na `rm -rf ~`.
  Cap 16KB (oversized+delete-intent -> BLOCK) + try/except.
- **Sibling-heredoc downgrade** (crit) — benign heredoc w sasiednim segmencie
  degradowal resolwowalny `rm -rf ~` do WARN(=allow). Analiza segmentow najpierw;
  hard-block wygrywa; line-opacity WARN tylko gdy zaden segment nie resolvowal.
- **Unbounded DELETE FROM** (high) — przechodzil gdy "WHERE" bylo w komentarzu
  `--` lub kolejnym statemencie. WHERE wiazane do tego statementu.
- **gh api --method DELETE** (high) — omijal GH_DESTRUCTIVE (tylko -X). Long-form.
- **kubectl delete -n prod deploy x** (high) — flaga przed kind = silent ALLOW.
  Flag-tolerant lookahead.
- **curl|python, base64 -d|perl** (high) — omijaly ENCODED_EXEC (tylko sh/bash/
  zsh). Wspolna stala `_INTERP` (python/perl/ruby/node/php/pwsh).
- **INGRESS damper** (high) — atakowalny `_DISCUSSES_INJECTION` ("For example,"
  przed payloadem) zapadal cala warstwe 7 i pomijal ML. Damper wymaga teraz
  prawdziwego framingu (granica zdania LUB cytat), nigdy nie degraduje HARD-hitu
  ponizej suspicious, nigdy nie wylacza ML.
- **sdist .npz** — model trenowany wchodzil tylko do wheela; `pip install
  gate.cat[ml]` ze zrodla cicho spadal do regex-floor. Dodano do sdist include.
- **ml_guard fail-fast** — weryfikuje ze model jest w cache lokalnie (bez
  blokujacego download w scan()); + `pytest-timeout` (timeout=90) by wiszacy
  test (np. `import onnxruntime` w WMI probe na Win/py3.13) failowal glosno.

### Security-hardening — runda 6 (INGRESS "wolna reka" 2026-07-07)

Frontier free-hand council (11 modeli, BEZ recepty na atak — "mysl inwariantem
klasy, nie narzedziem"). Kazdy zgloszony payload empirycznie przepuszczony przez
zywy probe. 2 potwierdzone przecieki na warstwie 7 (INGRESS), oba zamkniete:

- **Zakodowany SOFT-injection** (high) — `_encoded_injection` rescanowal po
  dekodowaniu URL/base64 tylko wzorce `_HARD`, wiec zakodowany persona-reset
  (`%79%6f%75...` = "you are now DAN") dekodowal sie, ale nigdy nie trafial na
  `_SOFT`. Kanal zakodowany byl slabszy niz jawny tekst. Fix: rescan tez `_SOFT`
  -> HARD=injection, SOFT=suspicious. (`input_guard._encoded_injection`)
- **Mixed-script evasion** (high) — grecka/cyrylicka litera podstawiona za ASCII
  wewnatrz angielskiego slowa (`sgnore` przez greckie sigma dla `i`) omijala regex
  czasownika override, a model i tak czyta "ignore". Fix: backstop po SUROWYM
  tekscie — slowo w wiekszosci ASCII-Latin z wcisnieta litera Greek/Cyrillic ->
  suspicious. Bramki (dlugosc >=4, wiekszosc Latin) trzymaja czysto zwykly rosyjski/
  grecki tekst i jednostki (`um`, `dT`, `kohm`). (`input_guard._residual_mixed_script`)

### Security-hardening — runda 7 (EGRESS "wolna reka" 2026-07-07)

Council z WYSPECJALIZOWANYMI rolami (SRE/cloud/DBA/supply-chain/storage/obfuscation),
wolna reka, DWIE fale z informacja zwrotna (fala 2 dostaje "co zablokowano" i szuka
czego pipeline jeszcze przepuszcza). Cel: powstrzymac szkodliwa AKCJE przed
wykonaniem. 22 komendy dostaly `allow`; po analizie **15 realnych dziur naprawionych**,
7 to nie-bledy (udokumentowane). Wszystkie naprawy z przypietymi testami:

- **Scrubber over-strip** (crit, systemowa przyczyna) — `_strip_inert_literals`
  BEZWARUNKOWO wymazywal tresc `echo/printf "..."`. Ale `echo "DROP TABLE" | mysql`
  to KOD podany rura do klienta, nie tekst; wymazanie ukrywalo payload, a nic dalej
  nie lapalo rury do `mysql`/`redis-cli`/`at`. Ogolny bypass ("schowaj cokolwiek w
  echo i podaj do interpretera"). Fix: NIE wymazuj tresci gdy echo/printf jest
  podane rura do executor-a (sh/bash/db-client/at/eval/interpreter); `echo "..." >
  plik` (do pliku) nadal traktowane jako dane. (`guard._strip_inert_literals`,
  `_PIPE_TO_EXECUTOR`)
- **Tautologiczny DELETE** (high) — `DELETE FROM x WHERE 1=1` (albo `col=col`)
  przechodzil test "ma WHERE", a kasuje wszystko. Fix: wykrycie samorownego
  predykatu. (`DB_DESTRUCTIVE`)
- **Interpreter delete ruby/node** (warn) — `ruby -e 'FileUtils.rm_rf(...)'`,
  `node ...rmdirSync(...)` byly nieobjete (tylko unlink/rm). Fix: rozszerzone
  wzorce ruby/node/php. (`RUNTIME_DELETE`)
- **Niszczenie plikow krytycznych** (high) — `sed -i '1,$d' /etc/fstab`, `rsync
  --delete .../ /etc/`, `tee /etc/hostname` przechodzily (rsync dest-list objal
  tylko /home//srv//var/). Fix: sed/perl -i na pliku krytycznym, rsync --delete do
  /etc//boot//usr//opt, tee do pliku krytycznego. (`OVERWRITE_DESTROY`)
- **Symlink-indirection** (high) — `ln -sf /etc/shadow /tmp/x && shred /tmp/x`
  niszczy CEL przez link. Fix: symlink-do-krytycznego + czasownik piszacy PRZEZ
  link (shred/truncate/dd/tee). `rm` na symlinku usuwa SAM LINK (nie cel) — celowo
  wykluczony. (`OVERWRITE_DESTROY`)
- **Masowe kasowanie referencji git** (high) — `... | git update-ref --stdin` z
  `delete` wycina wszystkie branche naraz. Fix: `update-ref --stdin` + token
  `delete`. (`GIT_DESTRUCTIVE`)
- **7 nie-bledow** (udokumentowane, slusznie `allow`): `rm` na symlinku usuwa link
  nie cel (2x); nazwy skryptow/workflow `npm run clean:force`/`gh workflow run
  destroy.yml` — statycznie nie do udowodnienia (blokada po nazwie = lawina FP);
  `git push` bez `--force` remote odrzuca (non-ff); `find -exec rm -f` pojedynczych
  plikow (nie `-rf`) — czyszczenie celowo nie twardo-blokowane.

### Testy

- Pelny suite **732 pass + 14 skip** (2 moduly pominiete — wymagaja opcjonalnych
  `httpx`/`Pillow`, bez zwiazku z guardrailem). 0 regresji przez 6+ rund hardeningu.
- **Korpus bypass_suite: catch 65/65 = 1.000** (bylo 58; +7 block-class z rundy 7),
  false-block-rate **2.6%** (1 celowo ujawniony przypadek).
- **INGRESS floor** trzyma benign czysto: rosyjski/grecki tekst, jednostki,
  base64/URL benign. Nowe regression piny: runda 6 `test_input_guard::F16` (8),
  runda 7 `bypass_suite` G1-G5 + `test_content_vs_command` scrubber-exception.
- (`test_ml_guard` wymaga dzialajacego `import onnxruntime` — na niektorych Win/
  py3.13 hostach zawiesza sie w probie WMI; timeout config zamienia to w glosny fail.)

## [Unreleased] -- Action-veto + dowody jakosci (2026-06-27)

Pivot pozycjonowania: fail-closed **action-veto** (blokada nieodwracalnej akcji agenta
ZANIM sie wykona) jako rdzen produktu. Kaskada gate -> koryto -> veto -> abstain.

### Dodane

- **Side-effect tool gating (fail-closed przy rejestracji)** -- `Tool.side_effect: bool`.
  Narzedzie ze skutkiem ubocznym (`side_effect=True`) NIE moze byc zarejestrowane bez
  `VetoGate` -- `ToolRegistry.register` rzuca `ValueError` zamiast cicho przepuscic
  nieodwracalna akcje. Read-only (default `side_effect=False`) = zero zmian.
  (`src/tools/registry.py`)
- **Explicit abstain** -- jawny stan `branch="abstain"` w three-branch routerze (opt-in
  `allow_abstain=True`): gdy model nie wie (gate-on) i ani cache, ani web nie maja jakosci,
  router JAWNIE sie wstrzymuje zamiast zgadywac. Trust-sygnal. Nigdy nie kradnie galezi,
  gdzie jest dowod (model pewny / cache trafny / web dobry). (`src/ensemble/router_three_branch.py`)
- **Dowod: prog jakosci web-snippetu odcina szum** -- `tests/test_web_snippet_threshold.py`.
  Trafny snippet wstrzykiwany, szum ponizej progu odrzucony (Badanie C: web-szum psuje
  base-correct 2-3x mocniej niz zly cache).
- **`ARCHITECTURE.md`** -- pelny dokument techniczny SDK (warstwy, moduly, przeplywy,
  modele danych, rozszerzanie, testy). Rozroznia SDK cacheback (bez ReAct) vs aplikacja iors.
- **`plan_verifier` (nowy modul produktu) -- koryto POSTEPU PROJEKTU.** Agent deklaruje
  'etap zrobiony' (rzeka), verifier wymaga NIEZALEZNEGO dowodu (test pass / plik+token /
  HTTP 2xx / command z allow-listy) zanim oznaczy done. `PlanVerifier`, `PlanStep`,
  `StepVerdict`, `PlanReport` eksportowane z `cacheback`. Fail-closed: brak dowodu = unproven.
  Kluczowe (po adversarial review): evidence z immutable spec (nie z narracji agenta),
  `progress_pct` liczy TYLKO `proven AND hard` (url/benchmark = soft/stale), allow-list
  binarek zamiast deny-listy, file wymaga `must_contain` + zero repo-root fallback.
  Dogfood: `scripts/verify_session_plan.py` liczy realny postep TEJ sesji dowodem
  (6/12 twardo proven, reszta uczciwie unproven). `tests/test_plan_verifier.py` (13 testow,
  regresja na 7 zmierzonych bypassow).

### Trust-loop (GTM: jak dotrzec do ludzi ktorzy zaczna ufac AI)

- **`cacheback audit data.jsonl` (CLI)** -- proof-point 'ile zgaduje TWOJ agent'. Dev wskazuje
  swoj model (OpenAI-compatible endpoint) + zestaw Q&A, dostaje liczbe confident-wrong
  (model myli sie PEWNIE) + AUC gate -> CTA do gate.cat. Konkretny mechanizm konwersji
  odwiedzajacego w uzytkownika: zmierz na WLASNYM agencie, zobacz ryzyko, wepnij veto.
  `examples/audit_sample.jsonl` (10 Q&A startowych), `tests/test_cli_audit.py` (3 testy, mock).

### Dowody jakosci (metryka #1: false-positive rate)

- `scripts/audit_false_positive.py` + `tests/test_false_positive.py` -- **FPR=0** (0 legalnych
  akcji blednie zablokowanych / 24), **false-refute=0** na hard channels (exec/calc), 8/8
  akcji finansowych poprawnie wymaga czlowieka.
- `tests/test_veto_bypass_e2e.py` -- **0 przeciekow** na 22 adversarialnych bypassach
  (tab/newline/komentarz SQL/case-games/rm-rf/terraform/kubectl) + E2E gate+koryto.

### Testy

- Suita cacheback: **391 pass + 3 skip**, 0 regresji (+ side-effect gating i explicit-abstain
  w aplikacji iors: `tests/test_tools/`, `tests/test_ensemble/` 241 pass).

## [Unreleased] -- CAS SDK Implementation (Phase 1.5)

### Cache-Augmented Synthesis (CAS) -- SDK integration

**Three-tier response system**
- VERBATIM (sim >= 0.92): Direct cache return, <10ms, $0.00
- SYNTHESIS (sim >= 0.80): Top-K cached Q&A synthesized via LLM, ~300ms, ~$0.002
- UPSTREAM (sim < 0.80): Full API call, ~500ms, ~$0.03

**New files**
- `cacheback/synthesis.py` -- SynthesisEngine, SynthesisCandidate, SynthesisResult
- `tests/test_synthesis.py` -- 26 tests (engine, integration, response flags, cache lookup)

**Modified files**
- `cacheback/cache.py` -- `lookup_for_synthesis()` (top-K at lower threshold), `get_entry()`
- `cacheback/openai.py` -- synthesis tier in CachedOpenAI, AsyncCachedOpenAI
- `cacheback/anthropic.py` -- synthesis tier in CachedAnthropic, AsyncCachedAnthropic

**New constructor params** (all wrappers, backward-compatible):
- `synthesis_mode`: "off" (default) | "auto" | "always"
- `synthesis_model`: model ID (default: "google/gemini-2.0-flash-lite-001")
- `synthesis_model_base_url`: API base URL (auto-detected from env)
- `synthesis_model_api_key`: API key (auto-detected from env)
- `synthesis_threshold`: min similarity for candidates (default: 0.80)
- `synthesis_top_k`: number of cached responses for synthesis (default: 5)

**New response attributes**:
- `response.cacheback_synthesized` -- True when CAS synthesized the response

**Tests**: 112 passing (was 86)

### Streaming synthesis
- Synthesis results replayed as synthetic stream chunks (both OpenAI and Anthropic)
- Both sync and async paths supported
- Tests: 113 passing

### Proxy mode (`cacheback-proxy`)
- OpenAI-compatible proxy server via FastAPI + uvicorn
- Zero code change: `client = OpenAI(base_url="http://localhost:8080/v1")`
- Streaming SSE with buffer-and-cache on miss
- Cache hit/synthesis headers: `X-Cacheback-Hit`, `X-Cacheback-Synthesized`
- `/health` and `/v1/cache/stats` endpoints
- Docker support: `docker run -e OPENAI_API_KEY=sk-... -p 8080:8080 cacheback/proxy`
- `pip install cacheback-ai[proxy]` extras group
- `cacheback-proxy` CLI entry point
- Config via env vars (`CACHEBACK_*` prefix)
- Tests: 127 passing (14 proxy tests added)

### CLAP audio embedder
- Full CLAP HTSAT implementation via ONNX Runtime (Xenova/clap-htsat-unfused)
- Accepts bytes (WAV/FLAC), file paths, numpy arrays
- Mel spectrogram preprocessing: 48kHz, 64 mel bins, 10s fixed duration
- 512-dim L2-normalized vectors for audio similarity caching
- Thread-safe with lazy model download from HuggingFace (~300MB)
- Registered as `"clap"` in embedder registry
- Shared audio utilities module (`_audio.py`): mel filterbank, STFT, resampling, audio I/O

### Whisper + MiniLM compound voice embedder
- Compound pipeline: Whisper tiny transcribes → MiniLM embeds text
- Full Whisper ONNX inference: encoder + greedy decoder with special tokens
- Audio preprocessing: 16kHz, 80 mel bins, Whisper-format log10 normalization
- Handles merged decoder model with KV-cache inputs (zero-sized for first pass)
- 384-dim L2-normalized vectors (MiniLM text embedding dimension)
- `transcribe()` utility method for debugging/standalone use
- Thread-safe with lazy model download (~75MB Whisper + ~90MB MiniLM)
- Registered as `"whisper"` in embedder registry
- Tests: 164 passing (27 new: 13 audio utils, 7 CLAP, 7 Whisper)

### CLIP image embedder
- Full CLIP ViT-B/32 implementation via ONNX Runtime
- Accepts PIL.Image, bytes (JPEG/PNG), file paths, np.ndarray
- Center-crop resize to 224x224 with CLIP normalization (mean/std)
- 512-dim L2-normalized vectors for image similarity caching
- Thread-safe with lazy model download from HuggingFace (~150MB)
- Registered as `"clip"` in embedder registry
- Tests: 137 passing (10 CLIP preprocessing tests added)

### Landing page update (site/index.html)
- Updated hero messaging: three-tier response, 30-90% cost savings, CAS badge
- Added CAS section with tier diagram (verbatim/synthesis/upstream cost/latency bars)
- Added Proxy Mode section with Docker + pip setup, env vars, endpoints, features panel
- Added Synthesis and Proxy tabs in code examples section
- Updated comparison table: +CAS, +Proxy mode, +Multimodal (image) rows
- Updated metrics strip: verbatim hit, synthesis latency, cost savings, CAS benchmark score
- Updated feature grid: +CAS card, +Proxy Mode card, merged Streaming & Async, merged Local & Zero Config
- Added nav links for Synthesis and Proxy sections
- Added Proxy and Image to providers strip

### Cache-Augmented Synthesis (CAS) validation infrastructure

**Full Results (100-question benchmark) -- GO**
- Mean judge ratio: **0.892** (threshold: 0.80) -- **ALL DOMAINS PASS**
- Synthesis model: Gemini 2.0 Flash Lite (cloud, via OpenRouter)
- Judge model: Gemini 3.1 Flash Lite
- Per-domain: customer_support 0.89, programming 0.86, science 0.89, general 0.94, creative 0.88
- ROUGE-L 0.167 (expected low -- synthesis paraphrases by design)
- Mean latency: 2687ms (cloud API -- local synthesis ~300ms)
- BERTScore: skipped (segfault on Windows, secondary metric)

**Benchmark Script** (`scripts/benchmark_cas.py`)
- 100 questions across 5 domains (customer_support, programming, science, general, creative)
- 5 semantically similar variants per question = 600 cached Q&A pairs
- Multi-metric evaluation: LLM-as-Judge (primary), BERTScore (secondary), ROUGE-L (tertiary)
- Fleet device integration via BGML orchestrator API (`force_device_id` + `skip_cache`)
- OpenRouter backend for dataset generation and judge scoring
- Quality gate: mean ratio >= 0.80, per-domain thresholds, latency < 2000ms
- ROUGE-L: hard floor 0.10, soft warning 0.30 (synthesis paraphrases, not copies)
- CLI: `--generate-dataset`, `--quick`, `--reference-model`, `--synthesis-model`, `--judge-model`
- Fixed Windows cp1252 Unicode encoding (ASCII-only print output)
- Answer truncation in synthesis context (500 chars max per cached answer)

**Dataset Generation**
- Quick dataset (10 questions): `benchmarks/cas_dataset_quick.json` (Gemini 3.1 Flash Lite)
- Full dataset (100 questions): `benchmarks/cas_dataset_gemini31.json` (in progress)

**Known Issues**
- Fleet synthesis (POS-B2 Phi-4-mini) times out on synthesis prompts (even truncated)
- Orchestrator retry flooding: visible as attempt #49-50 in logs
- BERTScore not installed (secondary metric, skipped in quick benchmark)
- customer_support domain borderline (0.80 vs 0.85 threshold, needs more samples)

## [0.1.1] — 2026-03-23

### Hardening release — CEO review fixes

**Thread Safety**
- Added `threading.RLock` to `CacheStore` — all write operations (store, record_hit, evict) are now thread-safe
- Double-check locking pattern in `_ensure_db()` prevents race conditions during lazy initialization
- Added `PRAGMA busy_timeout=5000` to SQLite connections (5s retry on concurrent writes)
- `VectorIndex.add()` already thread-safe via hnswlib internal locking

**Schema Migration System**
- New `cacheback_meta` table tracks schema version
- `MIGRATIONS` list supports incremental schema upgrades (from_ver → to_ver → SQL)
- `_run_migrations()` auto-upgrades on DB open — safe for rolling deploys
- Legacy DBs (no meta table) auto-detected and upgraded

**Error Recovery**
- Corrupt SQLite DB: detected via `sqlite3.DatabaseError`, auto-deleted and recreated
- Corrupt hnswlib index: detected on `load_index()`, auto-deleted and rebuilt fresh
- OpenAI wrapper: `response.choices[0].message.content = None` no longer crashes (tool_calls, empty responses)
- Negative cache: embedder failures during index rebuild now logged with warning (not silent `pass`)

**Tests**
- Added `tests/test_robustness.py` — 15 new tests covering:
  - Corrupt DB/index recovery (4 tests)
  - OpenAI null content handling (2 tests)
  - Schema migration versioning (4 tests)
  - Thread safety under concurrent load (3 tests)
  - Graceful degradation: flaky embedder, post-eviction store (2 tests)
- Total: 86 tests passing

**Deferred**
- Gemini Embedding 2 evaluation → `TODOS.md` (Phase 1.5, P2)

## [0.1.0] — 2026-03-22

### Initial release

- `SemanticCache` kernel: lookup, populate, evict, stats
- `CachedOpenAI` + `AsyncCachedOpenAI` — drop-in OpenAI wrapper with transparent caching
- `CachedAnthropic` + `AsyncCachedAnthropic` — Anthropic wrapper
- Streaming support: buffer-and-replay for both sync and async
- Negative cache: `cache.negative.add/check/list/remove` API
- `CachebackBlocked` exception for negative cache hits
- ONNX MiniLM-L6-v2 embedder (384-dim, ~90MB, lazy download)
- hnswlib HNSW vector index with cosine similarity
- SQLite WAL backend with TTL and LRU eviction
- CLI: `cacheback stats`, `cacheback clear`, `cacheback lookup`
- Apache 2.0 license
- PyPI: `pip install cacheback-ai`
