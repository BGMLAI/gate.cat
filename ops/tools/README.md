# gate.cat retro-scan

`gatecat_retroscan.py` reads the AI-agent session transcripts already on your disk,
extracts every command your agents actually executed, classifies the irreversible
ones, and writes a single self-contained HTML report.

It exists because nobody buys protection against a risk they have not measured, and
because a vendor's numbers are not evidence about your fleet. **You run this. On your
machine. Before anyone sells you anything.** Every number in the report is yours.

```bash
python3 ops/tools/gatecat_retroscan.py
# -> ./gatecat-retroscan-report.html
```

No install, no virtualenv, no `pip`, no config file. Python 3.11+ and nothing else.

---

## The four constraints, and how to check each one yourself

These are not preferences. They are the reason it is possible to run an unknown
script against your agent transcripts, which are among the most sensitive files on a
developer's laptop.

### 1. Zero third-party dependencies

Standard library only. Verify:

```bash
grep -nE "^\s*(import|from)\s+" ops/tools/gatecat_retroscan.py | sort -u
```

Every module listed will be one of: `argparse`, `dataclasses`, `datetime`, `html`,
`json`, `os`, `pathlib`, `posixpath`, `re`, `shlex`, `sys`, `typing`, `__future__`.
The test suite asserts this mechanically by parsing the file's AST
(`test_tool_imports_only_the_allowed_standard_library`), so it cannot rot.

### 2. Zero network calls

There is no networking import in the file and nothing that could construct one.
The tool prints the exact verification command for you:

```bash
python3 ops/tools/gatecat_retroscan.py --verify-offline
```

which is:

```bash
grep -nE "socket|urllib|http\.client|requests|httpx" ops/tools/gatecat_retroscan.py
```

**Expected output: nothing at all.** Not even a comment or a docstring — the
forbidden module names are assembled from string fragments inside the tool
(`_NETWORK_TOKENS`) precisely so that the auditor's grep returns a clean zero rather
than a "well, that one's just a comment" conversation. A single hit means the file
has been modified; do not run it.

The test `test_offline_verification_command_finds_nothing_in_the_tool` runs that
same grep in CI. `test_tool_imports_nothing_capable_of_networking` additionally bans
`subprocess`, `ssl`, `asyncio`, `ftplib`, `smtplib`, `webbrowser` and friends, so
there is no shell-out escape hatch either.

Nothing is uploaded, phoned home, or telemetered. If you want us to see the results,
you send them; that is the only path that exists.

### 3. Read-only

The only files written are the ones you name: `--out` (default
`./gatecat-retroscan-report.html`) and, if you ask for it, `--json`. Transcripts are
opened read-only, streamed, and never modified, moved, or deleted.
`test_cli_is_read_only_towards_transcripts` byte-compares and mtime-compares the whole
input tree before and after a full run.

### 4. Secrets are redacted before they reach the report

Every captured command passes through `redact()` at the moment a finding is created —
before classification results are stored, before rendering, before anything is
printed. Redaction is never optional and there is no flag to disable it.

Recognised and replaced with `«REDACTED:<kind>»`:

| kind | shape |
| --- | --- |
| `aws-access-key` | `AKIA…`, `ASIA…` |
| `github-token` | `ghp_`, `gho_`, `ghs_`, `ghu_`, `github_pat_…` |
| `anthropic-key` | `sk-ant-…` |
| `openai-key` | `sk-…` |
| `stripe-key` | `sk_live_…`, `rk_test_…` |
| `slack-token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-…` |
| `google-api-key` | `AIza…` |
| `bearer-token` | `Authorization: Bearer …` (scheme kept, token gone) |
| `jwt` | `eyJ….….…` |
| `private-key` | `-----BEGIN … PRIVATE KEY-----` blocks, including truncated ones |
| `basic-auth` | `https://user:pass@host` |
| `credential` | `password=`, `token=`, `api_key=`, `secret=` …, in shell, in files, and in URL query strings; plus the space-separated forms (`--token s3cr3t`, `aws configure set aws_secret_access_key …`) |

`redact()` is idempotent, and after rendering the tool runs a second pass over the
finished HTML/JSON looking for anything that survived. On a healthy run this changes
nothing; if it ever fires, the tool redacts the survivor, warns loudly on stderr, and
asks you to report the bug. `--no-redact-check` skips only that final verification
pass — it does **not** disable redaction.

---

## Usage

```
python3 gatecat_retroscan.py [PATHS...] [--out report.html] [--json out.json]
                             [--since YYYY-MM-DD] [--no-redact-check] [--quiet]
                             [--verify-offline] [--version]
```

With no `PATHS`, it auto-discovers `~/.claude/projects`, `~/.codex/sessions`,
`~/.cursor`, and `~/.aider*`. Give it explicit paths (files or directories) to scan
anywhere else — an archived transcript bundle, a colleague's export, a CI artifact.

`--json` emits the same findings in a stable, machine-readable schema so results can
be aggregated across machines later. Exit code is **always 0** on success: this is a
diagnostic, not a gate, and a non-zero exit would be indistinguishable from "the scan
itself broke".

## Input formats

| Source | Location | Result correlation | Confidence |
| --- | --- | --- | --- |
| Claude Code | `~/.claude/projects/<slug>/<session>.jsonl` | `tool_use` ↔ `tool_result` on `tool_use_id` | high |
| Codex CLI | `~/.codex/sessions/**/rollout-*.jsonl` | `function_call` ↔ `function_call_output` on `call_id`, plus `exit_code` | high |
| Cursor / aider / generic JSON | anywhere | none available | **low** |
| Shell history (`.bash_history`, `.zsh_history`, zsh extended format) | anywhere | none available | **low** |

Format is detected by sniffing content, with path hints only as a tie-break, because
people copy transcripts into odd places and a wrong guess silently loses data.

Fallback-parsed sources are quarantined in their own report section and excluded from
every headline number. A shell history is not agent activity — it is a human's
keystrokes, sometimes mixed with an agent's — and the report says so in its own voice.

### Executed vs. proposed

A command counts as **executed** only when the transcript carries a matching tool
result that is neither an error nor a permission denial. A tool call that was denied,
errored, or never returned is **proposed, not executed**, and is reported separately.

This is the credibility of the whole report. An inflated headline is worth less than
no headline. It also means the tool systematically *undercounts*: a command that ran
and then failed lands in the proposed bucket, not the executed one.

## The ten irreversible classes

Ordered most severe first; a command is assigned at most one class, so
`sudo rm -rf /etc/nginx` is a `recursive-delete`, not a `permission-escalation`
footnote.

1. `recursive-delete` — `rm -rf`/`-fr`/`-r --force`, `find … -delete`, `shutil.rmtree`, `Remove-Item -Recurse`
2. `disk-write` — `dd of=/dev/…`, `mkfs.*`, `fdisk`, `parted`, `shred`, `wipefs`
3. `history-rewrite` — `git push --force` (not `--force-with-lease`), `reset --hard`, `clean -fd`, `branch -D`, `filter-branch`, `rebase` onto a shared branch, `checkout .`
4. `infra-destroy` — `terraform destroy`, `apply -auto-approve`, `pulumi destroy`, `kubectl delete`, `helm uninstall`, `aws … delete-*` / `s3 rb` / `s3 rm --recursive`, `gcloud … delete`, `az … delete`
5. `db-destructive` — `DROP TABLE`/`DATABASE`, `TRUNCATE`, `DELETE FROM` with no `WHERE`, `flushall`, `db.dropDatabase()`, `alembic downgrade`, `prisma migrate reset`
6. `remote-code-exec` — `curl … | sh`, `wget … | bash`, `iex(irm …)`, any download piped into an interpreter
7. `credential-access` — `~/.ssh/id_*`, `~/.aws/credentials`, `.env`, `~/.netrc`, `gcloud auth print-access-token`, `security find-generic-password`, printing `$*_API_KEY`-shaped variables
8. `permission-escalation` — `sudo`, `doas`, `chmod 777`, `chown -R root`, `setcap`, `/etc/sudoers`
9. `package-publish` — `npm publish`, `twine upload`, `cargo publish`, `docker push`, `gh release create`, `pip install` from a URL or git ref
10. `process-kill` — `kill -9`, `killall`, `pkill -f`, `systemctl stop/disable`, `docker rm -f`, `docker system prune -a`

## What must NOT fire

Two false positives were found and fixed in the original build. They are the tool's
credibility test, and both have dedicated tests.

**Writing about a command is not running it.** Heredoc bodies (`cat > README.md
<<'EOF' … EOF`) are removed before anything is matched, and text emitters (`echo`,
`printf`, `cat`, `tee`) have their inert quoted literals stripped. `echo 'rm -rf /' >
danger.sh` and `git commit -m "stop using rm -rf"` are silent.

**Searching for a command is not running it.** `grep`, `rg`, `ag`, `history`,
`git log --grep=…`, `find` without `-delete`/`-exec` are judged by their executable
head and never classified. `grep -r 'rm -rf' .` is silent — otherwise this tool would
flag its own verification command.

Also silent: `--dry-run`, `--what-if`, `terraform plan`,
`kubectl … --dry-run=client`, `echo`-prefixed commands, and anything commented out
with `#`.

Quoting is not a blanket amnesty: a quoted span containing `$` or a backtick is
*kept*, because `cat "$HOME/.aws/credentials"` is a real read and `bash -c 'rm -rf /'`
is a real deletion. Likewise `echo $(rm -rf /etc/x)` fires — the substitution runs
before `echo` does.

### The disposable bucket

`rm -rf node_modules`, `.venv`, `dist`, `build`, `__pycache__`, `target`, `.next`,
`.pytest_cache`, `/tmp/…` and friends are counted but placed in a clearly separated
**low-severity / disposable** section, never in the headline. This matches gate.cat's
published corpus methodology exactly. One irreplaceable target in the argument list
poisons the whole cleanup: `rm -rf node_modules /srv/uploads` is *not* disposable.

Mixing build-cache chores into an incident number is how a scan earns the word "FUD".

## Robustness

Transcripts are large, occasionally truncated mid-line, and sometimes contain bytes
that are not UTF-8. None of that crashes the scan or silently vanishes:

- streamed line by line — a 500 MB JSONL is never materialised as a string
- a line above `MAX_LINE_BYTES` is dropped and counted, not loaded
- malformed JSON, undecodable bytes, and unreadable files are each counted separately
  and printed in the terminal summary and the report
- a single broken file can never end the scan
- unbalanced quotes fall back from `shlex` to whitespace splitting rather than raising

## The report

- **Terminal summary** — sessions, date range, executed count, proposed-but-not-executed
  count with reasons, per-class counts, the disposable bucket, and parse skips.
- **HTML** — one self-contained file. Inline CSS, no scripts, no fonts, no images, no
  external requests of any kind; readable with JavaScript disabled, and it renders in
  light or dark mode. Headline, per-class tables with the redacted command, timestamp
  and source session, then a methodology section.
- **JSON** (`--json`) — the same findings, stable schema, for aggregation.

The methodology section is not optional and is written in the tool's own voice. It
states what was counted, what was deliberately excluded, what the scan **could not
see** (commands run outside agent sessions; sessions already rotated, compacted, or
deleted; fallback-parsed sources), and this:

> A command in an irreversible class is not proof that harm occurred. It is proof that
> the class was reachable — that at the moment it ran, nothing in the loop was
> positioned to stop it.

> The scan is certain only about what it found; an unparsed session is unknown, not
> clean.

## Tests

```bash
python3 -m pytest ops/tools/test_retroscan.py -q
```

Standard library + pytest only. All fixtures are built inline via `tmp_path`; there
are no binary fixtures. Coverage includes every one of the ten classes on a live
example, both false-positive classes, dry-run/comment/echo suppression, disposable
bucketing, the `tool_use_id` correlation including the error and permission-denied
paths, every redaction pattern, malformed and truncated JSONL, invalid UTF-8, oversize
lines, argv-list vs string commands, and assertions that the HTML contains no external
asset reference and no unredacted secret from the fixture.

## Known limits

Stated here rather than discovered by a buyer:

- **Undercounts by design.** A command that ran and then exited non-zero is filed as
  proposed, not executed.
- **Text classification, not execution tracing.** The tool reads what the agent
  *asked the shell to do*. It cannot see what a script it invoked then did, what
  happened inside a container, or what a `$VAR` resolved to at runtime.
- **`kill -9` on a non-child PID is indistinguishable from one on a child PID** in a
  transcript, so all `kill -9` calls are counted.
- **Quoted paths with no expansion are treated as prose for text emitters**, so
  `echo "check ~/.aws/credentials"` is silent by design. `cat "$HOME/.aws/credentials"`
  is not.
- **Sessions rotate.** Whatever your agent tooling has already deleted or compacted is
  outside the scan, and the report says so.
