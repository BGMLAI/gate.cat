# TELEMETRY.md — spec (written BEFORE any telemetry code; council C20)

## Current state (v0.4.x)

**gate.cat does not phone home. There is no network telemetry endpoint.** The word "telemetry"
in `gatecat/integrations/_log.py` / `_audit.py` refers to a **local** JSONL audit log on your disk.
Nothing leaves your machine.

## If/when opt-in telemetry ships, it follows this contract

1. **Default OFF.** Enabled only by explicit `GATECAT_TELEMETRY=1`. No prompt, no nag, no
   dark pattern. Uninstall of the env var = off again.
2. **Fixed, minimal schema — nothing else is ever sent:**
   - `version` (package version string)
   - `policy_id` (which policy fired, e.g. `TERRAFORM_PROD`)
   - `verdict_class` (`block` / `warn` / `allow` / `disarmed`)
   - `integration` (`hook` / `adapter` / `api` / `proxy`)
   - `install_id` (random local UUID, generated once, no linkage to identity)
   - `ts_coarse` (hour-truncated timestamp)
3. **Never sent, by construction:** commands, arguments, file paths, prompts, model outputs,
   hostnames, usernames, environment variables. The client serializes ONLY the fields above —
   there is no free-text field to leak through.
4. **Transparency:** the exact payload is logged locally before send; `GATECAT_TELEMETRY_DRYRUN=1`
   prints instead of sending.
5. **Purpose limitation:** aggregate counts (installs actually armed, verdict mix, policy hit
   distribution) to honestly answer "is anyone using this?" — the T+30 gate's usage signal.
   If opt-in volume is ~0, the gate falls back to pypistats + GitHub API and says so.
6. **Not used for:** the enterprise guarantee rider (that is verified from the customer's OWN
   local logs), marketing attribution, or anything per-user.

Any change to this schema is a MAJOR version bump and a CHANGELOG headline.
