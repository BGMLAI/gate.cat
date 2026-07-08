"""Shared guard used by every framework adapter.

One mechanism: adapters never re-implement verification - they flatten the
action to text (:func:`flatten_call`), call the engine through the seam,
log the decision (D2), and raise :class:`ActionVetoed` on block.
Fail-closed: an unavailable or erroring engine blocks, it never allows.

A8 (shadow mode): the DEFAULT is enforce (block == block). Shadow mode is an
opt-in that turns every block into a logged-but-allowed decision - it lowers
adoption friction and harvests veto-stories, but it is NOT the product's
identity. A tool that advertises "an error is a block" must not ship defaulting
to a mode that blocks nothing, so shadow is never on unless a caller (or the
``GATECAT_VETO_SHADOW`` env var) explicitly asks for it.
"""

from __future__ import annotations

import functools
import os
import re
from typing import Any, Callable, Sequence

from gatecat.integrations._engine import (
    ActionVetoed,
    Decision,
    EngineUnavailable,
    evaluate,
)
from gatecat.integrations._log import ascii_safe, log_decision
from gatecat.integrations.policies import DOGFOOD_DEFAULTS, Policy

_ACTION_LIMIT = 2000
_GUARDED_ATTR = "_gatecat_guarded"
_SHADOW_ENV = "GATECAT_VETO_SHADOW"
# Policies whose CLASS the target-anchored analyzer owns (filesystem/cloud
# deletion). When the analyzer allows such an action, these regex walls are
# dropped from the engine fall-through so they can't re-block an analyzer-proven
# safe delete. DB_DESTRUCTIVE (SQL DROP), TERRAFORM_PROD, GIT_FORCE_PUSH,
# EMAIL_SEND, PAYMENTS are NOT delete-class - they keep their regex walls.
# ONLY "RM_RF": the analyzer ALLOWs plain filesystem-delete verbs (rm/rmdir/
# unlink/shred/truncate) and returns None for cloud-destroy, so CLOUD_DESTROY
# must NOT be dropped - otherwise `rm -rf dist.new && vastai destroy 999` (rm
# proves disposable -> skip) lets the paid-infra destroy through as ALLOW. That
# is a fail-OPEN on paid infra (re-review fix, 2026-07-06).
_DELETE_POLICY_NAMES = frozenset({"RM_RF"})
# Hard-block classes that destroy REAL external / irreplaceable resources: they
# are NEVER disarmed by the ephemeral/CI escape hatch (CLAUDE.md rule #11). Paid
# cloud infra (vastai/aws/gcloud/az/k8s), raw disks, and prod IaC teardown. NOT
# RM_RF or DB_DESTRUCTIVE - CI legitimately deletes test dirs / test databases.
_NEVER_DISARM = frozenset({"DISK_DESTROY", "CLOUD_DESTROY", "TERRAFORM_PROD"})

# Hybrid backstop (Codex round-4 + user 2026-07-07): the SDK path is fail-OPEN on
# any command no wall recognized, while the full ActionPipeline routes unknowns to
# human. To close that class WITHOUT regex whack-a-mole, an action that no wall
# matched but still carries a standalone HIGH-SIGNAL destructive verb is surfaced
# as warn (human), not silently allowed. Deliberately TIGHT: `delete/remove/drop`
# are omitted (too common in paths/names/prose - the specific walls cover them);
# only rarely-benign verbs are here. Runs on the inert-stripped action, so a verb
# inside a quoted echo / commit message / path segment does not trip it.
_SUSPICIOUS_DESTRUCTIVE = re.compile(
    r"(?<![\w/.-])(destroy|purge|erase|wipe|obliterate|decommission|deprovision|"
    r"teardown|terminate|flushall|flushdb)(?![\w-])",
    re.IGNORECASE,
)


def _suspicious_destructive_verb(action: str) -> str | None:
    m = _SUSPICIOUS_DESTRUCTIVE.search(action)
    return m.group(1) if m else None
# Truthy spellings accepted for the env var; everything else (incl. unset) is
# enforce. Fail-safe direction: an unrecognized value must NOT silently disable
# blocking, so we allow-list the "on" tokens rather than blocklist the "off" ones.
_SHADOW_ON = frozenset({"1", "true", "yes", "on", "shadow"})

# Environment variables that CI/sandbox runners set. Presence of any means the
# filesystem is a throwaway (a fresh git checkout in a disposable container),
# where a delete is git/container-recoverable and the veto adds no value.
_EPHEMERAL_ENV_MARKERS = (
    "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "BUILDKITE",
    "JENKINS_URL", "TEAMCITY_VERSION", "DRONE", "APPVEYOR", "CODEBUILD_BUILD_ID",
    "SWE_AGENT", "SWE_BENCH", "TERMINAL_BENCH",
)
# Explicit escape hatches (both directions), so behavior is never a silent guess.
_EPHEMERAL_FORCE_ON = frozenset({"1", "true", "yes", "on", "ephemeral"})
_EPHEMERAL_ENV = "GATECAT_VETO_EPHEMERAL"


def ephemeral_context(env: dict | None = None) -> str | None:
    """Return a short reason string if this looks like a THROWAWAY environment
    (CI runner / disposable sandbox), else None.

    Integrity note (council 5/5, "disarm-not-loosen"): this is used ONLY to
    DISARM the gate entirely (turn every action into an audited no-op) and say
    so loudly - never to selectively loosen individual blocks. Detection that
    loosens would be an allow-list bolted onto a veto and a bypass surface; a
    detection that only disarms-and-discloses adds no bypass path (an attacker
    gains nothing by faking CI beyond turning the whole gate off, which the log
    makes visible). An explicit ``GATECAT_VETO_EPHEMERAL=0`` forces armed even
    in CI, for teams that want the veto in their pipeline.
    """
    e = env if env is not None else os.environ
    forced = str(e.get(_EPHEMERAL_ENV, "")).strip().lower()
    if forced in _EPHEMERAL_FORCE_ON:
        return f"{_EPHEMERAL_ENV}={forced}"
    if forced in ("0", "false", "no", "off"):
        return None  # explicitly armed even if CI markers are present
    for marker in _EPHEMERAL_ENV_MARKERS:
        if e.get(marker):
            return f"ephemeral env marker {marker}={e.get(marker)!r}"
    return None


def shadow_enabled(explicit: bool | None = None) -> bool:
    """Resolve shadow mode. An explicit caller argument wins; otherwise the
    ``GATECAT_VETO_SHADOW`` env var decides; default is enforce (False).
    """
    if explicit is not None:
        return explicit
    return os.environ.get(_SHADOW_ENV, "").strip().lower() in _SHADOW_ON


def flatten_call(name: str, args: tuple, kwargs: dict) -> str:
    """Flatten a tool call into the single evaluable string the gate matches.

    Shared by every adapter so the security-relevant contract (how a call
    becomes deny-matchable text) can never drift between frameworks.
    """
    parts = [name]
    parts.extend(repr(a) for a in args)
    parts.extend(f"{k}={v!r}" for k, v in kwargs.items())
    return " ".join(parts)[:_ACTION_LIMIT]


def _raise_block(source: str, reason: str, action: str, policy: str | None,
                 *, stages: "list[tuple[str, str, str]] | None" = None) -> ActionVetoed:
    """Log a block (D2) and build the ASCII-safe exception (D1). Single
    place so every block path - engine-returned, engine-raised, fail-closed -
    is audited and cp1252-safe identically. ``stages`` carries the full per-stage
    trace into the audit log."""
    log_decision(source=source, decision="block", reason=reason, context=action,
                 policy=policy, stages=stages)
    return ActionVetoed(ascii_safe(reason))


def _shadow_allow(source: str, reason: str, action: str, policy: str | None) -> None:
    """A8: record a would-be block that shadow mode is letting through.

    Distinct ``decision`` value (``shadow_block``) so B2 adjudication can tell
    real allows from actions that WOULD have been blocked in enforce mode -
    the raw material for a "what would we have caught" report before a team
    flips enforcement on.
    """
    log_decision(
        source=source,
        decision="shadow_block",
        reason=f"SHADOW (would block): {reason}",
        context=action,
        policy=policy,
    )


def _policy_is_warn(policy_name: str | None, policies: Sequence[Policy]) -> bool:
    """True if the named policy is marked level='warn' (ambiguous-executable):
    the hybrid middle tier surfaces it to a human instead of hard-blocking."""
    if not policy_name:
        return False
    for p in policies:
        if p.name == policy_name:
            return getattr(p, "level", "block") == "warn"
    return False


# The heredoc-strip regexes backtrack super-linearly on a crafted body (CSO
# ReDoS: a padded `<<TAG` with no terminator hung check_action ~62s, a DoS of
# the guardrail itself). Cap the input before running them: over the limit we
# skip stripping and let the raw text hit the regex walls (a false-BLOCK at
# worst, never a false-allow) - fail-closed, and fast.
_HEREDOC_STRIP_MAX = 32 * 1024


def _strip_data_heredocs_safe(action: str) -> str:
    """Strip data-heredoc bodies before the regex walls. Best-effort: if the
    analyzer module is unavailable, return the action unchanged (the regex wall
    then sees the literal - a false-block, never a false-allow, so safe)."""
    # ReDoS guard: an over-long action is not run through the backtracking
    # heredoc regexes; the raw text goes to the walls (safe: false-block-only).
    if len(action) > _HEREDOC_STRIP_MAX:
        return action
    try:
        from gatecat.integrations.action_analysis import (
            _strip_data_heredocs, reduce_nonshell_heredocs,
        )
        # order: drop data-heredoc bodies, reduce interpreter heredocs to just
        # their real runtime-delete lines (so SQL-looking Python comments don't
        # false-block but a real shutil.rmtree still hits RUNTIME_DELETE), then
        # blank inert literals (echo/grep/commit-message args).
        return _strip_inert_literals(
            reduce_nonshell_heredocs(_strip_data_heredocs(action)))
    except Exception:
        return action


# Argument positions whose VALUE is inert text, not a shell command. A
# "DROP TABLE" / "terraform destroy" / "rm -rf" literal there is CONTENT (a
# message, a string being printed, a search pattern), not an action - blocking
# it is the content-vs-command false-block class (E2E audit 2026-07-05, HIGH:
# `echo 'rm -rf ...'`, `grep -r 'rm -rf' .` were false-blocked). We blank only
# these exact, well-known inert slots; everything else stays verbatim, so this
# can only turn a false-block into an allow, never mask a real shell verb.
#
# INERT slots:
#   1. git commit -m "<msg>"       - a commit message is never a command
#   2. echo/printf "<text>"        - text being printed, not run
#   3. grep/egrep/fgrep/rg "<pat>" - a search PATTERN, not a command
#
# NOT inert (still fully analyzed): `python -c "..."` / `bash -c "..."` bodies
# are EXECUTED code (a real `shutil.rmtree(...)` / `terraform destroy` must be
# caught). And crucially, blanking the printed/searched LITERAL does not hide a
# pipe-to-shell: `echo cm0... | sh` keeps the `| sh` visible, so ENCODED_EXEC
# still fires - we blank the quoted body, never the surrounding pipeline.
_INERT_LITERAL = re.compile(
    r"""(?:
          \bgit\b[^\n|;&]*?\bcommit\b[^\n|;&]*?\s-[a-zA-Z]*m[a-zA-Z]*\s+   # git commit ... -m
        | (?:^|[\s;&|])(?:echo|printf|grep|egrep|fgrep|rg)\b               # echo/printf/grep verb
          (?:\s+-[a-zA-Z]+)*\s+                                            #   its flags
    )
    (?P<q>['"])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)          # the quoted literal
    """,
    re.VERBOSE | re.DOTALL,
)


# A pipe into an INTERPRETER / DB-CLIENT / SCHEDULER: after it, echo/printf output
# is CODE being executed, not inert text. `echo "DROP TABLE x" | mysql`,
# `echo "FLUSHALL" | redis-cli`, `echo 'docker rmi -f ...' | at`, `echo "rm -rf /"
# | sh` - the quoted body must NOT be blanked (round-7 free-hand: blanking it hid
# the payload and nothing downstream caught the pipe-into-a-non-sh executor, so
# every one passed as allow). Prefixes (sudo/env/xargs/timeout ...) may sit before
# the executor.
_PIPE_TO_EXECUTOR = re.compile(
    r"\|\s*(?:(?:sudo|doas|env|nice|ionice|time|command|nohup|stdbuf|setsid|xargs|timeout)\s+"
    r"(?:-\S+\s+|\d\S*\s+)*)*"
    r"(?:(?:ba|z|d|a|k)?sh|bash|mysql|psql|sqlite3|redis-cli|mongosh|mongo|at|batch|eval|"
    r"python\d?|perl|ruby|node|php|pwsh|powershell)\b",
    re.IGNORECASE)


def _strip_inert_literals(action: str) -> str:
    """Blank the body of an inert literal slot (git commit message, echo/printf
    text, grep pattern) so a dangerous LITERAL inside it can't false-block.
    Conservative: ONLY these slots, whose value is never a shell command.
    `python -c` / `bash -c` bodies are executed code and are NOT blanked - the
    regex/runtime walls must still see e.g. `shutil.rmtree(...)`.

    EXCEPTION (round-7): an echo/printf whose output is PIPED INTO an executor
    (sh/bash/mysql/psql/redis-cli/mongo/at/eval/an interpreter) is executing that
    text, not printing it - so its body is kept verbatim for the deny-walls. Only
    a `| sh` was implicitly covered before (via ENCODED_EXEC on the pipe); a pipe
    into a DB client or `at` had no downstream catch, so `echo "DROP TABLE" | mysql`
    slipped. Keeping the body lets DB_DESTRUCTIVE/DATASTORE_FLUSH/etc. see it."""
    def _repl(m: "re.Match") -> str:
        whole = m.group(0)
        body_start = m.start("body") - m.start()
        body_end = m.end("body") - m.start()
        head = whole[:body_start]
        # echo/printf piped into an executor -> body is CODE, do not blank it.
        if re.search(r"(?:^|[\s;&|])(?:echo|printf)\b", head, re.IGNORECASE):
            seg = re.split(r";|&&|\|\||\n", action[m.end():], 1)[0]
            if _PIPE_TO_EXECUTOR.search(seg):
                return whole
        return head + "__INERT__" + whole[body_end:]
    try:
        return _INERT_LITERAL.sub(_repl, action)
    except Exception:
        return action


def _analyze_delete_class(
    source: str, action: str, policies: Sequence[Policy],
    *, cwd: str | None, env: dict | None, home: str | None,
) -> Decision | None:
    """Run the target-anchored delete analyzer. Returns a Decision (block/warn/
    allow) when the action is delete-relevant, else None (engine walls decide).

    Fail-closed: if the analyzer import or call errors, return None so the
    engine's own fail-closed path still runs - never silently allow here.
    ``protected_assets`` for the analyzer are seeded from any RM_RF/CLOUD/DB
    policy that a caller flagged as a declared asset (via Policy.params)."""
    try:
        from gatecat.integrations.action_analysis import (
            analyze_delete, DeletePolicy,
        )
    except Exception:
        return None  # analyzer unavailable -> engine walls (fail-closed there)

    # declared assets: any Policy carrying params["protected_assets"] contributes
    assets: list[str] = []
    for p in policies:
        extra = getattr(p, "params", {}) or {}
        assets.extend(extra.get("protected_assets", []) or [])
    del_policy = DeletePolicy(protected_assets=tuple(assets)) if assets else DeletePolicy()

    import os
    resolved_home = home or os.path.expanduser("~").replace("\\", "/")
    resolved_cwd = (cwd or os.getcwd()).replace("\\", "/")
    try:
        verdict = analyze_delete(action, home=resolved_home, cwd=resolved_cwd,
                                 policy=del_policy, env=env)
    except Exception:
        return None  # analyzer error -> defer to engine (fail-closed)
    if verdict is None:
        return None
    return Decision(blocked=verdict.blocked, reason=verdict.reason,
                    policy="DELETE_ANALYZER", level=verdict.level)


def check_action(
    source: str,
    action: str,
    policies: Sequence[Policy] = DOGFOOD_DEFAULTS,
    *,
    shadow: bool | None = None,
    cwd: str | None = None,
    env: dict | None = None,
    home: str | None = None,
) -> Decision:
    """Evaluate *action*; log every decision; raise :class:`ActionVetoed` if
    blocked. Returns the (allowing OR warning) decision so callers can inspect it.

    Delete-class actions (rm/rmdir/shred/find-delete/...) are judged by the
    target-anchored analyzer (:func:`gatecat.integrations.action_analysis.
    analyze_delete`) using the real ``cwd``/``env`` when the harness supplies
    them (D-narrow). It returns three levels: block (raise), warn (log + allow),
    allow. Non-delete actions fall through to the engine's policy walls.

    A8: if shadow mode is on (``shadow=True``, or ``GATECAT_VETO_SHADOW``
    truthy), a block is logged as ``shadow_block`` and the action is ALLOWED
    instead of raising. Default is enforce - shadow never turns on implicitly.

    Ephemeral disarm (council 5/5): in a THROWAWAY environment (CI runner /
    disposable sandbox, detected via env markers) the gate DISARMS entirely -
    every action is an audited no-op, logged as ``disarmed`` - because nothing
    there is irreversible (git checkout + container are recoverable) so a block
    only cries wolf. This DISARMS, it never selectively loosens: an attacker who
    fakes CI turns the whole gate off (visible in the log), gaining no bypass
    path to slip one action past an armed gate. ``GATECAT_VETO_EPHEMERAL=0``
    forces armed even in CI.
    """
    # Full per-stage trace: every stage that runs appends (stage, verdict, detail).
    # This is the audit/observability trail the council flagged (#1) and the recall
    # audit needs - it records what EACH stage said, not just the final verdict, so
    # an allowed action whose target a stage couldn't see is visible, not silent.
    stages: list[tuple[str, str, str]] = []

    ephemeral = ephemeral_context(env)
    if ephemeral is not None:
        # Hard-block classes that destroy REAL external / irreplaceable resources
        # are NEVER disarmed - not even in CI (CLAUDE.md rule #11: a paid-infra or
        # raw-disk destroy must always reach a human). Codex round-4: `vastai
        # destroy` was silently ALLOWed with env={"CI":"1"}. Run just those walls
        # before honoring the disarm.
        never = tuple(p for p in policies if p.name in _NEVER_DISARM)
        try:
            hard = evaluate(source, action, never) if never else None
        except Exception:
            hard = None
        if hard is not None and hard.blocked:
            stages.append(("ephemeral-disarm", "armed-hardblock",
                           f"{hard.policy}: hard-block class not disarmable in CI"))
            reason = (f"VETO [{hard.policy}]: {hard.reason} "
                      "(hard-block class - NOT disarmed in a throwaway/CI env)")
            raise _raise_block(source, reason, action, hard.policy, stages=stages)
        stages.append(("ephemeral-disarm", "disarmed", ephemeral))
        reason = f"gate.cat disarmed: {ephemeral} - throwaway env, veto is a no-op here"
        log_decision(source=source, decision="disarmed", reason=reason, context=action,
                     stages=stages)
        return Decision(blocked=False, reason=reason, policy=None, level="allow").with_stages(stages)
    stages.append(("ephemeral-disarm", "armed", "not a throwaway env"))

    shadow_on = shadow_enabled(shadow)

    # Target-anchored delete analyzer first (D-narrow: real cwd/env from the
    # harness). Only handles the delete class; returns None for everything else.
    del_decision = _analyze_delete_class(source, action, policies, cwd=cwd, env=env, home=home)
    engine_policies = policies
    deferred_warn = None  # a delete-analyzer WARN pending the deny-wall pass
    if del_decision is None:
        stages.append(("delete-analyzer", "n/a", "not a delete-class action"))
    else:
        stages.append(("delete-analyzer", del_decision.level,
                       f"{del_decision.policy}: {del_decision.reason}"[:200]))
        if del_decision.level == "warn":
            # UNDER-BLOCK FIX (re-review 2026-07-06): a WARN from the analyzer
            # (opaque/remote delete) must NOT skip the regex deny-walls. A line
            # like `rm -rf $(x) && dd if=/dev/zero of=/dev/sda` warns on the opaque
            # delete but STILL carries a DISK_DESTROY the walls must catch. Fall
            # through to evaluate() over the FULL action (all policies, nothing
            # dropped); a wall block/upgrade wins. Only if no wall fires do we
            # surface the warn (below, after the engine pass).
            deferred_warn = del_decision
            engine_policies = policies  # keep every wall for the warn path
        elif del_decision.blocked:
            reason = f"VETO [{del_decision.policy or 'delete'}]: {del_decision.reason}"
            if shadow_on:
                _shadow_allow(source, reason, action, del_decision.policy)
                return Decision(False, f"SHADOW: {ascii_safe(reason)}",
                                del_decision.policy, level="allow").with_stages(stages)
            raise _raise_block(source, reason, action, del_decision.policy, stages=stages)
        # analyzer ALLOWED this delete: the analyzer OWNS the plain fs-delete
        # class, so drop ONLY RM_RF (see _DELETE_POLICY_NAMES) from the engine
        # fall-through - otherwise `rm -rf dist.new` (analyzer-allowed) would be
        # re-blocked by the RM_RF regex. CLOUD_DESTROY and all non-delete walls
        # still run (the analyzer never allows cloud-destroy).
        engine_policies = [p for p in policies if p.name not in _DELETE_POLICY_NAMES]
        if not engine_policies:
            log_decision(source=source, decision="allow", reason=del_decision.reason,
                         policy="DELETE_ANALYZER", context=action, stages=stages)
            return del_decision.with_stages(stages)

    # Data-heredoc bodies (cat>file<<EOF ... EOF) are a document/script being
    # WRITTEN, not commands - strip them before the regex walls so a literal
    # "DROP TABLE"/"terraform destroy" inside written docs can't false-block
    # (content-vs-command class). Executed heredocs (bash<<EOF) are untouched.
    engine_action = _strip_data_heredocs_safe(action)
    try:
        decision = evaluate(source, engine_action, engine_policies)
    except EngineUnavailable as exc:
        stages.append(("deny-regex-walls", "engine-unavailable", str(exc)[:120]))
        reason = f"veto engine unavailable (fail-closed): {exc}"
        if shadow_on:
            _shadow_allow(source, reason, action, None)
            return Decision(blocked=False, reason=f"SHADOW: {ascii_safe(reason)}",
                            policy=None).with_stages(stages)
        raise _raise_block(source, reason, action, None, stages=stages) from exc
    except ActionVetoed as exc:
        # Engine signalled a block by raising (documented seam behavior). Still
        # audit it and ASCII-escape the reason - otherwise this block escapes
        # the D2 log and a non-ASCII engine reason crashes cp1252 consoles.
        stages.append(("deny-regex-walls", "block", str(exc)[:120]))
        reason = f"VETO [gate]: {str(exc) or 'blocked by veto gate'}"
        if shadow_on:
            _shadow_allow(source, reason, action, None)
            return Decision(blocked=False, reason=f"SHADOW: {ascii_safe(reason)}",
                            policy=None).with_stages(stages)
        raise _raise_block(source, reason, action, None, stages=stages) from exc
    except Exception as exc:
        stages.append(("deny-regex-walls", "error", f"{type(exc).__name__}: {exc}"[:120]))
        reason = f"veto evaluation error (fail-closed): {type(exc).__name__}: {exc}"
        if shadow_on:
            _shadow_allow(source, reason, action, None)
            return Decision(blocked=False, reason=f"SHADOW: {ascii_safe(reason)}",
                            policy=None).with_stages(stages)
        raise _raise_block(source, reason, action, None, stages=stages) from exc

    stages.append(("deny-regex-walls", decision.level or ("block" if decision.blocked else "allow"),
                   f"{decision.policy}: {decision.reason}"[:200]))
    if decision.blocked:
        # Hybrid middle tier: if the policy that fired is level="warn" (an
        # ambiguous-executable class like RUNTIME_DELETE), surface it to the
        # human instead of hard-blocking - a `python -c "rmtree(X)"` where X may
        # be a backup or a build cache should be reviewed, not silently killed.
        if _policy_is_warn(decision.policy, engine_policies):
            stages.append(("warn-tier", "warn", f"ambiguous-executable {decision.policy}"))
            wreason = f"unchecked [{decision.policy}]: {decision.reason}"
            log_decision(source=source, decision="warn", reason=wreason,
                         policy=decision.policy, context=action, stages=stages)
            return Decision(blocked=False, reason=wreason, policy=decision.policy,
                            level="warn").with_stages(stages)
        reason = f"VETO [{decision.policy or 'gate'}]: {decision.reason}"
        if shadow_on:
            _shadow_allow(source, reason, action, decision.policy)
            return Decision(
                blocked=False, reason=f"SHADOW: {ascii_safe(reason)}", policy=decision.policy
            ).with_stages(stages)
        raise _raise_block(source, reason, action, decision.policy, stages=stages)
    # No wall fired. If the analyzer had surfaced a WARN (opaque/remote delete),
    # it stands now that the deny-walls have run and found nothing to hard-block -
    # surface the unchecked delete rather than silently allowing it.
    if deferred_warn is not None:
        log_decision(source=source, decision="warn", reason=deferred_warn.reason,
                     policy=deferred_warn.policy, context=action, stages=stages)
        return deferred_warn.with_stages(stages)
    # Hybrid backstop: no wall recognized this, but it carries a high-signal
    # destructive verb -> route to human (warn) instead of failing open, matching
    # what the full ActionPipeline does for unknown commands.
    susp = _suspicious_destructive_verb(engine_action)
    if susp:
        stages.append(("warn-tier", "warn", f"unrecognized destructive verb '{susp}'"))
        wreason = (f"unchecked: '{susp}' looks destructive but no policy recognized "
                   "this command - review before running")
        log_decision(source=source, decision="warn", reason=wreason, policy=None,
                     context=action, stages=stages)
        return Decision(blocked=False, reason=wreason, policy=None,
                        level="warn").with_stages(stages)
    log_decision(
        source=source,
        decision="allow",
        reason=decision.reason,
        policy=decision.policy,
        context=action,
        stages=stages,
    )
    return decision.with_stages(stages)


def guard_callable(
    fn: Callable,
    policies: Sequence[Policy] = DOGFOOD_DEFAULTS,
    *,
    name: str | None = None,
    source: str = "guard",
    shadow: bool | None = None,
) -> Callable:
    """Wrap any tool callable so the gate runs before it executes.

    Framework-agnostic (AutoGen, plain functions, anything with a callable
    interface); framework adapters build on it. Idempotent-safe: the wrapper
    is tagged so higher-level helpers can skip double-wrapping.

    A8: ``shadow`` is forwarded to :func:`check_action` (default enforce).
    """
    tool_name = name or getattr(fn, "name", None) or getattr(fn, "__name__", "tool")

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        check_action(source, flatten_call(tool_name, args, kwargs), policies, shadow=shadow)
        return fn(*args, **kwargs)

    setattr(wrapper, _GUARDED_ATTR, True)
    return wrapper
