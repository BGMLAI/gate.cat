"""action_pipeline — the SIX-mechanism action veto, on the SAFETY axis.

The founder's canon (REJESTR_PRAWD 2026-07-05): gate.cat was always meant to be
6 mechanisms, not a flat deny-list. ``TruthPipeline`` (pipeline.py) already
chains all six, but on the TRUTH axis (is the model's ANSWER correct?). This
module runs the same six on the SAFETY axis (is the AGENT'S ACTION safe?), so a
command flows through every layer instead of a single deny-list.

Chain (mirrors TruthPipeline.evaluate, safety-flavored):

  [1] ALLOW-LIST   known-safe verb (ls/git/cat/build) -> allow, silent. The
                   only path to a silent allow: proven-safe, nothing else.
  [2] KORYTO       what will this command DO? Resolve the target (protect-list),
                   run any embedded code through the hardened sandbox. A target
                   under a protected root / a disk-wipe / a permission-lockout is
                   a HARD refute -> block (physically independent of any model).
  [3] GATE         self-consistency (BGML Study A): when koryto can't decide,
                   re-sample the model N times on the ORIGINAL task and measure
                   the SPREAD of its answers. Low spread = the model is confident
                   about what it's doing -> trust the action. High spread = the
                   model doesn't know -> escalate. This is NOT asking the model
                   "is this safe" - it's detecting the model's own uncertainty
                   about the task. (needs the original task text + sample_fn;
                   skipped when either is missing.)
  [4] STAGNATION   watches the rule base: a streak of refutes without progress
                   means the rules may be stale - don't trust blindly, surface.
  [5] ARBITER      resolves a soft koryto-vs-model disagreement (optional).
  [6] HUMAN        anything still unresolved -> a human decides. Unrecognized is
                   NEVER silently allowed - it lands here.

Verdict levels: "block" (hard-dangerous), "warn" (unresolved -> human),
"allow" (proven-safe). Fail-closed everywhere: any error -> not "allow".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from gatecat.integrations.action_analysis import (
    DeletePolicy,
    analyze_delete,
    split_segments,
)

# Policy names the target-anchored delete analyzer OWNS: when the analyzer proves
# a delete disposable, only THESE regex walls are skipped so they can't re-block
# it (F1). It is deliberately JUST "RM_RF": the analyzer only ever ALLOWs plain
# filesystem-delete verbs (rm/rmdir/unlink/shred/truncate) - it returns None for
# cloud-destroy - so putting CLOUD_DESTROY here would drop the CLOUD_DESTROY wall
# on a line like `rm -rf dist.new && vastai destroy 999` (rm proves disposable ->
# skip -> paid-infra destroy passes as ALLOW). That is a fail-OPEN on paid infra
# (re-review regression, 2026-07-06). RM_RF alone is safe because the analyzer
# genuinely owns and re-adjudicates every rm target.
_DELETE_POLICY_NAMES = frozenset({"RM_RF"})

# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------


@dataclass
class ActionVerdict:
    """Outcome of running one command through the six-mechanism chain."""

    level: str  # "block" | "warn" | "allow"
    reason: str
    channel: str = "none"  # which layer decided: allow-list|koryto|gate|stagnation|arbiter|human
    stages: list[dict] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.level == "block"

    @property
    def is_warn(self) -> bool:
        return self.level == "warn"

    def to_dict(self) -> dict:
        return {"level": self.level, "reason": self.reason,
                "channel": self.channel, "stages": self.stages}


def _block(reason: str, channel: str, stages: list) -> ActionVerdict:
    return ActionVerdict("block", reason, channel, stages)


def _warn(reason: str, channel: str, stages: list) -> ActionVerdict:
    return ActionVerdict("warn", reason, channel, stages)


def _allow(reason: str, channel: str, stages: list) -> ActionVerdict:
    return ActionVerdict("allow", reason, channel, stages)


# --------------------------------------------------------------------------
# [1] ALLOW-LIST — known-safe verbs (default-deny for everything else)
# --------------------------------------------------------------------------

# Verbs that are read-only or ordinary dev work with no irreversible reach on
# their own. The list is the SAFE set (allow-list); anything not here is not
# auto-allowed - it goes on to koryto/gate/human. Conservative on purpose.
SAFE_VERBS = frozenset({
    # read-only inspection
    "ls", "cat", "head", "tail", "grep", "rg", "find", "fd", "less", "more",
    "pwd", "cd", "echo", "printf", "wc", "sort", "uniq", "cut", "awk", "sed",
    "diff", "stat", "file", "readlink", "realpath", "dirname", "basename",
    "which", "whereis", "type", "env", "date", "sleep", "true", "false", "test",
    "ps", "top", "df", "du", "free", "uptime", "whoami", "id", "hostname",
    "tr", "tee", "jq", "yq", "column", "nl", "tac", "xxd", "od", "strings",
    # version control (read + ordinary write; destructive git handled by koryto)
    "git", "gh", "hg",
    # build / test / package (create, not destroy)
    "make", "cmake", "ninja", "cargo", "go", "npm", "npx", "pnpm", "yarn",
    "pip", "pip3", "uv", "poetry", "pytest", "tox", "coverage", "node", "deno",
    "python", "python3", "py", "ruby", "perl", "java", "javac", "mvn", "gradle",
    "tsc", "eslint", "prettier", "black", "ruff", "mypy", "gcc", "g++", "clang",
    "rustc", "dotnet", "bundle", "composer",
    # fetch (download, not upload/delete); curl/wget flagged by ENCODED_EXEC if piped to sh
    "curl", "wget",
    # misc safe
    "mkdir", "touch", "cp", "ln", "tar", "gzip", "gunzip", "unzip", "zip",
    "docker", "kubectl", "helm",  # container verbs; destructive subcommands caught by koryto
    # ordinary dev shell that is not irreversible on its own (destructive forms
    # are still caught by koryto's deny-walls / delete-analyzer):
    "chmod", "chown",             # perms; a lockout (chmod -R 000 /) is caught by koryto
    "export", "set", "unset", "alias", "source", ".", "eval",  # shell builtins
    "configure", "cmake", "autoconf", "automake", "libtoolize", "meson",
    "nano", "vim", "vi", "emacs", "code", "subl",  # editors (open a file)
    "apt", "apt-get", "dpkg", "yum", "dnf", "brew", "apk",  # pkg (purge caught by koryto)
    "systemctl", "service", "journalctl",  # service ctl (disable/mask caught by koryto)
    "ssh", "scp", "rsync", "sftp",  # remote (exfil/--delete caught by koryto)
    "mv", "rename",               # move (mv to /dev/null caught by koryto)
    "kill", "pkill", "killall",   # signals (kill -9 1 caught by koryto)
    "psql", "mysql", "sqlite3", "redis-cli", "mongo", "mongosh",  # db clients (DROP/FLUSH caught)
    "crontab", "at", "systemd-run",  # scheduling (crontab -r caught by koryto)
    "history",                    # (history -c caught by koryto)
})

# Prefixes that shift the real verb (unwrap them before checking).
_PREFIX = ("sudo", "doas", "nice", "ionice", "time", "command", "env",
           "nohup", "stdbuf", "setsid", "xargs", "timeout")


def _segment_verb(seg: str) -> Optional[str]:
    """The command verb of a segment, after unwrapping prefixes. None if empty."""
    toks = seg.strip().split()
    i = 0
    while i < len(toks):
        t = toks[i]
        base = t.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if base.endswith(".exe"):
            base = base[:-4]
        if "=" in t and re.match(r"^\w+=", t):  # VAR=val prefix
            i += 1
            continue
        if base in _PREFIX:
            i += 1
            if base == "timeout" and i < len(toks):  # timeout takes a duration arg
                i += 1
            continue
        return base
    return None


def all_verbs_safe(command: str) -> bool:
    """True only if EVERY segment's verb is a known-safe verb. Fail-closed: an
    unparseable command or any unrecognized verb -> False (not auto-allowed)."""
    try:
        segs = split_segments(command)
    except Exception:
        return False
    if not segs:
        return False
    for seg in segs:
        verb = _segment_verb(seg)
        if verb is None or verb not in SAFE_VERBS:
            return False
    return True


# --------------------------------------------------------------------------
# The six-mechanism pipeline
# --------------------------------------------------------------------------


class ActionPipeline:
    """Runs a shell command through the six safety mechanisms.

    Args:
        policy:      DeletePolicy for koryto (protect-list of assets). Optional.
        sample_fn:   callback(prompt)->str for the gate layer. When None, the
                     gate layer is skipped and unresolved actions go to human.
        n_samples:   gate probe count.
        disagreement_threshold: spread above which "the model doesn't know".
        human_approve: callback(command)->bool for the human layer. When None,
                     an action that reaches the human layer is WARN (surfaced),
                     never silently allowed.
        home, cwd:   resolution context for koryto (real values from the harness).
        env:         real environment for $VAR resolution in koryto (D-narrow).
    """

    def __init__(
        self,
        policy: Optional[DeletePolicy] = None,
        *,
        sample_fn: Optional[Callable[[str], str]] = None,
        n_samples: int = 5,
        disagreement_threshold: float = 0.30,
        embedder: Any = None,
        human_approve: Optional[Callable[[str], bool]] = None,
        home: str = "~",
        cwd: str = ".",
        env: Optional[dict] = None,
    ):
        self.policy = policy or DeletePolicy()
        self.human_approve = human_approve
        self.home = home
        self.cwd = cwd
        self.env = env
        # [3] gate — lazily built so gate.py import stays optional
        self._gate = None
        if sample_fn is not None:
            try:
                from gatecat.gate import Gate
                self._gate = Gate(sample_fn, n_samples=n_samples,
                                  threshold=disagreement_threshold, embedder=embedder)
            except Exception:
                self._gate = None
        # [4] stagnation — watches the rule base across calls
        self._monitor = None
        try:
            from gatecat.stagnation import StagnationMonitor
            self._monitor = StagnationMonitor()
        except Exception:
            self._monitor = None

    # -- [2] koryto: what will this command DO? -----------------------------

    def _koryto(self, command: str) -> ActionVerdict:
        """Deterministic safety check. Two deterministic sub-walls, both
        physically independent of any model:

          (a) the DENY policy walls (policies.DOGFOOD_DEFAULTS): every hard-danger
              class - RM_RF, SECRET_DELETE/READ, HISTORY_WIPE, DATASTORE_FLUSH,
              CLOUD/TERRAFORM/DB destroy, ENCODED_EXEC, SYSTEM_TAMPER (warn), ...
          (b) the target-anchored delete analyzer (protected root / disk / perms).

        Whichever is stricter wins (block > warn > allow); if neither fires the
        target is 'unknown' -> the gate/human layers upstream decide. Fail-closed:
        any error -> block."""
        stages: list[dict] = []
        # (b) target-anchored delete analyzer FIRST (F1, council 2026-07-06). It
        # OWNS the delete classes: a delete it proves disposable (rm -rf dist.new)
        # must not then be re-blocked by the RM_RF/CLOUD_DESTROY regex walls. This
        # mirrors guard.py:332 (the other entry path) - the analyzer runs before
        # the delete-family deny walls short-circuit, killing the 92.1% false-block.
        try:
            v = analyze_delete(command, home=self.home, cwd=self.cwd,
                               policy=self.policy, env=self.env)
        except Exception as exc:
            return _block(f"koryto error: {exc!r} - fail-closed", "koryto", stages)
        analyzer_allowed_delete = (v is not None and v.level == "allow")
        # (a) deny-regex policy walls. When the analyzer proved a delete disposable,
        # drop the delete-family policies so they can't re-block it; NON-delete
        # hard classes (GIT_FORCE_PUSH, ENCODED_EXEC, PAYMENTS, ...) still fire even
        # on the same line.
        deny = self._deny_walls(
            command, stages,
            skip=_DELETE_POLICY_NAMES if analyzer_allowed_delete else frozenset(),
        )
        if deny is not None and deny.level == "block":
            return deny  # a non-delete hard-deny class beats everything
        if v is not None:
            stages.append({"stage": "koryto", "sub": "delete-analyzer",
                           "level": v.level, "reason": v.reason})
            if v.level == "block":
                return _block(v.reason, "koryto", stages)
            if v.level == "warn":
                return _warn(v.reason, "koryto", stages)
            # analyzer proved the delete disposable -> allow, unless a deny wall
            # warned (a warn from deny still surfaces).
            if deny is not None and deny.level == "warn":
                return _warn(deny.reason, "koryto", stages)
            return _allow(v.reason, "koryto", stages)
        # analyzer had no opinion (not a delete). Fall back to the deny walls'
        # verdict: a warn-class deny (SYSTEM_TAMPER/PACKAGE_PURGE/SECRET_READ)
        # surfaces; otherwise unknown -> upstream (gate/human) decides.
        if deny is not None:
            return deny
        return ActionVerdict("unknown", "koryto: no deletion semantics, no deny match",
                             "koryto", stages)

    def _deny_walls(self, command: str, stages: list,
                    skip: "frozenset[str]" = frozenset()) -> Optional[ActionVerdict]:
        """Run the DENY policy walls (the full preset set) over the command.
        Returns a block/warn ActionVerdict on the first/strictest match, or None
        if nothing matches. Uses the same regex-wall mechanism as the engine, on
        the same content-stripped action (heredoc/interpreter-source aware).

        ``skip``: policy names to exclude (e.g. the delete-family walls when the
        target-anchored analyzer already proved the delete disposable - F1)."""
        try:
            from gatecat.integrations.policies import DOGFOOD_DEFAULTS
            from gatecat.integrations.guard import _strip_data_heredocs_safe
        except Exception:
            return None
        try:
            scrubbed = _strip_data_heredocs_safe(command)
        except Exception:
            scrubbed = command
        hit_warn: Optional[ActionVerdict] = None
        for pol in DOGFOOD_DEFAULTS:
            if pol.name in skip:
                continue
            for pat in pol.patterns:
                try:
                    if re.search(pat, scrubbed, re.IGNORECASE):
                        lvl = getattr(pol, "level", "block")
                        stages.append({"stage": "koryto", "sub": "deny-wall",
                                       "policy": pol.name, "level": lvl})
                        if lvl == "block":
                            return _block(f"[{pol.name}] {pol.reason}", "koryto", stages)
                        if hit_warn is None:  # remember first warn; block still wins
                            hit_warn = _warn(f"[{pol.name}] {pol.reason}", "koryto", stages)
                        break
                except re.error:
                    continue
        return hit_warn

    # -- [3] gate: does the model agree it's safe? --------------------------

    def _gate_uncertain(self, task: Optional[str], stages: list) -> Optional[bool]:
        """Self-consistency check: re-sample the model N times on the ORIGINAL
        task and measure the spread of its answers.

        Returns:
            True  -> HIGH spread: the model is uncertain about the task itself,
                     so its action is not to be trusted -> escalate to a human.
            False -> LOW spread: the model is confident about what it's doing.
            None  -> gate unavailable (no sample_fn, or no task text, or error).

        This does NOT ask "is this safe" - it detects the MODEL'S OWN uncertainty
        about the task it was given (BGML Study A: spread of N samples predicts
        'the model is guessing')."""
        if self._gate is None or not task:
            return None
        try:
            gv = self._gate.check(task)  # Gate re-samples sample_fn(task) N times
        except Exception as exc:
            stages.append({"stage": "gate", "error": repr(exc)})
            return None
        stages.append({"stage": "gate", **gv.to_dict()})
        return bool(gv.uncertain)  # high disagreement => model doesn't know

    # -- top-level: run the chain -------------------------------------------

    def check(self, command: str, task: Optional[str] = None) -> ActionVerdict:
        """Run a command through all six mechanisms. Returns block/warn/allow.

        ``task`` (optional): the ORIGINAL task the agent was given. Used by the
        gate layer to measure the model's self-consistency (spread of N samples
        on the task). Without it, the gate layer is skipped."""
        stages: list[dict] = []
        if not command or not command.strip():
            return _allow("empty command", "allow-list", stages)

        # [1] ALLOW-LIST: proven-safe verbs pass silently. Only path to allow.
        if all_verbs_safe(command):
            # even a safe-verb line can hide a destructive form (git push --force,
            # docker rm -f) - let koryto have a look; if koryto says block/warn,
            # that wins. If koryto is silent (unknown), the safe verbs stand.
            kv = self._koryto(command)
            if kv.level in ("block", "warn"):
                return kv
            stages.append({"stage": "allow-list", "all_verbs_safe": True})
            return _allow("all command verbs are known-safe", "allow-list", stages)

        # [2] KORYTO: deterministic safety of the target.
        kv = self._koryto(command)
        stages.extend(kv.stages)
        if kv.level == "block":
            self._observe(False, hard=True)
            return _block(kv.reason, "koryto", stages)
        if kv.level == "allow":
            self._observe(True)
            return _allow(kv.reason, "koryto", stages)

        # koryto is uncertain (warn) OR had no opinion (unknown): the action is
        # unrecognized. This is the exact case the model-gate + human exist for.
        # [3] GATE (self-consistency): is the MODEL itself sure about the task?
        uncertain = self._gate_uncertain(task, stages)
        # [4] STAGNATION: has the rule base been refuting without progress? (a
        # stale rule base makes koryto's 'warn' less trustworthy - lean to human)
        self._note_stagnation(stages)
        # A high-spread model (uncertain) is a strong "escalate" signal; a
        # low-spread model does NOT prove safety of an unrecognized action, so
        # either way we fail toward the human, never a silent allow.
        reason = kv.reason if kv.level == "warn" else \
            "unrecognized action - not on the safe allow-list"
        if uncertain:
            reason = f"{reason}; model is uncertain about the task (high answer spread)"
        return self._human_or_warn(command, reason, stages)

    # -- [5]/[6] arbiter + human --------------------------------------------

    def _human_or_warn(self, command: str, reason: str, stages: list) -> ActionVerdict:
        """[6] Human layer. If a human_approve callback is wired, ask it; else
        surface as WARN (never a silent allow)."""
        if self.human_approve is not None:
            try:
                approved = bool(self.human_approve(command))
            except Exception as exc:
                stages.append({"stage": "human", "error": repr(exc)})
                return _block(f"human callback error: {exc!r} - fail-closed", "human", stages)
            stages.append({"stage": "human", "approved": approved})
            if approved:
                return _allow("human approved", "human", stages)
            return _block("human rejected", "human", stages)
        stages.append({"stage": "human", "surfaced": True})
        return _warn(f"unchecked ({reason}) - review before running", "human", stages)

    # -- [4] stagnation feedback --------------------------------------------

    def _note_stagnation(self, stages: list) -> None:
        """[4] Record the stagnation monitor's current view of the rule base. A
        run of refutes without an allow (koryto_suspect) means the rules may be
        over-broad/stale - surfaced for observability and as a lean-to-human
        signal; it does not by itself flip a verdict."""
        if self._monitor is None:
            return
        try:
            st = getattr(self._monitor, "state", None)
            if st is not None:
                stages.append({"stage": "stagnation", **st.to_dict()})
        except Exception:
            pass

    def _observe(self, allowed: bool, hard: bool = False) -> None:
        """Feed the outcome to the stagnation monitor (watches the rule base).
        A streak of blocks without allows means the rules may be over-broad /
        stale - recorded for observability; does not change this verdict."""
        if self._monitor is None:
            return
        try:
            from gatecat.koryto import KorytoVerdict
            kv = KorytoVerdict(
                verdict=("confirm" if allowed else "refute"),
                channel="exec", hard=hard, answer="", truth=None,
            )
            self._monitor.observe(kv)
        except Exception:
            pass
