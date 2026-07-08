"""Tests for the target-anchored delete analyzer (gatecat.integrations.
action_analysis) - the Phase-1 replacement for the RM_RF regex.

Grounded in the dogfood study (14,717 real agent commands, 2026-07-04):
- 26 red-team bypasses that defeated the naive shlex design MUST NOT silently
  ALLOW (block or warn is acceptable; a silent allow is a security failure).
- 19 real-danger commands (paid infra, home/backup, prod DB) MUST block/warn.
- Representative false-blocks (build/temp/cache) MUST allow.
- D-narrow: with a real env, $VAR targets resolve by value.
- WARN: remote/opaque targets are surfaced, not hard-blocked.
"""
from __future__ import annotations

import pytest

from gatecat.integrations.action_analysis import (
    DeletePolicy,
    analyze_delete,
)

HOME = "/c/Users/bogum"
CWD = "/d/programistyczne/zeszyty-terapeutyczne"
POLICY = DeletePolicy(protected_assets=(
    "vastai destroy", "vastai stop", "laptop-backup", "bogum-backup",
    "personal-cloud", "204.168.129.200", "192.168.18.221",
))


def _level(cmd: str, *, env: dict | None = None, cwd: str = CWD) -> str:
    v = analyze_delete(cmd, home=HOME, cwd=cwd, policy=POLICY, env=env)
    return "none" if v is None else v.level


# --- 26 red-team bypasses: must NOT silently allow -------------------------
REDTEAM = [
    "sudo rm -rf /root/laptop-backup",
    "/bin/rm -rf ~/zeszyty-terapeutyczne",
    "echo ~/laptop-backup/C | xargs rm -rf",
    "FOO=1 rm -rf /root/cache_prod",
    "printf 'rm -rf ~/laptop-backup\\n' | bash",
    "bash <<EOF\nrm -rf ~/laptop-backup\nEOF",
    'powershell -c "Remove-Item -Recurse -Force $HOME\\laptop-backup"',
    # long-form -Command and cmd /c wrap the delete past the analyzer (round-3)
    'powershell -NoProfile -Command "Remove-Item -Recurse -Force /root/cache_prod"',
    'cmd /c "del /f /s /root/cache_prod"',
    "rm -rf /root/prod.new",
    "cd ~/ && rm -rf zeszyty-terapeutyczne",
    'rm -rf "$H"',
    "bash -c 'ssh prod \"rm -rf ~/zeszyty-terapeutyczne\"'",
    "find /root/cache_prod -delete",
    "rm -rf dist/prod-data",
    "find ~/zeszyty-terapeutyczne -delete",
    "rm -r ~/laptop-backup",
    "rm -rf ~/keep\nrm -rf /root/backup",
    "rm -rf {./dist,/root/cache_prod}",
    "cd /root/cache_prod && rm -rf .",
    "rm -rf /roo?/cache_prod",
    "printf 'rm -rf /root' | bash",
    "rm -rf ./dist/../../../root/.ssh",
    "rm -rf -- /root/cache_prod",
    "rm -rf $BUILD_DIR",
    "shred -u ~/laptop-backup",
    "truncate -s0 /root/prod.db",
    "git clean -fdx",
]


@pytest.mark.parametrize("cmd", REDTEAM)
def test_redteam_bypass_never_silently_allowed(cmd):
    """A known-dangerous bypass must block or warn - never a silent allow."""
    assert _level(cmd) in ("block", "warn"), f"SILENT ALLOW on bypass: {cmd!r}"


# --- 19 real-danger (regression suite): must block or warn -----------------
REAL_DANGER = [
    'ssh bgml@192.168.18.221 "rm -rf ~/zeszyty-terapeutyczne"',
    "vastai destroy 41674186",
    "vastai destroy 41695540",
    "rm -rf ~/laptop-backup/C",
    'ssh -i ~/.ssh/id_ed25519 bgml@192.168.18.21 "rm -rf ~/laptop-backup/C"',
    "rm -rf /opt/migrated-from-204",
    "rm -rf /root/cache_prod",
]


@pytest.mark.parametrize("cmd", REAL_DANGER)
def test_real_danger_blocks_or_warns(cmd):
    assert _level(cmd) in ("block", "warn"), f"real danger not caught: {cmd!r}"


# --- representative false-blocks: must ALLOW -------------------------------
BENIGN_DELETE = [
    "rm -rf dist.new && mkdir dist.new",
    "rm -rf dist",
    "rm -rf node_modules",
    "rm -rf functions.new",
    "rm -rf dist.broken",
    "rm -rf dist2",
    "rm -rf /tmp/zeszyty-dist.tar.gz",
    "rm -rf .pnpm-store",
    "rm -rf deploy-e0-staging && mkdir -p deploy-e0-staging",
    "rm -rf /d/tmp/gcverify",
    "rm -f ads_full.json",
    "rm -rf __pycache__",
]


@pytest.mark.parametrize("cmd", BENIGN_DELETE)
def test_benign_delete_allows(cmd):
    assert _level(cmd) == "allow" if "rm -rf" in cmd else _level(cmd) in ("allow", "none"), \
        f"false block on benign: {cmd!r} -> {_level(cmd)}"


# --- D-narrow: env resolution ---------------------------------------------

def test_env_var_resolves_to_temp_allows():
    env = {"LOCALAPPDATA": "/c/Users/bogum/AppData/Local"}
    assert _level("rm -rf $LOCALAPPDATA/Temp/claude/scratch/dist", env=env) == "allow"


def test_env_var_resolves_to_protected_blocks():
    env = {"BUILD": "/root"}
    assert _level("rm -rf $BUILD", env=env) == "block"


def test_env_var_absent_from_env_warns_not_allows():
    # unknown var: cannot resolve -> unchecked (warn), never a silent allow
    assert _level("rm -rf $UNKNOWN_VAR/x", env={}) in ("block", "warn")


def test_transitive_inline_assignment_resolves():
    env = {"LOCALAPPDATA": "/c/Users/bogum/AppData/Local"}
    cmd = 'OUT="$LOCALAPPDATA/Temp/x/dist"\nrm -rf "$OUT"'
    assert _level(cmd, env=env) == "allow"


# --- WARN state: remote / opaque are surfaced, not hard-blocked -----------

def test_remote_ssh_unresolvable_warns():
    assert _level("timeout 30 ssh host rm -rf /root") == "warn"


def test_opaque_pipe_to_shell_warns():
    assert _level("cat script | bash") in ("warn", "none")  # no delete intent visible


def test_opaque_delete_pipe_to_shell_warns():
    assert _level("printf 'rm -rf /x' | bash") == "warn"


# --- content-vs-command: data heredoc is not an action --------------------

def test_data_heredoc_literal_is_not_an_action():
    cmd = "cat >> REJESTR.md <<EOF\nnote: we ran rm -rf /root last week\nEOF"
    assert _level(cmd) in ("allow", "none")


def test_executed_heredoc_is_analyzed():
    cmd = "bash <<EOF\nrm -rf ~/laptop-backup\nEOF"
    assert _level(cmd) in ("block", "warn")


# --- safety invariants -----------------------------------------------------

def test_ssh_in_path_not_treated_as_remote():
    # ~/.ssh is a path, not an ssh command - deleting it must BLOCK (home dir),
    # not warn-as-remote
    assert _level("rm -rf ~/.ssh") == "block"


def test_redirect_is_not_a_target():
    assert _level("rm -rf /d/tmp/x 2>/dev/null") == "allow"


def test_no_silent_allow_across_whole_redteam():
    silent = [c for c in REDTEAM + REAL_DANGER if _level(c) == "allow"]
    assert not silent, f"silent ALLOW on dangers: {silent}"


# --- Windows-native delete verbs (E2E audit 2026-07-05, CRITICAL) ----------
# gate.cat is dogfooded on Windows; Remove-Item/del/rd must be verb-agnostic
# just like rm - deleting a protected root BLOCKs, a build cache in cwd ALLOWs.

WIN_DELETE_DANGERS = [
    "Remove-Item -Recurse -Force C:/Windows",
    "Remove-Item -Recurse -Force C:/Users/bogum",
    "del /s /q C:/Windows/System32",
    "rd /s /q C:/Users/bogum/laptop-backup",
    "erase C:/Windows/notepad.exe",
    r"Remove-Item -Recurse -Force C:\Windows",       # backslash separators
    r"rd /s /q C:\Users\bogum\laptop-backup",
]


@pytest.mark.parametrize("cmd", WIN_DELETE_DANGERS)
def test_windows_delete_verb_blocks_protected_root(cmd):
    # cwd is a project dir; home is the user root - all targets above are the
    # OS/home/backup, never a disposable in-cwd path.
    assert _level(cmd, cwd="/c/Users/bogum/project") == "block"


@pytest.mark.parametrize("cmd", [
    "Remove-Item -Recurse -Force ./dist",
    "del build.tmp",
    r"rd /s /q .\node_modules",           # backslash relative disposable
    r"Remove-Item -Recurse -Force .\dist",
])
def test_windows_delete_verb_allows_disposable_in_cwd(cmd):
    assert _level(cmd, cwd="/c/Users/bogum/project") == "allow"


def test_windows_and_posix_agree_on_same_target():
    # verb-agnostic promise: rm and Remove-Item reach the same verdict.
    for posix, win in [
        ("rm -rf /c/Windows", "Remove-Item -Recurse -Force C:/Windows"),
        ("rm -rf node_modules", "Remove-Item -Recurse -Force node_modules"),
    ]:
        assert _level(posix, cwd="/c/Users/bogum/project") == \
               _level(win, cwd="/c/Users/bogum/project")


# --- O(n^2) DoS / fail-open guard (E2E audit 2026-07-05, HIGH) --------------

def test_giant_padded_delete_is_fast_and_fails_closed():
    import time
    # a multi-MB trailing comment used to hang the tokenizer ~400s; now the
    # comment is stripped before tokenization, so this is instant and still
    # BLOCKs the real rm -rf ~.
    cmd = "rm -rf ~ #" + "A" * 3_000_000
    t = time.time()
    lvl = _level(cmd)
    assert time.time() - t < 2.0, "analyze_delete must not be superlinear"
    assert lvl == "block"


def test_comment_does_not_hide_or_invent_a_command():
    # a danger only in a comment is not an action; a real rm with a trailing
    # comment is still analyzed.
    assert _level("ls # rm -rf / in a comment") == "none"
    assert _level("rm -rf ./dist  # build output") == "allow"


# --- non-shell interpreter source is not shell (large-corpus fixes 2026-07-05)
# Found on nvidia/Nemotron-RL-Agentic-SWE-Pivot-v1 (3720 real agent commands):
# Python/Ruby/... source inside `python -c`/`python<<EOF` was misread as shell.

def test_python_heredoc_del_is_not_shell_delete():
    # `del sys.modules[m]` is a Python statement, NOT a Windows `del` verb.
    cmd = ("cd /w && python3 << 'EOF'\nimport sys\n"
           "for m in list(sys.modules): del sys.modules[m]\nEOF")
    assert _level(cmd, cwd="/w") in ("none", "allow")


def test_python_dashc_pandas_truncate_is_not_shell_truncate():
    # `df.truncate(...)` is a pandas method; multiline quotes must not break
    # parsing into a fail-closed warn either.
    cmd = ('python -c "\nimport pandas as pd\nprint(\'=\'*60)\n'
           'df.truncate(before=\'2020-01-07\')\n"')
    assert _level(cmd) in ("none", "allow")


def test_python_dashc_del_is_not_shell_delete():
    assert _level('python -c "d={}; del d[1]"') in ("none", "allow")


def test_real_shell_truncate_still_blocks():
    # the fix must not blind the analyzer to a genuine shell `truncate`.
    assert _level("truncate -s 0 /root/important.log") == "block"


def test_shell_dashc_delete_still_blocks():
    # bash -c "<rm>" is shell and must still fail-closed.
    assert _level('bash -c "rm -rf /root/backup"') == "block"


def test_bash_heredoc_rm_still_blocks():
    # a SHELL heredoc body is real commands - a delete in it still blocks.
    assert _level("bash << 'EOF'\nrm -rf ~/laptop-backup\nEOF") == "block"


# --- 0.2.1 security-hardening regressions (council 2026-07-06) --------------

def test_B2_sibling_data_heredoc_does_not_downgrade_protected_delete():
    # A benign data heredoc in a SIBLING segment must not weaken a resolvable
    # protected-root delete. Was: any _OPAQUE_LINE token short-circuited the
    # whole line to WARN, so `rm -rf ~ ; cat <<EOF` downgraded rm -rf ~ to
    # allow. Now the segment analyzer's hard block wins.
    assert _level("rm -rf ~/laptop-backup ; cat <<EOF\nsome data\nEOF") == "block"
    assert _level("rm -rf /root/laptop-backup ; echo done | tee log.txt") == "block"


def test_B2_genuinely_opaque_delete_still_warns_not_allows():
    # when the delete target really IS hidden behind a pipe-to-shell (no
    # resolvable deleting segment), we must still surface it (warn), never allow.
    assert _level("printf 'rm -rf /root/laptop-backup' | bash") in ("warn", "block")


def test_B1_oversized_unterminated_heredoc_with_delete_fails_closed_fast():
    # ReDoS guard: a large unterminated heredoc used to make the heredoc-strip
    # regex backtrack ~30-100s (hook killed -> fail-OPEN). Must now fail CLOSED
    # (block) and return quickly.
    import time
    big = "rm -rf ~/laptop-backup ; cat <<EOF\n" + ("A" * 50000)
    t0 = time.time()
    v = analyze_delete(big, home=HOME, cwd=CWD, policy=POLICY)
    assert time.time() - t0 < 3.0, "heredoc analysis is not bounded (ReDoS)"
    assert v is not None and v.blocked


def test_B1_oversized_benign_heredoc_defers_fast():
    # the same size bound, no delete intent -> defer to the other walls (None),
    # still fast. A huge benign document write is not this analyzer's problem.
    import time
    big = "echo hello ; cat <<EOF\n" + ("A" * 50000)
    t0 = time.time()
    v = analyze_delete(big, home=HOME, cwd=CWD, policy=POLICY)
    assert time.time() - t0 < 3.0
    assert v is None or not v.blocked


# --- F1 (council 2026-07-06): _koryto runs the analyzer BEFORE the delete-family
# deny walls, so an analyzer-allowed disposable delete is not re-blocked by the
# RM_RF regex (the 92.1% false-block). Non-delete hard classes still fire.

def test_F1_disposable_rm_rf_not_reblocked_by_regex():
    from gatecat.action_pipeline import ActionPipeline
    from gatecat.integrations.action_analysis import DeletePolicy
    pipe = ActionPipeline(policy=DeletePolicy(), home="/home/u", cwd="/home/u/proj")
    # a regenerable build dir under cwd: analyzer proves disposable -> allow,
    # NOT a hard RM_RF regex block.
    v = pipe._koryto("rm -rf dist.new")
    assert v.level in ("allow", "unknown", "warn"), f"over-blocked: {v.level}"


def test_F1_protected_root_delete_still_blocks():
    from gatecat.action_pipeline import ActionPipeline
    from gatecat.integrations.action_analysis import DeletePolicy
    pipe = ActionPipeline(policy=DeletePolicy(), home="/home/u", cwd="/home/u/proj")
    v = pipe._koryto("rm -rf ~/..")
    assert v.level == "block"


def test_F1_nondelete_hard_class_still_fires_on_analyzer_allowed_line():
    # a non-delete hard deny (git push --force) on the same line as an analyzer-
    # allowed disposable delete must STILL block (skip only the delete-family walls).
    from gatecat.action_pipeline import ActionPipeline
    from gatecat.integrations.action_analysis import DeletePolicy
    pipe = ActionPipeline(policy=DeletePolicy(), home="/home/u", cwd="/home/u/proj")
    v = pipe._koryto("rm -rf dist.new && git push --force origin main")
    assert v.level == "block"


@pytest.mark.parametrize("cmd,home,cwd", [
    ("rm -rf ~/tmp/important-notes", "/home/alice", "/home/alice/proj"),
    ("rm -rf /root/tmp/prod-secrets", "/root", "/root/proj"),
    ("shred -u ~/temp/id_backup", "/home/alice", "/home/alice/proj"),
    ("rm -rf ~/scratchpad/thesis", "/home/alice", "/home/alice/proj"),
    ("rm -rf ~/.tmp/wallet.dat", "/home/alice", "/home/alice/proj"),
    ("rm -rf /home/alice/Documents/temp/tax-2025", "/home/alice", "/home/alice/proj"),
])
def test_temp_component_under_protected_root_blocks(cmd, home, cwd):
    # re-review under-block fix (pre-existing, commit 9b482ae): a bare tmp/temp/
    # scratch path COMPONENT used to override the protected-root block, so a
    # recursive delete of real work under ~/tmp, /root/tmp, or .../Documents/temp
    # was silently ALLOWed. A temp component now only allows a RECOGNISED system
    # temp dir (AppData/Local/Temp) or an in-tree (under cwd) scratch subtree.
    from gatecat.integrations.action_analysis import analyze_delete, DeletePolicy
    v = analyze_delete(cmd, home=home, cwd=cwd, policy=DeletePolicy())
    assert v is not None and v.blocked, f"under-block: {cmd!r} -> {v}"


@pytest.mark.parametrize("cmd,home", [
    ("rm -rf ~/.cache", "/home/alice"),       # XDG cache: HF tokens/gated weights
    ("rm -rf ~/.gradle", "/home/alice"),      # gradle.properties credentials
    ("rm -rf /root/.cache", "/root"),
])
def test_convention_cache_names_under_home_block(cmd, home):
    # re-review under-block fix: `.cache`/`.gradle` are CONVENTION names whose
    # contents are arbitrary (secrets, gated weights), not tool-owned regenerable
    # dirs - so they must NOT be allowed anywhere. Out-of-tree/home deletion now
    # falls through to the protected-root block.
    from gatecat.integrations.action_analysis import analyze_delete, DeletePolicy
    v = analyze_delete(cmd, home=home, cwd=f"{home}/proj", policy=DeletePolicy())
    assert v is not None and v.blocked, f"under-block: {cmd!r} -> {v}"


@pytest.mark.parametrize("cmd", [
    "rm -rf .cache",                       # in-tree still allowed (regenerable_names)
    "rm -rf .gradle",
    "rm -rf /home/alice/proj/.cache",
])
def test_intree_cache_still_allowed(cmd):
    from gatecat.integrations.action_analysis import analyze_delete, DeletePolicy
    v = analyze_delete(cmd, home="/home/alice", cwd="/home/alice/proj", policy=DeletePolicy())
    assert v is not None and v.level == "allow", f"over-block in-tree: {cmd!r} -> {v}"


# --- re-review (final round): 3 fatal fail-open blockers ---------------------

@pytest.mark.parametrize("cmd", [
    "rm -rf $(echo x) && dd if=/dev/zero of=/dev/sda",   # opaque delete + disk wipe
    "rm -rf $(x) ; mkfs.ext4 /dev/sdb",
    "rm -rf $(x) ; wipefs -a /dev/sdb",
    "rm -rf $(x) && vastai destroy 999",
    "rm -rf $(x) && rm -rf /home/user/laptop-backup",
])
def test_opaque_sibling_does_not_downgrade_later_hard_block(cmd):
    # UNDER-BLOCK: an opaque delete segment used to early-return WARN, skipping
    # the rest of the line (and guard.check_action then skipped the deny-walls),
    # so a hard-block destruction in a LATER segment ran. The analyzer now keeps
    # scanning past an opaque delete, and check_action runs the walls on a WARN.
    from gatecat.integrations.guard import check_action
    from gatecat.integrations.policies import DOGFOOD_DEFAULTS
    from gatecat.integrations._engine import ActionVetoed
    try:
        d = check_action("agent", cmd, policies=DOGFOOD_DEFAULTS,
                         home="/home/user", cwd="/home/user/repo", env={})
        assert getattr(d, "blocked", False), f"downgraded to allow/warn: {cmd!r} -> {d}"
    except ActionVetoed:
        pass  # block via raise is the expected outcome


@pytest.mark.parametrize("cmd", [
    # Codex round-4: caught by the deny-walls via check_action (not analyze_delete)
    "python3 <<'PY'\nimport subprocess\nsubprocess.run(['rm','-rf','/root/cache_prod'])\nPY",
    "python3 <<'PY'\nimport os\nos.system('rm -rf /root/cache_prod')\nPY",
    "docker compose down -v",              # warn-tier volume loss
    # hybrid backstop: novel destructive verb no wall knows -> human, not allow
    "ceph osd purge 3 --yes-i-really-mean-it",
    "storagectl wipe volume-9",
])
def test_codex_round4_egress_reaches_human(cmd):
    from gatecat.integrations.guard import check_action
    from gatecat.integrations.policies import DOGFOOD_DEFAULTS
    from gatecat.integrations._engine import ActionVetoed
    try:
        d = check_action("agent", cmd, policies=DOGFOOD_DEFAULTS,
                         home="/root", cwd="/root", env={})
        assert d.level in ("block", "warn"), f"silently allowed: {cmd!r} -> {d.level}"
    except ActionVetoed:
        pass  # block via raise is fine


@pytest.mark.parametrize("cmd,home", [
    ("kubectl exec pod -- rm -rf ~", "/home/user"),
    ("kubectl exec pod -- rm -rf /home/user/data", "/home/user"),
    ("docker exec c rm -rf /root", "/root"),
    ("docker exec c rm -rf /home/user/backup", "/home/user"),
])
def test_remote_wrapper_prefix_around_local_delete_blocks(cmd, home):
    # UNDER-BLOCK: a remote-exec wrapper (kubectl/docker) used as a PREFIX around
    # a LOCAL resolvable protected-root delete was waved through as a generic
    # remote-warn (kubectl) / silently allowed. The wrapper is now unwrapped and
    # the inner `rm -rf <protected>` re-analyzed -> block.
    v = analyze_delete(cmd, home=home, cwd=f"{home}/repo", policy=DeletePolicy())
    assert v is not None and v.blocked, f"under-block: {cmd!r} -> {v}"


@pytest.mark.parametrize("cmd,home", [
    ("rm -rf /root/node_modules", "/root"),   # tool-owned: name == content
    ("rm -rf ~/__pycache__", "/home/alice"),
    ("rm -rf ~/.pytest_cache", "/home/alice"),
])
def test_tool_owned_cache_names_still_allowed_anywhere(cmd, home):
    # the 10 tool-owned names (npm/pytest/compiler-reconstructed) stay ALLOW
    # anywhere - narrowing them would be an over-block regression.
    from gatecat.integrations.action_analysis import analyze_delete, DeletePolicy
    v = analyze_delete(cmd, home=home, cwd=f"{home}/proj", policy=DeletePolicy())
    assert v is not None and v.level == "allow", f"over-block: {cmd!r} -> {v}"


@pytest.mark.parametrize("cmd,home", [
    ("rm -rf /root/local/temp/secrets", "/root"),
    ("rm -rf ~/local/temp/wallet", "/home/alice"),
    ("rm -rf /home/alice/mydata/local/temp/x", "/home/alice"),
])
def test_forged_local_temp_chain_blocks(cmd, home):
    # re-review #5: the OS-temp heuristic must require the FULL ordered
    # appdata/local/temp chain. An earlier `"local" in window` form was vacuous
    # (the preceding `local` satisfied it), so any `.../local/temp/...` under a
    # protected root wrongly ALLOWed real data. Only genuine AppData/Local/Temp
    # is the OS temp dir.
    from gatecat.integrations.action_analysis import analyze_delete, DeletePolicy
    v = analyze_delete(cmd, home=home, cwd=f"{home}/proj", policy=DeletePolicy())
    assert v is not None and v.blocked, f"under-block: {cmd!r} -> {v}"


@pytest.mark.parametrize("cmd,home,cwd", [
    ("rm -rf /c/Users/bob/AppData/Local/Temp/build123", "/c/Users/bob", "/c/Users/bob/proj"),
    ("rm -rf /c/Users/bob/AppData/Local/Temp/xyz/deep", "/c/Users/bob", "/c/Users/bob/proj"),
    ("rm -rf /tmp/build-xyz", "/home/alice", "/home/alice/proj"),
    ("rm -rf tmp/cache", "/home/alice", "/home/alice/proj"),
    ("rm -rf /home/alice/proj/tmp/x", "/home/alice", "/home/alice/proj"),
])
def test_legit_temp_still_allowed(cmd, home, cwd):
    # the fix must NOT over-block genuine disposable temp: the OS temp dir and an
    # in-tree tmp/scratch subtree stay ALLOW.
    from gatecat.integrations.action_analysis import analyze_delete, DeletePolicy
    v = analyze_delete(cmd, home=home, cwd=cwd, policy=DeletePolicy())
    assert v is not None and v.level == "allow", f"over-block on legit temp: {cmd!r} -> {v}"


def test_F1_cloud_destroy_still_blocks_after_analyzer_allowed_rm():
    # re-review regression fix: CLOUD_DESTROY must NOT be skipped when the analyzer
    # allows a sibling disposable rm - the analyzer never ALLOWs cloud-destroy, so
    # skipping it let `rm -rf dist.new && vastai destroy 999` pass as ALLOW
    # (fail-OPEN on paid infra). Only RM_RF is analyzer-owned.
    from gatecat.action_pipeline import ActionPipeline
    from gatecat.integrations.action_analysis import DeletePolicy
    pipe = ActionPipeline(policy=DeletePolicy(protected_assets=("vastai destroy",)),
                          home="/home/u", cwd="/home/u/proj")
    assert pipe._koryto("rm -rf dist.new && vastai destroy 999").level == "block"
    assert pipe._koryto(
        "rm -rf build && aws ec2 terminate-instances --instance-ids i-1").level == "block"
