"""SCAFFOLD_OVERWRITE — the create-vite-family / degit overwrite class (#80730).

A scaffolder run against an EXISTING NON-EMPTY directory can irreversibly
overwrite it (the claude-code #80730 incident: `npm create vite` inside a
populated project deleted a week of uncommitted work). gate.cat surfaces this as
a WARN — log+allow, never a hard block — because the danger predicate is not
objective enough to veto without false-blocking benign scaffolds (create-vite
deletes on confirm, but create-react-app aborts, and additive initializers run in
populated dirs on purpose). WARN preserves the F1a 0/13 false-block headline
exactly: a warn is neither a block nor a recall miss.

These pin the full danger/benign twin matrix from the design panel, with REAL
filesystem fixtures (this is the first analyzer that reads the live FS, so the
verdict depends on command + cwd + fs-state). The danger twins WARN; every benign
twin stays ALLOW; a chained hard-block still wins; and the class never raises.
"""
from __future__ import annotations

import os

import pytest

from gatecat import check_action

try:
    from gatecat import ActionVetoed
except Exception:  # pragma: no cover
    from gatecat.engine import ActionVetoed


def _verdict(cmd: str, *, cwd: str, env: dict | None = None) -> str:
    """('block' | 'warn' | 'allow') for a command evaluated against a real cwd."""
    try:
        d = check_action("agent", cmd, cwd=cwd, env=env)
    except ActionVetoed:
        return "block"
    if getattr(d, "blocked", False):
        return "block"
    return "warn" if getattr(d, "level", "") == "warn" else "allow"


@pytest.fixture()
def dirs(tmp_path):
    """A set of fixture dirs covering every emptiness state the analyzer keys on."""
    populated = tmp_path / "proj"
    (populated / "src").mkdir(parents=True)
    (populated / "README.md").write_text("x")
    (populated / "index.js").write_text("x")

    readme_only = tmp_path / "readme_only"
    readme_only.mkdir()
    (readme_only / "README.md").write_text("x")   # NOT ignored: the at-risk content

    empty = tmp_path / "empty"
    empty.mkdir()

    git_only = tmp_path / "git_only"
    (git_only / ".git").mkdir(parents=True)
    (git_only / ".gitignore").write_text("node_modules\n")

    # a populated root that also contains a populated ./pluto subdir
    root = tmp_path / "root"
    (root / "pluto").mkdir(parents=True)
    (root / "pluto" / "keep.txt").write_text("x")
    (root / "rootfile").write_text("x")

    return {
        "populated": str(populated), "readme_only": str(readme_only),
        "empty": str(empty), "git_only": str(git_only), "root": str(root),
    }


# --- DANGER: scaffolder into an existing non-empty dir MUST warn ----------------

def test_the_exact_80730_command_warns(dirs):
    # ./pluto exists and is populated — the exact incident shape.
    assert _verdict("npm create vite@latest pluto -- --template react --typescript",
                    cwd=dirs["root"]) == "warn"


@pytest.mark.parametrize("cmd", [
    "npm create vite@latest .",                       # explicit cwd, populated
    "npm create vite@latest",                         # no-arg target defaults to cwd
    "npm create vite@latest -- --template react",     # no-arg with passthrough flags
    "pnpm create vite .",
    "yarn create vite .",
    "bun create vite .",
    "npx create-vite .",
    "bunx create-vite .",
    "npm init vite@latest .",                         # npm create/init alias
    "npx degit user/repo",                            # degit no-dest -> cwd
])
def test_scaffold_into_populated_cwd_warns(dirs, cmd):
    assert _verdict(cmd, cwd=dirs["populated"]) == "warn"


def test_target_subdir_populated_warns(dirs):
    assert _verdict("pnpm create vite pluto", cwd=dirs["root"]) == "warn"
    assert _verdict("degit user/repo pluto --force", cwd=dirs["root"]) == "warn"


def test_cd_tracking_resolves_target_after_cd(dirs):
    # cd into the populated subdir first, then scaffold into "." there.
    assert _verdict("cd pluto && npm create vite@latest .", cwd=dirs["root"]) == "warn"


def test_readme_only_dir_is_populated(dirs):
    # create-vite's emptyDir() deletes a lone README.md on confirm -> at risk.
    assert _verdict("npm create vite@latest .", cwd=dirs["readme_only"]) == "warn"


def test_unresolvable_target_warns(dirs):
    # $VAR absent from env -> unprovable target -> advisory warn.
    assert _verdict("npm create vite@latest $TARGET", cwd=dirs["populated"], env={}) == "warn"


# --- BENIGN twins: every one MUST stay allow (protects F1a 0/13) ----------------

@pytest.mark.parametrize("cmd,where", [
    ("npm create vite@latest newapp -- --template react", "populated"),  # target absent
    ("npm create vite@latest packages/new-widget", "populated"),         # subdir absent
    ("npm create vite@latest .", "empty"),                               # empty cwd
    ("npm create vite@latest .", "git_only"),                           # only .git/.gitignore
    ("npx degit user/repo newfolder", "populated"),                     # dest absent
    ("npm create vite@latest --help", "populated"),                    # no-op flag
    ("npm create vite@latest --version", "populated"),
    ("npx degit user/repo . --dry-run", "populated"),                  # dry-run writes nothing
])
def test_benign_scaffold_stays_allow(dirs, cmd, where):
    assert _verdict(cmd, cwd=dirs[where]) == "allow"


@pytest.mark.parametrize("cmd", [
    "npm init",                                     # bare init, no initializer
    "npm init -y",
    "npm init @eslint/config",                      # additive config initializer
    "npm init playwright@latest",                   # additive
    "npx create-storybook",                         # additive tooling
    "npx create-react-app my-app",                  # off v1 list (abort-on-conflict)
    "npx create-react-app .",                       # off v1 list, safe-by-refusal
    "npx create-next-app@latest .",                 # off v1 list
    "npx vite",                                      # DEV SERVER, not a scaffolder
    "vite build",                                    # dev tool, not a scaffolder
    "docker create --name web nginx",               # cloud verb
    "kubectl create -f deploy.yaml",
    "gh pr create --fill",
    "npx nx generate @nrwl/react:app my-app",       # generator, additive
    "git clone https://github.com/user/repo pluto",  # not a scaffolder
    "cargo new pluto",                              # out of JS scope
])
def test_non_scaffold_and_excluded_tools_stay_allow(dirs, cmd):
    # all evaluated against the POPULATED dir — none may warn.
    assert _verdict(cmd, cwd=dirs["populated"]) == "allow"


# --- structural guarantees ------------------------------------------------------

def test_chained_hard_block_still_wins(dirs):
    # the scaffold warn must never mask a real destructive op in a later segment.
    assert _verdict("npm create vite@latest . && rm -rf /", cwd=dirs["populated"]) == "block"


def test_scaffold_class_never_raises(dirs):
    # WARN-only contract: even on the danger shape, check_action returns (never raises).
    d = check_action("agent", "npm create vite@latest .", cwd=dirs["populated"])
    assert d.blocked is False
    assert d.level == "warn"
    assert d.policy == "SCAFFOLD_OVERWRITE"


def test_scaffolder_in_commit_message_does_not_warn(dirs):
    # content-vs-command: a scaffolder quoted inside a git commit message is data.
    assert _verdict('git commit -m "ran npm create vite@latest . by mistake"',
                    cwd=dirs["populated"]) == "allow"


def test_missing_target_dir_permission_degrades_to_allow(tmp_path):
    # an unstattable target (does not exist) -> ALLOW (fresh scaffold), never crash.
    assert _verdict("npm create vite@latest brand-new-dir", cwd=str(tmp_path)) == "allow"
