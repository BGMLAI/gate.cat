"""GATECAT_EXTRA_POLICIES loader: convention + FAIL-CLOSED contract.

Two layers:

  * unit — ``load_extra_policies`` / ``policies_with_extras`` collect Policy
    objects by the ``*_PACK`` / ``POLICIES`` convention and raise
    ``ExtraPolicyError`` on any unimportable module, non-Policy object, or a
    named-but-empty module.
  * end-to-end — the packaged Claude Code hook, run as a real subprocess the
    way Claude Code invokes it, BLOCKS (exit 2) on a danger command matched by
    an operator-supplied pack, ALLOWS its benign twin, would ALLOW the same
    command with NO pack (proving the pack is what blocks it), and fails closed
    (exit 2) when the pack is broken — even in shadow mode.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from gatecat.integrations import (
    DOGFOOD_DEFAULTS,
    ExtraPolicyError,
    load_extra_policies,
    policies_with_extras,
)

PKG_ROOT = Path(__file__).resolve().parents[2]  # dir holding the gatecat/ package
HOOK_MODULE = "gatecat.hooks.claude_code"

_POLICY_IMPORT = "from gatecat.integrations.policies import Policy\n"


# --------------------------------------------------------------------------- #
# fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def make_module(tmp_path, monkeypatch):
    """Write a throwaway importable module onto sys.path; clean it out after.

    Returns a ``make(name, body)`` that materializes ``<name>.py`` (Policy import
    prepended for you) and yields the module name to pass in the env var. Unique
    names + a sys.modules pop keep the import cache clean across tests.
    """
    d = tmp_path / "xp_mods"
    d.mkdir()
    monkeypatch.syspath_prepend(str(d))
    created: list[str] = []

    def make(name: str, body: str, *, with_policy_import: bool = True) -> str:
        src = (_POLICY_IMPORT if with_policy_import else "") + textwrap.dedent(body)
        (d / f"{name}.py").write_text(src)
        created.append(name)
        return name

    yield make

    for name in created:
        sys.modules.pop(name, None)


# --------------------------------------------------------------------------- #
# unit: happy paths + conventions                                             #
# --------------------------------------------------------------------------- #
def test_unset_or_blank_returns_empty():
    assert load_extra_policies({}) == []
    assert load_extra_policies({"GATECAT_EXTRA_POLICIES": ""}) == []
    assert load_extra_policies({"GATECAT_EXTRA_POLICIES": "   ,  , "}) == []


def test_pack_suffix_convention_collects_all(make_module):
    name = make_module(
        "xp_two_packs",
        """
        FINTECH_PACK = [Policy(name="XP_A", patterns=("xp_a",), reason="a - human")]
        OTHER_PACK = [Policy(name="XP_B", patterns=("xp_b",), reason="b - human")]
        """,
    )
    pols = load_extra_policies({"GATECAT_EXTRA_POLICIES": name})
    assert sorted(p.name for p in pols) == ["XP_A", "XP_B"]


def test_explicit_POLICIES_attr(make_module):
    name = make_module(
        "xp_explicit",
        """
        POLICIES = [Policy(name="XP_C", patterns=("xp_c",), reason="c - human")]
        """,
    )
    pols = load_extra_policies({"GATECAT_EXTRA_POLICIES": name})
    assert [p.name for p in pols] == ["XP_C"]


def test_bare_single_policy_under_pack_is_tolerated(make_module):
    name = make_module(
        "xp_bare",
        """
        SOLO_PACK = Policy(name="XP_I", patterns=("xp_i",), reason="i - human")
        """,
    )
    pols = load_extra_policies({"GATECAT_EXTRA_POLICIES": name})
    assert [p.name for p in pols] == ["XP_I"]


def test_dedup_when_aggregate_reuses_same_objects(make_module):
    # POLICIES and FOO_PACK reference the SAME Policy instances -> loaded once.
    # (Mirrors gatecat_packs exposing individual *_PACK plus an aggregate.)
    name = make_module(
        "xp_dedup",
        """
        FOO_PACK = [Policy(name="XP_D", patterns=("xp_d",), reason="d - human")]
        POLICIES = list(FOO_PACK)  # same objects, different container
        """,
    )
    pols = load_extra_policies({"GATECAT_EXTRA_POLICIES": name})
    assert [p.name for p in pols] == ["XP_D"]


def test_multiple_comma_separated_modules(make_module):
    a = make_module("xp_m1", 'A_PACK = [Policy(name="XP_E", patterns=("xp_e",), reason="e - human")]')
    b = make_module("xp_m2", 'B_PACK = [Policy(name="XP_F", patterns=("xp_f",), reason="f - human")]')
    pols = load_extra_policies({"GATECAT_EXTRA_POLICIES": f" {a} , {b} "})  # whitespace tolerated
    assert sorted(p.name for p in pols) == ["XP_E", "XP_F"]


def test_policies_with_extras_appends_after_base(make_module):
    name = make_module("xp_compose", 'X_PACK = [Policy(name="XP_H", patterns=("xp_h",), reason="h - human")]')
    combined = policies_with_extras(env={"GATECAT_EXTRA_POLICIES": name})
    assert len(combined) == len(DOGFOOD_DEFAULTS) + 1
    assert combined[: len(DOGFOOD_DEFAULTS)] == tuple(DOGFOOD_DEFAULTS)  # base untouched, in order
    assert combined[-1].name == "XP_H"


def test_policies_with_extras_no_env_is_just_base():
    assert policies_with_extras(env={}) == tuple(DOGFOOD_DEFAULTS)


# --------------------------------------------------------------------------- #
# unit: FAIL-CLOSED — every misconfiguration must raise, never silently skip   #
# --------------------------------------------------------------------------- #
def test_fail_closed_unimportable_module():
    with pytest.raises(ExtraPolicyError) as ei:
        load_extra_policies({"GATECAT_EXTRA_POLICIES": "definitely.not.a.module.xyz"})
    assert "cannot import" in str(ei.value)


def test_fail_closed_import_time_crash(make_module):
    name = make_module("xp_boom", 'raise RuntimeError("kaboom at import time")', with_policy_import=False)
    with pytest.raises(ExtraPolicyError):
        load_extra_policies({"GATECAT_EXTRA_POLICIES": name})


def test_fail_closed_non_policy_in_list(make_module):
    name = make_module(
        "xp_badobj",
        """
        BAD_PACK = [
            Policy(name="XP_G", patterns=("xp_g",), reason="g - human"),
            "not a policy",
        ]
        """,
    )
    with pytest.raises(ExtraPolicyError) as ei:
        load_extra_policies({"GATECAT_EXTRA_POLICIES": name})
    assert "not a" in str(ei.value).lower()


def test_fail_closed_pack_attr_not_a_list(make_module):
    name = make_module("xp_notlist", 'MISC_PACK = "i am a string, not a list of Policy"', with_policy_import=False)
    with pytest.raises(ExtraPolicyError):
        load_extra_policies({"GATECAT_EXTRA_POLICIES": name})


def test_fail_closed_module_exports_no_policies(make_module):
    name = make_module("xp_empty", "SOMETHING_ELSE = 1  # no *_PACK, no POLICIES", with_policy_import=False)
    with pytest.raises(ExtraPolicyError) as ei:
        load_extra_policies({"GATECAT_EXTRA_POLICIES": name})
    assert "no" in str(ei.value).lower() and "policies" in str(ei.value).lower()


def test_fail_closed_one_bad_module_fails_the_whole_load(make_module):
    good = make_module("xp_ok", 'OK_PACK = [Policy(name="XP_J", patterns=("xp_j",), reason="j - human")]')
    with pytest.raises(ExtraPolicyError):
        load_extra_policies({"GATECAT_EXTRA_POLICIES": f"{good},definitely.not.a.module.xyz"})


# --------------------------------------------------------------------------- #
# end-to-end: the packaged hook actually enforces an operator pack             #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def hook_env_with_pack(tmp_path):
    """A subprocess env exposing a tiny fintech-style pack module ``xp_fin`` and
    a fresh audit log. Returns (env, module_name). The env DOES NOT yet set
    GATECAT_EXTRA_POLICIES — each test opts in, so the no-pack control is honest.
    """
    d = tmp_path / "hookpack"
    d.mkdir()
    (d / "xp_fin.py").write_text(
        _POLICY_IMPORT
        + textwrap.dedent(
            """
            # One block rule with a distinctive literal so no core policy can
            # match it — proving the block comes from THIS pack, not a built-in.
            FINTECH_PACK = [
                Policy(
                    name="XP_REFUND",
                    patterns=("stripe refunds create",),
                    reason="issuing a refund moves money irreversibly - requires a human",
                    level="block",
                ),
            ]
            """
        )
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in [str(d), str(PKG_ROOT), env.get("PYTHONPATH", "")] if p
    )
    env["GATECAT_VETO_LOG"] = str(tmp_path / "veto_log.jsonl")
    env.pop("GATECAT_EXTRA_POLICIES", None)
    env.pop("GATECAT_VETO_SHADOW", None)
    return env, "xp_fin"


def _run_hook(event, env, *, timeout=30, input_override=None):
    stdin = input_override if input_override is not None else json.dumps(event)
    proc = subprocess.run(
        [sys.executable, "-m", HOOK_MODULE],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    return proc.returncode, proc.stderr


_REFUND = {"tool_name": "Bash", "tool_input": {"command": "stripe refunds create --charge ch_1"}}
_BENIGN = {"tool_name": "Bash", "tool_input": {"command": "stripe refunds list --limit 5"}}


def test_hook_blocks_danger_via_extra_pack(hook_env_with_pack):
    env, mod = hook_env_with_pack
    env["GATECAT_EXTRA_POLICIES"] = mod
    code, err = _run_hook(_REFUND, env)
    assert code == 2, err
    assert "VETO" in err


def test_hook_allows_benign_twin_with_pack(hook_env_with_pack):
    env, mod = hook_env_with_pack
    env["GATECAT_EXTRA_POLICIES"] = mod
    code, err = _run_hook(_BENIGN, env)
    assert code == 0, err


def test_hook_without_pack_allows_the_same_danger(hook_env_with_pack):
    # Control: the built-ins do NOT cover payment refunds, so the SAME command
    # is allowed with no pack. This is the whole reason the loader exists — the
    # pack is useless in the hook without GATECAT_EXTRA_POLICIES.
    env, _mod = hook_env_with_pack  # GATECAT_EXTRA_POLICIES intentionally unset
    code, err = _run_hook(_REFUND, env)
    assert code == 0, err


def test_hook_fail_closed_on_broken_pack(hook_env_with_pack):
    env, _mod = hook_env_with_pack
    env["GATECAT_EXTRA_POLICIES"] = "definitely.not.a.module.xyz"
    code, err = _run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}}, env)
    assert code == 2, err
    assert "EXTRA_POLICIES" in err


def test_hook_fail_closed_blocks_even_in_shadow_mode(hook_env_with_pack):
    # A broken policy config is a config fault, not an action decision, so it
    # blocks even with shadow mode on (same class as ENGINE_UNAVAILABLE).
    env, _mod = hook_env_with_pack
    env["GATECAT_EXTRA_POLICIES"] = "definitely.not.a.module.xyz"
    env["GATECAT_VETO_SHADOW"] = "1"
    code, err = _run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}}, env)
    assert code == 2, err
    assert "EXTRA_POLICIES" in err
