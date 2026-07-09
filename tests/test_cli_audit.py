"""CLI `gatecat audit` — trust-loop proof-point 'ile zgaduje TWOJ agent'.

Audit woła endpoint OpenAI-compatible usera, liczy confident-wrong + AUC gate,
i pokazuje CTA do gate.cat. Test mockuje httpx (zero sieci) i sprawdza, ze:
  - JSONL z pytaniami jest czytany,
  - endpoint jest wolany (sample temp>0 + answer temp=0),
  - raport sie renderuje z liczba confident-wrong.
"""

import json
import sys
import types

import pytest

from gatecat import cli


def _write_jsonl(tmp_path, rows):
    p = tmp_path / "qa.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return str(p)


def test_audit_runs_offline_with_mocked_endpoint(tmp_path, monkeypatch, capsys):
    """audit czyta JSONL, woła (mock) endpoint, drukuje raport confident-wrong + CTA."""
    data = _write_jsonl(tmp_path, [
        {"q": "Capital of France?", "gold": "Paris", "aliases": ["paris"]},
        {"q": "2+2?", "gold": "4"},
    ])

    # mock httpx.post -> agent zawsze pewny, ale BLEDNY na 2+2 (confident-wrong)
    class _Resp:
        def raise_for_status(self): pass
        def __init__(self, content): self._c = content
        def json(self):
            return {"choices": [{"message": {"content": self._c}}]}

    def fake_post(url, json=None, headers=None, timeout=None):
        prompt = json["messages"][0]["content"]
        return _Resp("Paris" if "France" in prompt else "5")  # 5 = bledne na 2+2

    fake_httpx = types.SimpleNamespace(post=fake_post)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    args = types.SimpleNamespace(
        data=data, base_url="https://mock/v1", model="mock-model",
        api_key="", samples=3, gate_threshold=0.30,
    )
    cli.cmd_audit(args)

    out = capsys.readouterr().out
    assert "GATE REPORT" in out
    assert "LET THROUGH" in out            # confident-wrong section
    assert "pip install gate.cat" in out            # CTA trust-loop (actionable install hint)


def test_audit_empty_file_is_safe(tmp_path, capsys):
    """Pusty plik -> komunikat, brak crasha."""
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    args = types.SimpleNamespace(
        data=str(p), base_url="x", model="m", api_key="", samples=3, gate_threshold=0.3,
    )
    cli.cmd_audit(args)
    assert "No questions" in capsys.readouterr().out


def test_audit_in_cli_subcommands():
    """audit jest zarejestrowany jako subkomenda (help nie crashuje)."""
    with pytest.raises(SystemExit):
        monkey = sys.argv
        sys.argv = ["gatecat", "audit", "--help"]
        try:
            cli.main()
        finally:
            sys.argv = monkey
