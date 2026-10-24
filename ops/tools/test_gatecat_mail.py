"""Tests for the outbound mail channel.

The guardrails matter more than the happy path here. This tool lets an agent
send mail as the founder; the tests that count are the ones proving it refuses
to.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gatecat_mail as gm  # noqa: E402


CONFIG = """\
host = "smtp.example.com"
port = 465
username = "me@example.com"
password = "hunter2-app-password"
from_addr = "me@example.com"
from_name = "Me"
allow = ["isotoma.com", "contact@les-tilleuls.coop"]
daily_cap = 3
"""

MAIL = """\
To: hello@isotoma.com
Subject: a subject

A body.
"""


@pytest.fixture
def cfg_file(tmp_path):
    p = tmp_path / "mail.toml"
    p.write_text(CONFIG)
    p.chmod(0o600)
    return p


@pytest.fixture
def cfg(cfg_file):
    return gm.load_config(cfg_file)


# --------------------------------------------------------------------- config


def test_missing_config_explains_how_to_make_one(tmp_path):
    with pytest.raises(gm.MailError) as e:
        gm.load_config(tmp_path / "nope.toml")
    assert "chmod 600" in str(e.value)
    assert "App passwords" in str(e.value)


def test_world_readable_config_is_refused(tmp_path):
    p = tmp_path / "mail.toml"
    p.write_text(CONFIG)
    p.chmod(0o644)
    with pytest.raises(gm.MailError, match="readable beyond your user"):
        gm.load_config(p)


def test_group_readable_config_is_refused(tmp_path):
    p = tmp_path / "mail.toml"
    p.write_text(CONFIG)
    p.chmod(0o640)
    with pytest.raises(gm.MailError, match="readable beyond your user"):
        gm.load_config(p)


def test_empty_allowlist_is_refused(tmp_path):
    p = tmp_path / "mail.toml"
    p.write_text(CONFIG.replace('allow = ["isotoma.com", "contact@les-tilleuls.coop"]', "allow = []"))
    p.chmod(0o600)
    with pytest.raises(gm.MailError, match="Refusing to send"):
        gm.load_config(p)


@pytest.mark.parametrize("field", ["host", "username", "password", "from_addr"])
def test_missing_required_field_is_refused(tmp_path, field):
    body = "\n".join(l for l in CONFIG.splitlines() if not l.startswith(field))
    p = tmp_path / "mail.toml"
    p.write_text(body)
    p.chmod(0o600)
    with pytest.raises(gm.MailError, match=field):
        gm.load_config(p)


def test_password_never_appears_in_repr_or_str(cfg):
    assert "hunter2" not in repr(cfg)
    assert "hunter2" not in str(cfg)


def test_redaction_scrubs_password_from_exceptions(cfg):
    exc = RuntimeError("auth failed for hunter2-app-password")
    assert "hunter2" not in gm._redact(exc, cfg)
    assert "«REDACTED»" in gm._redact(exc, cfg)


# ----------------------------------------------------------------- parsing


def test_parses_headers_and_body():
    m = gm.parse_mail_file(MAIL)
    assert m.to == ["hello@isotoma.com"]
    assert m.subject == "a subject"
    assert m.body.strip() == "A body."
    assert m.cc == []


def test_parses_cc_and_multiple_recipients():
    m = gm.parse_mail_file(
        "To: a@isotoma.com, b@isotoma.com\nCc: c@isotoma.com\nSubject: s\n\nbody\n"
    )
    assert m.to == ["a@isotoma.com", "b@isotoma.com"]
    assert m.cc == ["c@isotoma.com"]
    assert set(m.recipients) == {"a@isotoma.com", "b@isotoma.com", "c@isotoma.com"}


def test_parses_display_name_form():
    m = gm.parse_mail_file('To: Doug Winter <doug@isotoma.com>\nSubject: s\n\nbody\n')
    assert m.to == ["doug@isotoma.com"]


def test_crlf_line_endings_are_handled():
    m = gm.parse_mail_file("To: a@isotoma.com\r\nSubject: s\r\n\r\nbody\r\n")
    assert m.subject == "s"
    assert m.body.strip() == "body"


@pytest.mark.parametrize(
    "text,match",
    [
        ("To: a@isotoma.com\nSubject: s\nbody with no blank line\n", "blank line"),
        ("Subject: s\n\nbody\n", "no To:"),
        ("To: a@isotoma.com\n\nbody\n", "no Subject:"),
        ("To: a@isotoma.com\nSubject: s\n\n   \n", "empty body"),
        ("To: not-an-address\nSubject: s\n\nbody\n", "not a valid address"),
        ("To: a@isotoma.com\nbroken header\nSubject: s\n\nbody\n", "unparseable header"),
    ],
)
def test_malformed_mail_files_are_refused(text, match):
    with pytest.raises(gm.MailError, match=match):
        gm.parse_mail_file(text)


# -------------------------------------------------------------- allowlist


def test_domain_on_allowlist_passes(cfg):
    gm.check_allowed(["anyone@isotoma.com"], cfg.allow)


def test_exact_address_on_allowlist_passes(cfg):
    gm.check_allowed(["contact@les-tilleuls.coop"], cfg.allow)


def test_address_outside_allowlist_is_blocked(cfg):
    with pytest.raises(gm.MailError, match="not on the allowlist"):
        gm.check_allowed(["someone@random.com"], cfg.allow)


def test_one_bad_recipient_blocks_the_whole_send(cfg):
    with pytest.raises(gm.MailError, match="random.com"):
        gm.check_allowed(["ok@isotoma.com", "bad@random.com"], cfg.allow)


def test_allowlist_is_case_insensitive(cfg):
    gm.check_allowed(["Someone@ISOTOMA.com"], cfg.allow)


def test_lookalike_domain_does_not_match(cfg):
    """`notisotoma.com` must not pass because it ends with the allowed string."""
    with pytest.raises(gm.MailError):
        gm.check_allowed(["x@notisotoma.com"], cfg.allow)


def test_subdomain_does_not_silently_pass(cfg):
    with pytest.raises(gm.MailError):
        gm.check_allowed(["x@mail.isotoma.com"], cfg.allow)


# ----------------------------------------------------------------- ledger


def test_duplicate_send_is_refused(tmp_path):
    ledger = tmp_path / "sent.jsonl"
    mail = gm.parse_mail_file(MAIL)
    gm.append_ledger(ledger, mail, "<id@example.com>")
    with pytest.raises(gm.MailError, match="Refusing to send it twice"):
        gm.check_not_duplicate(mail, gm.read_ledger(ledger))


def test_different_subject_to_same_person_is_allowed(tmp_path):
    ledger = tmp_path / "sent.jsonl"
    gm.append_ledger(ledger, gm.parse_mail_file(MAIL), "<id@example.com>")
    followup = gm.parse_mail_file(MAIL.replace("a subject", "a different subject"))
    gm.check_not_duplicate(followup, gm.read_ledger(ledger))


def test_daily_cap_blocks_once_reached(tmp_path):
    ledger = tmp_path / "sent.jsonl"
    for i in range(3):
        gm.append_ledger(ledger, gm.parse_mail_file(MAIL.replace("a subject", f"s{i}")), f"<{i}>")
    with pytest.raises(gm.MailError, match="daily cap reached"):
        gm.check_daily_cap(gm.read_ledger(ledger), 3)


def test_daily_cap_counts_only_today(tmp_path):
    ledger = tmp_path / "sent.jsonl"
    ledger.write_text(
        "\n".join(
            json.dumps({"at": "2020-01-01T00:00:00+00:00", "to": ["x@y.z"], "subject": f"s{i}"})
            for i in range(50)
        )
    )
    gm.check_daily_cap(gm.read_ledger(ledger), 3)  # ancient history does not count


def test_corrupt_ledger_line_does_not_brick_sending(tmp_path):
    ledger = tmp_path / "sent.jsonl"
    ledger.write_text('{"at":"2020-01-01T00:00:00+00:00","to":["a@b.c"],"subject":"x"}\n{broken\n\n')
    rows = gm.read_ledger(ledger)
    assert len(rows) == 1


def test_ledger_records_no_body_and_no_credential(tmp_path):
    ledger = tmp_path / "sent.jsonl"
    gm.append_ledger(ledger, gm.parse_mail_file(MAIL), "<id@example.com>")
    row = json.loads(ledger.read_text().strip())
    assert row["subject"] == "a subject"
    assert row["body_chars"] == len("A body.\n")
    assert "body" not in row
    assert "hunter2" not in ledger.read_text()


# ---------------------------------------------------------------- message


def test_built_message_has_the_headers_a_real_mta_wants(cfg):
    msg = gm.build_message(gm.parse_mail_file(MAIL), cfg)
    assert msg["From"] == "Me <me@example.com>"
    assert msg["To"] == "hello@isotoma.com"
    assert msg["Subject"] == "a subject"
    assert msg["Date"]
    assert msg["Message-ID"].endswith("example.com>")
    assert msg.get_content().strip() == "A body."


def test_cc_header_only_present_when_there_is_a_cc(cfg):
    assert gm.build_message(gm.parse_mail_file(MAIL), cfg)["Cc"] is None
    withcc = gm.parse_mail_file("To: a@isotoma.com\nCc: b@isotoma.com\nSubject: s\n\nb\n")
    assert gm.build_message(withcc, cfg)["Cc"] == "b@isotoma.com"


def test_no_attachment_api_exists():
    """Attachments are how a cold mail becomes a spam-filter casualty."""
    assert not hasattr(gm, "attach")
    assert "add_attachment" not in Path(gm.__file__).read_text()


def test_there_is_no_bulk_send_path():
    """The absence of a bulk mode is the point, so assert it on the parser.

    Checked against argparse rather than by grepping the source, because the
    source *documents* that there is no --to-file and an earlier version of
    this test matched its own docstring.
    """
    import argparse as _ap

    parser = gm.build_parser()
    sub = [a for a in parser._actions if isinstance(a, _ap._SubParsersAction)][0]
    send = sub.choices["send"]
    opts = {s for a in send._actions for s in a.option_strings}
    assert "--mail" in opts
    assert not {"--mails", "--to-file", "--all", "--batch", "--csv"} & opts
    # --mail takes exactly one value, so one invocation is one mail.
    mail_action = next(a for a in send._actions if "--mail" in a.option_strings)
    assert mail_action.nargs is None


# -------------------------------------------------------------------- CLI


def test_dry_run_is_the_default_and_sends_nothing(tmp_path, cfg_file, capsys, monkeypatch):
    sent = []
    monkeypatch.setattr(gm, "smtp_send", lambda *a, **k: sent.append(a))
    mail_file = tmp_path / "m.txt"
    mail_file.write_text(MAIL)
    ledger = tmp_path / "sent.jsonl"

    rc = gm.main(["--config", str(cfg_file), "--ledger", str(ledger),
                  "send", "--mail", str(mail_file)])

    assert rc == 0
    assert sent == []
    assert not ledger.exists()
    assert "DRY RUN" in capsys.readouterr().out


def test_confirm_actually_sends_and_writes_the_ledger(tmp_path, cfg_file, capsys, monkeypatch):
    sent = []
    monkeypatch.setattr(gm, "smtp_send", lambda msg, c: sent.append(msg))
    mail_file = tmp_path / "m.txt"
    mail_file.write_text(MAIL)
    ledger = tmp_path / "sent.jsonl"

    rc = gm.main(["--config", str(cfg_file), "--ledger", str(ledger),
                  "send", "--mail", str(mail_file), "--confirm"])

    assert rc == 0
    assert len(sent) == 1
    assert sent[0]["To"] == "hello@isotoma.com"
    assert "SENT" in capsys.readouterr().out
    assert json.loads(ledger.read_text().strip())["subject"] == "a subject"


def test_a_failed_send_is_not_written_to_the_ledger(tmp_path, cfg_file, monkeypatch):
    def boom(msg, c):
        raise smtplib_error()

    def smtplib_error():
        return RuntimeError("connection refused")

    monkeypatch.setattr(gm, "smtp_send", lambda msg, c: (_ for _ in ()).throw(RuntimeError("nope")))
    mail_file = tmp_path / "m.txt"
    mail_file.write_text(MAIL)
    ledger = tmp_path / "sent.jsonl"

    rc = gm.main(["--config", str(cfg_file), "--ledger", str(ledger),
                  "send", "--mail", str(mail_file), "--confirm"])

    assert rc == 1
    assert not ledger.exists(), "a failed send must not look like a sent one"


def test_blocked_recipient_never_reaches_smtp(tmp_path, cfg_file, monkeypatch):
    sent = []
    monkeypatch.setattr(gm, "smtp_send", lambda *a, **k: sent.append(a))
    mail_file = tmp_path / "m.txt"
    mail_file.write_text(MAIL.replace("hello@isotoma.com", "victim@random.com"))

    rc = gm.main(["--config", str(cfg_file), "--ledger", str(tmp_path / "l.jsonl"),
                  "send", "--mail", str(mail_file), "--confirm"])

    assert rc == 1
    assert sent == []


def test_ledger_command_lists_sends(tmp_path, cfg_file, capsys):
    ledger = tmp_path / "sent.jsonl"
    gm.append_ledger(ledger, gm.parse_mail_file(MAIL), "<id@example.com>")
    rc = gm.main(["--config", str(cfg_file), "--ledger", str(ledger), "ledger"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "hello@isotoma.com" in out and "a subject" in out


def test_ledger_command_on_empty_state(tmp_path, cfg_file, capsys):
    rc = gm.main(["--config", str(cfg_file), "--ledger", str(tmp_path / "none.jsonl"), "ledger"])
    assert rc == 0
    assert "nothing sent yet" in capsys.readouterr().out


def test_doctor_reports_a_missing_config_without_traceback(tmp_path, capsys):
    rc = gm.main(["--config", str(tmp_path / "nope.toml"),
                  "--ledger", str(tmp_path / "l.jsonl"), "doctor"])
    assert rc == 1
    assert "no config at" in capsys.readouterr().out


def test_module_makes_no_outbound_call_at_import_time():
    """Importing must never touch the network.

    Walks the module body with ast rather than grepping, because `def
    smtp_send(...)` is itself a top-level line containing "smtp_send(" and the
    first version of this test flagged the definition as if it were a call.
    """
    import ast

    tree = ast.parse(Path(gm.__file__).read_text())
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.If)):
            continue  # bodies only run when called / under __main__
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                name = getattr(sub.func, "id", "") or getattr(sub.func, "attr", "")
                assert name not in {"smtp_send", "SMTP", "SMTP_SSL", "login", "send_message"}, (
                    f"{name}() runs at import time"
                )
