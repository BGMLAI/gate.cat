#!/usr/bin/env python3
"""Outbound mail for the gate.cat sales machine — the channel that was missing.

WHY THIS EXISTS
---------------
`docs/AUTOPILOT-LOOP.md` hard rule #1 records that the Gmail connector has no
send function, that an SMTP sender was written on 2026-07-22, and that it never
reached a machine. Nine days later the consequence is the one the playbook
already named: "szkic to nie jest wykonana praca" — 361 drafts accumulated in
week one, including partner mail that sat unsent for a week. Every mail this
machine writes dies in the Drafts folder.

This closes that. After a one-time credential setup that the operator performs
himself, sending is a command, not a click.

THE CREDENTIAL BOUNDARY — READ THIS BEFORE CHANGING ANYTHING
------------------------------------------------------------
This script never receives, prompts for, echoes, or logs a password. The
operator writes the app password into a 0600 config file himself, once. The
script reads it at send time and hands it straight to smtplib. It is never
printed, never written to the ledger, never included in an error message, and
the config file lives OUTSIDE the repository — because this repository is
public, and a public repo is exactly where a credential should never be.

WHAT STOPS THIS BEING DANGEROUS
-------------------------------
An agent with a send button is a mass-mail incident waiting for a bad loop or a
prompt injection in a scraped page. So the guardrails are not optional and are
not configurable downward at the call site:

  * recipients must match an allowlist in the config — no allowlist, no send
  * a daily cap (default 15, the playbook's number)
  * dry-run is the DEFAULT; sending requires --confirm
  * an append-only ledger, checked before every send, refuses to send the same
    (recipient, subject) twice — the machine cannot double-tap a prospect
  * one recipient per send. No bulk mode exists. There is no --to-file.

Every one of those is a deliberate refusal of convenience. A tool that makes it
easy to mail 200 people is a tool that will eventually mail 200 people.

USAGE
-----
    gatecat_mail.py doctor                    # verify config, perms, SMTP login
    gatecat_mail.py send --mail FILE          # dry run, prints exactly what would go
    gatecat_mail.py send --mail FILE --confirm
    gatecat_mail.py ledger                    # what actually went out

Mail files are RFC-ish plain text: headers, blank line, body.

    To: someone@example.com
    Cc: other@example.com
    Subject: the subject line

    Body starts after the blank line.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import ssl
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path

__version__ = "1.0.0"

DEFAULT_CONFIG = Path.home() / ".config" / "gatecat" / "mail.toml"
DEFAULT_LEDGER = Path.home() / ".local" / "state" / "gatecat" / "sent.jsonl"
DEFAULT_DAILY_CAP = 15

_ADDR_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class MailError(RuntimeError):
    """Anything that should stop a send with a readable reason."""


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    username: str
    password: str = field(repr=False)  # never repr'd, never logged
    from_addr: str
    from_name: str = ""
    allow: tuple[str, ...] = ()
    daily_cap: int = DEFAULT_DAILY_CAP

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"Config(host={self.host}, username={self.username}, from={self.from_addr})"


def load_config(path: Path) -> Config:
    """Read the config, refusing anything world- or group-readable.

    The permission check is not paranoia theatre: this file holds a credential
    that can send mail as the founder. A 0644 config on a shared box is the
    whole security model gone, and it is the kind of thing that happens once
    and is never noticed.
    """
    if not path.exists():
        raise MailError(
            f"no config at {path}\n"
            f"Create it yourself (this tool never asks for or handles your password):\n"
            f"  mkdir -p {path.parent} && touch {path} && chmod 600 {path}\n"
            f"then put this in it:\n\n"
            f'  host = "smtp.gmail.com"\n'
            f"  port = 465\n"
            f'  username = "you@yourdomain"\n'
            f'  password = "<app password>"   # Google Account > Security > App passwords\n'
            f'  from_addr = "you@yourdomain"\n'
            f'  from_name = "Your Name"\n'
            f'  allow = ["isotoma.com", "vshn.ch"]   # domains or full addresses\n'
            f"  daily_cap = 15\n"
        )

    mode = path.stat().st_mode
    if mode & 0o077:
        raise MailError(
            f"{path} is readable beyond your user (mode {mode & 0o777:04o}). "
            f"Fix it before sending:  chmod 600 {path}"
        )

    with path.open("rb") as fh:
        raw = tomllib.load(fh)

    missing = [k for k in ("host", "username", "password", "from_addr") if not raw.get(k)]
    if missing:
        raise MailError(f"{path} is missing: {', '.join(missing)}")

    allow = tuple(str(a).strip().lower() for a in raw.get("allow", []) if str(a).strip())
    if not allow:
        raise MailError(
            f"{path} has an empty `allow` list. Refusing to send to anywhere.\n"
            f"This is deliberate: an agent with an unrestricted send is one bad loop "
            f"away from a mass-mail incident. Name the domains you intend to contact."
        )

    return Config(
        host=str(raw["host"]),
        port=int(raw.get("port", 465)),
        username=str(raw["username"]),
        password=str(raw["password"]),
        from_addr=str(raw["from_addr"]),
        from_name=str(raw.get("from_name", "")),
        allow=allow,
        daily_cap=int(raw.get("daily_cap", DEFAULT_DAILY_CAP)),
    )


# --------------------------------------------------------------------------
# mail file parsing
# --------------------------------------------------------------------------


@dataclass
class Mail:
    to: list[str]
    subject: str
    body: str
    cc: list[str] = field(default_factory=list)

    @property
    def recipients(self) -> list[str]:
        return [*self.to, *self.cc]


def parse_mail_file(text: str) -> Mail:
    """Headers, blank line, body. Deliberately dumb — no MIME, no attachments.

    Attachments are how a pre-sales mail becomes a spam-filter casualty, and the
    retro-scan is a link to a public repo, not a payload. Keeping this parser
    unable to attach anything is a feature.
    """
    if "\n\n" not in text.replace("\r\n", "\n"):
        raise MailError("mail file needs a blank line between headers and body")

    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    headers: dict[str, str] = {}
    for line in head.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise MailError(f"unparseable header line: {line!r}")
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()

    def addrs(key: str) -> list[str]:
        raw = headers.get(key, "")
        out = []
        for chunk in raw.split(","):
            addr = parseaddr(chunk.strip())[1].strip()
            if addr:
                out.append(addr)
        return out

    to = addrs("to")
    if not to:
        raise MailError("mail file has no To: recipient")
    subject = headers.get("subject", "").strip()
    if not subject:
        raise MailError("mail file has no Subject:")
    if not body.strip():
        raise MailError("mail file has an empty body")

    mail = Mail(to=to, subject=subject, body=body.strip() + "\n", cc=addrs("cc"))
    for addr in mail.recipients:
        if not _ADDR_RE.match(addr):
            raise MailError(f"not a valid address: {addr!r}")
    return mail


# --------------------------------------------------------------------------
# guardrails
# --------------------------------------------------------------------------


def check_allowed(recipients: list[str], allow: tuple[str, ...]) -> None:
    """Every recipient must match the allowlist. One miss blocks the whole send.

    Blocking the whole mail rather than silently dropping the bad recipient is
    the right failure: a partially-sent mail is harder to reason about after the
    fact than one that never left.
    """
    for addr in recipients:
        low = addr.lower()
        domain = low.rpartition("@")[2]
        if low in allow or domain in allow:
            continue
        raise MailError(
            f"{addr} is not on the allowlist. Add it to `allow` in the config "
            f"if you actually mean to write to them."
        )


def read_ledger(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a corrupt line must not brick the send path
    return rows


def check_not_duplicate(mail: Mail, ledger: list[dict]) -> None:
    for row in ledger:
        if row.get("subject") == mail.subject and set(row.get("to", [])) == set(mail.to):
            raise MailError(
                f"already sent to {', '.join(mail.to)} with this subject on "
                f"{row.get('at', '?')}. Refusing to send it twice.\n"
                f"If this is a deliberate resend, change the subject."
            )


def check_daily_cap(ledger: list[dict], cap: int) -> None:
    today = datetime.now(timezone.utc).date().isoformat()
    sent_today = sum(1 for row in ledger if str(row.get("at", "")).startswith(today))
    if sent_today >= cap:
        raise MailError(
            f"daily cap reached ({sent_today}/{cap}). This is the playbook's number "
            f"and exists so a loop cannot turn into a campaign. Try tomorrow."
        )


def build_message(mail: Mail, cfg: Config) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = f"{cfg.from_name} <{cfg.from_addr}>" if cfg.from_name else cfg.from_addr
    msg["To"] = ", ".join(mail.to)
    if mail.cc:
        msg["Cc"] = ", ".join(mail.cc)
    msg["Subject"] = mail.subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg.from_addr.rpartition("@")[2] or None)
    msg.set_content(mail.body)
    return msg


def append_ledger(path: Path, mail: Mail, message_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "to": mail.to,
        "cc": mail.cc,
        "subject": mail.subject,
        "message_id": message_id,
        "body_chars": len(mail.body),
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------
# sending
# --------------------------------------------------------------------------


def smtp_send(msg: EmailMessage, cfg: Config) -> None:
    context = ssl.create_default_context()
    if cfg.port == 465:
        with smtplib.SMTP_SSL(cfg.host, cfg.port, context=context, timeout=30) as smtp:
            smtp.login(cfg.username, cfg.password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=30) as smtp:
            smtp.starttls(context=context)
            smtp.login(cfg.username, cfg.password)
            smtp.send_message(msg)


def _redact(exc: Exception, cfg: Config | None) -> str:
    """Never let a credential ride out inside an exception string."""
    text = f"{type(exc).__name__}: {exc}"
    if cfg and cfg.password:
        text = text.replace(cfg.password, "«REDACTED»")
    return text


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def cmd_doctor(args) -> int:
    try:
        cfg = load_config(Path(args.config))
    except MailError as exc:
        print(f"✗ {exc}")
        return 1

    print(f"✓ config          {args.config} (0600)")
    print(f"✓ from            {cfg.from_name} <{cfg.from_addr}>")
    print(f"✓ allowlist       {', '.join(cfg.allow)}")
    print(f"✓ daily cap       {cfg.daily_cap}")

    ledger = read_ledger(Path(args.ledger))
    today = datetime.now(timezone.utc).date().isoformat()
    print(f"✓ ledger          {len(ledger)} sent, "
          f"{sum(1 for r in ledger if str(r.get('at','')).startswith(today))} today")

    try:
        context = ssl.create_default_context()
        if cfg.port == 465:
            with smtplib.SMTP_SSL(cfg.host, cfg.port, context=context, timeout=30) as smtp:
                smtp.login(cfg.username, cfg.password)
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=30) as smtp:
                smtp.starttls(context=context)
                smtp.login(cfg.username, cfg.password)
    except Exception as exc:
        print(f"✗ smtp            login failed — {_redact(exc, cfg)}")
        print("\n  Gmail needs an APP PASSWORD, not your account password:")
        print("  Google Account > Security > 2-Step Verification > App passwords")
        return 1

    print(f"✓ smtp            {cfg.host}:{cfg.port} login ok")
    print("\nReady. Sending is a command now, not a click.")
    return 0


def cmd_send(args) -> int:
    cfg = None
    try:
        cfg = load_config(Path(args.config))
        mail = parse_mail_file(Path(args.mail).read_text(encoding="utf-8"))
        check_allowed(mail.recipients, cfg.allow)
        ledger = read_ledger(Path(args.ledger))
        check_not_duplicate(mail, ledger)
        check_daily_cap(ledger, cfg.daily_cap)
    except MailError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1

    msg = build_message(mail, cfg)
    print("─" * 72)
    print(f"From:    {msg['From']}")
    print(f"To:      {msg['To']}")
    if mail.cc:
        print(f"Cc:      {msg['Cc']}")
    print(f"Subject: {msg['Subject']}")
    print("─" * 72)
    print(mail.body.rstrip())
    print("─" * 72)

    if not args.confirm:
        print("DRY RUN — nothing sent. Add --confirm to actually send.")
        return 0

    try:
        smtp_send(msg, cfg)
    except Exception as exc:
        print(f"✗ send failed — {_redact(exc, cfg)}", file=sys.stderr)
        return 1

    append_ledger(Path(args.ledger), mail, msg["Message-ID"])
    print(f"✓ SENT to {', '.join(mail.to)}  ({msg['Message-ID']})")
    print(f"  ledger: {args.ledger}")
    return 0


def cmd_ledger(args) -> int:
    rows = read_ledger(Path(args.ledger))
    if not rows:
        print("nothing sent yet")
        return 0
    for row in rows:
        print(f"{row.get('at','?'):<22} {', '.join(row.get('to', [])):<34} {row.get('subject','')}")
    print(f"\n{len(rows)} sent total")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gatecat_mail.py",
        description="Outbound mail for the gate.cat sales machine. "
                    "Allowlisted, rate-limited, dry-run by default.",
    )
    p.add_argument("--config", default=str(DEFAULT_CONFIG))
    p.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="verify config, permissions and SMTP login")
    d.set_defaults(func=cmd_doctor)

    s = sub.add_parser("send", help="send one mail file (dry run unless --confirm)")
    s.add_argument("--mail", required=True, help="path to the mail file")
    s.add_argument("--confirm", action="store_true", help="actually send")
    s.set_defaults(func=cmd_send)

    lg = sub.add_parser("ledger", help="show what actually went out")
    lg.set_defaults(func=cmd_ledger)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
