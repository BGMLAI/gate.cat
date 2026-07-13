"""gate.cat Cloud — client-side end-to-end encryption (the council red line).

The one load-bearing promise of Cloud: the off-machine copy of your veto history
is stored by a server that **cannot read it**. Every event is encrypted on your
machine, with a key that lives only on your machine, before it is shipped. We
(the operator) hold ciphertext and nothing else — not the commands, not the
policy ids, not the reasons.

Mechanism: AES-256-GCM (authenticated encryption). The key is 32 random bytes in
``~/.gatecat/cloud.key`` (0600), generated once by ``gate.cat cloud init`` and
never transmitted. The account API key (a separate secret) authenticates you to
the server; it does NOT decrypt anything. Lose the key file and even you can't
read your history — that is the point, and ``cloud init`` says so.

Team fleets share one key: ``gate.cat cloud key export`` prints it, and you drop
it into the other machines' ``~/.gatecat/cloud.key`` (out of band). The server
never participates in key exchange.

Requires the [cloud] extra (``pip install gate-cat[cloud]``) for `cryptography`.
The free gate never imports this module.
"""
from __future__ import annotations

import base64
import json
import os

KEY_PATH = os.path.expanduser("~/.gatecat/cloud.key")
_NONCE = 12  # AES-GCM standard nonce length


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "gate.cat Cloud encryption needs the [cloud] extra: "
            "pip install gate-cat[cloud]"
        ) from e
    return AESGCM


def key_path() -> str:
    return os.environ.get("GATECAT_CLOUD_KEY_FILE", KEY_PATH)


def load_or_create_key(path: str | None = None) -> bytes:
    """Return the 32-byte account key, creating it 0600 on first use.

    A passphrase (GATECAT_CLOUD_PASSPHRASE) derives a portable key via scrypt
    instead of a random file — handy for a Team that would rather remember a
    phrase than copy a file. Either way the key never leaves the machine.
    """
    passphrase = os.environ.get("GATECAT_CLOUD_PASSPHRASE")
    if passphrase:
        import hashlib
        # deterministic salt from a fixed label keeps the same passphrase -> same
        # key across a fleet without the server ever seeing salt or key.
        salt = hashlib.sha256(b"gate.cat/cloud/v1").digest()[:16]
        return hashlib.scrypt(passphrase.encode(), salt=salt, n=2**15, r=8, p=1,
                              dklen=32, maxmem=96 * 1024 * 1024)
    path = path or key_path()
    if os.path.exists(path):
        raw = open(path, "rb").read().strip()
        key = base64.urlsafe_b64decode(raw)
        if len(key) != 32:
            raise ValueError(f"{path}: not a 32-byte gate.cat cloud key")
        return key
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(base64.urlsafe_b64encode(key))
    return key


def export_key(path: str | None = None) -> str:
    """The key as a base64 string, to paste into a teammate's key file."""
    return base64.urlsafe_b64encode(load_or_create_key(path)).decode()


def import_key(b64: str, path: str | None = None) -> None:
    key = base64.urlsafe_b64decode(b64.strip())
    if len(key) != 32:
        raise ValueError("not a 32-byte key")
    path = path or key_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(base64.urlsafe_b64encode(key))


def encrypt_event(key: bytes, event: dict) -> str:
    """Encrypt one event dict -> base64(nonce || ciphertext||tag). Server-opaque."""
    AESGCM = _aesgcm()
    nonce = os.urandom(_NONCE)
    ct = AESGCM(key).encrypt(nonce, json.dumps(event, separators=(",", ":")).encode(), b"gate.cat/v1")
    return base64.b64encode(nonce + ct).decode()


def decrypt_event(key: bytes, blob: str) -> dict:
    """Reverse of encrypt_event. Raises on tamper (GCM auth fails)."""
    AESGCM = _aesgcm()
    raw = base64.b64decode(blob)
    nonce, ct = raw[:_NONCE], raw[_NONCE:]
    pt = AESGCM(key).decrypt(nonce, ct, b"gate.cat/v1")
    return json.loads(pt)
