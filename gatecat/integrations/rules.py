"""rules - signed, add-only, auto-updatable rule bundles (the hybrid feed).

Why (council 2026-07-05): the INGRESS injection base ROTS - new techniques
weekly. Freezing it in the pip package means users run stale defenses. The fix
is an antivirus-style model: the ENGINE stays local (0ms, commands never leave
the box), but the injection RULE BUNDLE is a signed artifact the client fetches
and verifies, so protection stays current without a hosted per-action service.

The five non-negotiables the council set, enforced here:

  1. SIGNED, key OFFLINE, public key PINNED in the package. A bundle is loaded
     only if its Ed25519 signature verifies against the public key baked in
     below (_TRUSTED_PUBKEYS) - never a key fetched at runtime. The PRIVATE key
     lives on the maintainer's laptop, never on any server. One VPS/CDN
     compromise cannot push a malicious rule: it isn't signed.
  2. ADD-ONLY, egress stays hardcoded-local. A bundle may only CONTRIBUTE new
     INGRESS (prompt-injection) patterns. It has no field and no code path that
     can remove, weaken, or override the compiled-in EGRESS block set
     (policies.DOGFOOD_DEFAULTS). A poisoned rule can at worst over-block
     (a false positive), never under-block the catastrophic classes.
  3. ANTI-ROLLBACK. A bundle carries a monotonic integer version; the loader
     refuses a version <= the last-accepted one, so a signed-but-old bundle
     can't be replayed to roll defenses back.
  4. FAIL-CLOSED / LAST-KNOWN-GOOD. A missing/corrupt/unverifiable bundle is
     ignored - the engine keeps its compiled-in rules; ingress protection never
     silently drops to nothing, and egress is entirely feed-independent.
  5. ZERO-KNOWLEDGE. This module only VERIFIES and LOADS a local file. It makes
     no network call and records nothing about which rule matched. Fetching is a
     separate, explicit `gate.cat update` step that GETs a static file by
     version only - never anything derived from the user's commands.

Verification is pure-python Ed25519 (no `cryptography` dependency, so the core
stays zero-dep and light) - the client only VERIFIES, it never signs.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------
# Pinned trusted public keys (hex-encoded Ed25519, 32 bytes). The maintainer
# signs bundles with the matching PRIVATE key on their laptop. Rotating a key =
# ship a new package version with a new pin; a compromised server cannot add a
# key here because this list is in the installed wheel, not fetched.
# The maintainer's production signing key (generated offline 2026-07-05 by
# scripts/sign_rules.py; the matching PRIVATE key lives only on the maintainer's
# laptop under ~/.gatecat-signing/, never on any server or in this repo).
# Rotating a key = ship a new package version that pins the NEW key alongside the
# old one, wait for clients to upgrade, then retire the old pin.
# --------------------------------------------------------------------------
_TRUSTED_PUBKEYS: tuple[str, ...] = (
    "1069a6798d8cd95d00c112fc09eaffc1846e0d06d706d7df7a17c9a7b3df5483",
)

_BUNDLE_ENV = "GATECAT_RULES_BUNDLE"
_DEFAULT_BUNDLE = Path.home() / ".gatecat" / "rules" / "ingress.bundle.json"
_STATE = Path.home() / ".gatecat" / "rules" / ".accepted_version"

_SCHEMA = "gatecat-rules-1"
_MAX_BUNDLE_BYTES = 512 * 1024   # rules are kilobytes of regex; cap for safety


@dataclass
class RuleBundle:
    """A verified, add-only ingress rule set."""

    version: int
    schema: str
    # each rule: {"name": str, "pattern": str, "level": "injection"|"suspicious"}
    ingress_rules: list[dict] = field(default_factory=list)

    def to_signing_bytes(self) -> bytes:
        """The exact bytes that are signed. Canonical JSON (sorted keys, no
        whitespace drift) so signer and verifier hash identical content."""
        body = {"schema": self.schema, "version": self.version,
                "ingress_rules": self.ingress_rules}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------
# Pure-python Ed25519 verify (RFC 8032). Client-side verify only; no signing,
# no third-party dep. Constant-ish; correctness over speed (bundles are rare).
# --------------------------------------------------------------------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * _inv(5)) % _P
_BX = _xrecover(_BY)
_B = (_BX % _P, _BY % _P)


def _edwards(pt1, pt2):
    x1, y1 = pt1
    x2, y2 = pt2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return (x3 % _P, y3 % _P)


def _scalarmult(pt, e):
    if e == 0:
        return (0, 1)
    q = _scalarmult(pt, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, pt)
    return q


def _on_curve(pt) -> bool:
    """Edwards curve membership: -x^2 + y^2 = 1 + d x^2 y^2 (mod p)."""
    x, y = pt
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _decodepoint(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    # F10 (council 2026-07-06): reject a non-canonical y (>= p) and a decoded
    # point that is not actually on the curve, matching RFC 8032 / the reference
    # implementation and the `cryptography`-based signer. The caller treats any
    # exception as verification failure (fail-closed).
    if y >= _P:
        raise ValueError("non-canonical point encoding (y >= p)")
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7):
        x = _P - x
    pt = (x, y)
    if not _on_curve(pt):
        raise ValueError("point is not on the curve")
    return pt


def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _ed25519_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        if len(sig) != 64 or len(pubkey) != 32:
            return False
        A = _decodepoint(pubkey)
        R = _decodepoint(sig[:32])
        S = int.from_bytes(sig[32:], "little")
        # F9 (council 2026-07-06): reject S >= L (RFC 8032 5.1.7). Without this,
        # (R, S) and (R, S+L) both verify -> signature malleability. Matches the
        # `cryptography` library used by the signer.
        if S >= _L:
            return False
        h = _hint(sig[:32] + pubkey + msg) % _L
        lhs = _scalarmult(_B, S)
        rhs = _edwards(R, _scalarmult(A, h))
        return lhs == rhs
    except Exception:
        return False


# --------------------------------------------------------------------------
# Loading + verification
# --------------------------------------------------------------------------
def _bundle_path() -> Path:
    return Path(os.environ.get(_BUNDLE_ENV, str(_DEFAULT_BUNDLE)))


def _state_mac(v: int, keys: "tuple[str, ...]") -> str:
    """Checksum binding the accepted-version counter to the pinned key set (F8).

    HONEST SCOPE (the key is the PUBLIC pin, baked into the wheel, so this is NOT
    a secret-keyed MAC): it detects a BLIND rewrite - a corrupted counter, a
    legacy bare-int file, or an attacker who resets the value without knowing the
    pin - and those fail closed. It does NOT stop an INFORMED attacker who reads
    the public pin and can write the counter file: they can recompute a valid
    checksum for any version. For that threat the counter must live where the
    attacker cannot write it - use GATECAT_RULES_STRICT_ROLLBACK=1 with an
    out-of-band first anchor. Bounded impact: a bundle is add-only INGRESS and
    egress is feed-independent, so the worst case of a defeated rollback is
    reverting to an older SIGNED ingress rule set (ingress over-block-loss),
    never an egress under-block."""
    import hashlib
    import hmac
    key = "|".join(sorted(k.lower() for k in keys)).encode("utf-8")
    return hmac.new(key, str(int(v)).encode("utf-8"), hashlib.sha256).hexdigest()


class _RollbackState:
    """The accepted-version counter with a tamper signal.

    `.version`  last accepted version (0 if never anchored).
    `.present`  a state file exists on disk (distinguishes a first-ever bootstrap
                from a deleted counter).
    `.trusted`  the state's MAC validates against the pinned key.

    A MISSING file is a legitimate first run (bootstrap allowed). A file that is
    PRESENT but whose MAC does not validate is the reset/forge attack - not
    bootstrap - and must fail closed."""
    __slots__ = ("version", "present", "trusted")

    def __init__(self, version: int, present: bool, trusted: bool):
        self.version = version
        self.present = present
        self.trusted = trusted


def _last_accepted_state(keys: "tuple[str, ...]") -> _RollbackState:
    try:
        raw = _STATE.read_text().strip()
    except OSError:
        return _RollbackState(0, present=False, trusted=False)  # never anchored
    # format: "<version>:<hmac>"; a legacy bare-int file is PRESENT but not MAC-
    # trusted -> treated as tampered (predates the MAC / could be a reset).
    try:
        vs, _, mac = raw.partition(":")
        v = int(vs)
        if mac and hmac_compare(mac, _state_mac(v, keys)):
            return _RollbackState(v, present=True, trusted=True)
        return _RollbackState(v, present=True, trusted=False)
    except (ValueError, TypeError):
        return _RollbackState(0, present=True, trusted=False)


def hmac_compare(a: str, b: str) -> bool:
    import hmac as _h
    return _h.compare_digest(a, b)


def _record_accepted_version(v: int, keys: "tuple[str, ...]") -> None:
    try:
        _STATE.parent.mkdir(parents=True, exist_ok=True)
        _STATE.write_text(f"{int(v)}:{_state_mac(v, keys)}")
    except OSError:
        pass


def verify_and_load(path: Path | None = None,
                    trusted: "tuple[str, ...] | None" = None) -> RuleBundle | None:
    """Verify a signed bundle file and return the RuleBundle, or None if it is
    absent, malformed, unsigned, signed by an untrusted key, or a rollback.

    The on-disk file is: {"bundle": {...}, "sig": "<hex ed25519 sig>",
    "pubkey": "<hex>"}. We recompute the signing bytes from `bundle`, verify the
    detached signature against a PINNED trusted key (never the file's own pubkey
    blindly), and enforce anti-rollback. Never raises - a bad bundle is None."""
    p = path or _bundle_path()
    keys = trusted if trusted is not None else _TRUSTED_PUBKEYS
    if not keys:
        return None  # no pinned key -> nothing can verify -> safe default
    try:
        if not p.exists() or p.stat().st_size > _MAX_BUNDLE_BYTES:
            return None
        raw = json.loads(p.read_text(encoding="utf-8"))
        body = raw["bundle"]
        sig = bytes.fromhex(raw["sig"])
        file_pub = bytes.fromhex(raw["pubkey"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    # the file's declared pubkey must be one we PINNED - otherwise an attacker
    # just ships their own key alongside their own signature.
    if raw["pubkey"].lower() not in {k.lower() for k in keys}:
        return None
    if body.get("schema") != _SCHEMA:
        return None
    try:
        bundle = RuleBundle(version=int(body["version"]), schema=body["schema"],
                            ingress_rules=list(body.get("ingress_rules", [])))
    except (KeyError, ValueError, TypeError):
        return None
    # verify the detached signature over the canonical signing bytes
    if not _ed25519_verify(file_pub, bundle.to_signing_bytes(), sig):
        return None
    # anti-rollback (F8): refuse a version <= last accepted. The counter is
    # MAC-bound to the pinned key; if the on-disk state is missing or its MAC does
    # not validate WHILE a signed bundle is present, that is exactly the reset-
    # the-sibling-counter attack - fail CLOSED (reject the bundle) rather than
    # silently trusting version 0 and accepting an old signed bundle.
    state = _last_accepted_state(keys)
    if state.present and not state.trusted:
        # the counter file exists but its MAC is invalid: a forged/recreated
        # counter (the reset-the-sibling attack). This IS detectable and we fail
        # CLOSED unconditionally.
        return None
    if not state.present and os.environ.get("GATECAT_RULES_STRICT_ROLLBACK") == "1":
        # a MISSING counter is normally a legitimate first run (bootstrap). A
        # deleted counter is indistinguishable from bootstrap WITHOUT storage the
        # attacker can't also remove (council's documented limit). Operators who
        # want the paranoid stance set STRICT_ROLLBACK=1: then a missing counter
        # with a present signed bundle is treated as a rollback and refused, and
        # the very first bundle must be anchored out-of-band.
        return None
    if bundle.version <= state.version:
        return None
    # add-only sanity: every rule must be an ingress pattern with a safe level;
    # a bundle can NEVER carry an egress/allow directive.
    safe: list[dict] = []
    for r in bundle.ingress_rules:
        if (isinstance(r, dict) and isinstance(r.get("pattern"), str)
                and r.get("level") in ("injection", "suspicious")
                and isinstance(r.get("name"), str)):
            safe.append({"name": r["name"], "pattern": r["pattern"], "level": r["level"]})
    bundle.ingress_rules = safe
    _record_accepted_version(bundle.version, keys)
    return bundle
