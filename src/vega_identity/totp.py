"""totp.py - the one-time code from an authenticator app (RFC 6238, which builds on RFC 4226), with QR set-up and replay protection.

  new_secret()                         a fresh 160-bit secret as base32 (what the app stores)
  otpauth_uri(secret, account, issuer) the set-up link the QR code carries (qr.encode(uri) draws it); it CONTAINS THE SECRET: show it once, on the enrolling person's screen
  code(secret, at, ...)                the code for a moment in time
  verify(secret, supplied, now, last_counter, window=1) -> (ok, counter)   accepts the current 30-second step and one step either side; a code is refused if its step is not
                                       newer than the last one accepted (so a code seen over a shoulder or on the wire cannot be used again), and the caller must save the counter
SHA-1 is the default because authenticator apps expect it (HMAC-SHA1 is not weakened by SHA-1's collision problems); SHA-256 and SHA-512 are available. The comparison is constant-time."""
import base64
import hashlib
import hmac
import secrets
import struct
import time

_ALGOS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


class TotpRefused(ValueError):
    pass


def new_secret(nbytes: int = 20) -> str:
    if not isinstance(nbytes, int) or isinstance(nbytes, bool) or not 16 <= nbytes <= 64:
        raise TotpRefused("secret size is 16 to 64 bytes")
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def _key(secret):
    if not isinstance(secret, str) or not secret:
        raise TotpRefused("secret is base32 text")
    s = secret.replace(" ", "").upper()
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)
    except (ValueError, TypeError) as exc:
        raise TotpRefused("secret is not valid base32") from exc


def _hotp(key: bytes, counter: int, digits: int, algo: str) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), _ALGOS[algo]).digest()
    o = mac[-1] & 0x0F
    v = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(v).zfill(digits)


def _check(step, digits, algo):
    if algo not in _ALGOS:
        raise TotpRefused("algorithm is sha1, sha256 or sha512")
    if not isinstance(step, int) or isinstance(step, bool) or not 15 <= step <= 120:
        raise TotpRefused("step is 15 to 120 seconds")
    if digits not in (6, 7, 8):
        raise TotpRefused("digits is 6, 7 or 8")


def code(secret: str, at: float = None, step: int = 30, digits: int = 6, algo: str = "sha1") -> str:
    _check(step, digits, algo)
    t = time.time() if at is None else at
    return _hotp(_key(secret), int(t // step), digits, algo)


def counter_of(at: float, step: int = 30) -> int:
    return int(at // step)


def verify(secret: str, supplied, now: float = None, last_counter: int = -1, step: int = 30, digits: int = 6, algo: str = "sha1", window: int = 1):
    """-> (ok, counter). On ok the caller must store `counter` as the new last_counter."""
    _check(step, digits, algo)
    if not isinstance(window, int) or isinstance(window, bool) or not 0 <= window <= 2:
        raise TotpRefused("window is 0 to 2 steps")
    if not isinstance(supplied, str) or len(supplied) != digits or not supplied.isascii() or not supplied.isdigit():
        return False, last_counter
    key = _key(secret)
    now_c = int((time.time() if now is None else now) // step)
    hit = None
    for c in range(now_c - window, now_c + window + 1):                 # every candidate is compared, so timing does not reveal which step matched
        if hmac.compare_digest(_hotp(key, c, digits, algo), supplied) and hit is None:
            hit = c
    if hit is None or hit <= last_counter:
        return False, last_counter
    return True, hit


def _pct(text: str) -> str:
    return "".join(c if c in _UNRESERVED else "".join("%%%02X" % b for b in c.encode("utf-8")) for c in text)


def otpauth_uri(secret: str, account: str, issuer: str, step: int = 30, digits: int = 6, algo: str = "sha1") -> str:
    _check(step, digits, algo)
    _key(secret)
    if not isinstance(account, str) or not account or ":" in account or len(account) > 100 or not account.isprintable():
        raise TotpRefused("account is 1 to 100 printable characters without ':'")
    if not isinstance(issuer, str) or not issuer or ":" in issuer or len(issuer) > 60 or not issuer.isprintable():
        raise TotpRefused("issuer is 1 to 60 printable characters without ':'")
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d" % (_pct(issuer), _pct(account), secret.replace(" ", "").upper(), _pct(issuer), algo.upper(), digits, step)
