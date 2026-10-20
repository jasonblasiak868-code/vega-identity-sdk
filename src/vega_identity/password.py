"""password.py - the 'something you know' factor: scrypt hashing with a per-user salt, constant-time checking, a strength check, and rehash detection.

A stored record looks like  scrypt$N$r$p$<salt b64>$<hash b64>  and carries its own parameters, so the cost can be raised later and old records still verify (needs_rehash says
when to upgrade). An optional server-side pepper is mixed in before hashing: it lives apart from the stored records, so a stolen record file alone cannot be cracked offline.
The strength check is a floor, not a promise: it refuses short, repetitive, common and name-containing passwords; length is the real strength, so use a passphrase."""
import base64
import hashlib
import hmac
import re
import secrets
import unicodedata

N_DEFAULT, R_DEFAULT, P_DEFAULT = 2 ** 15, 8, 1
MAX_PASSWORD_BYTES = 1024
_BASE_WORDS = ("password", "passw0rd", "letmein", "welcome", "qwerty", "admin", "administrator", "iloveyou", "changeme", "football", "monkey", "dragon", "trustno1")
MIN_LENGTH = 12
_COMMON = frozenset("""password password1 password123 123456789012 qwertyuiop12 iloveyou1234 administrator letmein12345 welcome12345 changeme1234 abc123456789 passw0rd1234
1234567890123 000000000000 111111111111 qwerty123456 football1234 monkey123456 dragon123456 trustno1trustno1""".split())


class PasswordRefused(ValueError):
    pass


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _prep(password: str, pepper: bytes) -> bytes:
    if not isinstance(password, str):
        raise PasswordRefused("a password is text")
    raw = unicodedata.normalize("NFKC", password).encode("utf-8")
    if not raw or len(raw) > MAX_PASSWORD_BYTES:
        raise PasswordRefused("a password is 1 to %d bytes" % MAX_PASSWORD_BYTES)
    return hmac.new(pepper, raw, hashlib.sha256).digest() if pepper else raw


def strength_problems(password: str, user: str = "") -> list:
    """Reasons this password is refused; an empty list means it passes the floor."""
    if not isinstance(password, str):
        return ["not text"]
    p = unicodedata.normalize("NFKC", password)
    problems = []
    if len(p) < MIN_LENGTH:
        problems.append("shorter than %d characters" % MIN_LENGTH)
    if len(set(p)) < 5:
        problems.append("fewer than 5 different characters")
    if p.strip().casefold() in _COMMON or re.sub(r"[^a-z0-9]", "", p.casefold()) in _COMMON:
        problems.append("a very common password")
    stem = re.sub(r"[^a-z]", "", p.casefold())
    if stem in _BASE_WORDS and re.fullmatch(r"[A-Za-z]+[^A-Za-z]*", p):
        problems.append("a very common password with digits or symbols added")
    u = re.sub(r"[^a-z0-9]", "", str(user).casefold())
    if len(u) >= 3 and u in re.sub(r"[^a-z0-9]", "", p.casefold()):
        problems.append("contains the account name")
    if re.fullmatch(r"(.)\1+", p) or re.fullmatch(r"(?:0123456789|1234567890|abcdefghij|qwertyuiop)+.*", p.casefold()):
        problems.append("a repeated or sequence pattern")
    if len(p.encode("utf-8")) > MAX_PASSWORD_BYTES:
        problems.append("longer than %d bytes" % MAX_PASSWORD_BYTES)
    return problems


def hash_password(password: str, pepper: bytes = b"", n: int = N_DEFAULT, r: int = R_DEFAULT, p: int = P_DEFAULT, check_strength: bool = True, user: str = "") -> str:
    if check_strength:
        bad = strength_problems(password, user)
        if bad:
            raise PasswordRefused("password refused: " + "; ".join(bad))
    if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (n, r, p)) or n & (n - 1) or n < 2 ** 10:
        raise PasswordRefused("scrypt cost must be a power of two of at least 1024")
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(_prep(password, pepper), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=2 ** 29)
    return "scrypt$%d$%d$%d$%s$%s" % (n, r, p, _b64(salt), _b64(h))


def _parse(record):
    try:
        alg, n, r, p, salt, h = record.split("$")
        if alg != "scrypt":
            return None
        n, r, p = int(n), int(r), int(p)
        salt, h = base64.b64decode(salt, validate=True), base64.b64decode(h, validate=True)
        if n < 2 ** 10 or n > 2 ** 20 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16 or len(salt) != 16 or len(h) != 32:
            return None
        return n, r, p, salt, h
    except (ValueError, AttributeError, TypeError):
        return None


def verify_password(password: str, record: str, pepper: bytes = b"") -> bool:
    """True only for the right password; a malformed record or a non-text password is False, never an exception."""
    parsed = _parse(record)
    if parsed is None:
        return False
    n, r, p, salt, want = parsed
    try:
        got = hashlib.scrypt(_prep(password, pepper), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=2 ** 29)
    except (PasswordRefused, ValueError):
        return False
    return hmac.compare_digest(got, want)


def needs_rehash(record: str, n: int = N_DEFAULT, r: int = R_DEFAULT, p: int = P_DEFAULT) -> bool:
    parsed = _parse(record)
    return parsed is None or (parsed[0], parsed[1], parsed[2]) != (n, r, p)
