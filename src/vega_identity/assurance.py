"""assurance.py - from the factors someone has just passed to an ASSURANCE LEVEL, and from an action to the level it needs.

Factors come in three FAMILIES: knows (password, knowledge questions), has (authenticator code, phone code, the human device key), is (voice or other biometric). Each factor has a
WEIGHT that reflects how hard it is to fake or take over; a family counts once; a factor is only counted while it is FRESH (passed in the last 15 minutes, the same cap as the
commitment lease).
  level 0  nothing fresh
  level 1  at least one fresh factor
  level 2  two families and weight 3 or more           (for example password + authenticator code)
  level 3  two families, weight 5 or more, and a 'has' factor of weight 2 or more
  level 4  all three families, weight 7 or more, and the device key or the authenticator code
A phone code is light on purpose (SIM swaps) and a voice is light on purpose (cloning): neither can lift anyone past level 1 without other factors.
POLICY: an action's required level comes from its class. HUMAN_ONLY actions (the jacket's list) and anything unknown need level 4. The check FAILS CLOSED.
An ASSERTION is a short-lived signed statement 'this user reached level L with these families at this time'; any component holding the secret can verify it; it expires within 15 minutes.
The assertion says who got in and how strongly, it never replaces the human's signature on a commitment: the commitment key is still the human's, and this decides whether the signing
console should be willing to use it."""
import hashlib
import hmac
import json
import secrets
import time

from vega_jacket import humanauth

MAX_AGE = 15 * 60
FAMILY = {"password": "knows", "knowledge": "knows", "totp": "has", "phone": "has", "device_key": "has", "voice": "is"}
WEIGHT = {"password": 1, "knowledge": 2, "totp": 2, "phone": 1, "device_key": 3, "voice": 1}
CLASS_LEVEL = (("read", 1), ("list", 1), ("view", 1), ("search", 1), ("write", 2), ("edit", 2), ("create", 2), ("delete", 3), ("send", 3), ("publish", 3), ("pay", 3), ("spend", 3), ("release", 3))


class AssuranceRefused(ValueError):
    pass


def level_of(passed: dict, now: float = None) -> dict:
    """passed: {factor: time it was passed}. -> {'level', 'families', 'weight', 'used'}. Unknown factors and stale ones count for nothing."""
    now = time.time() if now is None else now
    used = {f: t for f, t in passed.items() if f in FAMILY and isinstance(t, (int, float)) and not isinstance(t, bool) and 0 <= now - t <= MAX_AGE}
    fams = {FAMILY[f] for f in used}
    weight = sum(WEIGHT[f] for f in used)
    level = 0
    if used:
        level = 1
        if len(fams) >= 2 and weight >= 3:
            level = 2
            if weight >= 5 and any(FAMILY[f] == "has" and WEIGHT[f] >= 2 for f in used):
                level = 3
                if len(fams) == 3 and weight >= 7 and ("device_key" in used or "totp" in used):
                    level = 4
    return {"level": level, "families": sorted(fams), "weight": weight, "used": sorted(used)}


def required_level(action) -> int:
    if not isinstance(action, str) or not action:
        return 4
    if humanauth.is_human_only(action):
        return 4
    a = action.casefold().replace("-", "_")
    for prefix, lvl in CLASS_LEVEL:
        if a == prefix or a.startswith(prefix + "_") or a.startswith(prefix + ":"):
            return lvl
    return 4


def _mac(secret: bytes, body: dict) -> str:
    return hmac.new(secret, b"VEGA-ASSURANCE-1|" + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"), hashlib.sha256).hexdigest()


def issue(secret: bytes, user_ref: str, passed: dict, now: float = None, ttl: int = MAX_AGE) -> dict:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
        raise AssuranceRefused("the assertion secret is at least 32 bytes")
    now = time.time() if now is None else now
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= MAX_AGE:
        raise AssuranceRefused("ttl is 1 to %d seconds" % MAX_AGE)
    lv = level_of(passed, now)
    body = {"user": user_ref, "level": lv["level"], "families": lv["families"], "used": lv["used"], "issued": int(now), "expiry": int(now) + ttl, "nonce": secrets.token_hex(8)}
    return dict(body, mac=_mac(bytes(secret), body))


def verify(secret: bytes, assertion, now: float = None) -> bool:
    try:
        now = time.time() if now is None else now
        body = {k: assertion[k] for k in ("user", "level", "families", "used", "issued", "expiry", "nonce")}
        if not hmac.compare_digest(_mac(bytes(secret), body), assertion["mac"]):
            return False
        return isinstance(body["expiry"], int) and body["issued"] <= now < body["expiry"] and body["expiry"] - body["issued"] <= MAX_AGE
    except (KeyError, TypeError, ValueError):
        return False


def allow(secret: bytes, assertion, action, now: float = None) -> bool:
    """True only for a genuine, unexpired assertion whose level meets what this action needs."""
    return verify(secret, assertion, now) and isinstance(assertion.get("level"), int) and assertion["level"] >= required_level(action)
