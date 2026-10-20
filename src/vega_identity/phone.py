"""phone.py - a one-time code sent to the user's phone number (the 'something you have' factor with the weakest guarantee: a phone number can be taken over by a SIM swap, so
the assurance table gives it little weight and never lets it carry an action alone).

This module makes the code, remembers only a salted keyed hash of it, enforces expiry, attempt limits and send limits, and checks it. It does NOT send anything by itself: the caller
supplies send(number, text) (an SMS gateway, an authenticator push, anything), and without one a challenge is refused. The code is never logged and never returned.
  start(user, number)   -> challenge id      (sends the code through the caller's sender)
  check(id, code)       -> True once, for the right user and code, before it expires; a wrong code spends an attempt; after the limit the challenge is dead
Numbers must be E.164 (+ and 8 to 15 digits). The number is kept only as a keyed hash for rate-limiting."""
import hashlib
import hmac
import re
import secrets
import time

_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")


class PhoneRefused(ValueError):
    pass


def valid_number(number) -> bool:
    return isinstance(number, str) and bool(_E164.fullmatch(number))


def masked(number: str) -> str:
    if not valid_number(number):
        raise PhoneRefused("not an E.164 number")
    return number[:2] + "*" * (len(number) - 4) + number[-2:]


class PhoneChallenges:
    def __init__(self, send=None, pepper: bytes = None, clock=time.time, ttl: int = 300, max_attempts: int = 5, max_sends: int = 3, window: int = 3600, digits: int = 6, max_open: int = 1000):
        if pepper is None or not isinstance(pepper, (bytes, bytearray)) or len(pepper) < 16:
            raise PhoneRefused("a pepper of at least 16 bytes is required")
        if digits not in (6, 7, 8) or not 30 <= ttl <= 900 or not 1 <= max_attempts <= 10 or not 1 <= max_sends <= 10:
            raise PhoneRefused("parameter out of range")
        self._send, self._pepper, self._clock = send, bytes(pepper), clock
        self.ttl, self.max_attempts, self.max_sends, self.window, self.digits, self.max_open = ttl, max_attempts, max_sends, window, digits, max_open
        self._open = {}                                              # id -> {user, mac, expiry, attempts}
        self._sends = {}                                             # number hash -> [timestamps]

    def _mac(self, cid, user, code):
        return hmac.new(self._pepper, ("%s|%s|%s" % (cid, user, code)).encode("utf-8"), hashlib.sha256).hexdigest()

    def _nh(self, number):
        return hmac.new(self._pepper, b"NUM|" + number.encode("ascii"), hashlib.sha256).hexdigest()

    def start(self, user: str, number: str) -> str:
        if self._send is None:
            raise PhoneRefused("no delivery is configured: the caller must supply send(number, text)")
        if not isinstance(user, str) or not user or "|" in user:
            raise PhoneRefused("user is plain text")
        if not valid_number(number):
            raise PhoneRefused("not an E.164 number")
        now = self._clock()
        for cid in [c for c, v in self._open.items() if now >= v["expiry"]]:
            del self._open[cid]
        if len(self._open) >= self.max_open:
            raise PhoneRefused("too many codes outstanding")
        nh = self._nh(number)
        recent = [t for t in self._sends.get(nh, []) if now - t < self.window]
        if len(recent) >= self.max_sends:
            raise PhoneRefused("too many codes sent to this number: try later")
        code = str(secrets.randbelow(10 ** self.digits)).zfill(self.digits)
        cid = secrets.token_hex(16)
        try:
            self._send(number, "Your Vega code is %s. It expires in %d minutes. Never share it." % (code, self.ttl // 60))
        except Exception as exc:                                     # noqa: BLE001 - any delivery failure means no challenge exists
            raise PhoneRefused("the code could not be delivered") from exc
        self._sends[nh] = recent + [now]
        self._open[cid] = {"user": user, "mac": self._mac(cid, user, code), "expiry": now + self.ttl, "attempts": 0}
        return cid

    def check(self, cid: str, user: str, code) -> bool:
        v = self._open.get(cid) if isinstance(cid, str) else None
        if v is None or self._clock() >= v["expiry"] or v["user"] != user:
            return False
        if not isinstance(code, str) or len(code) != self.digits or not code.isascii() or not code.isdigit():
            v["attempts"] += 1
            if v["attempts"] >= self.max_attempts:
                del self._open[cid]
            return False
        v["attempts"] += 1
        ok = hmac.compare_digest(self._mac(cid, user, code), v["mac"])
        if ok or v["attempts"] >= self.max_attempts:
            del self._open[cid]                                      # used, or out of attempts: gone either way
        return ok
