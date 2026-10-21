"""service.py - the identity service: enrol a person, let them pass factors, count failures, lock them out, write what happened to the chain, and issue an assurance assertion.

  Identity(dag, secret, pepper, vault_key, send=None, voice=None)      secret: 32+ bytes that sign assertions; pepper: 16+ bytes for hashes; vault_key: 32 bytes for biometric templates
  enrol / begin_totp_setup / confirm_totp / set_phone / enrol_device_key / enrol_voice / knowledge_bank     set-up (a factor counts only once it is confirmed)
  login(user) -> Login    .password .totp .phone_start/.phone_check .device_challenge/.device_key .voice_challenge/.voice_verify .knowledge_start .assertion
EVERY failed factor counts against ONE per-person counter; five failures lock the account for a minute, doubling each time up to a day. Passing one factor does NOT clear the counter
(that would let someone who knows the password alternate clears with second-factor guesses); failures stop counting after FAIL_WINDOW (15 minutes) without a new one. The attempts of one
person run one at a time, so a burst of parallel guesses is counted exactly and cannot all be evaluated before the lock lands. A locked or unknown person gets the same plain 'no'
as a wrong answer, so nobody can use the service to learn who has an account; unknown people still cost the attacker the same hashing time.
THE CHAIN gets event kinds ID_ENROLLED, ID_FACTOR_OK, ID_FACTOR_FAIL, ID_LOCKED, ID_ASSERTION with a keyed hash of the user name, the factor name and the level: never a password, a code, an
answer, a phone number, an audio sample or a template. If the chain cannot be written, a success is refused (the record comes first).
HONEST LIMITS: state lives in this object; the caller must keep it (and the secrets) in an encrypted store; there is no network layer, no session cookie, no account recovery (recovery is the
dangerous part of any identity system and needs its own design and a human in the loop). The device-key factor proves possession of a private key by signing a fresh challenge; where that key lives
(a TPM, a hardware token) decides how strong it is."""
import contextlib
import functools
import hashlib
import hmac
import re
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vega_custody.dag.dag import DagError
from vega_identity import assurance, knowledge, password as pw, phone as phonemod, totp as totpmod, biometric

USER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")
MAX_FAILS, QUIZ_STARTS_PER_HOUR = 5, 3
FAIL_WINDOW = 15 * 60          # failures older than this no longer count toward a lock


class IdentityRefused(ValueError):
    pass


class Identity:
    def __init__(self, dag, secret: bytes, pepper: bytes, vault_key: bytes, clock=time.time, send=None, voice=None, scrypt_n: int = pw.N_DEFAULT, issuer: str = "Vega"):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32 or not isinstance(pepper, (bytes, bytearray)) or len(pepper) < 16:
            raise IdentityRefused("secret is 32+ bytes and pepper is 16+ bytes")
        self.dag, self._secret, self._pepper, self._clock, self._n, self.issuer = dag, bytes(secret), bytes(pepper), clock, scrypt_n, issuer
        self.phones = phonemod.PhoneChallenges(send=send, pepper=bytes(pepper), clock=clock)
        self.voice = voice if voice is not None else biometric.VoiceFactor(biometric.TemplateVault(vault_key), clock=clock)
        self.users = {}
        self._lock = threading.RLock()                       # set-up operations (enrol and the rest) run one at a time
        self._locks = {}                                     # user -> lock: that person's factor attempts run one at a time
        self._dummy = pw.hash_password("dummy-password-for-timing-only", self._pepper, n=scrypt_n, check_strength=False)

    # ---- helpers ------------------------------------------------------------------------------------------------
    def ref(self, user: str) -> str:
        return hmac.new(self._pepper, b"USER|" + str(user).encode("utf-8"), hashlib.sha256).hexdigest()[:24]

    def _event(self, kind, user, **kw) -> bool:
        try:
            self.dag.record(kind, dict({"user_ref": self.ref(user)}, **kw))
            return True
        except DagError:
            return False

    def _locked(self, u) -> bool:
        return self._clock() < u["locked_until"]

    def _user_lock(self, user):
        with self._lock:
            return self._locks.get(user) if isinstance(user, str) else None

    def _fail(self, user, u, factor) -> None:
        now = self._clock()
        if now - u.get("fail_at", 0.0) > FAIL_WINDOW:        # old failures stop counting; a success on another factor does not clear them
            u["fails"] = 0
        u["fail_at"] = now
        u["fails"] += 1
        self._event("ID_FACTOR_FAIL", user, factor=factor)
        if u["fails"] >= MAX_FAILS:
            u["lock_count"] += 1
            u["locked_until"] = self._clock() + min(86400, 60 * 2 ** (u["lock_count"] - 1))
            u["fails"] = 0
            self._event("ID_LOCKED", user, seconds=int(u["locked_until"] - self._clock()))

    # ---- set-up -----------------------------------------------------------------------------------------------------
    def enrol(self, user: str, password: str) -> None:
        if not isinstance(user, str) or not USER.fullmatch(user):
            raise IdentityRefused("user names are 3 to 40 lowercase letters, digits, '.', '_' or '-'")
        rec = pw.hash_password(password, self._pepper, n=self._n, user=user)        # the slow part runs outside the lock
        with self._lock:                                      # 'does it exist?', the record and the new account are one step
            if user in self.users:
                raise IdentityRefused("that user already exists")
            if not self._event("ID_ENROLLED", user):
                raise IdentityRefused("the chain could not be written: nothing was enrolled")
            self.users[user] = {"password": rec, "totp": None, "totp_pending": None, "last_counter": -1, "phone": None, "device_pub": None, "voice": None, "bank": None,
                                "fails": 0, "fail_at": 0.0, "lock_count": 0, "locked_until": 0.0, "quiz_starts": []}
            self._locks[user] = threading.RLock()

    def _u(self, user):
        u = self.users.get(user) if isinstance(user, str) else None
        if u is None:
            raise IdentityRefused("unknown user")
        return u

    def begin_totp_setup(self, user: str) -> str:
        u = self._u(user)
        u["totp_pending"] = totpmod.new_secret()
        return totpmod.otpauth_uri(u["totp_pending"], user, self.issuer)

    def confirm_totp(self, user: str, code: str) -> bool:
        u = self._u(user)
        if not u["totp_pending"]:
            raise IdentityRefused("no set-up in progress")
        ok, ctr = totpmod.verify(u["totp_pending"], code, self._clock())
        if ok:
            u["totp"], u["totp_pending"], u["last_counter"] = u["totp_pending"], None, ctr
        return ok

    def set_phone(self, user: str, number: str) -> None:
        if not phonemod.valid_number(number):
            raise IdentityRefused("not an E.164 number")
        self._u(user)["phone"] = number

    def enrol_device_key(self, user: str, public: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(bytes(public))
        except (ValueError, TypeError) as exc:
            raise IdentityRefused("not an Ed25519 public key") from exc
        self._u(user)["device_pub"] = bytes(public)

    def enrol_voice(self, user: str, audio_samples) -> None:
        self._u(user)["voice"] = self.voice.enroll(user, audio_samples)

    def knowledge_bank(self, user: str) -> knowledge.QuestionBank:
        u = self._u(user)
        if u["bank"] is None:
            u["bank"] = knowledge.QuestionBank(self._pepper, self._clock)
        return u["bank"]

    def login(self, user: str) -> "Login":
        return Login(self, user)


def _attempt(fn):
    """One person's factor attempts run one at a time (the lock is the person's, so different people do not wait for each other)."""
    @functools.wraps(fn)
    def inner(self, *a, **k):
        lk = self.svc._user_lock(self.user)
        with (lk if lk is not None else contextlib.nullcontext()):
            return fn(self, *a, **k)
    return inner


class Login:
    def __init__(self, svc: Identity, user: str):
        self.svc, self.user = svc, user
        self.u = svc.users.get(user) if isinstance(user, str) else None
        self.passed = {}
        self._phone_cid = self._device_nonce = self._voice_cid = self._quiz = None

    def _live(self) -> bool:
        return self.u is not None and not self.svc._locked(self.u)

    def _pass(self, factor) -> bool:
        if not self.svc._event("ID_FACTOR_OK", self.user, factor=factor):
            return False                                            # the record comes first
        self.passed[factor] = self.svc._clock()                      # the failure counter is NOT cleared here: one right factor must not buy more guesses at the others
        return True

    def _no(self, factor) -> bool:
        if self.u is not None and not self.svc._locked(self.u):
            self.svc._fail(self.user, self.u, factor)
        return False

    @_attempt
    def password(self, text) -> bool:
        rec = self.u["password"] if self.u is not None else self.svc._dummy
        ok = pw.verify_password(text, rec, self.svc._pepper)         # unknown users cost the same time
        if ok and self._live():
            return self._pass("password")
        return self._no("password")

    @_attempt
    def totp(self, code) -> bool:
        if not self._live() or not self.u["totp"]:
            return self._no("totp")
        ok, ctr = totpmod.verify(self.u["totp"], code, self.svc._clock(), self.u["last_counter"])
        if ok:
            self.u["last_counter"] = ctr                             # saved before success is reported: that code can never be used again
            return self._pass("totp")
        return self._no("totp")

    @_attempt
    def phone_start(self) -> bool:
        if not self._live() or not self.u["phone"]:
            return False
        try:
            self._phone_cid = self.svc.phones.start(self.user, self.u["phone"])
            return True
        except phonemod.PhoneRefused:
            return False

    @_attempt
    def phone_check(self, code) -> bool:
        if self._live() and self._phone_cid and self.svc.phones.check(self._phone_cid, self.user, code):
            self._phone_cid = None
            return self._pass("phone")
        return self._no("phone")

    def device_challenge(self):
        self._device_nonce = secrets.token_bytes(32) if self._live() and self.u["device_pub"] else None
        return self._device_nonce

    @_attempt
    def device_key(self, signature: bytes) -> bool:
        nonce, self._device_nonce = self._device_nonce, None         # single use
        if self._live() and nonce and self.u["device_pub"]:
            try:
                Ed25519PublicKey.from_public_bytes(self.u["device_pub"]).verify(bytes(signature), b"VEGA-DEVICE-LOGIN-1|" + self.user.encode("utf-8") + b"|" + nonce)
                return self._pass("device_key")
            except (InvalidSignature, ValueError, TypeError):
                pass
        return self._no("device_key")

    def voice_challenge(self):
        if not self._live() or not self.u["voice"]:
            return None
        self._voice_cid, phrase = self.svc.voice.liveness.challenge()
        return phrase

    @_attempt
    def voice_verify(self, audio) -> bool:
        if self._live() and self.u["voice"] and self._voice_cid:
            cid, self._voice_cid = self._voice_cid, None
            if self.svc.voice.verify(self.user, self.u["voice"], cid, audio)["ok"]:
                return self._pass("voice")
        return self._no("voice")

    @_attempt
    def knowledge_start(self):
        if not self._live() or self.u["bank"] is None or not self.u["bank"].available():
            return None
        now = self.svc._clock()
        self.u["quiz_starts"] = [t for t in self.u["quiz_starts"] if now - t < 3600]
        if len(self.u["quiz_starts"]) >= QUIZ_STARTS_PER_HOUR:
            return None
        self.u["quiz_starts"].append(now)
        self._quiz = self.u["bank"].start_quiz()
        return self._quiz.questions()

    @_attempt
    def knowledge_finish(self, answers: dict) -> bool:
        quiz, self._quiz = self._quiz, None
        if quiz is None or not self._live() or not isinstance(answers, dict):
            return self._no("knowledge")
        for qid in quiz.qids:
            try:
                quiz.answer(qid, answers.get(qid, ""))
            except knowledge.KnowledgeRefused:
                pass
        try:
            ok = quiz.result()
        except knowledge.KnowledgeRefused:
            ok = False
        return self._pass("knowledge") if ok else self._no("knowledge")

    def assertion(self):
        """The assurance assertion for what has been passed so far, or None for an unknown or locked person."""
        if not self._live() or not self.passed:
            return None
        a = assurance.issue(self.svc._secret, self.svc.ref(self.user), self.passed, self.svc._clock())
        if not self.svc._event("ID_ASSERTION", self.user, level=a["level"]):
            return None
        return a
