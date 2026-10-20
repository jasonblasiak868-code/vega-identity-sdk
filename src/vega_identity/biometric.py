"""biometric.py - the 'something you are' factor: a voice (or other biometric) match, with a challenge that a recording cannot answer, and a template that is never kept in the open.

WHAT IS HERE: the rules around a biometric, and a plain statistical matcher over feature VECTORS.
  TemplateVault      encrypts a user's enrolled template (AES-256-GCM, bound to the user id): the template is a secret and cannot be changed if stolen, so it is never stored or sent in the clear
  FeatureMatcher     enroll(samples) -> template; match(template, vector) -> (ok, distance). A reference matcher: per-feature mean and spread from enrollment, a distance limit taken from
                     the samples themselves. It shows the shape of the factor and is fine for tests; for a real voice it must be replaced by a speaker-embedding model
  Liveness           a random phrase to speak, single-use, short-lived; the spoken words (from the caller's speech-to-text) must match it, so an old recording of the person cannot answer
  VoiceFactor        ties the three together; it refuses to work (fails closed) if either the feature extractor or the speech-to-text is not supplied, and it refuses a recording it has seen before
WHAT IS NOT HERE: no audio signal processing and no speaker-recognition model: the caller supplies extract(audio) -> vector and transcribe(audio) -> text. Voice can be cloned by modern
tools, and a live deepfake can say a random phrase: so this factor carries little weight alone in the assurance table. Raw audio and templates are never written to a record; only a
yes/no and a rounded distance are."""
import hashlib
import hmac
import math
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

WORDS = tuple("""amber anchor aspen basil birch cedar coral dawn delta ember fable flint grove harbor indigo jasper kestrel lantern maple nectar onyx pebble quartz river saffron
tundra umber velvet willow yarrow zephyr cobalt copper dune falcon glacier heron ivory juniper lotus meadow nimbus orchid prairie quill raven sierra thistle""".split())


class BiometricRefused(ValueError):
    pass


class TemplateVault:
    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise BiometricRefused("the vault key is 32 bytes")
        self._aes = AESGCM(bytes(key))

    def seal(self, user: str, template: dict) -> bytes:
        import json
        nonce = secrets.token_bytes(12)
        return nonce + self._aes.encrypt(nonce, json.dumps(template, sort_keys=True).encode("utf-8"), b"vega-biometric-v1|" + user.encode("utf-8"))

    def open(self, user: str, blob: bytes) -> dict:
        import json
        try:
            return json.loads(self._aes.decrypt(bytes(blob[:12]), bytes(blob[12:]), b"vega-biometric-v1|" + user.encode("utf-8")))
        except (InvalidTag, ValueError, TypeError) as exc:
            raise BiometricRefused("the template does not open for this user") from exc


class FeatureMatcher:
    MIN_SAMPLES = 4

    @staticmethod
    def _vec(v):
        if not isinstance(v, (list, tuple)) or not 4 <= len(v) <= 512 or not all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in v):
            raise BiometricRefused("a feature vector is 4 to 512 finite numbers")
        return [float(x) for x in v]

    def enroll(self, samples) -> dict:
        vs = [self._vec(s) for s in samples]
        if len(vs) < self.MIN_SAMPLES or len({len(v) for v in vs}) != 1:
            raise BiometricRefused("enrollment needs at least %d samples of the same length" % self.MIN_SAMPLES)
        n, dim = len(vs), len(vs[0])
        mean = [sum(v[i] for v in vs) / n for i in range(dim)]
        std = [math.sqrt(sum((v[i] - mean[i]) ** 2 for v in vs) / (n - 1)) for i in range(dim)]      # unbiased: few samples understate the spread
        scale = [max(s, 0.05 * abs(m), 1e-3) for s, m in zip(std, mean)]
        t = {"mean": mean, "scale": scale, "n": n}
        loo = []
        for k in range(n):                                          # leave-one-out: how far is each enrollment sample from the rest
            rest = [vs[j] for j in range(n) if j != k]
            m2 = [sum(v[i] for v in rest) / len(rest) for i in range(dim)]
            loo.append(math.sqrt(sum(((vs[k][i] - m2[i]) / scale[i]) ** 2 for i in range(dim)) / dim))
        t["limit"] = max(2.0, 2.0 * max(loo))
        return t

    def match(self, template: dict, vector):
        v = self._vec(vector)
        if len(v) != len(template["mean"]):
            return False, float("inf")
        d = math.sqrt(sum(((v[i] - template["mean"][i]) / template["scale"][i]) ** 2 for i in range(len(v))) / len(v))
        return d <= template["limit"], d


class Liveness:
    def __init__(self, clock=time.time, ttl: int = 60, words: int = 4, need_ratio: float = 0.75):
        self._clock, self.ttl, self.words, self.need = clock, ttl, words, need_ratio
        self._open = {}

    def challenge(self):
        now = self._clock()
        for k in [k for k, v in self._open.items() if now >= v[1]]:
            del self._open[k]
        if len(self._open) > 500:
            raise BiometricRefused("too many open challenges")
        rnd = secrets.SystemRandom()
        phrase = rnd.sample(WORDS, self.words)
        cid = secrets.token_hex(8)
        self._open[cid] = (phrase, now + self.ttl)
        return cid, " ".join(phrase)

    def check(self, cid, transcript) -> bool:
        item = self._open.pop(cid, None) if isinstance(cid, str) else None          # single use, whether or not it passes
        if item is None or self._clock() >= item[1] or not isinstance(transcript, str):
            return False
        said = transcript.casefold().split()
        hits = sum(1 for w in item[0] if w in said)
        return hits / len(item[0]) >= self.need


class VoiceFactor:
    def __init__(self, vault: TemplateVault, extract=None, transcribe=None, matcher=None, liveness=None, clock=time.time):
        self.vault, self.extract, self.transcribe = vault, extract, transcribe
        self.matcher, self.liveness = matcher or FeatureMatcher(), liveness or Liveness(clock)
        self._seen = {}

    def enroll(self, user: str, audio_samples) -> bytes:
        if self.extract is None:
            raise BiometricRefused("no feature extractor is configured: voice enrollment is unavailable")
        return self.vault.seal(user, self.matcher.enroll([self.extract(a) for a in audio_samples]))

    def verify(self, user: str, sealed_template: bytes, challenge_id: str, audio: bytes) -> dict:
        """-> {'ok': bool, 'distance': rounded or None}. Fails closed if anything needed is missing."""
        if self.extract is None or self.transcribe is None:
            return {"ok": False, "distance": None, "why": "voice factor is not fully configured"}
        if not isinstance(audio, (bytes, bytearray)) or not audio:
            return {"ok": False, "distance": None, "why": "no audio"}
        digest = hashlib.sha256(bytes(audio)).hexdigest()
        seen = self._seen.setdefault(user, [])
        if digest in seen:
            return {"ok": False, "distance": None, "why": "this recording was already used"}
        seen.append(digest)
        del seen[:-200]
        try:
            live = self.liveness.check(challenge_id, self.transcribe(audio))
            tpl = self.vault.open(user, sealed_template)
            ok, d = self.matcher.match(tpl, self.extract(audio))
        except Exception:                                           # noqa: BLE001 - a crashing plug-in is a failed match, never a pass
            return {"ok": False, "distance": None, "why": "the voice check could not run"}
        return {"ok": bool(live and ok), "distance": round(d, 2), "why": "ok" if (live and ok) else ("not the spoken phrase" if not live else "voice does not match")}
