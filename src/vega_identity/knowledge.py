"""knowledge.py - questions the user never wrote: the model builds them from what the DKG knows about the user, and only the user can answer.

HOW IT WORKS. Some part of the system (the model reading the DKG) proposes FACTS: {question, accepted answers, where it came from}. This module is the GOVERNOR of those facts, not
the generator:
  - it refuses facts from public sources, facts about sensitive things (identifiers, money, health, passwords), and answers too short or too guessable to mean anything
  - it keeps each answer only as a SALTED KEYED HASH of its key words, so checking an answer needs neither the DKG nor the model, and a stolen bank reveals no answers
  - it draws questions at random, each question is used ONCE (burned the moment it is asked, answered or not), and the same question is never asked twice
  - a quiz asks several; a pass needs a set number correct; wrong attempts lock the account for longer each time
  - the factor is unavailable until enough questions exist (the system must know the user well before it can ask): a new account relies on other factors
WHAT IT CANNOT DO (read this): a question's TEXT is shown to whoever is at the screen, so each question exposes one fact: keep them low-sensitivity and single-use. Knowledge-based
answers can be guessed by someone who knows the person well (family, a stalker), so this factor adds assurance but is never enough alone for the highest level.
The generator is the model and can be wrong or manipulated: whatever it proposes goes through these filters, and nothing it proposes is trusted as an answer key unless a human enrolled it."""
import hashlib
import hmac
import re
import secrets
import time
import unicodedata

from vega_custody.dag.dag import contains_credential

ALLOWED_SOURCES = ("private_session", "private_note", "private_file")
STOP = frozenset("a an the of to in on at for and or is was were are be been it its this that with as by from my our your".split())
WEAK = frozenset("yes no true false none nothing nope yeah ok okay maybe".split())
_SENSITIVE = re.compile(r"\b(\d{3}-\d{2}-\d{4}|\d{9}|(?:\d[ -]?){13,19}|password|passcode|pin\b|passport|ssn|social security|diagnos\w*|prescription|medical|salary|account number|routing number|credit card|bank)\b", re.I)
MIN_POOL = 12


class KnowledgeRefused(ValueError):
    pass


def normalise(text: str) -> list:
    t = unicodedata.normalize("NFKC", str(text)).casefold()
    t = re.sub(r"[^\w\s]", " ", t)
    return [w for w in t.split() if w not in STOP]


def _h(salt: bytes, token: str) -> str:
    return hmac.new(salt, token.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


class QuestionBank:
    def __init__(self, pepper: bytes, clock=time.time, min_pool: int = MIN_POOL):
        if not isinstance(pepper, (bytes, bytearray)) or len(pepper) < 16:
            raise KnowledgeRefused("a pepper of at least 16 bytes is required")
        self._pepper, self._clock, self.min_pool = bytes(pepper), clock, min_pool
        self.questions = {}                                         # qid -> {text, salt, variants:[[token hashes]], need, state, source_ref, topic}
        self.failed_quizzes = 0
        self.locked_until = 0.0

    # ---- adding facts (the generator's output goes through here) -------------------------------------------
    def add(self, question: str, accepted, source: str, source_ref: str = "", topic: str = "general", need_ratio: float = 0.8) -> str:
        if not isinstance(question, str) or not 10 <= len(question) <= 300 or not question.isprintable():
            raise KnowledgeRefused("a question is 10 to 300 printable characters")
        if source not in ALLOWED_SOURCES:
            raise KnowledgeRefused("facts come only from the user's own private material, never from public sources")
        if isinstance(accepted, str) or not isinstance(accepted, (list, tuple)) or not 1 <= len(accepted) <= 6:
            raise KnowledgeRefused("accepted answers is a list of 1 to 6")
        if not isinstance(need_ratio, (int, float)) or isinstance(need_ratio, bool) or not 0.5 <= need_ratio <= 1.0:
            raise KnowledgeRefused("need_ratio is 0.5 to 1.0")
        blob = question + " " + " ".join(str(a) for a in accepted)
        if _SENSITIVE.search(blob) or contains_credential(blob):
            raise KnowledgeRefused("too sensitive to ask: identifiers, money, health and secrets are never used as questions")
        for existing in self.questions.values():
            if normalise(existing["text"]) == normalise(question):
                raise KnowledgeRefused("this question is already in the bank")
        salt = secrets.token_bytes(16)
        variants = []
        for a in accepted:
            toks = normalise(a)
            joined = "".join(toks)
            if not toks or len(joined) < 4 or (len(toks) == 1 and toks[0] in WEAK) or all(t in WEAK for t in toks) or (joined.isdigit() and len(joined) < 3):
                raise KnowledgeRefused("an accepted answer is too short or too easy to guess to mean anything")
            variants.append(sorted({_h(salt + self._pepper, t) for t in toks}))
        qid = secrets.token_hex(8)
        self.questions[qid] = {"text": question, "salt": salt, "variants": variants, "need": need_ratio, "state": "unused", "source_ref": hashlib.sha256(source_ref.encode("utf-8")).hexdigest() if source_ref else "",
                               "topic": str(topic)[:40]}
        return qid

    # ---- using them ---------------------------------------------------------------------------------------------
    def available(self) -> bool:
        return sum(1 for q in self.questions.values() if q["state"] == "unused") >= self.min_pool and self._clock() >= self.locked_until

    def start_quiz(self, count: int = 3, need: int = 2) -> "Quiz":
        if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 8 or not isinstance(need, int) or isinstance(need, bool) or not 1 <= need <= count:
            raise KnowledgeRefused("count is 1 to 8 and need is 1 to count")
        if self._clock() < self.locked_until:
            raise KnowledgeRefused("locked after wrong answers: try later")
        pool = [qid for qid, q in self.questions.items() if q["state"] == "unused"]
        if len(pool) < max(self.min_pool, count):
            raise KnowledgeRefused("the system does not know you well enough yet: not enough unused questions")
        picked, topics = [], set()
        rnd = secrets.SystemRandom()
        rnd.shuffle(pool)
        for qid in pool:                                             # prefer different topics so one subject cannot carry a quiz
            if len(picked) < count and self.questions[qid]["topic"] not in topics:
                picked.append(qid)
                topics.add(self.questions[qid]["topic"])
        for qid in pool:
            if len(picked) < count and qid not in picked:
                picked.append(qid)
        for qid in picked:
            self.questions[qid]["state"] = "asked"                   # burned at the moment it is shown
        return Quiz(self, picked, need)

    def _grade(self, qid, text) -> bool:
        q = self.questions[qid]
        if not isinstance(text, str) or len(text) > 400:
            return False
        toks = normalise(text)
        got = {_h(q["salt"] + self._pepper, t) for t in toks}
        for variant in q["variants"]:
            if len(toks) > 3 * len(variant) + 3:
                continue                                              # listing every word under the sun is not an answer
            hits = sum(1 for h in variant if h in got)
            if variant and hits / len(variant) >= q["need"]:
                return True
        return False

    def to_dict(self):
        return {"questions": {k: dict(v, salt=v["salt"].hex()) for k, v in self.questions.items()}, "failed": self.failed_quizzes, "locked_until": self.locked_until}

    @classmethod
    def from_dict(cls, d, pepper, clock=time.time):
        b = cls(pepper, clock)
        b.failed_quizzes, b.locked_until = int(d["failed"]), float(d["locked_until"])
        b.questions = {k: dict(v, salt=bytes.fromhex(v["salt"])) for k, v in d["questions"].items()}
        return b


class Quiz:
    def __init__(self, bank, qids, need):
        self._bank, self.qids, self.need = bank, list(qids), need
        self._answered, self._correct = {}, 0

    def questions(self):
        return [(qid, self._bank.questions[qid]["text"]) for qid in self.qids]

    def answer(self, qid: str, text) -> None:
        if qid not in self.qids or qid in self._answered:
            raise KnowledgeRefused("that question is not open")
        ok = self._bank._grade(qid, text)
        self._answered[qid] = ok
        self._correct += 1 if ok else 0
        self._bank.questions[qid]["state"] = "answered_ok" if ok else "answered_wrong"

    def result(self) -> bool:
        """True if enough were right. A quiz with unanswered questions is not finished: it counts as a failure when closed."""
        if len(self._answered) < len(self.qids):
            raise KnowledgeRefused("answer every question first")
        ok = self._correct >= self.need
        if ok:
            self._bank.failed_quizzes = 0
        else:
            b = self._bank
            b.failed_quizzes += 1
            b.locked_until = b._clock() + min(86400, 60 * 2 ** (b.failed_quizzes - 1))
        return ok
