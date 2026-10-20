"""Tests and attacks for the identity factors: QR, password, one-time codes, phone codes, knowledge questions, biometric rules, assurance levels."""
import json
import random
import secrets
import time
import unittest

from vega_identity import assurance, biometric, knowledge, password as pw, phone as ph, qr, totp

try:
    import cv2
    import numpy as np
except ImportError:                                                            # the QR decode check needs OpenCV; everything else does not
    cv2 = None


class Qr(unittest.TestCase):
    def decode(self, text):
        g = qr.encode(text)
        n, q = len(g), 4
        det = cv2.QRCodeDetector()
        for s in (6, 10, 20, 8, 14):                                           # the detector is flaky at some scales; the encoder is right if any decodes
            img = np.full(((n + 2 * q) * s, (n + 2 * q) * s), 255, np.uint8)
            for r in range(n):
                for c in range(n):
                    if g[r][c]:
                        img[(r + q) * s:(r + q + 1) * s, (c + q) * s:(c + q + 1) * s] = 0
            out, _, _ = det.detectAndDecode(img)
            if out == text:
                return True
        return False

    @unittest.skipIf(cv2 is None, "OpenCV not installed")
    def test_codes_decode_for_every_version_and_for_the_real_setup_uri(self):
        rnd = random.Random(7)
        uri = totp.otpauth_uri(totp.new_secret(), "alex@example.com", "Vega")
        for text in [uri, "hi", "é" * 40] + ["".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789:/?=&._-") for _ in range(n)) for n in (14, 26, 42, 62, 84, 106, 122, 152, 170, 180)]:
            self.assertTrue(self.decode(text), len(text.encode()))

    def test_refusals_and_outputs(self):
        for bad in ("", "x" * 181, None, 5, b"x"):
            with self.assertRaises(qr.QRRefused):
                qr.encode(bad)
        g = qr.encode("hello")
        self.assertEqual(len(g), 21)
        self.assertTrue(all(len(row) == 21 for row in g))
        self.assertTrue(g[0][0] and g[0][6] and g[6][0])                         # finder corners
        svg = qr.to_svg(g)
        self.assertTrue(svg.startswith("<svg") and "<rect" in svg)
        self.assertEqual(len(qr.to_text(g).split("\n")), 21)


class Password(unittest.TestCase):
    N = 2 ** 10

    def test_hash_verify_and_wrong_password(self):
        rec = pw.hash_password("a long enough passphrase", n=self.N)
        self.assertTrue(pw.verify_password("a long enough passphrase", rec))
        self.assertFalse(pw.verify_password("a long enough passphrasf", rec))
        self.assertNotEqual(rec, pw.hash_password("a long enough passphrase", n=self.N))       # fresh salt each time

    def test_pepper_is_part_of_the_hash(self):
        rec = pw.hash_password("a long enough passphrase", b"P" * 16, n=self.N)
        self.assertTrue(pw.verify_password("a long enough passphrase", rec, b"P" * 16))
        self.assertFalse(pw.verify_password("a long enough passphrase", rec, b"Q" * 16))
        self.assertFalse(pw.verify_password("a long enough passphrase", rec))

    def test_malformed_records_and_inputs_never_raise_and_never_pass(self):
        rec = pw.hash_password("a long enough passphrase", n=self.N)
        parts = rec.split("$")
        for bad in (None, "", "x", "bcrypt$a$b", rec + "$x", "$".join(parts[:-1]), "$".join(["scrypt", "3", "8", "1"] + parts[4:]), "$".join(["scrypt", str(2 ** 25), "8", "1"] + parts[4:]),
                    "$".join(parts[:4] + ["!!!", parts[5]]), "$".join(parts[:5] + ["AAAA"]), 5, b"scrypt"):
            self.assertFalse(pw.verify_password("a long enough passphrase", bad))
        for badpw in (None, 5, "", "x" * 2000, b"bytes"):
            self.assertFalse(pw.verify_password(badpw, rec))

    def test_a_record_that_asks_for_absurd_cost_is_not_even_tried(self):
        rec = pw.hash_password("a long enough passphrase", n=self.N)
        parts = rec.split("$")
        for n in (2 ** 21, 2 ** 31, 2 ** 9):
            self.assertIsNone(pw._parse("$".join([parts[0], str(n)] + parts[2:])))
        self.assertIsNotNone(pw._parse(rec))

    def test_unicode_forms_of_the_same_password_match(self):
        rec = pw.hash_password("café society 2026!", n=self.N)                     # e + combining accent
        self.assertTrue(pw.verify_password("café society 2026!", rec))

    def test_the_strength_floor(self):
        for weak, why in (("short1!", "shorter"), ("aaaaaaaaaaaaaa", "different characters"), ("password123", "shorter"), ("Password1234", "common"), ("alexander is cool 1", "account name"),
                          ("1234567890123456", "pattern")):
            probs = pw.strength_problems(weak, "alexander")
            self.assertTrue(any(why in p for p in probs), (weak, probs))
            with self.assertRaises(pw.PasswordRefused):
                pw.hash_password(weak, n=self.N, user="alexander")
        self.assertEqual(pw.strength_problems("purple river lantern 42 quietly", "alex"), [])
        for bad in (None, 5):
            self.assertTrue(pw.strength_problems(bad))

    def test_cost_checks_and_rehash(self):
        for n in (100, 1000, 2 ** 10 + 1, True, 0):
            with self.assertRaises(pw.PasswordRefused):
                pw.hash_password("a long enough passphrase", n=n)
        rec = pw.hash_password("a long enough passphrase", n=self.N)
        self.assertTrue(pw.needs_rehash(rec))
        self.assertFalse(pw.needs_rehash(rec, n=self.N))
        self.assertTrue(pw.needs_rehash("garbage"))


class Totp(unittest.TestCase):
    K1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                                          # "12345678901234567890" in base32
    K256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"                      # 32 bytes
    K512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"   # 64 bytes

    def test_the_published_rfc_6238_test_vectors(self):
        for t, want in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")):
            self.assertEqual(totp.code(self.K1, t, digits=8), want, t)
        self.assertEqual(totp.code(self.K256, 59, digits=8, algo="sha256"), "46119246")
        self.assertEqual(totp.code(self.K512, 59, digits=8, algo="sha512"), "90693936")

    def test_window_replay_and_reuse(self):
        s = totp.new_secret()
        now = 1_700_000_000.0
        c = totp.code(s, now)
        ok, ctr = totp.verify(s, c, now)
        self.assertTrue(ok)
        self.assertFalse(totp.verify(s, c, now, last_counter=ctr)[0])                    # the same code again
        self.assertFalse(totp.verify(s, c, now + 5, last_counter=ctr)[0])
        nxt = totp.code(s, now + 30)
        self.assertTrue(totp.verify(s, nxt, now + 30, last_counter=ctr)[0])
        self.assertTrue(totp.verify(s, totp.code(s, now - 30), now)[0])                  # one step early is allowed
        self.assertFalse(totp.verify(s, totp.code(s, now - 90), now)[0])                 # three steps is not
        self.assertFalse(totp.verify(s, totp.code(s, now + 90), now)[0])
        self.assertFalse(totp.verify(s, totp.code(s, now - 30), now, last_counter=ctr)[0])   # older than the last accepted step

    def test_bad_codes_and_parameters(self):
        s = totp.new_secret()
        now = 1_700_000_000.0
        for bad in (None, 123456, "", "12345", "1234567", "abcdef", "12 456", "١٢٣٤٥٦", "123456\n", ["1"] * 6):
            self.assertFalse(totp.verify(s, bad, now)[0])
        for kw in ({"algo": "md5"}, {"step": 5}, {"step": True}, {"digits": 4}, {"window": 5}, {"window": True}):
            with self.assertRaises(totp.TotpRefused):
                totp.verify(s, "123456", now, **kw)
        for secret in ("", None, "!!!", 5):
            with self.assertRaises(totp.TotpRefused):
                totp.code(secret, now)
        for n in (8, 100, True):
            with self.assertRaises(totp.TotpRefused):
                totp.new_secret(n)

    def test_the_setup_uri(self):
        s = totp.new_secret()
        uri = totp.otpauth_uri(s, "alex@example.com", "Vega OS")
        self.assertTrue(uri.startswith("otpauth://totp/Vega%20OS:alex%40example.com?secret=" + s))
        self.assertIn("issuer=Vega%20OS", uri)
        self.assertIn("algorithm=SHA1&digits=6&period=30", uri)
        for acct, iss in (("", "V"), ("a:b", "V"), ("a", ""), ("a", "V:x"), ("a\n", "V"), ("x" * 101, "V"), ("a", "x" * 61), (5, "V")):
            with self.assertRaises(totp.TotpRefused):
                totp.otpauth_uri(s, acct, iss)
        with self.assertRaises(totp.TotpRefused):
            totp.otpauth_uri("!!!", "a", "V")


class Phone(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.now = {"t": 1000.0}
        self.pc = ph.PhoneChallenges(send=lambda n, t: self.sent.append((n, t)), pepper=b"p" * 16, clock=lambda: self.now["t"])

    def code(self):
        import re
        return re.search(r"code is (\d+)", self.sent[-1][1]).group(1)

    def test_a_code_works_once_for_the_right_user(self):
        cid = self.pc.start("alex", "+15551234567")
        self.assertEqual(self.sent[-1][0], "+15551234567")
        self.assertNotIn(self.code(), cid)
        self.assertFalse(self.pc.check(cid, "someone-else", self.code()))
        self.assertTrue(self.pc.check(cid, "alex", self.code()))
        self.assertFalse(self.pc.check(cid, "alex", self.code()))                        # spent

    def test_wrong_codes_burn_attempts_and_then_kill_the_challenge(self):
        cid = self.pc.start("alex", "+15551234567")
        real = self.code()
        wrong = "000000" if real != "000000" else "111111"
        for _ in range(5):
            self.assertFalse(self.pc.check(cid, "alex", wrong))
        self.assertFalse(self.pc.check(cid, "alex", real))                               # out of attempts: even the right code is dead

    def test_another_user_cannot_burn_a_challenge_that_is_not_theirs(self):
        cid = self.pc.start("alex", "+15551234567")
        real = self.code()
        wrong = "000000" if real != "000000" else "111111"
        for _ in range(10):
            self.assertFalse(self.pc.check(cid, "mallory", wrong))                       # a stranger guessing at alex's challenge spends nothing of alex's
        self.assertTrue(self.pc.check(cid, "alex", real))                                # alex can still finish

    def test_expiry(self):
        cid = self.pc.start("alex", "+15551234567")
        real = self.code()
        self.now["t"] += 301
        self.assertFalse(self.pc.check(cid, "alex", real))

    def test_send_limits_and_open_cap(self):
        for _ in range(3):
            self.pc.start("alex", "+15551234567")
        with self.assertRaises(ph.PhoneRefused):
            self.pc.start("alex", "+15551234567")
        self.now["t"] += 3601
        self.pc.start("alex", "+15551234567")
        small = ph.PhoneChallenges(send=lambda n, t: None, pepper=b"p" * 16, clock=lambda: 0.0, max_open=2, max_sends=10)
        small.start("a", "+15550000001")
        small.start("b", "+15550000002")
        with self.assertRaises(ph.PhoneRefused):
            small.start("c", "+15550000003")

    def test_nothing_is_sent_without_a_sender_and_a_failed_send_leaves_no_challenge(self):
        with self.assertRaises(ph.PhoneRefused):
            ph.PhoneChallenges(pepper=b"p" * 16).start("alex", "+15551234567")

        def boom(n, t):
            raise RuntimeError("gateway down")
        pc = ph.PhoneChallenges(send=boom, pepper=b"p" * 16)
        with self.assertRaises(ph.PhoneRefused):
            pc.start("alex", "+15551234567")
        self.assertEqual(pc._open, {})

    def test_numbers_codes_and_parameters_are_validated(self):
        for bad in ("5551234567", "+0555123456", "+1555", "+1555123456789012", "+1 555 123 4567", "", None, 5, "+1555123456a"):
            self.assertFalse(ph.valid_number(bad))
            with self.assertRaises(ph.PhoneRefused):
                self.pc.start("alex", bad)
        cid = self.pc.start("alex", "+15551234567")
        for bad in (None, 123456, "12345", "abcdef", "١٢٣٤٥٦", "1234567"):
            self.assertFalse(self.pc.check(cid, "alex", bad))
        self.assertFalse(self.pc.check("nope", "alex", "123456"))
        self.assertFalse(self.pc.check(None, "alex", "123456"))
        self.assertEqual(ph.masked("+15551234567"), "+1********67")
        for bad in ("5551234567", "", None, "+1"):
            with self.assertRaises(ph.PhoneRefused):
                ph.masked(bad)
        for kw in ({"pepper": b"short"}, {"pepper": None}, {"ttl": 5}, {"digits": 4}, {"max_attempts": 0}):
            with self.assertRaises(ph.PhoneRefused):
                ph.PhoneChallenges(**dict({"send": lambda n, t: None, "pepper": b"p" * 16}, **kw))
        with self.assertRaises(ph.PhoneRefused):
            self.pc.start("a|b", "+15551234567")

    def test_the_stored_hash_does_not_hold_the_code(self):
        cid = self.pc.start("alex", "+15551234567")
        self.assertNotIn(self.code(), json.dumps(self.pc._open))
        self.assertNotIn("5551234567", json.dumps(self.pc._sends))


def ans(i):
    return "k%03dq" % i


def facts(bank, n=14):
    topics = ["boats", "music", "food", "travel", "garden", "books", "cars"]
    for i in range(n):
        bank.add("What was the name of the sailboat you talked about in session number %d?" % i, ["the Marigold %s" % ans(i)], "private_session", "node-%d" % i, topics[i % len(topics)])


class Knowledge(unittest.TestCase):
    def setUp(self):
        self.now = {"t": 5000.0}
        self.bank = knowledge.QuestionBank(b"k" * 16, clock=lambda: self.now["t"])

    def test_facts_are_filtered(self):
        add = self.bank.add
        n = [0]

        def good(**edit):
            n[0] += 1
            return dict(dict(question="What did you call the little red notebook number %d that you carried?" % n[0], accepted=["Ember book"], source="private_note"), **edit)
        add(**good())
        for edit in ({"source": "public_web"}, {"source": "internet"}, {"question": "short?"}, {"question": "x" * 301}, {"accepted": []}, {"accepted": "Ember book"}, {"accepted": ["yes"]},
                     {"accepted": ["no"]}, {"accepted": ["ok"]}, {"accepted": ["42"]}, {"accepted": ["ab"]}, {"accepted": ["a"] * 7}, {"need_ratio": 0.2}, {"need_ratio": True},
                     {"accepted": ["abc"]}, {"accepted": ["yes yes"]},
                     {"question": "What is the password you used on the old laptop?"}, {"accepted": ["my social security 123-45-6789"]}, {"accepted": ["4111 1111 1111 1111"]},
                     {"question": "What was the diagnosis your doctor gave you last spring?"}, {"accepted": ["sk-" + "aB3dE5gH" * 4]}, {"question": "Wh\u0000at did you call the little red notebook you carried?"}):
            with self.assertRaises(knowledge.KnowledgeRefused, msg=str(edit)[:50]):
                add(**good(**edit))
        add(**good(accepted=["Ember book", "the ember journal"]))                          # a good fact with two accepted answers still goes in
        with self.assertRaises(knowledge.KnowledgeRefused):
            add(question="what did you call the LITTLE red notebook number 1 that you carried", accepted=["Ember book"], source="private_note")     # the same question again

    def test_a_quiz_grades_by_keywords_and_burns_every_question_it_shows(self):
        facts(self.bank, 20)                                                      # every quiz uses up questions: the bank must keep being refilled
        quiz = self.bank.start_quiz(3, 2)
        qs = quiz.questions()
        self.assertEqual(len(qs), 3)
        self.assertEqual(sum(1 for q in self.bank.questions.values() if q["state"] == "asked"), 3)
        for qid, text in qs:
            i = int(text.split("number ")[1].split("?")[0])
            quiz.answer(qid, "I think it was the marigold %s" % ans(i))
        self.assertTrue(quiz.result())
        again = self.bank.start_quiz(3, 2)
        self.assertFalse({q for q, _ in again.questions()} & {q for q, _ in qs})                 # the same questions are never asked twice

    def test_wrong_and_padded_answers_fail_and_wrong_quizzes_lock_for_longer(self):
        facts(self.bank, 30)
        for expected_lock in (60, 120, 240):
            quiz = self.bank.start_quiz(3, 2)
            for qid, text in quiz.questions():
                quiz.answer(qid, "no idea at all")
            self.assertFalse(quiz.result())
            self.assertAlmostEqual(self.bank.locked_until - self.now["t"], expected_lock, delta=1)
            with self.assertRaises(knowledge.KnowledgeRefused):
                self.bank.start_quiz(3, 2)
            self.now["t"] += expected_lock + 1
        quiz = self.bank.start_quiz(3, 2)
        qid, text = quiz.questions()[0]
        i = int(text.split("number ")[1].split("?")[0])
        self.assertFalse(self.bank._grade(qid, " ".join(["marigold %s" % ans(i)] + ["word%d" % k for k in range(40)])))        # right words buried in a flood
        self.assertFalse(self.bank._grade(qid, "marigold"))                                                                       # half the key words is not enough
        self.assertTrue(self.bank._grade(qid, "marigold %s" % ans(i)))
        self.assertFalse(self.bank._grade(qid, "x" * 500))
        self.assertFalse(self.bank._grade(qid, None))

    def test_the_factor_waits_until_the_system_knows_enough(self):
        facts(self.bank, 5)
        self.assertFalse(self.bank.available())
        with self.assertRaises(knowledge.KnowledgeRefused):
            self.bank.start_quiz()
        facts_more = knowledge.QuestionBank(b"k" * 16)
        facts(facts_more, 12)
        self.assertTrue(facts_more.available())

    def test_a_stolen_bank_holds_no_answers(self):
        facts(self.bank)
        blob = json.dumps(self.bank.to_dict())
        for secret_word in ("marigold", "k001q", "k002q"):
            self.assertNotIn(secret_word, blob.casefold().replace("sailboat", ""))
        back = knowledge.QuestionBank.from_dict(json.loads(blob), b"k" * 16, clock=lambda: self.now["t"])
        quiz = back.start_quiz(2, 1)
        qid, text = quiz.questions()[0]
        i = int(text.split("number ")[1].split("?")[0])
        quiz.answer(qid, "Marigold " + ans(i))
        self.assertTrue(back.questions[qid]["state"] == "answered_ok")
        other = knowledge.QuestionBank.from_dict(json.loads(blob), b"z" * 16)                    # the wrong pepper cannot grade
        self.assertFalse(other._grade(qid, "Marigold " + ans(i)))

    def test_quiz_misuse_is_refused(self):
        facts(self.bank)
        for kw in ({"count": 0}, {"count": 9}, {"count": True}, {"count": 3, "need": 4}, {"count": 3, "need": 0}):
            with self.assertRaises(knowledge.KnowledgeRefused):
                self.bank.start_quiz(**kw)
        quiz = self.bank.start_quiz(3, 2)
        with self.assertRaises(knowledge.KnowledgeRefused):
            quiz.result()                                                          # not finished
        qid = quiz.questions()[0][0]
        quiz.answer(qid, "x")
        with self.assertRaises(knowledge.KnowledgeRefused):
            quiz.answer(qid, "x")                                                  # no second try
        with self.assertRaises(knowledge.KnowledgeRefused):
            quiz.answer("nosuch", "x")
        for bad in (b"short", None):
            with self.assertRaises(knowledge.KnowledgeRefused):
                knowledge.QuestionBank(bad)

    def test_topics_are_spread(self):
        facts(self.bank, 28)
        for _ in range(3):                                                         # 9 of 28 used leaves at least 5 topics: three different ones are always available
            quiz = self.bank.start_quiz(3, 2)
            topics = {self.bank.questions[q]["topic"] for q, _ in quiz.questions()}
            self.assertEqual(len(topics), 3)


class Biometric(unittest.TestCase):
    def setUp(self):
        self.rnd = random.Random(3)
        self.me = [1.0, 5.0, -2.0, 0.3, 8.0, 2.2, -1.1, 4.4]

    def sample(self, centre, noise=0.08):
        return [x + self.rnd.gauss(0, noise * (abs(x) + 1)) for x in centre]

    def test_the_vault_encrypts_per_user(self):
        v = biometric.TemplateVault(secrets.token_bytes(32))
        t = {"mean": [1.0], "scale": [1.0], "limit": 1.0, "n": 3}
        blob = v.seal("alex", t)
        self.assertNotIn(b"mean", blob)
        self.assertEqual(v.open("alex", blob), t)
        with self.assertRaises(biometric.BiometricRefused):
            v.open("blake", blob)
        bad = bytearray(blob)
        bad[20] ^= 1
        with self.assertRaises(biometric.BiometricRefused):
            v.open("alex", bytes(bad))
        with self.assertRaises(biometric.BiometricRefused):
            biometric.TemplateVault(b"short")
        with self.assertRaises(biometric.BiometricRefused):
            biometric.TemplateVault(secrets.token_bytes(32)).open("alex", blob)

    def test_the_reference_matcher_accepts_the_owner_and_rejects_others(self):
        m = biometric.FeatureMatcher()
        t = m.enroll([self.sample(self.me) for _ in range(6)])
        genuine = sum(m.match(t, self.sample(self.me))[0] for _ in range(50))
        other = [x + 3 * (abs(x) + 1) * (1 if i % 2 else -1) for i, x in enumerate(self.me)]
        impostor = sum(m.match(t, self.sample(other))[0] for _ in range(50))
        self.assertGreaterEqual(genuine, 45)
        self.assertEqual(impostor, 0)

    def test_enrollment_and_matching_inputs_are_checked(self):
        m = biometric.FeatureMatcher()
        for bad in ([self.me] * 3, [self.me, self.me, self.me, self.me[:-1]], [[1, 2, 3]] * 4, [[float("nan")] * 8] * 4, [[True] * 8] * 4, ["x"] * 4, [[1.0] * 600] * 4):
            with self.assertRaises(biometric.BiometricRefused):
                m.enroll(bad)
        t = m.enroll([self.sample(self.me) for _ in range(4)])
        self.assertEqual(m.match(t, self.me[:-1]), (False, float("inf")))
        for bad in (None, "x", [float("inf")] * 8, [1, 2]):
            with self.assertRaises(biometric.BiometricRefused):
                m.match(t, bad)

    def test_liveness_phrases_are_single_use_and_expire(self):
        now = {"t": 0.0}
        lv = biometric.Liveness(clock=lambda: now["t"])
        cid, phrase = lv.challenge()
        self.assertEqual(len(phrase.split()), 4)
        self.assertTrue(lv.check(cid, "um " + phrase))
        self.assertFalse(lv.check(cid, phrase))                                           # used
        cid, phrase = lv.challenge()
        self.assertFalse(lv.check(cid, "completely different words here"))
        self.assertFalse(lv.check(cid, phrase))                                           # a failed try also burns it
        cid, phrase = lv.challenge()
        now["t"] += 61
        self.assertFalse(lv.check(cid, phrase))
        cid, phrase = lv.challenge()
        self.assertTrue(lv.check(cid, " ".join(phrase.split()[:3])))                       # 3 of 4 words is enough
        for bad in (None, 5, "nope"):
            self.assertFalse(lv.check(bad, "x"))

    def make_factor(self, **kw):
        state = {"speaker": self.me, "words": ""}
        f = biometric.VoiceFactor(biometric.TemplateVault(secrets.token_bytes(32)), extract=lambda a: self.sample(state["speaker"], 0.05) if kw.get("extract", True) else None,
                                  transcribe=(lambda a: state["words"]) if kw.get("transcribe", True) else None)
        if not kw.get("extract", True):
            f.extract = None
        return f, state

    def test_the_voice_factor_needs_the_phrase_and_the_voice(self):
        f, st = self.make_factor()
        sealed = f.enroll("alex", [b"a1", b"a2", b"a3", b"a4"])
        cid, phrase = f.liveness.challenge()
        st["words"] = phrase
        self.assertTrue(f.verify("alex", sealed, cid, b"live-1")["ok"])
        cid, phrase = f.liveness.challenge()
        st["words"] = "wrong words said here today"
        r = f.verify("alex", sealed, cid, b"live-2")
        self.assertFalse(r["ok"])
        self.assertEqual(r["why"], "not the spoken phrase")
        cid, phrase = f.liveness.challenge()
        st["words"], st["speaker"] = phrase, [x * 3 + 7 for x in self.me]
        r = f.verify("alex", sealed, cid, b"live-3")
        self.assertFalse(r["ok"])
        self.assertEqual(r["why"], "voice does not match")

    def test_a_recording_cannot_be_used_twice_and_a_template_cannot_be_used_by_another_user(self):
        f, st = self.make_factor()
        sealed = f.enroll("alex", [b"a1", b"a2", b"a3", b"a4"])
        cid, phrase = f.liveness.challenge()
        st["words"] = phrase
        self.assertTrue(f.verify("alex", sealed, cid, b"same-audio")["ok"])
        cid, phrase = f.liveness.challenge()
        st["words"] = phrase
        self.assertEqual(f.verify("alex", sealed, cid, b"same-audio")["why"], "this recording was already used")
        cid, phrase = f.liveness.challenge()
        st["words"] = phrase
        self.assertFalse(f.verify("blake", sealed, cid, b"other-audio")["ok"])

    def test_missing_plug_ins_and_crashes_fail_closed(self):
        f, st = self.make_factor(extract=False)
        with self.assertRaises(biometric.BiometricRefused):
            f.enroll("alex", [b"x"] * 4)
        self.assertEqual(f.verify("alex", b"x", "c", b"audio")["why"], "voice factor is not fully configured")
        f2, st2 = self.make_factor(transcribe=False)
        self.assertEqual(f2.verify("alex", b"x", "c", b"audio")["why"], "voice factor is not fully configured")
        f3, st3 = self.make_factor()
        sealed = f3.enroll("alex", [b"a", b"b", b"c", b"d"])
        f3.extract = lambda a: 1 / 0
        cid, phrase = f3.liveness.challenge()
        st3["words"] = phrase
        self.assertFalse(f3.verify("alex", sealed, cid, b"audio")["ok"])
        for bad in (None, b"", "text"):
            self.assertFalse(f3.verify("alex", sealed, "c", bad)["ok"])


class Assurance(unittest.TestCase):
    NOW = 1_000_000.0

    def lv(self, *factors, age=10):
        return assurance.level_of({f: self.NOW - age for f in factors}, self.NOW)["level"]

    def test_the_level_table(self):
        self.assertEqual(self.lv(), 0)
        self.assertEqual(self.lv("password"), 1)
        self.assertEqual(self.lv("password", "knowledge"), 1)                              # one family twice is one family
        self.assertEqual(self.lv("password", "phone"), 1)                                  # weight 2: not enough
        self.assertEqual(self.lv("phone", "voice"), 1)
        self.assertEqual(self.lv("password", "totp"), 2)
        self.assertEqual(self.lv("device_key", "password"), 2)
        self.assertEqual(self.lv("password", "totp", "voice"), 2)
        self.assertEqual(self.lv("password", "totp", "knowledge"), 3)
        self.assertEqual(self.lv("password", "totp", "voice", "device_key"), 4)
        self.assertEqual(self.lv("knowledge", "totp", "voice", "device_key"), 4)
        self.assertEqual(self.lv("password", "knowledge", "phone", "voice"), 2)             # no strong 'has' factor: capped
        self.assertEqual(self.lv("password", "knowledge", "totp", "phone", "device_key"), 3)       # heavy, but only two families: not level four
        self.assertEqual(self.lv("password", "totp", "voice", "phone"), 3)             # weight 5 with a strong possession factor

    def test_stale_future_and_unknown_factors_count_for_nothing(self):
        self.assertEqual(self.lv("password", "totp", age=16 * 60), 0)
        self.assertEqual(assurance.level_of({"password": self.NOW + 100, "totp": self.NOW + 100}, self.NOW)["level"], 0)
        self.assertEqual(assurance.level_of({"password": self.NOW - 1, "retina": self.NOW - 1}, self.NOW)["used"], ["password"])
        for bad in (True, "now", None, float("nan")):
            self.assertEqual(assurance.level_of({"password": bad}, self.NOW)["level"], 0)

    def test_actions_and_the_levels_they_need(self):
        for action, lvl in (("read_file", 1), ("list", 1), ("write_file", 2), ("delete_record", 3), ("send_message", 3), ("release_public", 4), ("spend_funds", 4), ("Release-Public", 4),
                            ("RELEASE_PUBLIC", 4), ("change_gate_config", 4), ("something_new", 4), ("", 4), (None, 4), (5, 4), ("readme_evil", 4), ("spend_x", 3), ("read:thing", 1)):
            self.assertEqual(assurance.required_level(action), lvl, action)

    def test_assertions_are_signed_short_and_checked(self):
        secret = secrets.token_bytes(32)
        a = assurance.issue(secret, "ref1", {"password": self.NOW - 5, "totp": self.NOW - 5}, self.NOW)
        self.assertEqual((a["level"], a["families"]), (2, ["has", "knows"]))
        self.assertTrue(assurance.verify(secret, a, self.NOW + 1))
        self.assertFalse(assurance.verify(secret, a, self.NOW + 901))
        self.assertFalse(assurance.verify(secret, a, self.NOW - 100))
        self.assertFalse(assurance.verify(secrets.token_bytes(32), a, self.NOW + 1))
        for field, value in (("level", 4), ("user", "other"), ("expiry", a["expiry"] + 5000), ("families", ["has", "is", "knows"]), ("used", ["device_key"])):
            self.assertFalse(assurance.verify(secret, dict(a, **{field: value}), self.NOW + 1), field)
        self.assertFalse(assurance.verify(secret, {k: v for k, v in a.items() if k != "mac"}, self.NOW))
        self.assertFalse(assurance.verify(secret, None, self.NOW))
        for ttl in (0, 901, True):
            with self.assertRaises(assurance.AssuranceRefused):
                assurance.issue(secret, "r", {"password": self.NOW}, self.NOW, ttl=ttl)
        with self.assertRaises(assurance.AssuranceRefused):
            assurance.issue(b"short", "r", {}, self.NOW)

    def test_allow_needs_a_genuine_assertion_at_the_actions_level(self):
        secret = secrets.token_bytes(32)
        two = assurance.issue(secret, "r", {"password": self.NOW, "totp": self.NOW}, self.NOW)
        self.assertTrue(assurance.allow(secret, two, "write_file", self.NOW))
        self.assertFalse(assurance.allow(secret, two, "delete_record", self.NOW))
        self.assertFalse(assurance.allow(secret, two, "release_public", self.NOW))
        self.assertFalse(assurance.allow(secret, dict(two, level=4), "release_public", self.NOW))
        four = assurance.issue(secret, "r", {"password": self.NOW, "totp": self.NOW, "voice": self.NOW, "device_key": self.NOW}, self.NOW)
        self.assertTrue(assurance.allow(secret, four, "release_public", self.NOW))
        self.assertFalse(assurance.allow(secret, four, "release_public", self.NOW + 1000))


if __name__ == "__main__":
    unittest.main()
