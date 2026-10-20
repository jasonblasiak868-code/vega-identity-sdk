"""Tests and attacks for the identity service: full logins, lockout, replay, user enumeration, the chain record, failing closed."""
import json
import pathlib
import random
import re
import secrets
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vega_custody.dag.dag import Dag, DagError
from vega_identity import assurance, biometric, knowledge, service, totp

PASSWORD = "purple river lantern 42 quietly"
T0 = 1_800_000_000.0


class Rig:
    def __init__(self):
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.now = {"t": T0}
        self.sms = []
        self.secret = secrets.token_bytes(32)
        self.rnd = random.Random(5)
        self.me = [1.0, 5.0, -2.0, 0.3, 8.0, 2.2, -1.1, 4.4]
        self.speaker, self.words = self.me, ""
        vault = biometric.TemplateVault(secrets.token_bytes(32))
        self.voice = biometric.VoiceFactor(vault, extract=lambda a: [x + self.rnd.gauss(0, 0.05 * (abs(x) + 1)) for x in self.speaker], transcribe=lambda a: self.words, clock=lambda: self.now["t"])
        self.svc = service.Identity(self.dag, self.secret, b"pepper-pepper-pepper", secrets.token_bytes(32), clock=lambda: self.now["t"], send=lambda n, t: self.sms.append(t), voice=self.voice, scrypt_n=2 ** 10)
        self.svc.enrol("alex", PASSWORD)

    def full(self):
        """Alex with every factor set up."""
        s = self.svc
        uri = s.begin_totp_setup("alex")
        self.totp_secret = re.search(r"secret=([A-Z2-7]+)", uri).group(1)
        assert s.confirm_totp("alex", totp.code(self.totp_secret, self.now["t"]))
        self.now["t"] += 30
        s.set_phone("alex", "+15551234567")
        self.device = Ed25519PrivateKey.generate()
        s.enrol_device_key("alex", self.device.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        s.enrol_voice("alex", [b"v1", b"v2", b"v3", b"v4"])
        bank = s.knowledge_bank("alex")
        for i in range(30):
            bank.add("Which harbour did we plan the trip to in conversation number %d?" % i, ["Port %s" % ("k%03dq" % i)], "private_session", "n%d" % i, "topic%d" % (i % 6))
        return self

    def code(self):
        return totp.code(self.totp_secret, self.now["t"])

    def events(self):
        return [e for e in self.dag.content.entries() if e["kind"].startswith("ID_")]


class Logins(unittest.TestCase):
    def test_password_alone_is_level_one_and_the_assertion_checks_out(self):
        r = Rig()
        lg = r.svc.login("alex")
        self.assertTrue(lg.password(PASSWORD))
        a = lg.assertion()
        self.assertEqual(a["level"], 1)
        self.assertTrue(assurance.verify(r.secret, a, r.now["t"]))
        self.assertEqual(a["user"], r.svc.ref("alex"))
        self.assertNotIn("alex", json.dumps(a))

    def test_password_and_authenticator_code_reach_level_two_and_a_code_cannot_be_reused(self):
        r = Rig().full()
        r.now["t"] += 30
        lg = r.svc.login("alex")
        c = r.code()
        self.assertTrue(lg.password(PASSWORD))
        self.assertTrue(lg.totp(c))
        self.assertEqual(lg.assertion()["level"], 2)
        lg2 = r.svc.login("alex")
        lg2.password(PASSWORD)
        self.assertFalse(lg2.totp(c))                                               # a code seen once is dead
        self.assertEqual(lg2.assertion()["level"], 1)

    def test_every_factor_together_reaches_level_four(self):
        r = Rig().full()
        r.now["t"] += 30
        lg = r.svc.login("alex")
        self.assertTrue(lg.password(PASSWORD))
        self.assertTrue(lg.totp(r.code()))
        nonce = lg.device_challenge()
        self.assertTrue(lg.device_key(r.device.sign(b"VEGA-DEVICE-LOGIN-1|alex|" + nonce)))
        phrase = lg.voice_challenge()
        r.words = phrase
        self.assertTrue(lg.voice_verify(b"my-voice-1"))
        a = lg.assertion()
        self.assertEqual(a["level"], 4)
        self.assertTrue(assurance.allow(r.secret, a, "release_public", r.now["t"]))

    def test_phone_code_flow(self):
        r = Rig().full()
        lg = r.svc.login("alex")
        self.assertTrue(lg.phone_start())
        code = re.search(r"code is (\d+)", r.sms[-1]).group(1)
        self.assertFalse(lg.phone_check("000000" if code != "000000" else "111111"))
        self.assertTrue(lg.phone_check(code))
        self.assertEqual(lg.passed.keys(), {"phone"})
        no_phone = Rig()
        self.assertFalse(no_phone.svc.login("alex").phone_start())

    def test_device_key_challenge_is_single_use_and_bound_to_the_user(self):
        r = Rig().full()
        lg = r.svc.login("alex")
        nonce = lg.device_challenge()
        good = r.device.sign(b"VEGA-DEVICE-LOGIN-1|alex|" + nonce)
        self.assertFalse(lg.device_key(Ed25519PrivateKey.generate().sign(b"VEGA-DEVICE-LOGIN-1|alex|" + nonce)))
        self.assertFalse(lg.device_key(good))                                       # the challenge was spent by the failed try
        nonce = lg.device_challenge()
        self.assertFalse(lg.device_key(r.device.sign(b"VEGA-DEVICE-LOGIN-1|blake|" + nonce)))
        nonce = lg.device_challenge()
        self.assertTrue(lg.device_key(r.device.sign(b"VEGA-DEVICE-LOGIN-1|alex|" + nonce)))
        self.assertFalse(lg.device_key(b"x"))
        self.assertIsNone(Rig().svc.login("alex").device_challenge())

    def test_voice_flow_needs_a_fresh_phrase_each_time(self):
        r = Rig().full()
        lg = r.svc.login("alex")
        self.assertFalse(lg.voice_verify(b"audio-without-a-challenge"))
        r.words = lg.voice_challenge()
        r.speaker = [x * 3 + 9 for x in r.me]
        self.assertFalse(lg.voice_verify(b"somebody-else"))
        r.speaker = r.me
        r.words = lg.voice_challenge()
        self.assertTrue(lg.voice_verify(b"alex-live"))

    def test_the_knowledge_quiz_and_its_limits(self):
        r = Rig().full()
        lg = r.svc.login("alex")
        qs = lg.knowledge_start()
        self.assertEqual(len(qs), 3)
        answers = {qid: "It was port %s" % ("k%03dq" % int(text.split("number ")[1].split("?")[0])) for qid, text in qs}
        self.assertTrue(lg.knowledge_finish(answers))
        for _ in range(2):
            lg2 = r.svc.login("alex")
            self.assertIsNotNone(lg2.knowledge_start())
        self.assertIsNone(r.svc.login("alex").knowledge_start())                       # three quiz starts an hour is the limit
        r.now["t"] += 3601
        self.assertIsNotNone(r.svc.login("alex").knowledge_start())
        lg3 = r.svc.login("alex")
        self.assertFalse(lg3.knowledge_finish({}))                                      # no quiz was started on this login

    def test_a_new_account_without_enough_knowledge_cannot_use_the_factor(self):
        r = Rig()
        r.svc.knowledge_bank("alex")
        self.assertIsNone(r.svc.login("alex").knowledge_start())


class Lockout(unittest.TestCase):
    def test_five_failures_lock_for_a_minute_then_longer_and_success_resets(self):
        r = Rig()
        for _ in range(5):
            self.assertFalse(r.svc.login("alex").password("wrong wrong wrong"))
        lg = r.svc.login("alex")
        self.assertFalse(lg.password(PASSWORD))                                         # right password, but locked
        self.assertIsNone(lg.assertion())
        r.now["t"] += 61
        self.assertTrue(r.svc.login("alex").password(PASSWORD))
        for _ in range(5):
            r.svc.login("alex").password("wrong wrong wrong")
        r.now["t"] += 61
        self.assertFalse(r.svc.login("alex").password(PASSWORD))                        # the second lock is two minutes
        r.now["t"] += 120
        self.assertTrue(r.svc.login("alex").password(PASSWORD))
        kinds = [e["kind"] for e in r.events()]
        self.assertEqual(kinds.count("ID_LOCKED"), 2)

    def test_unknown_and_locked_people_get_the_same_plain_no(self):
        r = Rig()
        ghost = r.svc.login("nobody")
        self.assertFalse(ghost.password(PASSWORD))
        self.assertFalse(ghost.totp("123456"))
        self.assertFalse(ghost.phone_start())
        self.assertIsNone(ghost.device_challenge())
        self.assertIsNone(ghost.voice_challenge())
        self.assertIsNone(ghost.knowledge_start())
        self.assertIsNone(ghost.assertion())
        for bad in (None, 5, ["alex"], "", "ALEX"):
            lg = r.svc.login(bad)
            self.assertFalse(lg.password(PASSWORD))
        self.assertEqual([e for e in r.events() if "nobody" in json.dumps(e)], [])      # nothing about a ghost reaches the chain by name

    def test_failures_on_any_factor_share_one_counter(self):
        r = Rig().full()
        lg = r.svc.login("alex")
        for code in ("000000", "111111", "222222"):
            lg.totp(code)
        lg.password("wrong wrong wrong")
        lg.phone_check("999999")
        self.assertFalse(r.svc.login("alex").password(PASSWORD))                         # five mixed failures: locked

    def test_a_locked_person_cannot_pass_other_factors_either(self):
        r = Rig().full()
        for _ in range(5):
            r.svc.login("alex").password("wrong wrong wrong")
        r.now["t"] += 1
        lg = r.svc.login("alex")
        self.assertFalse(lg.totp(r.code()))
        self.assertIsNone(lg.device_challenge())
        self.assertFalse(lg.phone_start())


class SetupAndRecord(unittest.TestCase):
    def test_names_passwords_and_duplicates_are_checked(self):
        r = Rig()
        for bad in ("ab", "A" * 3, "has space", "x" * 41, "", None, 5, "-lead", "a/b"):
            with self.assertRaises(service.IdentityRefused):
                r.svc.enrol(bad, PASSWORD)
        with self.assertRaises(service.IdentityRefused):
            r.svc.enrol("alex", PASSWORD)
        with self.assertRaises(Exception):
            r.svc.enrol("blake", "short")
        with self.assertRaises(service.IdentityRefused):
            r.svc.set_phone("alex", "5551234567")
        with self.assertRaises(service.IdentityRefused):
            r.svc.enrol_device_key("alex", b"short")
        with self.assertRaises(service.IdentityRefused):
            r.svc.confirm_totp("alex", "123456")                                        # no set-up in progress
        with self.assertRaises(service.IdentityRefused):
            r.svc.begin_totp_setup("nobody")
        for kw in ({"secret": b"short"}, {"pepper": b"short"}):
            args = dict(dag=r.dag, secret=secrets.token_bytes(32), pepper=b"p" * 16, vault_key=secrets.token_bytes(32))
            args.update(kw)
            with self.assertRaises(service.IdentityRefused):
                service.Identity(**args)

    def test_a_totp_set_up_is_only_active_once_confirmed(self):
        r = Rig()
        r.svc.begin_totp_setup("alex")
        lg = r.svc.login("alex")
        self.assertFalse(lg.totp("123456"))
        self.assertFalse(r.svc.confirm_totp("alex", "000000"))
        self.assertIsNone(r.svc.users["alex"]["totp"])

    def test_the_chain_records_what_happened_and_never_a_secret(self):
        r = Rig().full()
        r.now["t"] += 30
        lg = r.svc.login("alex")
        c = r.code()
        lg.password(PASSWORD)
        lg.totp(c)
        lg.password("definitely wrong pass")
        a = lg.assertion()
        blob = json.dumps(r.events())
        for secret in (PASSWORD, c, r.totp_secret, "5551234567", "definitely wrong pass", "wrong"):
            self.assertNotIn(secret, blob)
        kinds = [e["kind"] for e in r.events()]
        for k in ("ID_ENROLLED", "ID_FACTOR_OK", "ID_FACTOR_FAIL", "ID_ASSERTION"):
            self.assertIn(k, kinds)
        self.assertEqual([e["payload"]["level"] for e in r.events() if e["kind"] == "ID_ASSERTION"], [a["level"]])
        self.assertTrue(all(e["payload"]["user_ref"] == r.svc.ref("alex") for e in r.events()))
        self.assertTrue(r.dag.verify()[0])

    def test_if_the_chain_cannot_be_written_nothing_succeeds(self):
        r = Rig()
        real = r.dag.record

        def failing(kind, payload, parents=None):
            raise DagError("disk full")
        r.dag.record = failing
        lg = r.svc.login("alex")
        self.assertFalse(lg.password(PASSWORD))                                         # the record comes first
        self.assertEqual(lg.passed, {})
        with self.assertRaises(service.IdentityRefused):
            r.svc.enrol("blake", PASSWORD)
        self.assertNotIn("blake", r.svc.users)
        r.dag.record = real
        lg = r.svc.login("alex")
        self.assertTrue(lg.password(PASSWORD))
        r.dag.record = failing
        self.assertIsNone(lg.assertion())                                               # no assertion without a record of it

    def test_the_ref_is_a_keyed_hash_not_the_name(self):
        r = Rig()
        self.assertEqual(len(r.svc.ref("alex")), 24)
        self.assertNotIn("alex", r.svc.ref("alex"))
        other = service.Identity(r.dag, r.secret, b"another-pepper-xxxx", secrets.token_bytes(32), scrypt_n=2 ** 10)
        self.assertNotEqual(r.svc.ref("alex"), other.ref("alex"))


if __name__ == "__main__":
    unittest.main()
