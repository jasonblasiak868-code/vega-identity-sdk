"""Regression tests (2026-10-22): the level an action needs was taken from its first word only, so 'read_and_delete_all' needed the lowest level. The highest class named
anywhere in a compound action name now decides."""
import unittest

from vega_identity import assurance as A


class Compound(unittest.TestCase):
    def test_the_highest_class_in_the_name_wins(self):
        for name, lvl in (("read_and_delete_all", 3), ("list_then_send_funds", 3), ("view_and_pay", 3), ("write_then_read", 2), ("search:release_notes", 3),
                          ("Read-And-Delete", 3), ("read_notes", 1), ("view", 1), ("delete_all", 3), ("create:file", 2)):
            self.assertEqual(A.required_level(name), lvl, name)

    def test_unknown_or_malformed_actions_need_the_top_level(self):
        for name in ("", None, 5, "frobnicate", "_read", "launch_read", "release_public"):
            self.assertEqual(A.required_level(name), 4, repr(name))


class LivenessFlood(unittest.TestCase):
    """Liveness passed when 75% of the challenge words appeared ANYWHERE in the transcript, so reading out the whole 48-word vocabulary always passed."""

    def test_reading_out_the_vocabulary_fails_and_the_real_phrase_passes(self):
        from vega_identity import biometric as BM
        lv = BM.Liveness()
        cid, phrase = lv.challenge()
        self.assertFalse(lv.check(cid, " ".join(BM.WORDS)))
        cid, phrase = lv.challenge()
        self.assertTrue(lv.check(cid, phrase))
        cid, phrase = lv.challenge()
        self.assertTrue(lv.check(cid, "um " + phrase + " thanks"))
        cid, phrase = lv.challenge()
        self.assertFalse(lv.check(cid, "something else entirely"))


class FirstFactorFirst(unittest.TestCase):
    """Anyone who knew a username could read that person's private questions (each start burned one) or make the system text their phone, with no proof of who they were."""

    def test_questions_and_text_codes_need_a_passed_first_factor(self):
        import redteam_2_service as S
        r = S.Rig().full()
        sent = len(r.sms)
        for _ in range(6):                                                           # a stranger trying again and again
            stranger = r.svc.login("alex")
            self.assertFalse(stranger.phone_start())
            self.assertIsNone(stranger.knowledge_start())
        self.assertEqual(len(r.sms), sent)                                           # nothing was texted
        lg = r.svc.login("alex")
        self.assertTrue(lg.password(S.PASSWORD))
        self.assertIsNotNone(lg.knowledge_start())                                   # the strangers burned none of the hourly quiz starts
        self.assertTrue(lg.phone_start())
        self.assertEqual(len(r.sms), sent + 1)

    def test_a_wrong_password_does_not_open_them(self):
        import redteam_2_service as S
        r = S.Rig().full()
        lg = r.svc.login("alex")
        self.assertFalse(lg.password("wrong wrong wrong"))
        self.assertFalse(lg.phone_start())
        self.assertIsNone(lg.knowledge_start())


if __name__ == "__main__":
    unittest.main()
