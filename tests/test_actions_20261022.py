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


if __name__ == "__main__":
    unittest.main()
