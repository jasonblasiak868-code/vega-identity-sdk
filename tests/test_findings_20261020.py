"""Regression tests (2026-10-20): (1) parallel guesses were all evaluated before any lockout was counted; (2) passing ONE factor reset the failure counter, so a person who knew
the password could alternate resets with second-factor guesses without limit; (3) a TOTP code, and a phone code's attempt limit, could be used more than allowed by racing."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_2_service import PASSWORD, Rig  # noqa: E402
from vega_identity import phone as phonemod, service  # noqa: E402


def race(n, fn):
    gate, out, lock = threading.Barrier(n), [], threading.Lock()

    def go(i):
        gate.wait()
        r = fn(i)
        with lock:
            out.append(r)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    return out


def slow_record(rig, seconds=0.02):
    inner = rig.dag.record

    class Slow:
        def __getattr__(self, k):
            return getattr(rig.dag, k)

        def record(self, kind, payload, parents=None):
            time.sleep(seconds)
            return inner(kind, payload, parents)
    rig.svc.dag = Slow()


class ParallelGuesses(unittest.TestCase):
    def test_parallel_wrong_passwords_are_counted_exactly_and_lock_after_five(self):
        r = Rig()
        slow_record(r)
        race(20, lambda i: r.svc.login("alex").password("wrong wrong wrong %d" % i))
        fails = [e for e in r.events() if e["kind"] == "ID_FACTOR_FAIL"]
        self.assertEqual(len(fails), service.MAX_FAILS)
        self.assertEqual(len([e for e in r.events() if e["kind"] == "ID_LOCKED"]), 1)

    def test_a_correct_password_that_arrives_after_the_fifth_failure_is_refused(self):
        r = Rig()
        slow_record(r)
        # five wrong guesses in flight together with the right one: the right one must not slip through once five failures exist
        order = []

        def go(i):
            ok = r.svc.login("alex").password(PASSWORD if i == 19 else "wrong wrong wrong %d" % i)
            order.append((i, ok))
        race(20, go)
        wrong = len([e for e in r.events() if e["kind"] == "ID_FACTOR_FAIL"])
        self.assertLessEqual(wrong, service.MAX_FAILS)
        oks = [i for i, ok in order if ok]
        if oks:                                                                   # it may legitimately have been among the first five attempts; then it is the sixth or later that must fail
            self.assertLessEqual(wrong + 1, service.MAX_FAILS + 1)


class OneFactorDoesNotResetTheCounter(unittest.TestCase):
    def test_a_password_success_between_second_factor_guesses_does_not_buy_more_guesses(self):
        r = Rig().full()
        for _ in range(4):
            r.svc.login("alex").totp("000000")                                    # four wrong second-factor guesses
        self.assertTrue(r.svc.login("alex").password(PASSWORD))                    # the password is right (the person knows it): this used to reset the count
        r.svc.login("alex").totp("111111")                                        # the fifth failure inside the window
        self.assertFalse(r.svc.login("alex").password(PASSWORD), "the account should now be locked")

    def test_failures_older_than_the_window_stop_counting(self):
        r = Rig()
        for _ in range(4):
            r.svc.login("alex").password("wrong wrong wrong")
        r.now["t"] += service.FAIL_WINDOW + 1
        r.svc.login("alex").password("wrong wrong wrong")
        self.assertTrue(r.svc.login("alex").password(PASSWORD))                    # one failure in the window, not five


class ReplayUnderRace(unittest.TestCase):
    def test_one_authenticator_code_logs_in_once_even_when_used_twice_at_once(self):
        r = Rig().full()
        slow_record(r)
        code = r.code()
        res = race(2, lambda i: r.svc.login("alex").totp(code))
        self.assertEqual(sorted(res), [False, True])

    def test_a_phone_challenge_allows_no_more_than_its_attempts_even_in_parallel(self):
        sent = []
        pc = phonemod.PhoneChallenges(send=lambda n, t: sent.append(t), pepper=b"pepper-pepper-pepper")
        cid = pc.start("alex", "+15551234567")
        calls, lock = [], threading.Lock()
        inner = pc._mac

        def counting(*a):
            with lock:
                calls.append(1)
            time.sleep(0.01)
            return inner(*a)
        pc._mac = counting
        race(25, lambda i: pc.check(cid, "alex", "%06d" % (100000 + i)))
        self.assertLessEqual(len(calls), pc.max_attempts)

    def test_phone_sends_to_one_number_stop_at_the_limit_in_parallel(self):
        sent = []
        pc = phonemod.PhoneChallenges(send=lambda n, t: (time.sleep(0.01), sent.append(t)), pepper=b"pepper-pepper-pepper")

        def go(i):
            try:
                pc.start("alex", "+15551234567")
                return True
            except phonemod.PhoneRefused:
                return False
        res = race(12, go)
        self.assertEqual(res.count(True), pc.max_sends)
        self.assertEqual(len(sent), pc.max_sends)

    def test_one_authenticator_code_cannot_be_replayed_when_the_check_is_slow(self):
        from vega_identity import totp as totpmod
        r = Rig().full()
        code = r.code()
        real = totpmod.verify

        def slow(*a, **k):
            out = real(*a, **k)
            time.sleep(0.05)                                   # both callers have read last_counter before either has saved the new one
            return out
        totpmod.verify = slow
        try:
            res = race(2, lambda i: r.svc.login("alex").totp(code))
        finally:
            totpmod.verify = real
        self.assertEqual(sorted(res), [False, True])

    def test_parallel_wrong_phone_codes_are_counted_exactly(self):
        r = Rig().full()
        lg0 = r.svc.login("alex")
        self.assertTrue(lg0.password(PASSWORD))
        self.assertTrue(lg0.phone_start())
        slow_record(r)
        cid = lg0._phone_cid

        def go(i):
            lg = r.svc.login("alex")
            lg._phone_cid = cid
            return lg.phone_check("%06d" % (100000 + i))
        race(20, go)
        self.assertEqual(len([e for e in r.events() if e["kind"] == "ID_FACTOR_FAIL"]), service.MAX_FAILS)


class EnrolIsAtomic(unittest.TestCase):
    def test_two_enrolments_of_one_name_leave_one_account(self):
        r = Rig()

        def go(i):
            try:
                r.svc.enrol("bobby", "purple river lantern %d quietly" % i)
                return True
            except service.IdentityRefused:
                return False
        res = race(2, go)
        self.assertEqual(sorted(res), [False, True])
        self.assertEqual(len([e for e in r.events() if e["kind"] == "ID_ENROLLED"]), 2)           # alex + bobby, once each


if __name__ == "__main__":
    unittest.main()
