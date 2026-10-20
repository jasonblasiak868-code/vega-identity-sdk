"""Mutation check for the identity SDK: each protection removed in a COPY must make one of the two test files fail.
Run: source SDK_FAMILY/env_family.sh; python tests/mutations_identity.py"""
import os, pathlib, shutil, subprocess, sys, tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
PW, TP, PH, KN, BI, AS, SV, QR = "password.py", "totp.py", "phone.py", "knowledge.py", "biometric.py", "assurance.py", "service.py", "qr.py"
MUTATIONS = [
    ("password compare", PW, "return hmac.compare_digest(got, want)", "return True"),
    ("password length floor", PW, "if len(p) < MIN_LENGTH:", "if False:"),
    ("unicode forms match", PW, 'raw = unicodedata.normalize("NFKC", password).encode("utf-8")', 'raw = password.encode("utf-8")'),
    ("pepper is mixed in", PW, "return hmac.new(pepper, raw, hashlib.sha256).digest() if pepper else raw", "return raw"),
    ("record cost ceiling", PW, " or n > 2 ** 20", ""),
    ("common password stem", PW, "if stem in _BASE_WORDS and", "if False and"),
    ("totp replay", TP, "if hit is None or hit <= last_counter:", "if hit is None:"),
    ("totp ascii digits only", TP, " or not supplied.isascii()", ""),
    ("totp window", TP, "for c in range(now_c - window, now_c + window + 1):", "for c in range(now_c - window - 3, now_c + window + 4):"),
    ("uri account colon", TP, ' or ":" in account', ""),
    ("phone attempts", PH, "if ok or v[\"attempts\"] >= self.max_attempts:", "if ok:"),
    ("phone expiry", PH, 'v is None or self._clock() >= v["expiry"] or v["user"] != user', 'v is None or v["user"] != user'),
    ("phone user binding", PH, ' or v["user"] != user', ""),
    ("phone send limit", PH, "if len(recent) >= self.max_sends:", "if False:"),
    ("phone number format", PH, "if not valid_number(number):", "if False:"),
    ("knowledge sources", KN, "if source not in ALLOWED_SOURCES:", "if False:"),
    ("knowledge sensitive filter", KN, "if _SENSITIVE.search(blob) or contains_credential(blob):", "if False:"),
    ("knowledge burn on ask", KN, 'self.questions[qid]["state"] = "asked"                   # burned at the moment it is shown', "pass"),
    ("knowledge lockout", KN, "b.locked_until = b._clock() + min(86400, 60 * 2 ** (b.failed_quizzes - 1))", "b.locked_until = 0"),
    ("knowledge keyword ratio", KN, 'if variant and hits / len(variant) >= q["need"]:', "if variant and hits > 0:"),
    ("knowledge flood guard", KN, "if len(toks) > 3 * len(variant) + 3:", "if False:"),
    ("knowledge min pool", KN, "if len(pool) < max(self.min_pool, count):", "if len(pool) < count:"),
    ("knowledge weak answers", KN, "len(joined) < 4 or ", ""),
    ("knowledge topics", KN, 'if len(picked) < count and self.questions[qid]["topic"] not in topics:', "if len(picked) < count:"),
    ("knowledge duplicates", KN, 'if normalise(existing["text"]) == normalise(question):', "if False:"),
    ("knowledge one answer each", KN, "if qid not in self.qids or qid in self._answered:", "if qid not in self.qids:"),
    ("liveness single use", BI, "item = self._open.pop(cid, None) if isinstance(cid, str) else None", "item = self._open.get(cid, None) if isinstance(cid, str) else None"),
    ("liveness expiry", BI, "item is None or self._clock() >= item[1] or", "item is None or"),
    ("recording replay", BI, "if digest in seen:", "if False:"),
    ("voice fails closed unconfigured", BI, "if self.extract is None or self.transcribe is None:", "if False:"),
    ("voice needs phrase and match", BI, '"ok": bool(live and ok)', '"ok": bool(ok)'),
    ("assurance freshness", AS, "0 <= now - t <= MAX_AGE", "True"),
    ("assurance two families", AS, "if len(fams) >= 2 and weight >= 3:", "if weight >= 3:"),
    ("assurance level four", AS, 'if len(fams) == 3 and weight >= 7 and ("device_key" in used or "totp" in used):', "if weight >= 7:"),
    ("human-only needs level four", AS, "if humanauth.is_human_only(action):", "if False:"),
    ("unknown actions need level four", AS, "    return 4\n\n\ndef _mac", "    return 1\n\n\ndef _mac"),
    ("assertion mac", AS, 'if not hmac.compare_digest(_mac(bytes(secret), body), assertion["mac"]):\n            return False', 'if False:\n            return False'),
    ("assertion expiry", AS, 'body["issued"] <= now < body["expiry"]', "True"),
    ("allow checks the level", AS, 'assertion["level"] >= required_level(action)', "True"),
    ("lockout", SV, 'if u["fails"] >= MAX_FAILS:', "if False:"),
    ("record before success", SV, 'if not self.svc._event("ID_FACTOR_OK", self.user, factor=factor):\n            return False', "pass"),
    ("totp counter saved", SV, 'self.u["last_counter"] = ctr', "pass"),
    ("device challenge single use", SV, "nonce, self._device_nonce = self._device_nonce, None", "nonce = self._device_nonce"),
    ("quiz start limit", SV, 'if len(self.u["quiz_starts"]) >= QUIZ_STARTS_PER_HOUR:', "if False:"),
    ("locked means locked", SV, "return self.u is not None and not self.svc._locked(self.u)", "return self.u is not None"),
    ("enrol needs the chain", SV, 'if not self._event("ID_ENROLLED", user):', "if False:"),
    ("assertion needs the chain", SV, 'if not self.svc._event("ID_ASSERTION", self.user, level=a["level"]):', "if False:"),
    ("qr alignment patterns", QR, "if (r, c) in ((6, 6), (6, pts[-1]), (pts[-1], 6)):", "if func[r][c]:"),
]
if __name__ != "__main__":
    MUTATIONS = []                       # importing this file (test discovery) must not start the mutation run
survivors = []
for name, fname, old, new in MUTATIONS:
    tmp = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(REPO / "src" / "vega_identity", tmp / "vega_identity")
    f = tmp / "vega_identity" / fname
    text = f.read_text(encoding="utf-8")
    if old not in text:
        print("CANNOT APPLY", name)
        survivors.append(name + " (could not apply)")
        continue
    f.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp) + os.pathsep + env.get("PYTHONPATH", "")
    killed = False
    for t in ("redteam_1_factors.py", "redteam_2_service.py"):
        r = subprocess.run([sys.executable, "-W", "ignore", str(REPO / "tests" / t)], capture_output=True, text=True, env=env, timeout=600)
        if r.returncode != 0:
            killed = True
            break
    print(("killed   " if killed else "SURVIVED ") + name, flush=True)
    if not killed:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
