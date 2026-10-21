# vega-identity-sdk — Capabilities

## At a glance

| Item | Value |
|------|-------|
| **Capabilities documented** | 7 (one per module) |
| **Test coverage** | 67 tests (40 factor tests + 17 service tests + 10 regression tests) |
| **Mutation survival** | 3/55 (phone user binding, knowledge topics, QR alignment) |
| **Layer** | 1 (authority) |

## Table of contents

- [Capability inventory](#capability-inventory)
- [DKG + lattice integration](#dkg--lattice-integration)
- [Family predictive loop role](#family-predictive-loop-role)
- [A category of its own](#a-category-of-its-own)

## Capability inventory

Each capability is documented as: **capability** / **why a policy-or-prompt-level approach structurally cannot provide it** / **where enforced in this repo's code** / **which test file demonstrates it** / **honest limit**.

### 1. Password hashing with strength floor and pepper

| Aspect | Detail |
|--------|--------|
| **Capability** | scrypt hashing with per-user salt, optional server-side pepper, configurable cost (N/r/p), minimum 12 chars / 5 unique / not common / no name / no patterns, rehash detection |
| **Why policy fails** | A model can be prompted to "check password strength" but cannot enforce it at the cryptographic boundary; a compromised agent can skip the check entirely. The pepper lives outside the record store — stolen records alone are uncrackable offline. |
| **Enforced in** | `src/vega_identity/password.py`: `hash_password` (lines 63-72), `verify_password` (lines 89-99), `strength_problems` (lines 38-60) |
| **Test** | `tests/redteam_1_factors.py::Password::test_the_strength_floor`, `test_pepper_is_part_of_the_hash`, `test_malformed_records_and_inputs_never_raise_and_never_pass` |
| **Honest limit** | Strength floor is a minimum, not a guarantee; passphrases recommended. Pepper must be managed by caller (not included in package). Cost ceiling (2^20) prevents DoS but limits future-proofing. |

### 2. TOTP with replay protection and QR set-up

| Aspect | Detail |
|--------|--------|
| **Capability** | RFC 6238 TOTP (SHA-1/256/512), 6-8 digits, 15-120s step, ±1 window, base32 secret, QR encoder (byte mode, EC level M, versions 1-9), replay protection via monotonic counter |
| **Why policy fails** | A prompt "verify the code" cannot prevent replay; the counter must be stored and enforced at the verification boundary. The QR code contains the secret — showing it once on the enrolling user's screen is a physical constraint no policy can enforce. |
| **Enforced in** | `src/vega_identity/totp.py`: `verify` (lines 66-81) compares all candidate steps in constant time, rejects `hit <= last_counter`; `src/vega_identity/qr.py`: `encode`/`to_svg` |
| **Test** | `tests/redteam_1_factors.py::Totp::test_window_replay_and_reuse`, `test_the_published_rfc_6238_test_vectors`, `tests/redteam_1_factors.py::Qr::test_codes_decode_for_every_version_and_for_the_real_setup_uri` |
| **Honest limit** | SHA-1 is default for app compatibility (HMAC-SHA1 not weakened by collisions). Window ±1 allows clock drift but widens replay window. No hardware token binding — secret is software-stored. |

### 3. Phone codes with expiry, attempt limits, and send rate limiting

| Aspect | Detail |
|--------|--------|
| **Capability** | 6-8 digit codes, 300s TTL, 5 attempts per challenge, 3 sends/hour per number (E.164), delivery injected by caller, codes stored only as salted keyed HMAC hashes |
| **Why policy fails** | "Send a code and check it" as a prompt cannot enforce attempt limits, send limits, or prevent the code from being logged. The caller-supplied `send` function means the SDK never touches the transport — but also means delivery reliability is the caller's problem. |
| **Enforced in** | `src/vega_identity/phone.py`: `PhoneChallenges.start` (lines 49-73), `check` (lines 75-88) |
| **Test** | `tests/redteam_1_factors.py::Phone::test_expiry`, `test_wrong_codes_burn_attempts_and_then_kill_the_challenge`, `test_send_limits_and_open_cap`, `test_the_stored_hash_does_not_hold_the_code` |
| **Honest limit** | SIM swap attacks: phone factor weight=1, cannot lift assurance past level 1 alone. No built-in SMS gateway — caller must supply. Number stored as keyed hash only; if pepper rotates, rate limit history resets. |

### 4. Knowledge questions from private DKG sources

| Aspect | Detail |
|--------|--------|
| **Capability** | Governor for model-generated questions: only private sources (`private_session`, `private_note`, `private_file`); sensitive content filter (identifiers, money, health, passwords); answers stored as salted keyed HMAC-SHA256 hashes of key words; questions burned on ask (never reused); quiz with topic spread; exponential lockout on failure (1m, 2m, 4m... up to 1 day); 3 quiz starts/hour |
| **Why policy fails** | A model can be asked "generate a question only the user knows" but cannot enforce: source privacy, answer secrecy (model sees answer in context), single-use, or lockout. The salted keyed hash means even a stolen question bank reveals no answers without the pepper. |
| **Enforced in** | `src/vega_identity/knowledge.py`: `QuestionBank.add` (lines 53-79) filters sources/sensitivity/weakness; `start_quiz` (lines 85-105) burns questions; `_grade` (lines 107-119) matches key-word hashes with flood guard |
| **Test** | `tests/redteam_1_factors.py::Knowledge::test_facts_are_filtered`, `test_a_stolen_bank_holds_no_answers`, `test_a_quiz_grades_by_keywords_and_burns_every_question_it_shows`, `test_wrong_and_padded_answers_fail_and_wrong_quizzes_lock_for_longer` |
| **Honest limit** | Each question exposes one fact when shown. Someone who knows the user well (family, stalker) can guess answers. Adds assurance but never enough alone for level 4. Requires minimum 12 unused questions before available — new accounts cannot use it. |

### 5. Biometric templates with encryption and liveness

| Aspect | Detail |
|--------|--------|
| **Capability** | AES-256-GCM per-user template encryption (user-bound AAD); statistical reference feature matcher (per-feature mean/scale from enrollment, leave-one-out limit); spoken-phrase liveness challenge (4 random words, single-use, 60s TTL, 75% match); recording replay detection via SHA-256 audio digest (last 200); fail-closed if extractor/transcriber missing or crash |
| **Why policy fails** | "Check the voice" as a prompt cannot enforce: template encryption, liveness phrase freshness, replay detection, or fail-closed behavior when the speaker model crashes. The template is a secret that cannot be rotated if stolen — it must never be in the clear. |
| **Enforced in** | `src/vega_identity/biometric.py`: `TemplateVault` (lines 29-46), `FeatureMatcher` (lines 48-79), `Liveness` (lines 82-106), `VoiceFactor.verify` (lines 119-137) |
| **Test** | `tests/redteam_1_factors.py::Biometric::test_the_vault_encrypts_per_user`, `test_the_reference_matcher_accepts_the_owner_and_rejects_others`, `test_liveness_phrases_are_single_use_and_expire`, `test_missing_plug_ins_and_crashes_fail_closed`, `test_a_recording_cannot_be_used_twice_and_a_template_cannot_be_used_by_another_user` |
| **Honest limit** | Voice can be cloned; live deepfakes can speak random phrases. Voice factor weight=1, cannot lift assurance past level 1 alone. No speaker-recognition model included — reference matcher is statistical only. Real deployment needs a speaker embedding model and STT engine as plug-ins. |

### 6. Assurance levels from factor families and weights

| Aspect | Detail |
|--------|--------|
| **Capability** | Computes level 0-4 from fresh factors (15-min window): 0=none, 1=any, 2=2 families + weight≥3, 3=weight≥5 + strong 'has', 4=3 families + weight≥7 + device_key/totp. Maps actions to required levels (CLASS_LEVEL prefixes + HUMAN_ONLY=4). Issues HMAC-SHA256 signed assertions (user_ref, level, families, used, issued, expiry, nonce). `verify` and `allow` fail closed. |
| **Why policy fails** | A model cannot be trusted to compute its own authorization level. The level must be derived cryptographically from fresh, single-use factors — not from a claim. The assertion is signed by a secret the model never holds. |
| **Enforced in** | `src/vega_identity/assurance.py`: `level_of` (lines 34-49), `required_level` (lines 52-61), `issue`/`verify`/`allow` (lines 68-91) |
| **Test** | `tests/redteam_1_factors.py::Assurance::test_the_level_table`, `test_stale_future_and_unknown_factors_count_for_nothing`, `test_assertions_are_signed_short_and_checked`, `test_allow_needs_a_genuine_assertion_at_the_actions_level` |
| **Honest limit** | Phone and voice weight=1 (SIM swap, cloning) — cannot carry level 2+ alone. 15-min freshness window matches commitment lease but may be too long for high-value actions. HUMAN_ONLY actions always need level 4 — no override. |

### 7. Identity service orchestration with chain-first recording

| Aspect | Detail |
|--------|--------|
| **Capability** | Orchestrates enrolment, all 6 factors, single failure counter with exponential lockout, chain-first recording (success only if dag.write succeeds), dummy hash for unknown users (timing equality), assertion issuance with chain record, TOTP counter saved before success reported, device challenge single-use |
| **Why policy fails** | A prompt "log the attempt" cannot enforce: chain-write-before-success, shared failure counter across factors, locked-user behavior, or timing equality for unknown users. The dag is the source of truth — if it's unavailable, the system stops. |
| **Enforced in** | `src/vega_identity/service.py`: `Identity.enrol` (lines 67-76), `Login._pass` (lines 133-138), `Login._no` (lines 140-143), `Identity._fail` (lines 57-64), `assertion` (lines 229-236) |
| **Test** | `tests/redteam_2_service.py::Logins::test_password_alone_is_level_one_and_the_assertion_checks_out`, `Lockout::test_five_failures_lock_for_a_minute_then_longer_and_success_resets`, `Lockout::test_unknown_and_locked_people_get_the_same_plain_no`, `SetupAndRecord::test_if_the_chain_cannot_be_written_nothing_succeeds` |
| **Honest limit** | State lives in memory (caller must persist encrypted). No account recovery. No network/session layer. Chain failure = total availability loss for that identity. |

## DKG + lattice integration

This kit **consumes** the DKG (via `vega-dkg-lattice-sdk`) as a source of private facts for knowledge questions:

- **Import:** `from vega_custody.dag.dag import contains_credential` (used in `knowledge.py` line 20)
- **Flow:** Model reads DKG → proposes facts → `QuestionBank.add` filters (private sources only, no sensitive content) → answers stored as salted keyed hashes → quiz draws from bank
- **No direct import of** `vega-reasoning-sdk` or `vega-galaxy-sdk` — those are up-layer consumers of this kit's output (assurance assertions)

The lattice does not influence factor verification directly; it only feeds the question generator. The assurance level is computed purely from factor freshness, families, and weights.

## Family predictive loop role

This kit plays a specific role in the Vega family's predictive loop:

```
records → lessons → knowledge graph → lattice foresight → human decision
    │                                                          ▲
    │                     (this kit produces records)          │
    └──────────────────────────────────────────────────────────┘
```

1. **Records:** Every factor attempt (success/failure) and assertion issuance writes to the custody dag (`ID_FACTOR_OK`, `ID_FACTOR_FAIL`, `ID_LOCKED`, `ID_ASSERTION`). These records are the raw material.
2. **Lessons:** `vega-librarian-sdk` (layer 5) distills patterns from these records — e.g., "user X fails TOTP at 3 AM" or "voice factor false-reject rate is Y%".
3. **Knowledge graph:** `vega-dkg-lattice-sdk` (layer 7) builds the graph with origin/licence per fact — including identity events.
4. **Lattice foresight:** `vega-reasoning-sdk` (layer 11) forecasts from the graph — e.g., "probability of lockout in next hour given current failure rate".
5. **Human decision:** `vega-governance-feed-sdk` (layer 13) / `vega-galaxy-sdk` (layer 14) show the forecast to the human, who adjusts factor enrolment or assurance thresholds.

This kit does not run the lattice or produce foresight — it produces the **ground-truth records** that make the loop possible.

## A category of its own

What differentiates this identity architecture from policy-based approaches:

| Differentiator | What this design does |
|----------------|----------------------|
| **Authority outside the model** | Factors are cryptographic checks; the model never holds the pepper, TOTP secret, device key, or assertion signing key. A compromised model cannot mint factors or assertions. |
| **Deterministic factor verification** | No model in the verification loop. `verify_password`, `totp.verify`, `phone.check`, `knowledge._grade`, `biometric.match`, `assurance.allow` are pure functions with fail-closed semantics. |
| **Single-use human commitments** | The assurance assertion feeds the jacket's commitment gate — but the commitment key is human-only. Identity proves *who*; the commitment proves *what action*. |
| **Chain-of-custody by default** | Every factor event lands in the append-only dag. No separate logging pipeline to configure or lose. |
| **Lattice-informed foresight** | The records this kit produces feed the librarian → DKG → reasoning → galaxy pipeline, giving the human predictive visibility into their own identity posture (lockout risk, factor ageing, anomaly patterns). |

**Honest framing:** This is a reference implementation with tests. It has not been independently security-reviewed; the cryptography has not been expert-reviewed. The voice factor's statistical matcher is a placeholder for a real speaker-embedding model. Do not protect real secrets with it before an independent review.
