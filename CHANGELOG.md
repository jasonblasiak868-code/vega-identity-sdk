# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **Parallel guesses were all evaluated before any lockout landed.** 20 parallel wrong passwords were all counted and checked (the limit is 5). One person's factor attempts now run one at a time, so the lock lands after the fifth failure.
- **Passing one factor cleared the failure counter.** Someone who knew the password could alternate clearing the count with second-factor guesses without limit. The count is no longer cleared by a success; failures stop counting after 15 minutes without a new one (`FAIL_WINDOW`).
- **Phone codes:** the per-challenge attempt limit and the per-number send limit could be exceeded in parallel (25 attempts and 12 texts against limits of 5 and 3). Both now hold.
- A TOTP code could be replayed by racing two logins; `enrol` could create the same name twice. Both fixed.

### Changed (read before upgrading)
- The failure counter is no longer reset by a successful factor. It decays by time instead.
