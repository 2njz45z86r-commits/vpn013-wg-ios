## Security release rule
For every website, app, API, or bot task, read SECURITY-POLICY.md and SECURITY-CHECKLIST.md from the repository root before changing or publishing code. Apply all 34 checks to the exact source state. Audit read-only first; mask secrets; keep detailed findings private. Do not publish with findings, unverified items, or an outdated/incomplete security-review.json. Complete safe implementation work and report any remaining release blocker accurately. The CI gate verifies review records; it does not replace the audit.

