# Security Policy

## Supported versions
Only the latest release of DoctorG receives security fixes.

## Reporting a vulnerability
Please do NOT open a public issue for security problems.

Use GitHub's private reporting instead:
1. Open the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe the problem, the steps to reproduce it, your Android version, phone model and the DoctorG version.

We aim to reply within 7 days and will credit you in the release notes if you wish.

## In scope
- Bugs that leak user data or bypass App Lock, Vault or SMS command PIN checks
- Ways to run commands or wipe a phone without the owner's consent
- Tampering with signature, rule or blocklist updates
- Scanner flaws that could be abused

## Out of scope
- False positives and false negatives in scan results (use the "False positive" issue template)
- Issues that need a rooted or already-compromised phone
- Social engineering and spam reports

## Please do not
- Share keystores, passwords or personal data in issues or discussions
- Test against devices or accounts you do not own
