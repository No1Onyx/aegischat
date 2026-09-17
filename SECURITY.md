# Security Policy

## Status

**AegisChat has not had an independent security audit.** It should be treated as
pre-release software. Do not rely on it as the sole protection for
communications where disclosure would put someone at risk of harm until it has
been reviewed by qualified third parties and tested in the field.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what the design intends to
protect and, importantly, what it does **not**.

## Reporting a vulnerability

Please report privately. Do **not** open a public issue for a security bug.

- Email: `mku95.at@gmail.com` (PGP key fingerprint:
  `7F2B 0720 992C 4F15 1B76  EB34 358D A78E C2B7 8227`,
  public key: [`SECURITY.pgp.asc`](SECURITY.pgp.asc))
- Expect an acknowledgement within 7 days.
- Please include: affected component, version/commit, a description of the
  impact, and steps or a proof-of-concept to reproduce.
- Coordinated disclosure: we aim to ship a fix within 90 days of a confirmed
  report and will credit you unless you ask otherwise.

If you believe a report describes an actively exploited issue affecting real
users, say so prominently.

## Scope

In scope: `client/`, `server/`, `core-crypto/`, the protocols, the build.

Out of scope (see threat model for detail): attacks requiring a pre-compromised
unlocked device; global traffic-correlation; social engineering of users;
issues in third-party dependencies (report those upstream, but do tell us so we
can pin/patch).

## What we've done so far

The `SECURITY_REVIEW_CHECKLIST.md` and threat model document the current
posture. In brief: X3DH + Double Ratchet (with a `MAX_SKIP` bound and
commit-after-verify), Signal-style Sender Keys for groups, sealed-sender so the
relay does not see 1:1 or group senders, trust-on-first-use identity pinning
with forced safety-number verification, Argon2id-derived at-rest encryption of
all key material, a duress phrase, and bounded server resources. Automated
tests: `npm run test:crypto`, `npm run test:security`, `npm run test:live`,
`cargo test`, plus adversarial-input and fuzz targets.
