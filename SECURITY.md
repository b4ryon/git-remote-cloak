# Security Policy

git-remote-cloak is an encryption tool, so the correctness of its security
invariants is the whole point. Reports showing a way to break confidentiality,
integrity, authenticity, rollback or repo-identity protection, or the
fail-closed behavior are especially valuable. The project is maintained on a
best-effort basis by a single maintainer; the process below reflects what can
actually be operated, not a formal program.

## Supported versions

Security fixes are issued only for the latest released version (the most recent
git tag). Older pre-1.0 versions do not receive updates; upgrade to the latest
release.

| Version                          | Supported |
|----------------------------------|-----------|
| Latest release (most recent tag) | Yes       |
| Any older version                | No        |

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions, or via social media or direct messages.

Report privately through GitHub's private vulnerability reporting: the
repository's Security tab -> Report a vulnerability
(https://github.com/b4ryon/git-remote-cloak/security/advisories/new). This
opens an advisory visible only to you and the maintainer.

## What to include

Where you can, include:

- the affected version, tag, or commit SHA;
- a clear description of the issue and why it is a security problem;
- steps to reproduce or a proof of concept;
- relevant logs, payloads, or screenshots;
- the security impact, and any known mitigation or fix.

Never send real secrets in a report: no master key, exported key material, or
plaintext repository contents (redacted or synthetic examples are enough). Do
not run destructive tests against hosts or data you do not own, and do not
publish an exploit before a fix is available.

## Response expectations

- Acknowledgment within 5 business days.
- An initial assessment (confirmed or not, and likely severity) as triage time
  allows, with follow-up through the private advisory thread.

This is a personal open-source project: best-effort response times, no bug
bounty.

## Disclosure

Confirmed vulnerabilities are handled through GitHub Security Advisories. A fix
is prepared and released first, then the advisory is published, crediting the
reporter unless you ask otherwise; timing is coordinated with you where
practical.

## Out of scope

These are documented, accepted trade-offs of the design, not vulnerabilities
(see "Trust model and accepted risks" in `README.md`):

- Metadata the host inevitably observes: the repository's existence, owner,
  total size, pack count and sizes, the generation/push count, and push timing.
- Trust-on-first-use on a brand-new clone (no pin yet); close it by comparing
  `git cloak status` against another machine.
- Local or endpoint compromise: cloak trusts the machines that hold the key and
  their Keychain/disk.
- `git cloak key export --force-insecure` deliberately skipping the
  user-presence gate for non-interactive backups.
