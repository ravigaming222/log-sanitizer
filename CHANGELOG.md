# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [SemVer](https://semver.org/).

## [1.0.1] - 2026-11-10

### Changed
- The UI, README, SECURITY, CHANGELOG, tests and code comments are now in English.

## [1.0.0] - 2026-11-10

### Added
- A single self-contained `log-sanitizer.html` with no build, dependencies or network requests (the CSP forbids the network).
- Detectors: e-mail, IPv4, IPv6, MAC, JWT, prefixed keys (AWS, GitHub, Slack, Google, Stripe, npm, GitLab), authorization headers and cookies, key=value pairs and JSON fields, URL credentials, private key blocks, cards (Luhn), IBAN (mod 97), phones.
- Optional detectors: internal hosts and FQDNs, UUID, usernames, custom words and regexes; a whitelist.
- Replacement modes: type, stable pseudonyms, partial mask, full removal.
- Mapping file (JSON) and the "Restore" tab.
- Single-pass replacement with priority-based overlap resolution.
- Node tests (`npm test`), CI and an automatic release on `v*` tags.
