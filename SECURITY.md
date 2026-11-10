# Security

Log Sanitizer is fully offline: the page makes no network requests, and a strict Content-Security-Policy
(`default-src 'none'`) technically forbids them in the browser. Text and the mapping live only in page memory.
Only checkboxes and the replacement mode are saved to localStorage.

## How to report a problem

- **A missed pattern** (the tool failed to find a secret of a known format) or a false positive: open an
  [Issue](https://github.com/ravigaming222/log-sanitizer/issues). Use **fictional examples only**, never real secrets.
- **A vulnerability in the page itself** (for example XSS, a CSP bypass or a data leak): use
  [Security Advisories](https://github.com/ravigaming222/log-sanitizer/security/advisories/new) so it is not disclosed publicly before a fix.

## What the tool does not guarantee

It finds known patterns and does not replace manual review. See "Threat model and limitations" in the README.
