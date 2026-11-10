# Log Sanitizer

An offline, single-file HTML tool that strips secrets and personal data (keys, tokens, e-mails, IPs, cards and more) from logs, tickets and configs before you share them. No network, no dependencies, no build step. MIT licensed.

People copy logs together with passwords, tokens and addresses, then send them to colleagues, paste them into tickets or chats, or hand them to an AI assistant. Log Sanitizer removes that data locally in your browser: download one file, `log-sanitizer.html`, and open it with a double click.

## Features

- One self-contained file (HTML, CSS and JS inside), no build and no dependencies.
- Nothing leaves your machine. A strict Content-Security-Policy (`default-src 'none'`) technically forbids network requests. You can turn off your internet and verify.
- Every data type has its own checkbox; there is also a whitelist and custom words or regexes.
- Four replacement modes, stable pseudonyms and reversible restoration through a mapping file.
- Single-pass replacement with overlap resolution; works on inputs up to 5 MB.
- Re-running already sanitized text is safe: the tool's own labels are never masked again.

## What it detects

| Type | What it catches | Default |
|---|---|---|
| E-mail | addresses like `name@domain.tld` | on |
| IPv4 | four octets 0-255; versions after `version`/`v` are ignored | on |
| IPv6 | full and compressed forms (strict validation, times like `10:23:45` are not matched) | on |
| MAC | `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` | on |
| JWT | three base64url parts starting with `eyJ` | on |
| Prefixed keys | AWS (`AKIA`/`ASIA`), GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), Slack (`xox[baprs]-`), Google (`AIza`), Stripe (`sk_live_`, `rk_live_`), npm (`npm_`), GitLab (`glpat-`) | on |
| Authorization headers | `Authorization: Bearer/Basic ...`, `X-Api-Key`, `Cookie`/`Set-Cookie` values (attributes such as `Path` or `Expires` are left alone) | on |
| key=value and JSON | values of fields named `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `apikey`, `access_key`, `private_key`, `client_secret`, `auth`; the field name is kept | on |
| URL credentials | `scheme://user:pass@host`: both user and pass are masked | on |
| Private keys | the whole `-----BEGIN ... PRIVATE KEY-----` ... `-----END ... PRIVATE KEY-----` block | on |
| Bank cards | 13-19 digits (spaces and hyphens allowed), first digit 2-6, only if the Luhn check passes | on |
| IBAN | only if the mod 97 check passes | on |
| Phones | international format: `+` and 8-15 digits, deliberately conservative | on |
| Internal hosts and FQDNs | names with well-known TLDs and internal zones (`.internal`, `.corp`, `.local`, ...) | off |
| UUID | standard 8-4-4-4-12 form | off |
| Usernames | `user=`, `username:`, `for <name> from` | off |
| Custom words and regexes | one per line, `re:` prefix for a regex | off |

The option "Skip private and loopback addresses" (off by default) leaves `10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16` and, for IPv6, `::1`, `fe80::/10`, `fc00::/7` untouched.
Whitelist: values that must never be masked (one per line, exact match).

## Replacement modes

1. **Type**: `[EMAIL]`, `[IPV4]`, `[JWT]`, `[SECRET]` and so on.
2. **Pseudonyms**: `EMAIL_1`, `IPV4_1`, `IPV4_2`. The same original value always gets the same pseudonym within a session.
3. **Partial mask**: keeps the last 4 characters (`************1234`), for cards, keys and tokens only; other types behave like "Type".
4. **Removal**: `[REDACTED]`.

## Using restoration

1. Pick the "Pseudonyms" mode and sanitize your text. Send the sanitized text to an assistant or a colleague.
2. Click "Download mapping (JSON)". **The file contains the original secrets: never pass it on.**
3. When a reply containing pseudonyms comes back, open the "Restore" tab, paste the reply, paste or load the mapping (if the mapping field is empty, the current session mapping is used) and click "Restore".

Substitution goes from the longest pseudonyms to the shortest, so `IPV4_10` is not broken by replacing `IPV4_1`. The mapping lives only in page memory: nothing is written to disk or localStorage until you download it yourself. "Clear text" also wipes the session mapping.

## Try online

Live copy (still fully client-side, nothing is uploaded): <https://ravigaming222.github.io/log-sanitizer/>

## Download

Latest release: <https://github.com/ravigaming222/log-sanitizer/releases/latest>. A release contains `log-sanitizer.html`, the archive `log-sanitizer-<tag>.zip` and `SHA256SUMS.txt`. To verify checksums (keep the files in the same folder):

```bash
sha256sum -c SHA256SUMS.txt
```

## Run locally

Download `log-sanitizer.html` and open it in a browser with a double click. No server is needed. To run the tests (Node.js 18+, no dependencies):

```bash
npm test
```

## How it works

- **Single-pass detection.** All enabled detectors scan the original text and collect matches (position, type, priority). Overlaps are then resolved by priority: private keys > JWT and prefixed keys > URL credentials > headers and key=value pairs > cards and IBAN > e-mail > IP and MAC > phones > the rest. On equal priority the longer match wins. The output is then built in one pass over positions, with no sequential `replace` over the whole text. That is why, for example, a password inside a URL or a token inside a JSON field is masked exactly once and correctly.
- **Why pseudonyms are stable.** A session keeps a table "type + original value -> pseudonym" and per-type counters. A repeated value reuses its pseudonym, a new one takes the next number. If the text already contains something like `EMAIL_1`, that pseudonym is never issued, so restoration cannot get confused.
- **Idempotency.** Values that are themselves labels (`[EMAIL]`, `EMAIL_1`, `****1234`) are not masked again.
- **Output.** The result is shown in a textarea; optional highlighting is built through the DOM API and `textContent`, never `innerHTML` with user data. For very large results highlighting is turned off.
- **Code layout.** The pure logic (no DOM) sits between the `LOGIC:START` and `LOGIC:END` markers in `log-sanitizer.html`; the tests extract it from there directly.

## Threat model and limitations

Goal: avoid leaking secrets by accident when copying logs. The tool runs in the user's browser and has no network access.

What the tool does **not** guarantee:

- It finds **known patterns** only. It is not a replacement for manual review: always reread the result before sending it.
- People's names, company names, order numbers and other arbitrary business data without a recognizable pattern are **not found** (use custom words and regexes for them).
- Secrets in non-standard formats, split across several lines or encoded (base64, URL encoding, JSON escaping) may be missed.
- The mapping file **contains the originals** of your secrets. Treat it as a secret and do not share it with anyone you would not trust with the originals.
- Custom regexes run as written: a pathological regex can hang the tab.
- Phones and cards are matched conservatively (only `+` international format; cards need a valid Luhn sum and a first digit 2-6), so misses and rare false positives are possible.

To report a problem see [SECURITY.md](SECURITY.md).

## Ideas

- Batch processing of several files.
- More key and token formats, driven by requests in Issues.
- Export and import of a settings bundle together with custom rules.
- Extended IBAN validation using per-country lengths.

## License

[MIT](LICENSE), © 2026 ravigaming222.
