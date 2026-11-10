'use strict';
// Dependency-free tests: extract the logic block from log-sanitizer.html and run it in Node.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'log-sanitizer.html'), 'utf8');
const START = '/* === LOGIC:START === */';
const END = '/* === LOGIC:END === */';
const block = html.slice(html.indexOf(START) + START.length, html.indexOf(END));
const LS = new Function(block + '\nreturn LS;')();

// Fake secrets are built by concatenation so secret scanners do not mistake them for leaks.
const FAKE = {
  aws: 'AKIAIOSFODNN7EXAMPLE',
  ghp: 'gh' + 'p_' + '0123456789abcdefghijklmnopqrstuvwxyz',
  slack: 'xo' + 'xb-' + '123456789012-1234567890123-abcdefghijklmnopqrstuvwx',
  google: 'AI' + 'zaSyA-1234567890abcdefghijklmnopqrstu',
  stripe: 'sk_' + 'live_' + 'EXAMPLEEXAMPLE1234567890',
  npm: 'np' + 'm_' + '0123456789abcdefghijklmnopqrstuvwxyz',
  gitlab: 'gl' + 'pat-' + 'abcdefghij0123456789',
  jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  pem: '-----BEGIN ' + 'RSA PRIVATE KEY-----\nMIIFAKEFAKEFAKE0000\nFAKEFAKEFAKE1111\n-----END ' + 'RSA PRIVATE KEY-----'
};

const run = (text, opts) => LS.sanitize(text, opts);
const out = (text, opts) => run(text, opts).text;

test('e-mail', () => {
  assert.equal(out('write to alice@example.com now'), 'write to [EMAIL] now');
  assert.equal(out('a.b+tag@sub.example.co.uk.'), '[EMAIL].');
  assert.equal(out('no mail here @ all, x@y'), 'no mail here @ all, x@y');
});

test('IPv4: positives and false positives', () => {
  assert.equal(out('from 203.0.113.42 port 22'), 'from [IPV4] port 22');
  assert.equal(out('ip=192.0.2.1.'), 'ip=[IPV4].');
  assert.equal(out('version 1.2.3.4 released'), 'version 1.2.3.4 released');
  assert.equal(out('app v1.2.3.4'), 'app v1.2.3.4');
  assert.equal(out('999.1.1.1 and 256.0.0.1'), '999.1.1.1 and 256.0.0.1');
  assert.equal(out('1.2.3.4.5 oid 1.3.6.1.4.1'), '1.2.3.4.5 oid 1.3.6.1.4.1');
  assert.equal(out('date 2024.01.15 and 3.14159'), 'date 2024.01.15 and 3.14159');
});

test('IPv4: private address option', () => {
  const t = 'a 10.0.0.5 b 192.168.1.1 c 127.0.0.1 d 172.16.0.1 e 203.0.113.9 f 172.32.0.1';
  assert.equal(out(t, { skipPrivate: true }), 'a 10.0.0.5 b 192.168.1.1 c 127.0.0.1 d 172.16.0.1 e [IPV4] f [IPV4]');
  assert.equal(out('x 10.0.0.5'), 'x [IPV4]');
});

test('IPv6', () => {
  assert.equal(out('addr 2001:db8::8a2e:370:7334 ok'), 'addr [IPV6] ok');
  assert.equal(out('addr 2001:0db8:0000:0000:0000:ff00:0042:8329'), 'addr [IPV6]');
  assert.equal(out('time 10:23:45 and 12:30'), 'time 10:23:45 and 12:30');
  assert.equal(out('lo ::1 fe80::1', { skipPrivate: true }), 'lo ::1 fe80::1');
  assert.equal(out('lo ::1'), 'lo [IPV6]');
  assert.equal(out('see 2001:db8::1: failed'), 'see [IPV6]: failed');
});

test('MAC', () => {
  assert.equal(out('mac 00:1B:44:11:3A:B7 up'), 'mac [MAC] up');
  assert.equal(out('mac 00-1b-44-11-3a-b7'), 'mac [MAC]');
  assert.equal(out('not 00:1B:44:11:3A'), 'not 00:1B:44:11:3A');
});

test('JWT', () => {
  assert.equal(out('t=' + FAKE.jwt + ' end', { types: { kv: false } }), 't=[JWT] end');
  assert.equal(out('eyJabc.def'), 'eyJabc.def');
});

test('prefixed keys', () => {
  for (const k of ['aws', 'ghp', 'slack', 'google', 'stripe', 'npm', 'gitlab']) {
    assert.equal(out('key ' + FAKE[k] + ' end'), 'key [KEY] end', k);
  }
  assert.equal(out('github_pat_' + 'A'.repeat(30)), '[KEY]');
  assert.equal(out('AKIA123'), 'AKIA123');
});

test('authorization headers and cookies', () => {
  assert.equal(out('Authorization: Bearer abc.def-123'), 'Authorization: Bearer [SECRET]');
  assert.equal(out('Authorization: Basic dXNlcjpwYXNz'), 'Authorization: Basic [SECRET]');
  assert.equal(out('X-Api-Key: zzz999'), 'X-Api-Key: [SECRET]');
  assert.equal(out('Cookie: sid=abc; theme=dark'), 'Cookie: sid=[SECRET]; theme=[SECRET]');
  assert.equal(out('Set-Cookie: sid=abc; Path=/; HttpOnly; Secure'), 'Set-Cookie: sid=[SECRET]; Path=/; HttpOnly; Secure');
});

test('key=value pairs and JSON', () => {
  assert.equal(out('password=hunter2 next'), 'password=[SECRET] next');
  assert.equal(out('{"password": "hunter2", "name": "x"}'), '{"password": "[SECRET]", "name": "x"}');
  assert.equal(out("db_passwd: 'p@ss'"), "db_passwd: '[SECRET]'");
  assert.equal(out('client_secret=abc&api_key=def'), 'client_secret=[SECRET]&api_key=[SECRET]');
  assert.equal(out('--password=abc'), '--password=[SECRET]');
  assert.equal(out('author=bob authors: x'), 'author=bob authors: x');
  assert.equal(out('token: null'), 'token: null');
  assert.equal(out('password:\nnext'), 'password:\nnext');
});

test('URL credentials: user and pass are masked', () => {
  assert.equal(out('https://bob:s3cret@host.example.com/p'), 'https://[USER]:[SECRET]@host.example.com/p');
  assert.equal(out('https://example.com/a@b'), 'https://example.com/a@b');
});

test('priority: password inside URL and token inside JSON field', () => {
  const r = run('url=postgres://u:pw123@db.example.com password=pw123');
  assert.equal(r.text, 'url=postgres://[USER]:[SECRET]@db.example.com password=[SECRET]');
  assert.equal(out('{"token": "' + FAKE.jwt + '"}'), '{"token": "[JWT]"}');
  assert.equal(out('token=' + FAKE.ghp), 'token=[KEY]');
  assert.equal(out('Authorization: Bearer ' + FAKE.jwt), 'Authorization: Bearer [JWT]');
  // an e-mail-like part of URL credentials must not be split
  assert.equal(out('ftp://me:x@example.com/'), 'ftp://[USER]:[SECRET]@example.com/');
});

test('private key block with line breaks', () => {
  const t = 'before\n' + FAKE.pem + '\nafter';
  assert.equal(out(t), 'before\n[PRIVATE_KEY]\nafter');
  const t2 = '{"private_key": "' + FAKE.pem.replace(/\n/g, '\\n') + '"}';
  assert.ok(!out(t2).includes('MIIFAKE'));
});

test('Luhn check and cards', () => {
  assert.ok(LS.luhnOk('4111111111111111'));
  assert.ok(!LS.luhnOk('4111111111111112'));
  assert.equal(out('card 4111 1111 1111 1111 ok'), 'card [CARD] ok');
  assert.equal(out('card 4111-1111-1111-1111'), 'card [CARD]');
  assert.equal(out('card 4111 1111 1111 1112'), 'card 4111 1111 1111 1112');
  assert.equal(out('ts 1699999999999 id 1234567890123456'), 'ts 1699999999999 id 1234567890123456');
});

test('IBAN mod 97 check', () => {
  assert.ok(LS.ibanOk('GB82WEST12345698765432'));
  assert.ok(!LS.ibanOk('GB82WEST12345698765433'));
  assert.equal(out('iban GB82 WEST 1234 5698 7654 32 end'), 'iban [IBAN] end');
  assert.equal(out('iban DE89370400440532013000'), 'iban [IBAN]');
  assert.equal(out('iban GB82 WEST 1234 5698 7654 32 AND more'), 'iban [IBAN] AND more');
  assert.equal(out('iban GB82 WEST 1234 5698 7654 33'), 'iban GB82 WEST 1234 5698 7654 33');
});

test('phones', () => {
  assert.equal(out('call +1 (202) 555-0143 now'), 'call [PHONE] now');
  assert.equal(out('call +49 30 123456 now'), 'call [PHONE] now');
  assert.equal(out('1234567890 and 202-555-0143 and +123'), '1234567890 and 202-555-0143 and +123');
  assert.equal(out('2024-01-15T10:00:00+0100 +2024-01-15'), '2024-01-15T10:00:00+0100 +2024-01-15');
});

test('optional detectors are off by default', () => {
  const t = 'host app01.corp.example.com id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 user=alice';
  assert.ok(out(t).includes('app01.corp.example.com'));
  assert.ok(out(t).includes('3f2504e0'));
  assert.equal(out('user=alice').includes('alice'), true);
});

test('hosts, UUID, usernames', () => {
  const on = { types: { hosts: true, uuid: true, usernames: true } };
  assert.equal(out('see app01.corp.internal ok', on), 'see [HOST] ok');
  assert.equal(out('id 3f2504e0-4f89-11d3-9a0c-0305e82c3301', on), 'id [UUID]');
  assert.equal(out('user=alice', on), 'user=[USER]');
  assert.equal(out('username: bob', on), 'username: [USER]');
  assert.equal(out('Failed password for root from 203.0.113.1', Object.assign({}, on)), 'Failed password for [USER] from [IPV4]');
  assert.equal(out('app.log config.json', on), 'app.log config.json');
});

test('custom words and regexes', () => {
  const o = { types: { custom: true }, custom: ['ProjectX', 're:ORD-\\d{4}', 're:(', ''] };
  assert.equal(out('ProjectX order ORD-1234 done', o), '[CUSTOM] order [CUSTOM] done');
  assert.equal(LS.buildCustom(o.custom).errors.length, 1);
  assert.equal(out('ProjectX', { custom: ['ProjectX'] }), 'ProjectX'); // checkbox is off
});

test('whitelist', () => {
  const o = { whitelist: ['support@example.com', '203.0.113.1'] };
  assert.equal(out('a support@example.com b other@example.com c 203.0.113.1 d 203.0.113.2', o),
    'a support@example.com b [EMAIL] c 203.0.113.1 d [IPV4]');
  // a whitelisted value must not let nested detectors fire
  assert.equal(out('x support@example.com', { whitelist: ['support@example.com'], types: { hosts: true } }), 'x support@example.com');
});

test('replacement modes', () => {
  const t = 'a@example.com 4111 1111 1111 1111 ' + FAKE.aws;
  assert.equal(out(t, { mode: 'type' }), '[EMAIL] [CARD] [KEY]');
  assert.equal(out(t, { mode: 'remove' }), '[REDACTED] [REDACTED] [REDACTED]');
  assert.equal(out(t, { mode: 'partial' }), '[EMAIL] ************1111 ' + '*'.repeat(16) + 'MPLE');
  assert.equal(out(t, { mode: 'pseudonyms' }), 'EMAIL_1 CARD_1 KEY_1');
  assert.equal(out('password=abcd', { mode: 'partial' }), 'password=****');
});

test('alias stability', () => {
  const s = LS.createSession();
  const a = LS.sanitize('a@example.com b@example.com a@example.com 203.0.113.1 203.0.113.2', { mode: 'pseudonyms' }, s).text;
  assert.equal(a, 'EMAIL_1 EMAIL_2 EMAIL_1 IPV4_1 IPV4_2');
  const b = LS.sanitize('later b@example.com and c@example.com and 203.0.113.2', { mode: 'pseudonyms' }, s).text;
  assert.equal(b, 'later EMAIL_2 and EMAIL_3 and IPV4_2');
});

test('reversibility: restore(sanitize(x)) === x', () => {
  const ips = Array.from({ length: 12 }, (_, i) => '203.0.113.' + (i + 1)).join(' ');
  const x = [
    'mail a@example.com ' + ips, 'Authorization: Bearer abc123token', 'password=hunter2',
    'https://u:p@h.example.com/', 'card 4111 1111 1111 1111', 'iban GB82 WEST 1234 5698 7654 32',
    '+1 202 555 0143', FAKE.aws, FAKE.pem, FAKE.jwt, 'ip 2001:db8::1 mac 00:1B:44:11:3A:B7'
  ].join('\n');
  const s = LS.createSession();
  const r = LS.sanitize(x, { mode: 'pseudonyms' }, s);
  assert.notEqual(r.text, x);
  assert.ok(r.text.includes('IPV4_10'));
  assert.equal(LS.restore(r.text, LS.exportMap(s)), x);
  assert.equal(LS.restore(r.text, JSON.stringify(LS.exportMap(s))), x);
});

test('restore: long aliases are not broken by short ones', () => {
  const map = { entries: [{ alias: 'IPV4_1', original: 'A' }, { alias: 'IPV4_10', original: 'B' }] };
  assert.equal(LS.restore('IPV4_10 IPV4_1 IPV4_10', map), 'B A B');
  assert.throws(() => LS.restore('x', '{not json'));
  assert.throws(() => LS.restore('x', {}));
});

test('aliases do not clash with labels already in the text', () => {
  const x = 'EMAIL_1 is a word, mail a@example.com';
  const s = LS.createSession();
  const r = LS.sanitize(x, { mode: 'pseudonyms' }, s);
  assert.equal(r.text, 'EMAIL_1 is a word, mail EMAIL_2');
  assert.equal(LS.restore(r.text, LS.exportMap(s)), x);
});

test('idempotency in all modes', () => {
  const x = [
    'a@example.com 203.0.113.1 2001:db8::1 00:1B:44:11:3A:B7', 'password=hunter2 token: "abc"',
    'https://bob:pw@h.example.com/', 'Authorization: Bearer abc.def', 'Cookie: sid=abc',
    '4111 1111 1111 1111', 'GB82 WEST 1234 5698 7654 32', '+1 202 555 0143',
    FAKE.aws, FAKE.jwt, FAKE.pem, 'user=alice host x.corp.internal 3f2504e0-4f89-11d3-9a0c-0305e82c3301'
  ].join('\n');
  const all = { types: { hosts: true, uuid: true, usernames: true } };
  for (const mode of ['type', 'pseudonyms', 'partial', 'remove']) {
    const once = LS.sanitize(x, Object.assign({ mode }, all)).text;
    const twice = LS.sanitize(once, Object.assign({ mode }, all)).text;
    assert.equal(twice, once, mode);
    assert.equal(LS.sanitize(once, Object.assign({ mode }, all)).total, 0, mode + ' total');
  }
});

test('per-type counters', () => {
  const r = run('a@example.com b@example.com 203.0.113.1 password=x');
  assert.deepEqual({ ...r.counts }, { EMAIL: 2, IPV4: 1, SECRET: 1 });
  assert.equal(r.total, 4);
  assert.equal(r.segments.length, 4);
});

test('disabled types do not fire', () => {
  assert.equal(out('a@example.com', { types: { email: false } }), 'a@example.com');
});

test('performance: 5 MB in under 3 seconds', () => {
  const line = '2025-03-14 10:21:08 INFO user=alice mail a@example.com from 203.0.113.42 token=abc123 card 4111 1111 1111 1111 pid=12345 ok\n';
  const filler = 'GET /index.html 200 1532 "Mozilla/5.0" took 12ms version 1.2.3.4 trace 0123456789abcdef\n';
  let text = '';
  while (text.length < 5 * 1024 * 1024) text += line + filler;
  const t0 = process.hrtime.bigint();
  const r = LS.sanitize(text, { mode: 'pseudonyms', types: { hosts: true, uuid: true, usernames: true } });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(r.total > 1000);
  assert.ok(ms < 3000, 'too slow: ' + Math.round(ms) + ' ms');
});
