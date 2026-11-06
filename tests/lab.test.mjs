import test from 'node:test';
import assert from 'node:assert/strict';
import { dissect, gradeHeaders, parseCidr, subnet, traceEdge } from '../site/lab.js';
import { readHeaders } from './headers.mjs';

test('subnet works out a normal network', () => {
  const r = subnet('198.51.100.77', 26);
  assert.equal(r.network, '198.51.100.64');
  assert.equal(r.broadcast, '198.51.100.127');
  assert.equal(r.firstHost, '198.51.100.65');
  assert.equal(r.lastHost, '198.51.100.126');
  assert.equal(r.mask, '255.255.255.192');
  assert.equal(r.wildcard, '0.0.0.63');
  assert.equal(r.hosts, 62);
  assert.equal(r.bits.length, 32);
});

test('subnet handles the edge prefixes', () => {
  const all = subnet('203.0.113.9', 0);
  assert.equal(all.network, '0.0.0.0');
  assert.equal(all.broadcast, '255.255.255.255');
  assert.equal(all.mask, '0.0.0.0');
  assert.equal(all.hosts, 4294967294);

  const high = subnet('255.255.255.254', 31);
  assert.equal(high.firstHost, '255.255.255.254');
  assert.equal(high.lastHost, '255.255.255.255');
  assert.equal(high.broadcast, 'None');
  assert.equal(high.hosts, 2);

  const single = subnet('192.0.2.1', 32);
  assert.equal(single.firstHost, '192.0.2.1');
  assert.equal(single.lastHost, '192.0.2.1');
  assert.equal(single.mask, '255.255.255.255');
  assert.equal(single.hosts, 1);
});

test('subnet rejects bad input', () => {
  for (const bad of ['', 'abc', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.-4', '1.2.3.4/24']) {
    assert.ok(subnet(bad, 24).error, bad);
  }
  for (const bad of [-1, 33, 1.5, NaN]) assert.ok(subnet('192.0.2.1', bad).error, String(bad));
  assert.ok(parseCidr('192.0.2.1').error);
  assert.ok(parseCidr('192.0.2.1/99').error);
  assert.equal(parseCidr(' 192.0.2.1/24 ').network, '192.0.2.0');
});

test('dissect reads a valid header in any common hex format', () => {
  const hex = '450000541a2b400040013432c000020ec633640a';
  for (const text of [hex, hex.toUpperCase(), hex.match(/../g).join(' '), hex.match(/../g).join(':')]) {
    const p = dissect(text);
    assert.equal(p.source, '192.0.2.14');
    assert.equal(p.destination, '198.51.100.10');
    assert.equal(p.protocol, 'ICMP');
    assert.equal(p.ttl, 64);
    assert.equal(p.id, '0x1a2b');
    assert.equal(p.checksumValid, true);
    assert.equal(p.fields.reduce((bits, f) => bits + f.width, 0), 160);
    assert.equal(p.fields.find((f) => f.name === 'Flags').value, 'DF');
  }
});

test('dissect spots a corrupted checksum', () => {
  assert.equal(dissect('4500003cc0de400034061f53cb00714dc633640a').checksumValid, false);
});

test('dissect rejects bad input', () => {
  const cases = [
    ['', /Paste/],
    ['xyz', /not valid hex/],
    ['450', /not valid hex/],
    ['4500', /at least 20/],
    [`45${'00'.repeat(60)}`, /at most/],
    [`65${'00'.repeat(19)}`, /version 6/],
    [`44${'00'.repeat(19)}`, /header length/],
    [`4f${'00'.repeat(19)}`, /header length/],
  ];
  for (const [text, message] of cases) assert.match(dissect(text).error, message, text);
});

test('the real customHttp.yml passes every header check', () => {
  const results = gradeHeaders(Object.entries(readHeaders()));
  assert.equal(results.length, 5);
  assert.deepEqual(results.filter((r) => !r.passed), []);
});

test('traceEdge reads real Amplify response headers', () => {
  const miss = traceEdge([['Server', 'AmazonS3'], ['X-Cache', 'Miss from cloudfront'], ['X-Amz-Cf-Pop', 'VIE50-P4']]);
  assert.deepEqual(miss, { onAws: true, pop: 'VIE50-P4', city: 'Vienna', cacheHit: false, origin: 'AmazonS3' });
  assert.equal(traceEdge([['x-amz-cf-pop', 'FRA56-P1'], ['x-cache', 'Hit from cloudfront']]).cacheHit, true);
  assert.equal(traceEdge([['x-amz-cf-pop', 'QQQ1-P1']]).city, 'QQQ');
  assert.equal(traceEdge([['x-amz-cf-pop', 'QQQ1-P1']]).origin, 'Unknown');
  assert.deepEqual(traceEdge([['content-type', 'text/html']]), { onAws: false });
});

test('missing or weak headers fail', () => {
  assert.ok(gradeHeaders([]).every((r) => !r.passed));
  const weak = gradeHeaders([
    ['Content-Security-Policy', "script-src 'self' 'unsafe-inline'"],
    ['Strict-Transport-Security', 'max-age=60'],
    ['X-Frame-Options', 'ALLOWALL'],
    ['X-Content-Type-Options', 'sniff'],
    ['Referrer-Policy', 'unsafe-url'],
  ]);
  assert.ok(weak.every((r) => !r.passed));
});
