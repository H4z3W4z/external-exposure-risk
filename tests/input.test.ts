import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDomain, parseInput } from '../src/input.js';
import { publicIp } from '../src/discovery/dns.js';
test('normalizes case, trailing dot, IDN and duplicate portfolio entries', () => {
  assert.deepEqual(parseInput({ domains: [' Example.COM. ', 'example.com', 'bücher.de'] }).domains, ['example.com', 'xn--bcher-kva.de']);
  assert.equal(parseInput({ domain: 'example.com' }).submittedCount, 1);
});
for (const invalid of ['', 'localhost', '1.2.3.4', 'https://example.com', 'example.com:443', '*.example.com', 'a..com', '-a.com', 'a_.com', 'a.com/path', 'a com', 'a@b.com', null, 12, 'a'.repeat(64)+'.com']) {
  test(`rejects malformed domain ${JSON.stringify(invalid)}`, () => assert.throws(() => normalizeDomain(invalid)));
}
for (const raw of [{}, null, [], { domains: [] }, { domains: 'example.com' }, { domains: ['example.com'], domain: 'example.com' }, { domains: Array(101).fill('example.com') }, { domain: 'example.com', highEpssThreshold: 2 }, { domain: 'example.com', maxIpsPerDomain: 1.5 }, { domain: 'example.com', discoverRelatedHosts: 'true' }, { domain: 'example.com', mystery: 1 }]) {
  test(`rejects invalid input ${JSON.stringify(raw).slice(0, 80)}`, () => assert.throws(() => parseInput(raw)));
}
test('excludes private, loopback, reserved, multicast and mapped private addresses', () => {
  for (const ip of ['127.0.0.1','10.0.0.1','192.168.1.1','169.254.169.254','224.0.0.1','203.0.113.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1']) assert.equal(publicIp(ip), false, ip);
  assert.equal(publicIp('8.8.8.8'), true);
  assert.equal(publicIp('2606:4700:4700::1111'), true);
});
