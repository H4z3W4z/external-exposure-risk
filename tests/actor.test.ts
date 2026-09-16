import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
test('real Actor lifecycle writes Dataset, SUMMARY and DIAGNOSTICS without secret leakage', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'exposure-actor-'));
  const secret = 'synthetic-secret-do-not-output';
  try {
    await mkdir(join(dir, 'key_value_stores/default'), { recursive: true });
    await writeFile(join(dir, 'key_value_stores/default/INPUT.json'), JSON.stringify({ domains: ['example.com','example.org'] }));
    const env = { ...process.env, CRAWLEE_STORAGE_DIR: dir, APIFY_IS_AT_HOME: '', SHODAN_API_KEY: secret, APIFY_TOKEN: '', APIFY_LOG_LEVEL: 'INFO' };
    const r = await exec(process.execPath, ['--import', 'tsx', '--import', './tests/actor-network.mjs', 'src/main.ts'], { env, timeout: 30000 });
    const files = (await readdir(join(dir, 'datasets/default'))).filter(n => n.endsWith('.json') && !n.startsWith('__'));
    assert.equal(files.length, 2);
    const record = JSON.parse(await readFile(join(dir, 'datasets/default', files[0]), 'utf8'));
    assert.equal(record.summary.highPriority, 1);
    assert.equal(record.status, 'ok');
    const summary = await readFile(join(dir, 'key_value_stores/default/SUMMARY.txt'), 'utf8');
    const diagnostics = await readFile(join(dir, 'key_value_stores/default/DIAGNOSTICS.json'), 'utf8');
    assert.equal(JSON.parse(diagnostics).shodanRequests, 1);
    assert.equal(JSON.parse(diagnostics).domainsAnalyzed, 2);
    assert.ok(![r.stdout, r.stderr, JSON.stringify(record), summary, diagnostics].some(s => s.includes(secret)));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
