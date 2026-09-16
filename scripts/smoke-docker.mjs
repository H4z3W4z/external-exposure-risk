import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
const dir = await mkdtemp(join(tmpdir(), 'exposure-docker-'));
try {
  await mkdir(join(dir, 'key_value_stores/default'), { recursive: true });
  await writeFile(join(dir, 'key_value_stores/default/INPUT.json'), JSON.stringify({ domains: ['example.com', 'example.org'] }));
  const args = ['run', '--rm', '--network', 'none', '--memory', '256m', '--cpus', '1',
    '--user', `${process.getuid()}:${process.getgid()}`,
    '-e', 'SHODAN_API_KEY=synthetic-docker-key', '-e', 'CRAWLEE_STORAGE_DIR=/work/storage',
    '-v', `${dir}:/work/storage`, '-v', `${resolve('tests/actor-network.mjs')}:/app/fixture.mjs:ro`,
    process.env.ACTOR_TEST_IMAGE || 'external-exposure-risk:local', 'node', '--import', '/app/fixture.mjs', 'dist/main.js'];
  const { stdout, stderr } = await exec('docker', args, { timeout: 60_000 });
  const files = (await readdir(join(dir, 'datasets/default'))).filter(n => n.endsWith('.json') && !n.startsWith('__'));
  if (files.length !== 2) throw new Error('Expected two Dataset records.');
  const records = await Promise.all(files.map(async f => JSON.parse(await readFile(join(dir, 'datasets/default', f), 'utf8'))));
  const diagnostics = JSON.parse(await readFile(join(dir, 'key_value_stores/default/DIAGNOSTICS.json'), 'utf8'));
  const summary = await readFile(join(dir, 'key_value_stores/default/SUMMARY.txt'), 'utf8');
  if (records.some(r => r.status !== 'ok' || r.summary.highPriority !== 1)) throw new Error('Unexpected assessment output.');
  if (JSON.stringify([records, diagnostics, summary, stdout, stderr]).includes('synthetic-docker-key')) throw new Error('Synthetic credential leaked.');
  console.log(JSON.stringify({ verification: 'production container with offline fixtures; networking disabled', records: records.length,
    memoryLimitMb: 256, runtimeSeconds: diagnostics.runtimeSeconds, peakMemoryBytes: diagnostics.peakMemoryBytes,
    shodanRequests: diagnostics.shodanRequests, kevRefreshes: diagnostics.kevRefreshes, epssRequests: diagnostics.epssRequests }, null, 2));
} finally { await rm(dir, { recursive: true, force: true }); }
