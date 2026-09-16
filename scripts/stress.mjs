import { mkdir, mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
const dir = await mkdtemp(join(tmpdir(), 'exposure-stress-'));
const reports = [];
try {
  for (const profile of ['shared', 'diverse', 'oversized', 'epss_churn']) {
    console.log(`Running ${profile} with networking disabled and a 256 MB container limit...`);
    await exec('docker', ['run', '--rm', '--network', 'none', '--memory', '256m', '--memory-swap', '256m', '--cpus', '1',
      '--user', `${process.getuid()}:${process.getgid()}`, '-e', `STRESS_REPORT=/reports/${profile}.json`,
      '-v', `${dir}:/reports`, '-v', `${resolve('scripts/stress-worker.mjs')}:/app/scripts/stress-worker.mjs:ro`,
      process.env.ACTOR_TEST_IMAGE || 'external-exposure-risk:local', 'node', '--max-old-space-size=160', '/app/scripts/stress-worker.mjs', profile],
    { timeout: 180_000, maxBuffer: 2_000_000 });
    const report = JSON.parse(await readFile(join(dir, `${profile}.json`), 'utf8')); reports.push(report);
    console.log(`${profile}: ${report.domainsCompleted} domains, ${report.wallSeconds}s, ${report.diagnostics.peakMemoryBytes} peak RSS bytes, ${report.maxRecordBytes} largest record bytes`);
  }
  await mkdir('artifacts', { recursive: true });
  await writeFile('artifacts/stress-report.json', JSON.stringify({ generatedAt: new Date().toISOString(), memoryLimitMb: 256, reports }, null, 2) + '\n');
} finally { await rm(dir, { recursive: true, force: true }); }
