import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
const checks = [];
await mkdir('artifacts/qa-logs', { recursive: true });
function run(name, command, args) {
  console.log(`QA: ${name}`);
  const start = performance.now();
  try {
    const stdout = execFileSync(command, args, { encoding: 'utf8', timeout: 300_000, maxBuffer: 16_000_000, stdio: ['ignore', 'pipe', 'pipe'] });
    checks.push({ name, status: 'passed', seconds: +((performance.now() - start) / 1000).toFixed(3) });
    return stdout;
  } catch (error) {
    checks.push({ name, status: 'failed', seconds: +((performance.now() - start) / 1000).toFixed(3) });
    // These commands use synthetic fixtures; persist local diagnostics without printing huge logs.
    const log = `${error.stdout ?? ''}\n${error.stderr ?? ''}`;
    throw Object.assign(new Error(`QA failed: ${name}`), { log, check: name });
  }
}
try {
  const tests = run('types-and-tests', 'npm', ['run','check']);
  await writeFile('artifacts/qa-logs/tests.txt', tests);
  run('production-build', 'npm', ['run','build']);
  run('synthetic-demo', 'npm', ['run','demo']);
  run('docker-build', 'docker', ['build','-q','-t','external-exposure-risk:local','.']);
  await writeFile('artifacts/qa-logs/docker-smoke.txt', run('docker-lifecycle', 'npm', ['run','smoke:docker']));
  run('bounded-portfolio-stress', 'npm', ['run','stress']);
  run('deployment-dry-run', 'npm', ['run','deploy']);
  const stress = JSON.parse(await readFile('artifacts/stress-report.json', 'utf8'));
  await writeFile('artifacts/cost-diagnostics.json', JSON.stringify(stress.reports[1].diagnostics, null, 2));
  const cost = run('cost-cli', 'npm', ['run','--silent','cost','--','artifacts/cost-diagnostics.json','examples/prices.hypothetical.json']);
  const costReport = JSON.parse(cost);
  if (costReport.totalUsd === null || costReport.basis !== 'estimate_from_user_supplied_rates') throw new Error('Cost CLI did not label its hypothetical estimate correctly.');
  await writeFile('artifacts/cost-example.json', cost);
  let audit;
  try { audit = JSON.parse(execFileSync('npm', ['audit','--json'], { encoding: 'utf8', maxBuffer: 4_000_000 })); }
  catch (e) { if (!e.stdout) throw new Error('Dependency audit unavailable.'); audit = JSON.parse(e.stdout); }
  if (audit.error || !audit.metadata) throw new Error('Dependency audit unavailable.');
  const advisories = Object.values(audit.vulnerabilities ?? {}).flatMap(v => v.via.filter(a => typeof a === 'object'));
  if (advisories.some(a => a.url !== 'https://github.com/advisories/GHSA-528h-pc64-c93x' || a.severity !== 'moderate')) throw new Error('New dependency advisory requires review.');
  checks.push({ name: 'dependency-audit', status: advisories.length ? 'known_advisory_only' : 'passed' });
  await writeFile('artifacts/dependency-audit.json', JSON.stringify(audit, null, 2));
  run('whitespace', 'git', ['diff','--check']);
  const paths = [...new Set(execFileSync('git', ['ls-files','-co','--exclude-standard','-z'], { encoding: 'utf8' }).split('\0').filter(Boolean))];
  for (const path of paths) {
    if (/^(storage|dist|node_modules|artifacts)\/|^\.env(?:\.|$)/.test(path)) throw new Error('Generated/private artifacts are tracked.');
    const content = await readFile(path, 'utf8');
    if (/gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|apify_api_[A-Za-z0-9]{20,}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(content)) throw new Error('Potential credential detected; review source locally.');
    for (const secret of [process.env.SHODAN_API_KEY, process.env.APIFY_TOKEN].filter(Boolean)) if (content.includes(secret)) throw new Error('Runtime credential appeared in source.');
  }
  checks.push({ name: 'source-secret-artifact-check', status: 'passed', files: paths.length });
  const count = Number(tests.match(/(?:ℹ |# )?tests (\d+)/)?.[1]);
  await writeFile('artifacts/qa-report.json', JSON.stringify({ completedAt: new Date().toISOString(), status: 'passed', tests: count || null, checks,
    limitations: ['Live Shodan and hosted Apify verification not performed.', 'Known moderate stream-json advisory remains reviewed and documented.', 'Synthetic stress skips network and rate-limit latency.'] }, null, 2) + '\n');
  console.log(`QA passed: ${count || 'all'} tests; container, stress, deployment dry run and cost CLI verified.`);
} catch (error) {
  if (error.log) await writeFile(`artifacts/qa-logs/${error.check}.txt`, error.log);
  await writeFile('artifacts/qa-report.json', JSON.stringify({ status: 'failed', checks }, null, 2));
  console.error(`${error.message}. Inspect artifacts/qa-logs.`); process.exitCode = 1;
}
