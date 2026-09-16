import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { ApifyClient } from 'apify';
import { ActorSourceType, type ActorVersionTarball } from 'apify-client';
import { deploymentPlan, applyDeployment } from '../src/deployment.js';

try {
  const args = process.argv.slice(2);
  if (args.some(a => a !== '--apply') || args.length > 1) throw new Error('Usage: npm run deploy -- [--apply]');
  const manifest = JSON.parse(await readFile('.actor/actor.json', 'utf8'));
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const repo = process.env.DEPLOY_REPOSITORY || 'https://github.com/H4z3W4z/external-exposure-risk';
  const plan = deploymentPlan(repo, commit, process.env.DEPLOY_ACTOR_NAME || manifest.name, manifest.version);
  await mkdir('artifacts', { recursive: true });
  await writeFile('artifacts/deploy-plan.json', JSON.stringify(plan, null, 2) + '\n');
  console.log(JSON.stringify({ mode: args.includes('--apply') ? 'apply' : 'dry_run', ...plan }, null, 2));
  if (args.includes('--apply')) {
    if (execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim()) throw new Error('Commit and push a clean working tree before deployment.');
    if (!process.env.APIFY_TOKEN) throw new Error('Set APIFY_TOKEN securely before applying.');
    const client = new ApifyClient({ token: process.env.APIFY_TOKEN, maxRetries: 0, timeoutSecs: 30 });
    const user = await client.user('me').get();
    if (!user?.username) throw new Error('Unable to determine the Apify account.');
    const source: ActorVersionTarball = { versionNumber: plan.version, sourceType: ActorSourceType.Tarball, tarballUrl: plan.tarballUrl, buildTag: plan.buildTag, applyEnvVarsToBuild: false };
    const result = await applyDeployment(plan, {
      getActor: async name => { const a = await client.actor(`${user.username}~${name}`).get(); return a ? { id: a.id, isPublic: a.isPublic } : undefined; },
      createActor: async () => client.actors().create({ name: plan.name, title: 'External Exposure Risk Actor', isPublic: false, versions: [source] }),
      getVersion: (id, version) => client.actor(id).version(version).get(),
      writeVersion: async (id, _plan, exists) => { if (exists) await client.actor(id).version(plan.version).update(source); else await client.actor(id).versions().create(source); },
      build: (id, version) => client.actor(id).build(version),
    });
    await writeFile('artifacts/deployment.json', JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result, null, 2));
  }
} catch {
  // Never print SDK error objects, response bodies or headers containing authentication.
  console.error('Deployment preparation/apply failed. Check clean committed source, input settings and account access. Mutations are not retried automatically; inspect Apify before retrying --apply.');
  process.exitCode = 1;
}
