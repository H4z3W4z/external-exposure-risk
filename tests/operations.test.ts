import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateCost } from '../src/cost.js';
import { deploymentPlan, applyDeployment, type DeploymentApi } from '../src/deployment.js';
const diagnostics = { domainsAnalyzed: 10, domainsWithObservations: 8, runtimeSeconds: 3600, shodanRequests: 100, shodanSearchPages: 2 };
test('cost estimates use allocated GB-hours, additive supplied rates and explicit other costs', () => {
  const r = calculateCost(diagnostics, { allocatedMemoryMb: 512, computeUsdPerCu: 2, shodanUsdPerRequest: 0.01, shodanUsdPerSearchPage: 0.5, otherRunUsd: 1 });
  assert.deepEqual(r.components, { apifyUsd: 1, shodanUsd: 2, otherRunUsd: 1 });
  assert.equal(r.totalUsd, 4); assert.equal(r.perAnalyzedDomainUsd, 0.4); assert.equal(r.perObservedDomainUsd, 0.5);
  assert.equal(r.basis, 'estimate_from_user_supplied_rates');
});
test('unknown prices stay incomplete; actual final costs override modeled rates', () => {
  const unknown = calculateCost(diagnostics, {}); assert.equal(unknown.totalUsd, null); assert.equal(unknown.knownSubtotalUsd, 0);
  assert.ok(unknown.missing.includes('shodanUsdPerRequest'));
  const final = calculateCost(diagnostics, { apifyFinalUsd: 3, shodanFinalUsd: 2, otherRunUsd: 0, computeUsdPerCu: 999 });
  assert.equal(final.totalUsd, 5); assert.equal(final.basis, 'user_supplied_final_costs');
});
test('zero counts avoid division by zero and do not require prices for nonexistent requests', () => {
  const r = calculateCost({ ...diagnostics, domainsAnalyzed: 0, domainsWithObservations: 0, shodanRequests: 0, shodanSearchPages: 0 }, { apifyFinalUsd: 0, otherRunUsd: 0 });
  assert.equal(r.totalUsd, 0); assert.equal(r.perAnalyzedDomainUsd, null); assert.equal(r.perObservedDomainUsd, null);
});
test('resumed usage cannot present a complete modeled estimate', () => {
  const r = calculateCost({ ...diagnostics, usageMayBeIncomplete: true }, { allocatedMemoryMb: 256, computeUsdPerCu: 0, shodanUsdPerRequest: 0, shodanUsdPerSearchPage: 0, otherRunUsd: 0 });
  assert.equal(r.totalUsd, null); assert.ok(r.missing.includes('completeUsageAfterInterruption'));
});
test('cost rejects invalid numbers, inconsistent counters and overflow', () => {
  for (const value of [-1, NaN, Infinity, '1', null]) assert.throws(() => calculateCost(diagnostics, { otherRunUsd: value }));
  assert.throws(() => calculateCost({ ...diagnostics, domainsWithObservations: 11 }, {}));
  assert.throws(() => calculateCost({ ...diagnostics, shodanRequests: 0.5 }, {}));
  assert.throws(() => calculateCost(diagnostics, { apifyFinalUsd: 1e308, shodanFinalUsd: 1e308, otherRunUsd: 0 }));
});
const plan = deploymentPlan('https://github.com/H4z3W4z/external-exposure-risk', 'a'.repeat(40));
function deploymentApi(): { api: DeploymentApi; calls: string[] } {
  const calls: string[] = [];
  const api: DeploymentApi = {
    getActor: async () => undefined, createActor: async p => { assert.equal(p.isPublic, false); calls.push('create'); return { id: 'actor' }; },
    getVersion: async () => undefined, writeVersion: async () => { calls.push('version'); },
    build: async () => { calls.push('build'); return { id: 'build' }; },
  };
  return { api, calls };
}
test('deployment plan pins immutable source and cannot contain URL credentials', () => {
  assert.ok(plan.gitRepoUrl.endsWith('#' + 'a'.repeat(40))); assert.equal(plan.applyEnvVarsToBuild, false); assert.equal(plan.runAutomatically, false);
  for (const repo of ['https://secret@github.com/u/r','http://github.com/u/r','https://evil.test/u/r','https://github.com/u/r?token=x']) assert.throws(() => deploymentPlan(repo, 'a'.repeat(40)));
  assert.throws(() => deploymentPlan(plan.repository, 'main'));
});
test('deployment creates private Actor and starts a build without starting a paid run', async () => {
  const { api, calls } = deploymentApi(); const r = await applyDeployment(plan, api);
  assert.deepEqual(calls, ['create','build']); assert.equal(r.buildId, 'build');
});
test('deployment updates matching source and refuses public or unrelated existing Actors', async () => {
  const { api, calls } = deploymentApi(); api.getActor = async () => ({ id: 'existing', isPublic: true });
  await assert.rejects(applyDeployment(plan, api)); assert.deepEqual(calls, []);
  api.getActor = async () => ({ id: 'existing', isPublic: false });
  api.getVersion = async () => ({ sourceType: 'GIT_REPO', gitRepoUrl: 'https://github.com/other/project.git#main' });
  await assert.rejects(applyDeployment(plan, api)); assert.deepEqual(calls, []);
  api.getVersion = async () => ({ sourceType: 'GIT_REPO', gitRepoUrl: plan.gitRepoUrl });
  await applyDeployment(plan, api); assert.deepEqual(calls, ['version','build']);
});
test('ambiguous deployment mutations are not automatically retried', async () => {
  const { api, calls } = deploymentApi(); api.createActor = async () => { calls.push('create'); throw new Error('timeout'); };
  await assert.rejects(applyDeployment(plan, api)); assert.deepEqual(calls, ['create']);
});
