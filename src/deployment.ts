export interface DeploymentPlan {
  name: string; isPublic: false; version: string; repository: string; commit: string;
  tarballUrl: string; buildTag: string; applyEnvVarsToBuild: false;
  secrets: 'runtime-only; configure separately'; runAutomatically: false;
}
export function deploymentPlan(repository: string, commit: string, name = 'external-exposure-risk', version = '0.1'): DeploymentPlan {
  if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/.test(repository) || !/^[a-f0-9]{40}$/.test(commit) || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(name) || !/^\d{1,2}\.\d{1,2}$/.test(version)) throw new Error('Invalid deployment repository, commit, name or version.');
  const repo = repository.replace(/\.git$/, '');
  return { name, isPublic: false, version, repository: repo, commit, tarballUrl: `${repo}/archive/${commit}.zip`,
    buildTag: 'latest', applyEnvVarsToBuild: false, secrets: 'runtime-only; configure separately', runAutomatically: false };
}
export interface DeploymentApi {
  getActor(name: string): Promise<{ id: string; isPublic: boolean } | undefined>;
  createActor(plan: DeploymentPlan): Promise<{ id: string }>;
  getVersion(id: string, version: string): Promise<{ gitRepoUrl?: string; tarballUrl?: string; sourceType?: string } | undefined>;
  writeVersion(id: string, plan: DeploymentPlan, exists: boolean): Promise<void>;
  build(id: string, version: string): Promise<{ id: string }>;
}
/** Mutations are called only by the CLI's explicit --apply path. No token enters a plan. */
export async function applyDeployment(plan: DeploymentPlan, api: DeploymentApi) {
  let actor = await api.getActor(plan.name);
  if (actor?.isPublic) throw new Error('Deployment automation only manages private Actors.');
  if (!actor) actor = { ...(await api.createActor(plan)), isPublic: false };
  else {
    const version = await api.getVersion(actor.id, plan.version);
    const sameGit = version?.sourceType === 'GIT_REPO' && version.gitRepoUrl?.split('#')[0].replace(/\.git$/, '') === plan.repository;
    const archivePrefix = `${plan.repository}/archive/`;
    const sameArchive = version?.sourceType === 'TARBALL' && version.tarballUrl?.startsWith(archivePrefix) && /^[a-f0-9]{40}\.zip$/.test(version.tarballUrl.slice(archivePrefix.length));
    if (version && !sameGit && !sameArchive) throw new Error('Existing version has a different source; refusing to overwrite it.');
    await api.writeVersion(actor.id, plan, !!version);
  }
  const build = await api.build(actor.id, plan.version);
  return { actorId: actor.id, buildId: build.id, consoleUrl: `https://console.apify.com/actors/${actor.id}`, status: 'build_started' };
}
