# Operations

## Verify and inspect

Use Node.js 22+, Git, and Docker. From the repository root:

```bash
npm ci --ignore-scripts
npm run qa
```

QA runs 95 offline tests and strict type checks, builds production code and Docker, exercises the real SDK lifecycle, runs four synthetic portfolio profiles under a 256 MB container limit, prepares a deployment plan, tests the cost CLI, reviews dependency advisories, and checks source for credential patterns. Builds and dependency audit need public network access; test providers are synthetic and stress containers have networking disabled. QA does not call Shodan or create an Apify Actor. GitHub Actions uploads `artifacts/` as `qa-reports`, including JSON results and test logs.

`npm run stress` alone requires an existing `external-exposure-risk:local` image. `npm run smoke:public` independently exercises real DNS, CISA KEV, and EPSS. Local `artifacts/`, storage, and environment files are ignored by Git.

## Analysis and output limits

Each domain has fixed budgets of 8,000,000 serialized observation bytes, 20,000 endpoint-CVE associations, and 5,000 observations (including host-level observations). These apply in addition to input caps. If the next observation cannot fit, collection stops and the record explicitly warns that unassessed observations/IPs may contain additional priorities. These budgets bound assessment work; they cannot guarantee the most important finding occurs within the assessed subset.

Among assessed observations, the best 2,000 findings are retained using the deterministic priority ordering. Each Dataset row is further limited to 4,000,000 compact UTF-8 JSON bytes, below the [Apify per-item limit](https://docs.apify.com/storage/dataset). To fit, the formatter removes duplicated asset details first, then the duplicated EPSS source index and lower-priority findings. A retained finding keeps its evidence, timestamps, and confidence rationale. Very large individual findings can be omitted entirely. This is a bounded single-row output, not exhaustive streaming output.

Read `output.findingsAssessed`, `findingsRetained`, `findingsOmitted`, `assetsOmitted`, `analysisLimited`, `truncated`, and `serializedBytes`. `summaryScope` is `assessed_observations`: aggregate counts can exceed the detail retained in the row. Truncation changes an otherwise successful record to `partial`. Input/enrichment limits can independently cause partial status; inspect warnings as well.

Normalized Shodan and EPSS memory caches each have an 8,000,000 serialized-byte budget, with respective entry caps of 1,000 and 10,000. The in-memory fallback public cache is also bounded. These are serialized-payload budgets, not exact heap limits. Least-recently-used eviction can cause later retrievals; diagnostics count evictions. Shodan results remain in memory only, while public KEV/EPSS cache entries may persist in the named public-intelligence store.

## Resume an interrupted run

`RUN_STATE` stores a versioned input fingerprint and usage checkpoint. It excludes the Shodan key. The Dataset is the authority for completed domain rows: a restart reconciles it before doing more work, so a successful append with a lost acknowledgement is recognized. `SUMMARY` is refreshed after each domain. Changed input, duplicate domains in storage, or unrecognized existing rows stop the run for review.

For local recovery, retain the same storage and input and set `CRAWLEE_PURGE_ON_START=false` before `npm start`. Default local startup can purge run storage. Use a new `CRAWLEE_STORAGE_DIR` for a fresh assessment. Hosted migration/restart must preserve the same default Dataset and key-value store. No cross-run storage copying is automatic.

Recovery assumes one writer. It does not implement distributed exactly-once transactions. An ambiguous Dataset write stops execution instead of blindly appending again; inspect storage and resume after the write has settled. Completed `failed` and `no_data` rows are still completed work; use fresh storage to reassess them. Graceful interruption finishes/checkpoints the current domain when time permits. Abrupt termination can lose in-flight work and its usage counters.

`domainsResumed` records skipped completed rows across resumptions. Diagnostics mark `usageMayBeIncomplete` after any resume, since requests made after the last checkpoint may be unrecorded. Cost modeling refuses to report a complete modeled total for this case; final externally reconciled expenses can still be supplied. See [Apify state persistence](https://docs.apify.com/actors/development/builds-and-runs/state-persistence).

## Deployment preparation and apply

```bash
npm run deploy
```

This dry run writes `artifacts/deploy-plan.json` without account credentials. It uses a GitHub ZIP archive pinned to local Git HEAD, uses the manifest name/version, sets the Actor private, disables build-time environment variables, and does not start runs. `DEPLOY_REPOSITORY` and `DEPLOY_ACTOR_NAME` optionally select another GitHub source/name. The repository archive must be readable by the hosted builder. Apify Git source fragments accept branches/tags rather than raw commit hashes, so the deployment uses its ZIP archive source type. Commit and push all changes before applying; the CLI requires a clean working tree but does not prove the remote contains your commit.

To create/update the private Actor and start a build, supply an Apify token in the environment:

```bash
read -rsp 'Apify token: ' APIFY_TOKEN
export APIFY_TOKEN
npm run deploy -- --apply
unset APIFY_TOKEN
```

Apply creates the named private Actor or updates the matching repository archive version (or migrates an existing Git source for that repository) of an existing private Actor. It refuses public Actors and conflicting version sources. SDK mutations are not automatically retried: after an ambiguous failure, inspect the account before retrying. `artifacts/deployment.json` records the Actor/build IDs and console URL. `build_started` means accepted for building; it does not mean the build succeeded. Inspect the build result in Apify, then configure the Shodan runtime secret and perform acceptance runs. This automation does not publish, configure billing, inject Shodan credentials, or run targets. Hosted build/run verification and licensing review remain release gates.

## Cost calculator

```bash
npm run --silent cost -- storage/key_value_stores/default/DIAGNOSTICS.json examples/prices.hypothetical.json
```

The included prices are invented test assumptions, not provider quotations. Copy that file to an ignored local location and substitute actual account assumptions. No market price is embedded in the calculator.

| Field | Meaning |
| --- | --- |
| `label` | Optional description of the assumptions |
| `allocatedMemoryMb` | Allocated run memory, not observed RSS |
| `computeUsdPerCu` | Your USD rate per GB-hour |
| `shodanUsdPerRequest` | Assumed incremental cost for every counted Shodan attempt, including retries/search attempts |
| `shodanUsdPerSearchPage` | Additional assumed cost per consumed search page |
| `apifyFinalUsd` | Optional final reconciled Apify expense; overrides compute modeling |
| `shodanFinalUsd` | Optional final reconciled Shodan expense; overrides request/page modeling |
| `otherRunUsd` | Explicit remaining expense, including any storage, transfer, or minimums not already included; zero is allowed |

Modeled compute is `allocatedMemoryMb / 1024 × runtimeSeconds / 3600 × computeUsdPerCu`. Modeled Shodan expense adds request and page charges. Use explicit zero where your plan bundles a component to avoid double counting. Subscription allocation is a caller assumption, not measured incremental expense. Measured pipeline runtime can omit billable startup/shutdown and interruption work; reconcile final platform charges when available.

Missing required prices produce `totalUsd: null` with a `missing` list and a known subtotal. Invalid/negative/nonfinite prices or counters fail. Per-domain costs use all analyzed domains; a second denominator uses domains with observations. Zero denominators return null. Estimates are labeled `estimate_from_user_supplied_rates`; providing all three final expense fields yields `user_supplied_final_costs`. Neither result calculates margin or establishes a retail price.

The Shodan credential supplied for acceptance testing is test-only. Supply a replacement production/customer key at runtime before production use; never promote the test key into Actor defaults, environment configuration, source, or build settings.
