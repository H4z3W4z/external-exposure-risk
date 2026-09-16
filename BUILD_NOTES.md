# Build notes

## Architecture and accuracy

- TypeScript/Node.js 22+, Apify SDK 3.7.2; separate Shodan, KEV and EPSS adapters. The priority engine consumes normalized models and uses exact CVE joins.
- No active target traffic beyond DNS. No raw banner output, provider error bodies, fuzzy CVE matching, cross-customer Shodan cache, or generic CVE enrichment.
- Sequential bounded portfolios; per-run Shodan deduplication, daily persistent public-intelligence caches, short retries, per-domain partial/no-data/failure reporting.
- Host-only CVEs remain host-only. Latest observations supersede older associations; equal-time conflicts reduce confidence. Missing KEV/EPSS is unknown, not negative.
- Accuracy takes precedence over filling every category: `CRITICAL_PRIORITY` is reserved but not emitted until reliable independent affected-version evaluation exists. A Shodan `verified` flag is provenance, not proof of target vulnerability. High confidence refers to evidence/association quality.
- Pay Per Event unit is prepared as `domain_analyzed`; event charging is disabled pending pricing and release review.

## Verification and observed usage

- Strict source/test TypeScript checks and 62 automated tests passed, including real local Apify SDK lifecycle, two-domain Dataset output, summaries, diagnostics, schema validation, rate limits, stale intelligence, invalid input, deduplication, and secret redaction.
- Production Docker image built successfully on Node 22. The actual production entrypoint passed a two-domain fixture run with Docker networking disabled and a 256 MB memory limit: two Dataset records, readable summary, diagnostics, one request per provider, and no synthetic secret leakage. In-container analysis took 0.044 seconds with peak RSS 86,683,648 bytes; mocked network timing is not a live throughput estimate.
- Public-source smoke on 2026-09-16 02:08 UTC: two DNS queries returned four public addresses; one KEV request parsed 1,710 entries (catalog date 2026-09-14); one EPSS request returned a dated score for CVE-2021-44228. No Shodan calls. Runtime 1.334 seconds; peak RSS 116,383,744 bytes for the `tsx` smoke process, not the production Actor.
- Offline two-domain shared-IP test: one Shodan request plus one request each to KEV and EPSS. Fixture data is synthetic; it establishes behavior, not target vulnerability or real provider costs.
- Actual marginal cost is unmeasured. Diagnostics return null rather than inventing a dollar estimate. Final hosted-run usage and customer Shodan incremental cost are required.

## Remaining release checks

- Live Shodan account entitlements and representative authorized-target runs: pending customer key.
- Hosted Apify build/run and final cost measurement: pending account access/token. Local Docker is not hosted verification.
- Shodan commercial/derived-output/storage rights: unresolved; [review and questions](docs/SHODAN_LICENSING.md). BYO is not assumed to clear this gate.
- Retail pricing, charging configuration and portfolio-scale cost measurement: deferred until live validation.
- Very large records can exceed Apify Dataset item limits at raised caps; start with defaults and inspect truncation warnings. Further portfolio scaling and streaming output are V2 work.

## Dependency advisory

`npm audit` reports one moderate underlying advisory, surfaced through three packages: `stream-json` → `@crawlee/core` → `apify`. [GHSA-528h-pc64-c93x](https://github.com/advisories/GHSA-528h-pc64-c93x) affects path filters; the advisory explicitly excludes array/object/value streamers. Installed Crawlee imports `stream-json/streamers/StreamArray`; this Actor uses bounded `JSON.parse` for provider responses and does not use the affected filters. No affected path was identified here. Retain the compatible SDK, track its upstream fix, and reassess if code paths change. A forced major override to stream-json 3.x changes exports and breaks the SDK's import; an automatic downgrade of Apify is not appropriate.

## V2 if demand appears

First add recurring exposure/KEV deltas, then larger portfolios and webhooks. Independent vendor/CPE affected-version evaluation should precede critical classifications. Keep the provider-neutral correlation engine reusable for defensive change monitoring; defer UI, extra providers and active scanning.
