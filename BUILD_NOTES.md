# Build notes

## Architecture and accuracy

- TypeScript/Node.js 22+, Apify SDK 3.7.2; separate Shodan, KEV and EPSS adapters. The priority engine consumes normalized models and uses exact CVE joins.
- No active target traffic beyond DNS. No raw banner output, provider error bodies, fuzzy CVE matching, cross-customer Shodan cache, or generic CVE enrichment.
- Sequential bounded portfolios; bounded per-run Shodan deduplication, daily persistent public-intelligence caches, short retries, per-domain partial/no-data/failure reporting.
- Host-only CVEs remain host-only. Latest observations supersede older associations; equal-time conflicts reduce confidence. Missing KEV/EPSS is unknown, not negative.
- Accuracy takes precedence over filling every category: `CRITICAL_PRIORITY` is reserved but not emitted until reliable independent affected-version evaluation exists. A Shodan `verified` flag is provenance, not proof of target vulnerability. High confidence refers to evidence/association quality.
- Pay Per Event unit is prepared as `domain_analyzed`; event charging is disabled pending pricing and release review.

## Verification and observed usage

- Strict source/test TypeScript checks and 95 automated tests passed, including real local Apify SDK lifecycle, two-domain Dataset output, summaries, diagnostics, schema validation, rate limits, stale intelligence, invalid input, deduplication, and secret redaction.
- Production Docker image built successfully on Node 22. The actual production entrypoint passed a two-domain fixture run with Docker networking disabled and a 256 MB memory limit: two Dataset records, readable summary, diagnostics, one request per provider, and no synthetic secret leakage. In-container analysis took 0.044 seconds with peak RSS 86,683,648 bytes; mocked network timing is not a live throughput estimate.
- Public-source smoke on 2026-09-16 04:33 UTC: two DNS queries returned four public addresses; one KEV request parsed 1,710 entries (catalog date 2026-09-14); one EPSS request returned a dated score for CVE-2021-44228. No Shodan calls. Runtime 1.194 seconds; peak RSS 103,575,552 bytes for the `tsx` smoke process, not the production Actor.
- Offline two-domain shared-IP test: one Shodan request plus one request each to KEV and EPSS. Fixture data is synthetic; it establishes behavior, not target vulnerability or real provider costs.
- Actual marginal cost is unmeasured. Diagnostics return null rather than inventing a dollar estimate. Post-completion usage is now measured for one small hosted acceptance run; customer Shodan incremental cost and representative portfolio expenses remain unknown.

## Credential-independent hardening completed

- Four synthetic stress profiles passed in production-image containers with 256 MB memory, one CPU, and networking disabled. The 100-domain diverse portfolio assessed 800,000 findings in 16.13 seconds with peak process RSS 155,336,704 bytes; network/rate-limit latency is excluded. See [QA_REPORT.md](docs/QA_REPORT.md) and its machine-readable results.
- Records are capped at 4,000,000 UTF-8 bytes and 2,000 retained findings. Per-domain observation, service, and association budgets prevent unbounded accumulation. Bounded LRU caches were exercised through 12,000 distinct CVEs and 2,000 EPSS evictions.
- Recovery reconciles Dataset rows with an input manifest, covering interruptions and lost write acknowledgements. It requires one writer and matching storage/input; post-interruption usage can be incomplete.
- New failure and prioritization scenarios cover timeouts, malformed responses, persistent-cache failures, shared CDN attribution, stale VPN observations, possibly backported versions, and family-only evidence.
- Private deployment automation supports commit-pinned dry runs and explicit apply. Its API behavior is tested with mocks and a private hosted build/run has now passed; see the hosted follow-up below.
- Offline cost calculation accepts supplied rates/final expenses, validates counters, labels hypothetical estimates, and keeps incomplete totals unknown.
- Full local `npm run qa` passed on 2026-09-16 at 04:28 UTC; GitHub Actions now runs the same QA sequence.

## Remaining release checks

- Test-key Shodan authentication and passive host lookups passed. Replacement production/customer credentials and representative authorized-target validation remain required.
- Private hosted build and two-domain acceptance run passed. Representative hosted portfolios, live CVE-bearing observations, and final all-provider cost reconciliation remain to be validated.
- Shodan commercial/derived-output/storage rights: unresolved; [review and questions](docs/SHODAN_LICENSING.md). BYO is not assumed to clear this gate.
- Retail pricing, charging configuration and portfolio-scale cost measurement: deferred until live validation.
- Fixed analysis/output budgets now bound large records, with explicit omission metadata and partial status. Portfolios above 100 domains, exhaustive analysis beyond those budgets, and live portfolio cost measurement remain outside V1.

## Dependency advisory

`npm audit` reports one moderate underlying advisory, surfaced through three packages: `stream-json` → `@crawlee/core` → `apify`. [GHSA-528h-pc64-c93x](https://github.com/advisories/GHSA-528h-pc64-c93x) affects path filters; the advisory explicitly excludes array/object/value streamers. Installed Crawlee imports `stream-json/streamers/StreamArray`; this Actor uses bounded `JSON.parse` for provider responses and does not use the affected filters. No affected path was identified here. Retain the compatible SDK, track its upstream fix, and reassess if code paths change. A forced major override to stream-json 3.x changes exports and breaks the SDK's import; an automatic downgrade of Apify is not appropriate.

## V2 if demand appears

First add recurring exposure/KEV deltas, then larger portfolios and webhooks. Independent vendor/CPE affected-version evaluation should precede critical classifications. Keep the provider-neutral correlation engine reusable for defensive change monitoring; defer UI, extra providers and active scanning.

## Hosted deployment follow-up

On 2026-09-16, both supplied API credentials authenticated. The Shodan credential is restricted by user instruction to testing. The first private hosted build exposed that Apify Git source fragments resolve branches/tags rather than raw commit hashes. Deployment now uses a GitHub ZIP archive pinned to the full commit SHA, with matching-source validation and a regression test. The corrected build and live run succeeded. The run assessed two domains through four Shodan lookups with 47 service observations, no retries or provider errors, and two deliberately IP-capped partial records. Encrypted run-input storage and absence of the two API keys from output/logs were verified. See [LIVE_ACCEPTANCE.md](docs/LIVE_ACCEPTANCE.md) for scope and measured usage.
