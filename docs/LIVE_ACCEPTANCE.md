# Live acceptance — 2026-09-16

A private hosted build and a bounded two-domain acceptance run passed using the user-supplied **test-only Shodan key**. This key must be replaced for production. It was supplied only for the test run, not configured as an Actor default, persistent environment setting, build secret, or source constant. Source control contains neither supplied API key. No account login/password was needed for API operations.

## Build correction

The initial Git source URL used a raw commit SHA in its fragment. Apify treated it as a branch name and rejected the build. Deployment now uses a GitHub ZIP archive addressed by the full commit SHA, matching Apify's [supported source types](https://docs.apify.com/actors/development/deployment/source-types). Source validation accepts only the same repository and a full SHA archive; it can migrate the prior same-repository Git source. A new regression test covers archive-source checks, bringing the suite to 95 passing tests.

The successful hosted build used commit `85b36bb6e065117e6db9330cb3b9c06aa88a2e52`, build number recorded by the private Actor. It ran the production Dockerfile. The Actor remains private and billing events remain disabled. Later documentation-only commits do not alter this tested runtime.

## Run scope and results

| Measure | Result |
| --- | --- |
| Domains | `example.com`, `example.org` |
| Allocation and timeout | 256 MB, 180 seconds |
| Limits | 2 IPs/domain, 20 services/IP, 50 CVEs/domain; related-host search disabled |
| Hosted status | `SUCCEEDED` |
| Domain output | 2 records, both `partial` because current DNS exceeded the deliberate IP cap |
| Shodan attempts | 4; 47 service observations consumed |
| Provider errors / retries | 0 / 0 |
| CVE associations | 0; no KEV/EPSS enrichment requested by this run |
| Hosted duration | 7.434 seconds |
| Platform maximum memory | 108,482,560 bytes |
| Platform compute | 0.00051625 CU |
| Output record sizes | 42,807 and 41,076 bytes; exact UTF-8 sizes verified |
| Secret storage | Shodan input stored with `ENCRYPTED_VALUE:` prefix |
| Credential leakage checks | Neither API key present in Dataset, SUMMARY, DIAGNOSTICS, or run log |

The local real-key smoke also completed two domains with four lookups and no errors. Query and scan credit balances were 100 before and after testing; this is an observed balance, not a claim that Shodan service has zero cost. No scanning or hostname search was requested.

## Usage and limits of verification

Apify reported post-completion run usage of **$0.000521121360629797**, approximately $0.00026056 per analyzed domain for this small run. The successful build reported $0.005832666666666667; the rejected build reported $0.00022222222222222223. These are platform-reported usage snapshots, exclude customer Shodan expense and any later storage/transfer effects, and do not establish final marginal cost, pricing, or margin. In-run diagnostics correctly kept marginal cost unknown and showed an earlier, smaller platform usage snapshot.

These tests verify deployed execution, real Shodan authentication/host retrieval, bounded output, secret-input decryption, and private storage output. They do not establish completeness of domain attribution or absence of risk. Because the observed hosts returned no CVEs, live KEV/EPSS joins were not exercised by this hosted run; public-intelligence retrieval and exact-CVE correlation have separate public-source and synthetic tests. Representative authorized targets, production credentials, commercial Shodan permissions, and all-provider cost reconciliation remain necessary before commercial release.

Detailed private run identifiers, diagnostics, and platform counters remain in ignored local `artifacts/live-acceptance-report.json`. Credentials are not included in that report.
