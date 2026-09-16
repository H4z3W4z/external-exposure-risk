# QA report

Local full QA passed on 2026-09-16 at 04:28 UTC: **94 tests**, strict source/test TypeScript checks, production build, Docker lifecycle/restart behavior, deployment dry run, cost CLI, source checks, and all four stress profiles. [Machine-readable measured results](qa-results.json) retain the counters and timings. GitHub Actions runs the same `npm run qa` command and publishes reports for each revision.

| Synthetic profile | Domains | Findings assessed / retained | Peak process RSS (bytes) | Largest row (bytes) | Seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| Shared IP | 100 | 20,000 / 20,000 | 92,319,744 | 404,937 | 0.837 |
| Diverse infrastructure | 100 | 800,000 / 200,000 | 155,336,704 | 3,819,385 | 16.130 |
| Oversized evidence | 2 | 40,000 / 222 | 153,735,168 | 3,745,510 | 1.865 |
| 12,000 distinct CVEs | 6 | 12,000 / 12,000 | 140,251,136 | 3,968,546 | 0.877 |

Every profile ran the compiled pipeline in the production image with a 256 MB container limit, one CPU, a 160 MB V8 old-space limit, and networking disabled. DNS, provider responses, and output storage were injected synthetic implementations. Rate-limit sleeps were skipped. RSS is sampled process memory, not exact total container usage. These results establish bounded behavior for these fixtures, not real-world throughput, exhaustive coverage, or an Apify bill.

The shared-IP case used one Shodan lookup. Diverse infrastructure exercised 328 cache evictions. The distinct-CVE case exercised 2,000 EPSS cache evictions. Oversized evidence reached the analysis budget in both rows; output trimming preserved complete evidence for every retained finding. Diverse portfolios retained the best 2,000 assessed findings per domain. Truncated records reported partial status and omission metadata.

Additional test coverage includes timeout/retry exhaustion, 429/503 handling, permanent authentication errors, malformed service/intelligence responses, stale cache fallback, cache read/write failures, quoted credential redaction, lost write acknowledgements, interrupted recovery, changed-input rejection, duplicate stored rows, shared CDN attribution, stale VPN observations, potentially backported versions, family-only evidence, and unknown/final cost handling. Actual local SDK restart retained two Dataset rows without duplicating completed domains.

Known limitations: live Shodan account behavior and hosted Apify build/run have not been verified. Commercial licensing and final costs remain unresolved. One known moderate `stream-json` advisory remains accepted for the currently reviewed, unaffected import path; see [BUILD_NOTES.md](../BUILD_NOTES.md). QA fails on new advisory identities or severities. Deployment API behavior is mock-tested; dry run performs no hosted mutation.
