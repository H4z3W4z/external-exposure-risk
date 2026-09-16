# External Exposure Risk Actor

Turn externally observable attack-surface data into prioritized security risk using **Shodan, CISA KEV, and FIRST EPSS**.

This Apify Actor answers: **Which externally observable exposures deserve attention first, and why?** It combines existing service observations with exact CVE intelligence, produces explainable priorities, and preserves the evidence needed to investigate. It makes no requests to target HTTP/TLS services and performs no active scans.

**Status:** V1 implementation with 94 automated tests, bounded portfolio stress verification, recovery support, deployment preparation, and public-source smoke verification. Live customer-key Shodan and hosted Apify acceptance runs are still required. Paid public release is gated on the [Shodan licensing review](docs/SHODAN_LICENSING.md).

## What it does

- Accepts one domain or a portfolio of up to 100 domains; normalizes case, IDNs, trailing dots and duplicates.
- Resolves public IPv4/IPv6 addresses and retrieves existing Shodan observations. Optional related-host discovery uses one hostname-search page.
- Deduplicates IP/service endpoints and retains the latest service observation, its timestamp, product, version, CPE, and explicit CVE associations.
- Joins exact CVEs to the official CISA KEV catalog and fetches EPSS only for relevant CVEs.
- Returns one Dataset record per normalized domain, ordered findings, evidence, confidence, limitations, a readable summary, and run diagnostics.

The product is external exposure prioritization, not a generic CVE scanner. It supports vulnerability management and attack surface management workflows for cybersecurity teams, MSPs, and MSSPs without equating external attack surface observations with confirmed vulnerability.

## Quick start

Requires Node.js 22 or later.

```bash
npm ci --ignore-scripts
npm run check
npm run build
npm run demo
```

The demo is entirely synthetic and makes no network calls. See [its output](examples/synthetic-output.json) and [readable summary](examples/synthetic-summary.txt). The example CVE metadata is fictitious and must not be used as threat intelligence.

For a real local run, put this JSON in `storage/key_value_stores/default/INPUT.json`:

```json
{ "domains": ["example.com", "example.org"] }
```

Alternatively use `{ "domain": "example.com" }`. Provide one form, not both. Bare domain names only; IP, ASN, CIDR, wildcard and URL inputs are rejected.

Supply your own Shodan key without placing it in a committed file or shell command history:

```bash
read -rsp 'Shodan API key: ' SHODAN_API_KEY
export SHODAN_API_KEY
npm start
unset SHODAN_API_KEY
```

Local results appear in `storage/datasets/default/`. The default key-value store receives `SUMMARY.txt` and `DIAGNOSTICS.json`. `storage/` and `.env*` are excluded from Git and the Docker build context. For alternate local storage, set `CRAWLEE_STORAGE_DIR`. Leave `APIFY_IS_AT_HOME` **unset** locally.

## Apify setup and credentials

1. Create a private Actor from this GitHub repository. The `.actor/actor.json` manifest points to the Dockerfile and input/output schemas. Use 256 MB initially; measure representative portfolios before raising caps.
2. Build the Actor. Supply each customer's key through the **Your Shodan API key** input, which has `isSecret: true`, or a secret `SHODAN_API_KEY` runtime environment variable. The input takes precedence. Never configure the key as a Docker build argument.
3. Run on representative domains you are authorized to assess. Review Dataset output, `SUMMARY`, and `DIAGNOSTICS`, including stale/partial/no-data cases.
4. Complete the release checks in [BUILD_NOTES.md](BUILD_NOTES.md) before listing a paid Actor in the Store.

Apify encrypts secret inputs and decrypts them inside `Actor.getInput()`; see [secret inputs](https://docs.apify.com/actors/development/actor-definition/input-schema/secret-input). Local plain input files do not gain platform encryption, so use the environment for local credentials. The Actor never deliberately logs input keys, raw provider exceptions, credential-bearing URLs, or raw banners. Output is also redacted against known runtime credentials.

## Input options

| Field | Default | Meaning |
| --- | --- | --- |
| `domains` / `domain` | Required | 1–100 submitted domains; duplicates count toward the submission cap but are analyzed once |
| `shodanApiKey` | Environment fallback | Encrypted customer key on Apify |
| `discoverRelatedHosts` | `false` | One Shodan hostname-search page; may consume query credits |
| `maxIpsPerDomain` | `20` | 1–100; current DNS addresses take precedence over historical hostnames |
| `maxServicesPerIp` | `200` | 1–1,000 normalized services; limits analysis, not bytes returned by Shodan |
| `maxCvesPerDomain` | `2000` | 1–5,000 EPSS enrichments; remaining associations still receive exact KEV correlation |
| `staleAfterDays` | `30` | 1–365; older observations cannot receive high priority |
| `highEpssThreshold` | `0.9` | Probability, not percentile; range 0–1 |

Limits produce warnings and partial status. Domains are processed sequentially; Shodan request starts are spaced by at least 1.1 seconds. Network/429/5xx failures receive at most two retries, with capped backoff; each attempt counts toward usage. Repeated authentication/access/rate-limit failure disables further Shodan requests for the run. Shared IPs and public intelligence are reused while present in bounded memory caches; eviction can cause additional requests. Fixed per-domain analysis and output budgets apply even when input caps are raised; see [operating limits](docs/OPERATIONS.md).

## Output and interpretation

Each domain record contains `schemaVersion`, `domain`, `analyzedAt`, `status`, `summary`, `priorities`, `assets`, `sources`, `warnings`, `humanSummary`, and `output`. The `output` metadata reports byte limits, omitted findings/assets, and whether analysis stopped at a budget. Records stay at or below 4,000,000 UTF-8 bytes; retained findings keep their evidence. Summary counts cover all assessed observations, including omitted detail. Findings include endpoint, product/version/CPE, CVE, KEV status, ransomware context, EPSS probability/percentile/date, priority, confidence rationale, observation age, correlation method, and evidence URLs/timestamps.

An abbreviated **synthetic** finding:

```json
{
  "priority": "HIGH_PRIORITY",
  "ip": "203.0.113.10",
  "port": 443,
  "product": "Example Gateway",
  "version": "1.2.3",
  "cve": "CVE-2024-0001",
  "cisaKev": true,
  "epss": 0.968,
  "confidence": "HIGH",
  "applicability": "ASSOCIATED",
  "correlationMethod": "EXACT_CVE",
  "observedAt": "2026-09-14T12:00:00.000Z"
}
```

`ok` means the requested data pipeline completed, **not** that the domain is safe. `partial` indicates unavailable/stale intelligence, failed discovery steps, or caps. `no_data` means no usable observations; `failed` means essential DNS/Shodan collection failed without usable observations. Individual domain failures do not stop the portfolio. Clients must inspect each record's status even if the Actor run succeeds.

Summary counts measure endpoint-CVE associations, so a CVE on two services counts twice; `uniqueCves` deduplicates CVE IDs. `kevMatches` includes matches from a labeled stale fallback catalog; `highEpss` counts only fresh high-score associations. `knownRansomwareUse` is `true` or `null` (unknown), never an inferred negative. KEV absence is `false` only against a fresh catalog; an unavailable or stale catalog yields `null` for missing matches. Missing EPSS is `null`, not zero.

### Priority definitions

| Category | Deterministic rule |
| --- | --- |
| `CRITICAL_PRIORITY` | Reserved for strong, independently checked affected-version evidence plus KEV. **Not emitted in V1**: Shodan's `verified` flag and product/version/CPE do not establish that evidence. |
| `HIGH_PRIORITY` | Recent, non-conflicting service-level exact KEV association; or recent product/version plus exact CVE association and fresh EPSS at/above the threshold. |
| `MEDIUM_PRIORITY` | Exact CVE association with incomplete exploitation/applicability evidence; also stale, conflicting, or host-only KEV associations. |
| `INFORMATIONAL` | Recent structured service/product observation without supplied CVE associations. |
| `INSUFFICIENT_EVIDENCE` | Service observation has weak, conflicting, stale, missing-date, or future-date evidence and no usable CVE association. A domain with no observations has no findings and an explicit insufficient-evidence summary. |

There is no opaque numerical risk score. Sorting uses category, KEV match, EPSS probability, then a stable finding ID. For identical input, clock, observations, and intelligence, findings are deterministic. Run timing and cache metadata naturally vary.

### Confidence and applicability

`HIGH` describes a recent explicit CVE association or structured product/version/CPE observation. `MEDIUM` describes a confidently observed product with incomplete detail. `LOW` covers stale/invalid timestamps, equal-time conflicts, missing structured product evidence, and host-only CVEs. High confidence in an association is **not** high confidence that an endpoint is vulnerable.

V1 emits `OBSERVED` and `ASSOCIATED` applicability only. It neither independently checks vendor affected-version ranges nor emits `POTENTIALLY_AFFECTED` or `CONFIRMED_VULNERABLE`. No product-name fuzzy matching occurs. Older CVEs are not merged into newer service observations. Host-level associations stay unattributed to any port.

## Sources, caching, and attribution

- [Shodan host/search API](https://developer.shodan.io/api): existing observations only, no scan requests. Normalized results live in a per-run memory cache. Raw banners are discarded. Shodan observation materials remain owned/copyrighted by Shodan; outputs identify their source. No endorsement is implied.
- [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json): exact CVE joins, vendor/product, dates, required action, notes, and ransomware context. CISA due dates are catalog metadata, not a deadline assigned to the customer by this Actor.
- [FIRST EPSS API](https://api.first.org/epss/): probability, percentile, and data date. Requests batch up to 50 relevant CVEs, below the API's 2,000-character CVE query limit. EPSS is exploitation probability for a CVE, not a host vulnerability test.

Public KEV/EPSS results are cached for 24 hours in the caller's named `external-exposure-public-intel-v1` key-value store. A refresh failure may use a labeled fallback at most seven days old; missing/stale EPSS never raises priority. EPSS data dates three or more days old are also labeled stale. Cache failures fall back to direct retrieval. The Shodan cache is scoped to one provider instance/run; normalized assessment output remains in the user's Dataset according to that user's storage retention settings.

## Usage, costs, and billing

`DIAGNOSTICS` records domain counts, Shodan attempts/results/search pages, DNS queries, KEV refreshes, EPSS/CVE requests, retries, cache hits/misses/fallbacks, sanitized error counts, runtime, peak RSS, and Apify compute/usage snapshots where available.

`actualMarginalCostPerDomainUsd` stays `null` until final costs are known. A local run does not imply zero marginal cost, and a running Actor's Apify usage is not its final bill. BYO Shodan cost is not known to this Actor. Reconcile final run usage plus actual incremental provider expense, divided by unique domains analyzed; report no-data/failure rates alongside this metric. Do not treat `usageTotalUsd` as final net developer margin.

Pay Per Event preparation uses `domain_analyzed` as the intended future unit and tracks observed-domain eligibility. **No charging events are enabled and no retail price is finalized.** Related-host search can consume Shodan credits; see [Shodan credit rules](https://help.shodan.io/the-basics/credit-types-explained). Set caps and confirm your account's entitlements before large portfolios.

The offline cost calculator accepts your rates or final expenses and reports unknown totals as `null`. Deployment automation prepares a private Actor build pinned to a Git commit. See [operations, recovery, deployment, and cost commands](docs/OPERATIONS.md).

## API, bulk and agents

After deployment, send the same input to your Actor's Apify API. For example, using a secret environment variable and a non-secret `APIFY_ACTOR_ID` (`owner~actor-name`):

```js
const response = await fetch(`https://api.apify.com/v2/acts/${process.env.APIFY_ACTOR_ID}/run-sync-get-dataset-items`, {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${process.env.APIFY_TOKEN}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    domains: ['example.com', 'example.org'],
    shodanApiKey: process.env.SHODAN_API_KEY,
  }),
});
if (!response.ok) throw new Error(`Actor request failed (${response.status})`);
const assessments = await response.json();
```

Use asynchronous Actor runs and retrieve the Dataset for longer portfolios; synchronous API requests have platform time limits. Split portfolios above 100 domains into separate runs. Do not retry a running invocation blindly, since it may still be consuming resources.

Use [Apify's MCP server](https://docs.apify.com/integrations/mcp) to invoke the deployed Actor from an agent with access to it. Output schemas expose the Dataset, summary, and diagnostics. Agents can filter `assets`, `priorities`, or `cisaKev === true`; no separate MCP server or bespoke operations are implemented.

## Limitations and safety

DNS addresses and historical hostnames do not prove ownership. Shared hosting, reverse proxies, CDNs, reassigned IPs, and incomplete IPv6 coverage affect attribution. Historical hostname discovery is optional and deliberately incomplete. An observed version can be misleading, backported patches are not visible, and an associated CVE may require configuration or local privileges that this Actor does not establish.

No exploitation, payload delivery, credential testing, brute force, authentication bypass, Nmap, Nuclei, sqlmap, on-demand Shodan scans, directory discovery, screenshots, or target HTTP/TLS fetching is implemented. Optional CVE metadata enrichment, historical deltas, alerts, dashboards and custom MCP are deferred.

> External Exposure Risk Actor correlates externally observed technology and service information with vulnerability intelligence. A vulnerability association does not by itself confirm that a target is vulnerable. Internet observations may be incomplete or stale. Verify affected versions, configuration, exposure, and remediation status before taking action. Use the Actor only for systems and organizations you are authorized to assess or for legitimate defensive intelligence purposes.

## Development and verification

`npm run check` runs strict TypeScript checking and offline tests, including the actual Apify lifecycle with mocked network responses. `npm run smoke:public` makes DNS, KEV and EPSS calls without Shodan credentials. `docker build -t external-exposure-risk:local .` builds the production container; `npm run smoke:docker` tests it with networking disabled and synthetic fixtures under a 256 MB limit. `npm run qa` runs the full sequence plus four bounded-memory stress profiles, deployment dry run, cost CLI verification, dependency review, and source credential checks. GitHub Actions runs the same QA command on pushes and pull requests and uploads its reports. Docker is required for full QA.

See the [QA report](docs/QA_REPORT.md) and [BUILD_NOTES.md](BUILD_NOTES.md) for measured results, unresolved release items, and the scoped dependency advisory. The repository's Apache 2.0 license applies to this code, not to Shodan data or other third-party content.
