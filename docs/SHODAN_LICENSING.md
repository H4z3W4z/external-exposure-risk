# Shodan licensing gate

Reviewed 2026-09-16 UTC (2026-09-15 Pacific). **Commercial release is not cleared.**

Source: [Shodan Website & API Plans — Terms of Service](https://static.shodan.io/legal/terms.html), fetched during implementation. Account-specific agreements may differ; no such agreement was supplied.

| Topic | Published terms / unresolved question |
| --- | --- |
| Commercial use | Section 6.8 restricts Academic/Research access to noncommercial use. Confirm the customer's plan and this paid Actor use case. |
| Paid third-party services | Section 6.5 restricts resale of the Services without separate permission. BYO credentials do not establish permission for paid prioritization. |
| Derived results | Section 9.2 restricts specified uses of protected Content, including derivatives. Confirm whether our normalized evidence and derived findings are permitted. |
| Redistribution | Confirm permission for the precise Dataset fields and customer exports; do not assume source attribution grants redistribution rights. |
| Caching/storage | No clear retention allowance for this use case was established. Confirm in-run caching and persisted customer assessment evidence. |
| Attribution | Section 6.7 requires attribution and ownership/copyright identification. Findings, summaries and README identify Shodan. |

## Implementation pending confirmation

Customers supply their own API key. The code calls existing-observation APIs, caches normalized Shodan observations only in run memory, and omits raw banners. Derived results include selected evidence in the caller's Dataset, so they are still stored and must be covered by the applicable agreement. Public KEV/EPSS caching is separate.

Before a paid Store launch, obtain written confirmation covering the above questions, record the applicable plan/agreement and review date, and set permitted retention/export policies. Source code publication is not a claim that commercial data rights are cleared. No Shodan contact or agreement has been made on the user's behalf.

Technical references: [API](https://developer.shodan.io/api), [credit rules](https://help.shodan.io/the-basics/credit-types-explained).
