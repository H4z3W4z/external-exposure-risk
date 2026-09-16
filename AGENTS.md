# External Exposure Risk Actor

Build a passive Apify Actor, not an active scanner or a dashboard.
Keep provider response shapes out of the priority engine. Exact CVE joins only.
Never turn a Shodan association or its `verified` flag into confirmed vulnerability or independently checked affected-version evidence.
Do not persist raw Shodan responses across runs. Public KEV/EPSS caches may persist.
Never log input credentials, provider URLs containing keys, raw provider errors or raw banners.
Run `npm run check` and `npm run build` before committing changes.
Record scope decisions and actual verification results in BUILD_NOTES.md.
Keep public release gated on Shodan licensing review and live Apify verification.

The Shodan credential supplied for acceptance testing is test-only. Never configure it as a production default; production requires a replacement customer/runtime key.
