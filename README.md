![](Tenboro.png)

# ExHentai Igneous Generator

Fetch an ExHentai igneous cookie via a PaaS network proxy.

## Branches

- `main` — Cloudflare Pages deployment. Used to fetch exhentai.org via plain `fetch()`, with a fixed egress IP of `2a06:98c0:3600::103` that ExHentai geolocates as the UK. Now uses `connect()` to talk directly to the origin, implementing TLS 1.3 + HTTP by hand, with a `CF-Connecting-IP` header spoofing an egress IP from any country.
- `r` — formerly used for the Azure / GCP egress IPs.
- `vercel` — unused, since Vercel's egress still ends up going through AWS anyway.
- `awslambda` — deploys to AWS Lambda.
- `azurefunc` — deploys to Microsoft Azure Functions.
- `cloudrun` — deploys to Google Cloud Run.

## `main` branch layout

- `_worker.js` — Cloudflare Pages Function entry point.
  - `/api` takes `ipb_member_id` / `ipb_pass_hash` (and an optional `cf_connecting_ip`), checks the forums for an account ban (plain `fetch()`), then connects directly to exhentai.org's `/uconfig.php` to grab igneous and the other account cookies, along with the currently-detected browsing country.
  - `/api/scan` powers the country scanner: it runs a pre-flight check against e-hentai.org's origin (aborting up front if the account is logged out, suspended, or rate-limited, and only proceeding once it positively confirms a browsing country comes back), then probes each country in the requested list (the 27 random-IP countries, or all ~249 when the request sets `all_countries`) over a **single** TLS/HTTP/2 connection to `s.exhentai.org` — each country is a separate multiplexed stream carrying its own spoofed `CF-Connecting-IP`, fired in waves — and streams each result back as NDJSON. When exhentai withholds the browsing country (which happens on the same responses that hand back a `mystery` igneous), a second persistent e-hentai connection fills it in for the same IP.
- `index.html` — the single-lookup frontend.
- `scan.html` — the country scanner: sweeps countries via `/api/scan`, filling a live results table and colouring an SVG world map (green = real igneous, amber = mystery/deleted, red = failed, grey = not scanned) as results stream in. By default it only covers the 27 countries with a randomly generated VPN egress address (`RANDOM_IP_COUNTRIES`); the "all countries" checkbox sends `all_countries` to widen the sweep to all ~249, which costs ~9x the requests to probe one static IP per country.
- `Tenboro.png` / `privacy_policy.txt` — static assets.
- `BlankMap-World.svg` — the [Wikimedia Commons BlankMap-World](https://commons.wikimedia.org/wiki/File:BlankMap-World.svg) map, whose land paths each carry their ISO 3166-1 alpha-2 code as a CSS class, used by the scanner to colour countries by result.
- `lib/directTls.js` — the `cloudflare:sockets`-based direct-connect implementation: opens a TCP socket, does the TLS 1.3 handshake via subtls, then speaks HTTP/2 by hand (ALPN-negotiated, HPACK-encoded frames), demultiplexing frames by stream ID so one connection can carry several concurrent requests. It opens the HTTP/2 flow-control windows wide in the connection preface (a large `SETTINGS_INITIAL_WINDOW_SIZE` plus a connection-level `WINDOW_UPDATE`), since it never sends incremental `WINDOW_UPDATE`s — without this, response bodies get truncated once many streams share the default 64 KB window (as in the scan).
- `vendor/subtls/` — the third-party TLS 1.3 client ([jawj/subtls](https://github.com/jawj/subtls), MIT licensed), pulled in as a git subtree and trimmed to just what the Workers build needs (dropping Postgres and the Node/browser-specific transports; `src/h2.ts` and `src/util/hpackBytes.ts` were restored from upstream for `directTls.js`'s HTTP/2 client). Its runtime dependency on the `hextreme` package has also been removed in favor of a couple of equivalent local functions (see `src/util/hextremeLite.ts`), so deploying doesn't require running `npm install`.
- `certs.index.json` / `certs.binary.txt` — a snapshot of Mozilla's root certificate database, served as static assets for subtls's certificate chain verification.
- `country-ips.js` — an ES module (imported by both `_worker.js` and the two frontend pages) holding the country name -> probe IP map (`COUNTRY_IPS`) used by the `CF-Connecting-IP` picker and the scan, plus `COUNTRY_ZH` (Chinese names) and `COUNTRY_CODE` (name -> ISO alpha-2, bridging country names to the map's CSS classes). 27 countries skip the fixed probe IP entirely and get a fresh random address per request, via `spoofIpForCountry()`: the United States goes through `generateUsWarpIp()` (Cloudflare WARP), and 26 others through `generateFastlyVpnIp()`, which draws from that country's own Fastly MASQUE (Firefox VPN) `/44` blocks in `FASTLY_VPN_GROUPS` — exhentai's IP database honours Fastly's announced egress locations but resolves every WARP address to the US. Those 27 are exported as `RANDOM_IP_COUNTRIES`, the scanner's default country list.
- `wrangler.toml` / `package.json` — Cloudflare Pages deployment config.
