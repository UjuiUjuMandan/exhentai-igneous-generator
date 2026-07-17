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

- `_worker.js` — Cloudflare Pages Function entry point. `/api` takes `ipb_member_id` / `ipb_pass_hash` (and an optional `cf_connecting_ip`), checks the forums for an account ban (plain `fetch()`), then connects directly to exhentai.org's `/uconfig.php` to grab igneous and the other account cookies, along with the currently-detected browsing country.
- `index.html` / `Tenboro.png` / `privacy_policy.txt` — frontend page and static assets.
- `lib/directTls.js` — the `cloudflare:sockets`-based direct-connect implementation: opens a TCP socket, does the TLS 1.3 handshake via subtls, and hand-parses HTTP/1.1 requests/responses (`Content-Length`, `chunked`, and read-until-close are all supported), so one connection can carry more than one request.
- `vendor/subtls/` — the third-party TLS 1.3 client ([jawj/subtls](https://github.com/jawj/subtls), MIT licensed), pulled in as a git subtree and trimmed to just what the Workers build needs (dropping HTTP/2, Postgres, and the Node/browser-specific transports). Its runtime dependency on the `hextreme` package has also been removed in favor of a couple of equivalent local functions (see `src/util/hextremeLite.ts`), so deploying doesn't require running `npm install`.
- `certs.index.json` / `certs.binary.txt` — a snapshot of Mozilla's root certificate database, served as static assets for subtls's certificate chain verification.
- `country-ips.js` — the country name -> probe IP map used by the `CF-Connecting-IP` picker in the frontend. United States is special-cased: `generateUsWarpIp()` generates a fresh random Cloudflare WARP IPv6 on the spot instead of using one fixed IP.
- `wrangler.toml` / `package.json` — Cloudflare Pages deployment config.
