import { openDirectHttpsSession } from './lib/directTls.js';
import {
  spoofIpForCountry,
  RANDOM_IP_COUNTRIES,
  COUNTRY_IPS,
} from './country-ips.js';

const IP_RE = /^[0-9a-fA-F:.]+$/;
const MEMBER_ID_RE = /^\d{1,20}$/;
const PASS_HASH_RE = /^[a-f0-9]{16,128}$/i;
const IGNEOUS_RE = /igneous=([^;,]+)/;

const RATE_LIMIT_RE =
  /This IP address has been temporarily banned due to an excessive request rate\..*?The ban expires in (.*?)$/;
const GUEST_RE = /<p class="pcen"><b>Welcome Guest<\/b>/;
const LOGGED_IN_RE = /<p class="home"><b>Logged in as:\s*<a[^>]*>(.*?)<\/a>/;
const BOUNCE_LOGIN_RE = /\/bounce_login\.php/;
const ACCOUNT_SUSPENDED_FORUMS_RE =
  /<div class="errorwrap">\s*<h4>The error returned was:<\/h4>\s*<p>Your account has been temporarily suspended\. This suspension is due to end on (.*?)\.<\/p>/;
const ACCOUNT_SUSPENDED_RE =
  /This page is currently not available, as your account has been suspended\./;
const EXHENTAI_BROWSING_COUNTRY_RE =
  /<p>You appear to be browsing the site from <strong>(.*?)<\/strong>/;
const EHENTAI_BROWSING_COUNTRY_RE =
  /<p>You appear to be located in <strong>(.*?)<\/strong>/;

// AS60781 LeaseWeb Netherlands B.V. Scanned Jul 18 2026
const EHENTAI_ORIGIN_IPS = [
  '212.7.200.92',
  '212.7.200.95',
  '212.7.202.35',
  '212.7.202.48',
  '37.48.81.199',
  '37.48.81.210',
  '37.48.81.211',
  '37.48.92.184',
  '5.79.104.107',
  '5.79.104.108',
  '89.149.222.76',
  '89.149.222.79',
  '95.211.79.41',
  '95.211.79.42',
];

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const ipRequestHistory = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const timestamps = ipRequestHistory.get(ip) || [];
  const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

  if (recent.length >= RATE_LIMIT_MAX_REQUESTS) {
    ipRequestHistory.set(ip, recent);
    return true;
  }

  recent.push(now);
  ipRequestHistory.set(ip, recent);

  if (ipRequestHistory.size > 10000) {
    for (const [k, v] of ipRequestHistory.entries()) {
      if (!v.some((t) => now - t < RATE_LIMIT_WINDOW_MS)) {
        ipRequestHistory.delete(k);
      }
    }
  }

  return false;
}

const FORWARDED_CLIENT_HEADERS = ['User-Agent', 'Accept-Language'];

function clientHeaders(request) {
  const result = {};
  for (const name of FORWARDED_CLIENT_HEADERS) {
    const value = request.headers.get(name);
    if (value) result[name] = value;
  }
  return result;
}

function jsonError(message, status, corsHeaders) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api') {
      const requestOrigin = request.headers.get('Origin');
      const corsHeaders =
        requestOrigin === url.origin
          ? {
              'Access-Control-Allow-Origin': requestOrigin,
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type',
            }
          : {};

      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders });
      }

      const clientIp = request.headers.get('CF-Connecting-IP') || 'anonymous';
      if (isRateLimited(clientIp)) {
        return jsonError(
          'Too many requests, please slow down.',
          429,
          corsHeaders,
        );
      }

      const useFetch = url.searchParams.get('fetch') === '1';

      let ipbMemberId, ipbPassHash, cfConnectingIp;
      try {
        if (request.method === 'GET') {
          ipbMemberId = url.searchParams.get('ipb_member_id');
          ipbPassHash = url.searchParams.get('ipb_pass_hash');
          cfConnectingIp = url.searchParams.get('cf_connecting_ip');
        } else if (request.method === 'POST') {
          const body = await request.json();
          ipbMemberId = body.ipb_member_id;
          ipbPassHash = body.ipb_pass_hash;
          cfConnectingIp = body.cf_connecting_ip;
        } else {
          return jsonError(
            'Only GET, POST, and OPTIONS methods are supported',
            405,
            corsHeaders,
          );
        }

        if (!ipbMemberId || !ipbPassHash) {
          return jsonError(
            'Missing required parameters: ipb_member_id and ipb_pass_hash',
            400,
            corsHeaders,
          );
        }

        if (!MEMBER_ID_RE.test(ipbMemberId)) {
          return jsonError('Invalid ipb_member_id', 400, corsHeaders);
        }

        if (!PASS_HASH_RE.test(ipbPassHash)) {
          return jsonError('Invalid ipb_pass_hash', 400, corsHeaders);
        }

        if (cfConnectingIp && !IP_RE.test(cfConnectingIp)) {
          return jsonError('Invalid cf_connecting_ip', 400, corsHeaders);
        }

        const cookie = `ipb_member_id=${ipbMemberId}; ipb_pass_hash=${ipbPassHash}`;
        const headers = new Headers(clientHeaders(request));
        headers.set('Cookie', cookie);

        const forumsUrl = 'https://forums.e-hentai.org';

        const forumsResponse = await fetch(forumsUrl, {
          method: 'GET',
          headers,
        });
        const forumsHtml = await forumsResponse.text();

        const loggedInMatch = forumsHtml.match(LOGGED_IN_RE);

        if (!loggedInMatch && GUEST_RE.test(forumsHtml)) {
          const fetchHeaders =
            useFetch ? (await queryExhentai()).headersObject : undefined;
          return new Response(
            JSON.stringify(
              {
                accountStatus: 'unauthenticated',
                ...(fetchHeaders ? { headers: fetchHeaders } : {}),
              },
              null,
              2,
            ),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json', ...corsHeaders },
            },
          );
        }

        const loginName = loggedInMatch ? loggedInMatch[1] : undefined;
        const suspendedMatch = forumsHtml.match(ACCOUNT_SUSPENDED_FORUMS_RE);

        if (suspendedMatch) {
          const suspendedUntil = suspendedMatch[1];

          return new Response(
            JSON.stringify(
              {
                accountStatus: 'suspended',
                loginName: loginName,
                suspendedUntil: suspendedUntil,
              },
              null,
              2,
            ),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json', ...corsHeaders },
            },
          );
        }

        // exhentai.org is geo-blocked at Cloudflare's edge, and a normal fetch()
        // always shows Cloudflare's own (UK) CF-Connecting-IP to the origin,
        // overwriting anything we set. So this bypasses fetch() entirely:
        // connect() straight to the origin (s.exhentai.org) and speak TLS +
        // HTTP/2 ourselves, which lets us set an arbitrary CF-Connecting-IP
        // to spoof any country. /uconfig.php alone sets igneous (and the rest
        // of the account cookies) and reports the browsing country, so one
        // request covers both - no need to also hit "/".
        const directHeaders = { ...clientHeaders(request), Cookie: cookie };
        if (cfConnectingIp) directHeaders['CF-Connecting-IP'] = cfConnectingIp;

        async function queryExhentai() {
          if (useFetch) {
            const response = await fetch('https://exhentai.org/uconfig.php', {
              headers,
            });
            const headersObject = {};
            for (const [key, value] of response.headers.entries()) {
              headersObject[key] = value;
            }
            const body = await response.text();

            const rateLimitMatch = body.match(RATE_LIMIT_RE);
            if (rateLimitMatch) {
              return {
                headersObject,
                browsingCountry: null,
                rateLimitExpiresIn: rateLimitMatch[1],
              };
            }
            if (ACCOUNT_SUSPENDED_RE.test(body)) {
              return {
                headersObject,
                browsingCountry: null,
                accountSuspended: true,
              };
            }
            const match = body.match(EXHENTAI_BROWSING_COUNTRY_RE);
            return {
              headersObject,
              browsingCountry: match ? match[1] : null,
            };
          }

          const session = await openDirectHttpsSession({
            origin: url.origin,
            connectHost: 's.exhentai.org',
            hostHeader: 'exhentai.org',
            sniHost: 'exhentai.org',
          });
          try {
            const uconfigResponse = await session.request({
              path: '/uconfig.php',
              headers: directHeaders,
            });
            const rateLimitMatch = uconfigResponse.body.match(RATE_LIMIT_RE);
            if (rateLimitMatch) {
              return {
                headersObject: uconfigResponse.headers,
                browsingCountry: null,
                rateLimitExpiresIn: rateLimitMatch[1],
              };
            }
            if (ACCOUNT_SUSPENDED_RE.test(uconfigResponse.body)) {
              return {
                headersObject: uconfigResponse.headers,
                browsingCountry: null,
                accountSuspended: true,
              };
            }
            const match = uconfigResponse.body.match(
              EXHENTAI_BROWSING_COUNTRY_RE,
            );
            return {
              headersObject: uconfigResponse.headers,
              browsingCountry: match ? match[1] : null,
            };
          } finally {
            await session.close();
          }
        }

        async function queryEhentai() {
          if (useFetch) {
            const uconfigResponse = await fetch(
              'https://e-hentai.org/uconfig.php',
              { headers, redirect: 'manual' },
            );
            if (
              uconfigResponse.status >= 300 &&
              uconfigResponse.status < 400 &&
              BOUNCE_LOGIN_RE.test(
                uconfigResponse.headers.get('location') || '',
              )
            ) {
              return { unauthenticatedConfirmed: true };
            }
            const body = await uconfigResponse.text();
            const ehentaiRateLimitMatch = body.match(RATE_LIMIT_RE);
            if (ehentaiRateLimitMatch) {
              return { rateLimitExpiresIn: ehentaiRateLimitMatch[1] };
            }
            if (ACCOUNT_SUSPENDED_RE.test(body)) {
              return { accountSuspended: true };
            }
            const ehentaiMatch = body.match(EHENTAI_BROWSING_COUNTRY_RE);
            return { browsingCountry: ehentaiMatch ? ehentaiMatch[1] : null };
          }

          const ehentaiIp =
            EHENTAI_ORIGIN_IPS[
              Math.floor(Math.random() * EHENTAI_ORIGIN_IPS.length)
            ];
          const ehentaiSession = await openDirectHttpsSession({
            origin: url.origin,
            connectHost: ehentaiIp,
            hostHeader: 'e-hentai.org',
            sniHost: 'e-hentai.org',
          });
          try {
            const ehentaiResponse = await ehentaiSession.request({
              path: '/uconfig.php',
              headers: directHeaders,
            });
            if (
              ehentaiResponse.status >= 300 &&
              ehentaiResponse.status < 400 &&
              BOUNCE_LOGIN_RE.test(ehentaiResponse.headers.location || '')
            ) {
              return { unauthenticatedConfirmed: true };
            }
            const ehentaiRateLimitMatch =
              ehentaiResponse.body.match(RATE_LIMIT_RE);
            if (ehentaiRateLimitMatch) {
              return { rateLimitExpiresIn: ehentaiRateLimitMatch[1] };
            }
            if (ACCOUNT_SUSPENDED_RE.test(ehentaiResponse.body)) {
              return { accountSuspended: true };
            }
            const ehentaiMatch = ehentaiResponse.body.match(
              EHENTAI_BROWSING_COUNTRY_RE,
            );
            return { browsingCountry: ehentaiMatch ? ehentaiMatch[1] : null };
          } finally {
            await ehentaiSession.close();
          }
        }

        const [exhentaiResult, ehentaiResult] = await Promise.all([
          queryExhentai(),
          queryEhentai(),
        ]);

        const headersObject = exhentaiResult.headersObject;
        const unauthenticatedConfirmed = ehentaiResult.unauthenticatedConfirmed;
        const accountSuspended =
          exhentaiResult.accountSuspended || ehentaiResult.accountSuspended;
        const browsingCountry =
          exhentaiResult.browsingCountry ??
          ehentaiResult.browsingCountry ??
          null;
        const rateLimitExpiresIn =
          exhentaiResult.rateLimitExpiresIn || ehentaiResult.rateLimitExpiresIn;

        const accountStatus = unauthenticatedConfirmed
          ? 'unauthenticated'
          : accountSuspended
            ? 'suspended'
            : loggedInMatch || browsingCountry !== null
              ? 'not suspended'
              : 'Unknown';

        return new Response(
          JSON.stringify(
            {
              accountStatus: accountStatus,
              loginName: loginName,
              ipStatus: rateLimitExpiresIn ? 'rateLimited' : 'OK',
              ...(rateLimitExpiresIn ? { rateLimitExpiresIn } : {}),
              headers: headersObject,
              ...(accountStatus === 'not suspended'
                ? { browsingCountry: browsingCountry }
                : {}),
            },
            null,
            2,
          ),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          },
        );
      } catch (err) {
        return jsonError(err.message, 500, corsHeaders);
      }
    }

    const SCAN_WAVE_SIZE = 25;

    if (url.pathname === '/api/scan') {
      const requestOrigin = request.headers.get('Origin');
      const corsHeaders =
        requestOrigin === url.origin
          ? {
              'Access-Control-Allow-Origin': requestOrigin,
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type',
            }
          : {};

      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders });
      }
      if (request.method !== 'POST') {
        return jsonError(
          'Only POST and OPTIONS methods are supported',
          405,
          corsHeaders,
        );
      }

      let ipbMemberId, ipbPassHash, turnstileToken, allCountries;
      try {
        const body = await request.json();
        ipbMemberId = body.ipb_member_id;
        ipbPassHash = body.ipb_pass_hash;
        turnstileToken = body.turnstile_token;
        allCountries = body.all_countries === true;
      } catch {
        return jsonError('Invalid JSON body', 400, corsHeaders);
      }

      if (!ipbMemberId || !ipbPassHash) {
        return jsonError(
          'Missing required parameters: ipb_member_id and ipb_pass_hash',
          400,
          corsHeaders,
        );
      }
      if (!MEMBER_ID_RE.test(ipbMemberId)) {
        return jsonError('Invalid ipb_member_id', 400, corsHeaders);
      }
      if (!PASS_HASH_RE.test(ipbPassHash)) {
        return jsonError('Invalid ipb_pass_hash', 400, corsHeaders);
      }

      if (env.TURNSTILE_SECRET_KEY) {
        if (!turnstileToken) {
          return jsonError('Missing Turnstile token', 400, corsHeaders);
        }
        const form = new FormData();
        form.append('secret', env.TURNSTILE_SECRET_KEY);
        form.append('response', turnstileToken);
        const clientIp = request.headers.get('CF-Connecting-IP');
        if (clientIp) form.append('remoteip', clientIp);
        try {
          const verifyRes = await fetch(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            {
              method: 'POST',
              body: form,
            },
          );
          const verify = await verifyRes.json();
          if (!verify.success) {
            return jsonError('Turnstile verification failed', 403, corsHeaders);
          }
        } catch (err) {
          return jsonError(
            'Turnstile verification error: ' + err.message,
            502,
            corsHeaders,
          );
        }
      }

      const cookie = `ipb_member_id=${ipbMemberId}; ipb_pass_hash=${ipbPassHash}`;
      const baseHeaders = clientHeaders(request);

      const encoder = new TextEncoder();
      const stream = new ReadableStream({
        async start(controller) {
          const send = (obj) =>
            controller.enqueue(encoder.encode(JSON.stringify(obj) + '\n'));

          const scanCountries = allCountries
            ? Object.keys(COUNTRY_IPS).sort()
            : RANDOM_IP_COUNTRIES;

          try {
            const ehentaiIp =
              EHENTAI_ORIGIN_IPS[
                Math.floor(Math.random() * EHENTAI_ORIGIN_IPS.length)
              ];
            const checkSession = await openDirectHttpsSession({
              origin: url.origin,
              connectHost: ehentaiIp,
              hostHeader: 'e-hentai.org',
              sniHost: 'e-hentai.org',
            });
            let precheck;
            try {
              const res = await checkSession.request({
                path: '/uconfig.php',
                headers: { ...baseHeaders, Cookie: cookie },
              });
              if (
                res.status >= 300 &&
                res.status < 400 &&
                BOUNCE_LOGIN_RE.test(res.headers.location || '')
              ) {
                precheck = { unauthenticated: true };
              } else if (ACCOUNT_SUSPENDED_RE.test(res.body)) {
                precheck = { suspended: true };
              } else if (res.body.match(RATE_LIMIT_RE)) {
                precheck = { rateLimited: res.body.match(RATE_LIMIT_RE)[1] };
              } else {
                const countryMatch = res.body.match(
                  EHENTAI_BROWSING_COUNTRY_RE,
                );
                const loggedInMatch = res.body.match(LOGGED_IN_RE);
                precheck = {
                  browsingCountry: countryMatch ? countryMatch[1] : undefined,
                  loginName: loggedInMatch ? loggedInMatch[1] : undefined,
                };
              }
            } finally {
              await checkSession.close();
            }

            if (precheck.unauthenticated) {
              send({ type: 'aborted', accountStatus: 'unauthenticated' });
              controller.close();
              return;
            }
            if (precheck.suspended) {
              send({ type: 'aborted', accountStatus: 'suspended' });
              controller.close();
              return;
            }
            if (precheck.rateLimited) {
              send({
                type: 'aborted',
                accountStatus: 'rateLimited',
                rateLimitExpiresIn: precheck.rateLimited,
              });
              controller.close();
              return;
            }
            if (!precheck.browsingCountry) {
              send({ type: 'aborted', accountStatus: 'unconfirmed' });
              controller.close();
              return;
            }
            send({
              type: 'ready',
              accountStatus: 'not suspended',
              loginName: precheck.loginName,
              browsingCountry: precheck.browsingCountry,
              total: scanCountries.length,
              countries: scanCountries,
            });
          } catch (err) {
            send({
              type: 'error',
              message: 'Pre-flight check failed: ' + err.message,
            });
            controller.close();
            return;
          }

          // Two persistent TLS+HTTP/2 connections, each reused across every
          // country as separate multiplexed streams. CF-Connecting-IP is a
          // per-request header, so each stream can spoof a different country
          // over the one connection - no per-country handshake.
          //   - exhentai (s.exhentai.org): the real probe, sets igneous and
          //     usually reports the browsing country.
          //   - e-hentai: a fallback used only when exhentai withholds the
          //     country (which happens on the same responses that hand back a
          //     "mystery" igneous). e-hentai still resolves the geo for the
          //     spoofed IP, so we can fill the column in from there.
          let session, ehentaiSession;
          try {
            session = await openDirectHttpsSession({
              origin: url.origin,
              connectHost: 's.exhentai.org',
              hostHeader: 'exhentai.org',
              sniHost: 'exhentai.org',
            });
          } catch (err) {
            send({
              type: 'error',
              message: 'Failed to open origin connection: ' + err.message,
            });
            controller.close();
            return;
          }
          try {
            const ehentaiIp =
              EHENTAI_ORIGIN_IPS[
                Math.floor(Math.random() * EHENTAI_ORIGIN_IPS.length)
              ];
            ehentaiSession = await openDirectHttpsSession({
              origin: url.origin,
              connectHost: ehentaiIp,
              hostHeader: 'e-hentai.org',
              sniHost: 'e-hentai.org',
            });
          } catch {
            ehentaiSession = null;
          }

          async function ehentaiCountry(spoofedIp) {
            if (!ehentaiSession) return undefined;
            try {
              const res = await ehentaiSession.request({
                path: '/uconfig.php',
                headers: {
                  ...baseHeaders,
                  Cookie: cookie,
                  'CF-Connecting-IP': spoofedIp,
                },
              });
              const m = res.body.match(EHENTAI_BROWSING_COUNTRY_RE);
              return m ? m[1] : undefined;
            } catch {
              return undefined;
            }
          }

          async function probeCountry(country) {
            const spoofedIp = spoofIpForCountry(country);
            const headers = {
              ...baseHeaders,
              Cookie: cookie,
              'CF-Connecting-IP': spoofedIp,
            };
            try {
              const res = await session.request({
                path: '/uconfig.php',
                headers,
              });
              const rateLimit = res.body.match(RATE_LIMIT_RE);
              if (rateLimit) {
                return {
                  type: 'result',
                  country,
                  spoofedIp,
                  status: 'rateLimited',
                  rateLimitExpiresIn: rateLimit[1],
                };
              }
              if (ACCOUNT_SUSPENDED_RE.test(res.body)) {
                return {
                  type: 'result',
                  country,
                  spoofedIp,
                  status: 'suspended',
                };
              }
              const setCookie = res.headers['set-cookie'] || '';
              const igneousMatch = setCookie.match(IGNEOUS_RE);
              const igneous = igneousMatch ? igneousMatch[1] : 'null';
              const countryMatch = res.body.match(EHENTAI_BROWSING_COUNTRY_RE);
              let browsingCountry = countryMatch ? countryMatch[1] : undefined;
              // exhentai withholds the country on the same responses that give a
              // "mystery" igneous - fall back to e-hentai for the same IP.
              if (!browsingCountry)
                browsingCountry = await ehentaiCountry(spoofedIp);
              return {
                type: 'result',
                country,
                spoofedIp,
                status: 'ok',
                igneous,
                browsingCountry: browsingCountry ?? null,
              };
            } catch (err) {
              return {
                type: 'result',
                country,
                spoofedIp,
                status: 'error',
                message: err.message,
              };
            }
          }

          try {
            const countries = scanCountries;
            // Fire in fixed-size waves so we stay under the server's
            // SETTINGS_MAX_CONCURRENT_STREAMS and don't hammer the origin all
            // at once. Results within a wave stream out as they resolve.
            for (let i = 0; i < countries.length; i += SCAN_WAVE_SIZE) {
              const wave = countries.slice(i, i + SCAN_WAVE_SIZE);
              await Promise.all(
                wave.map(async (country) => {
                  send(await probeCountry(country));
                }),
              );
            }
            send({ type: 'done' });
          } catch (err) {
            send({ type: 'error', message: err.message });
          } finally {
            try {
              await session.close();
            } catch {}
            try {
              if (ehentaiSession) await ehentaiSession.close();
            } catch {}
            controller.close();
          }
        },
      });

      return new Response(stream, {
        status: 200,
        headers: {
          'Content-Type': 'application/x-ndjson; charset=utf-8',
          'Cache-Control': 'no-store',
          ...corsHeaders,
        },
      });
    }

    const response = await env.ASSETS.fetch(request);

    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('text/html')) {
      return new HTMLRewriter()
        .on('option[data-cloud-run-api]', new SetAPI(env.CLOUD_RUN_API))
        .on('option[data-aws-lambda-api]', new SetAPI(env.AWS_LAMBDA_API))
        .on('option[data-azure-func-api]', new SetAPI(env.AZURE_FUNC_API))
        .on('html', new SetCommitSha(env.CF_PAGES_COMMIT_SHA))
        .on('#source-code-link', new SetSourceLink(env.CF_PAGES_COMMIT_SHA))
        .transform(response);
    }

    return response;
  },
};

class SetCommitSha {
  constructor(commitSha) {
    this.commitSha = commitSha;
  }

  element(element) {
    if (this.commitSha) {
      element.setAttribute('data-commit-sha', this.commitSha);
    }
  }
}

class SetSourceLink {
  constructor(commitSha) {
    this.commitSha = commitSha;
  }

  element(element) {
    if (this.commitSha) {
      element.setAttribute(
        'href',
        `https://github.com/UjuiUjuMandan/exhentai-igneous-generator/tree/${this.commitSha}`,
      );
      element.setInnerContent(this.commitSha.slice(0, 7));
    }
  }
}

class SetAPI {
  constructor(newAPI) {
    this.newAPI = newAPI;
  }

  element(element) {
    if (this.newAPI) {
      element.setAttribute('value', this.newAPI);
      element.removeAttribute('hidden');
    } else {
      element.remove();
    }
  }
}
