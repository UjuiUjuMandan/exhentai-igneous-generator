import { openDirectHttpsSession } from "./lib/directTls.js";

// Only plain IPv4/IPv6 characters allowed, so a spoofed value can never break
// out of the header line (no CR/LF, no ": " injection).
const IP_RE = /^[0-9a-fA-F:.]+$/;
// IPB member IDs are plain integers. ipb_pass_hash is a hex hash digest - MD5
// (32 chars) today, but not pinned to that exact length in case the site
// ever changes hash algorithms; hex-only is what actually matters here, so a
// stray CR/LF or other header-breaking character can never reach the
// hand-rolled HTTP request we build in lib/directTls.js.
const MEMBER_ID_RE = /^\d{1,20}$/;
const PASS_HASH_RE = /^[a-f0-9]{16,128}$/i;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api") {
      // Same-origin only: our own frontend never needs cross-origin reads,
      // and there's no reason to let arbitrary third-party sites' JS read
      // responses from this endpoint via a visitor's browser.
      const requestOrigin = request.headers.get("Origin");
      const corsHeaders = requestOrigin === url.origin
        ? {
            "Access-Control-Allow-Origin": requestOrigin,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
          }
        : {};

      let ipbMemberId, ipbPassHash, cfConnectingIp;
      try {
        if (request.method === "GET") {
          ipbMemberId = url.searchParams.get("ipb_member_id");
          ipbPassHash = url.searchParams.get("ipb_pass_hash");
          cfConnectingIp = url.searchParams.get("cf_connecting_ip");
        } else if (request.method === "POST") {
          const body = await request.json();
          ipbMemberId = body.ipb_member_id;
          ipbPassHash = body.ipb_pass_hash;
          cfConnectingIp = body.cf_connecting_ip;
        } else if (request.method === "OPTIONS") {
          return new Response(null, { status: 204, headers: corsHeaders });
        } else {
          return new Response("Only GET, POST, and OPTIONS methods are supported", { status: 405, headers: corsHeaders });
        }

        if (!ipbMemberId || !ipbPassHash) {
          return new Response("Missing required parameters: ipb_member_id and ipb_pass_hash", { status: 400, headers: corsHeaders });
        }

        if (!MEMBER_ID_RE.test(ipbMemberId)) {
          return new Response("Invalid ipb_member_id", { status: 400, headers: corsHeaders });
        }

        if (!PASS_HASH_RE.test(ipbPassHash)) {
          return new Response("Invalid ipb_pass_hash", { status: 400, headers: corsHeaders });
        }

        if (cfConnectingIp && !IP_RE.test(cfConnectingIp)) {
          return new Response("Invalid cf_connecting_ip", { status: 400, headers: corsHeaders });
        }

        const cookie = `ipb_member_id=${ipbMemberId}; ipb_pass_hash=${ipbPassHash}`;
        const headers = new Headers();
        headers.set("Cookie", cookie);

        const forumsUrl = "https://forums.e-hentai.org";

        const forumsResponse = await fetch(forumsUrl, { method: "GET", headers });
        const forumsHtml = await forumsResponse.text();

        const banMatch = forumsHtml.match(
          /<div class="errorwrap">\s*<h4>The error returned was:<\/h4>\s*<p>Your account has been temporarily suspended\. This suspension is due to end on (.*?)\.<\/p>/
        );

        if (banMatch) {
          const banEndDate = banMatch[1];

          return new Response(
            JSON.stringify(
              {
                accountStatus: "banned",
                banEndDate: banEndDate,
              },
              null,
              2
            ),
            {
              status: 200,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        // exhentai.org is geo-blocked at Cloudflare's edge, and a normal fetch()
        // always shows Cloudflare's own (UK) CF-Connecting-IP to the origin,
        // overwriting anything we set. So this bypasses fetch() entirely:
        // connect() straight to the origin (s.exhentai.org) and speak TLS +
        // HTTP/1.1 ourselves, which lets us set an arbitrary CF-Connecting-IP
        // to spoof any country. /uconfig.php alone sets igneous (and the rest
        // of the account cookies) and reports the browsing country, so one
        // request covers both - no need to also hit "/".
        const directHeaders = { Cookie: cookie };
        if (cfConnectingIp) directHeaders["CF-Connecting-IP"] = cfConnectingIp;

        const session = await openDirectHttpsSession({
          origin: url.origin,
          connectHost: "s.exhentai.org",
          hostHeader: "exhentai.org",
        });

        let headersObject, browsingCountry;
        try {
          const uconfigResponse = await session.request({ path: "/uconfig.php", headers: directHeaders });
          headersObject = uconfigResponse.headers;
          const match = uconfigResponse.body.match(/<p>You appear to be browsing the site from <strong>(.*?)<\/strong>/);
          browsingCountry = match ? match[1] : "Unknown";
        } finally {
          await session.close();
        }

        return new Response(
          JSON.stringify(
            {
              accountStatus: "Unknown",
              headers: headersObject,
              browsingCountry: browsingCountry,
            },
            null,
            2
          ),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      } catch (err) {
        return new Response(`Error: ${err.message}`, { status: 500, headers: corsHeaders });
      }
    }

    if (url.pathname === "/" || url.pathname.endsWith(".html")) {
      const response = await env.ASSETS.fetch(request);

      return new HTMLRewriter()
        .on("option[data-cloud-run-api]", new SetAPI(env.CLOUD_RUN_API))
        .on("option[data-aws-lambda-api]", new SetAPI(env.AWS_LAMBDA_API))
        .on("option[data-azure-func-api]", new SetAPI(env.AZURE_FUNC_API))
        .transform(response);
    }
    
    return env.ASSETS.fetch(request);
  },
};

class SetAPI {
  constructor(newAPI) {
    this.newAPI = newAPI;
  }

  element(element) {
    if (this.newAPI) {
      element.setAttribute("value", this.newAPI);
      element.removeAttribute("hidden");
    } else {
      // Safari doesn't respect `hidden` on <option> elements (still shows
      // them in the popup), so actually drop the element instead.
      element.remove();
    }
  }
}
