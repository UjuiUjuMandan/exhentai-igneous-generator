import { openDirectHttpsSession } from "./lib/directTls.js";

// Only plain IPv4/IPv6 characters allowed, so a spoofed value can never break
// out of the header line (no CR/LF, no ": " injection).
const IP_RE = /^[0-9a-fA-F:.]+$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api") {
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
          return new Response(null, {
            status: 204,
            headers: {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
              "Access-Control-Allow-Headers": "Content-Type",
            },
          });
        } else {
          return new Response("Only GET, POST, and OPTIONS methods are supported", { status: 405 });
        }

        if (!ipbMemberId || !ipbPassHash) {
          return new Response("Missing required parameters: ipb_member_id and ipb_pass_hash", { status: 400 });
        }

        if (cfConnectingIp && !IP_RE.test(cfConnectingIp)) {
          return new Response("Invalid cf_connecting_ip", { status: 400 });
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
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            }
          );
        }

        // exhentai.org is geo-blocked at Cloudflare's edge, and a normal fetch()
        // always shows Cloudflare's own (UK) CF-Connecting-IP to the origin,
        // overwriting anything we set. So these requests bypass fetch()
        // entirely: connect() straight to the origin (s.exhentai.org) and
        // speak TLS + HTTP/1.1 ourselves, which lets us set an arbitrary
        // CF-Connecting-IP to spoof any country. Both requests reuse the same
        // TLS connection instead of handshaking twice.
        const directHeaders = { Cookie: cookie };
        if (cfConnectingIp) directHeaders["CF-Connecting-IP"] = cfConnectingIp;

        const session = await openDirectHttpsSession({
          origin: url.origin,
          connectHost: "s.exhentai.org",
          hostHeader: "exhentai.org",
        });

        let headersObject, browsingCountry;
        try {
          const response = await session.request({ path: "/", headers: directHeaders });
          headersObject = response.headers;

          // Same direct-connect path, so the reported browsing country
          // actually reflects the spoofed CF-Connecting-IP instead of
          // Cloudflare's edge.
          const uconfigResponse = await session.request({ path: "/uconfig.php", headers: directHeaders });
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
            headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
            },
          }
        );
      } catch (err) {
        return new Response(`Error: ${err.message}`, {
          status: 500,
          headers: {
            "Access-Control-Allow-Origin": "*",
          },
        });
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
