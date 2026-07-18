import fetch from 'node-fetch';

const ALLOWED_ORIGIN = 'https://exhentai-igneous-generator.pages.dev';

const RATE_LIMIT_RE = /This IP address has been temporarily banned due to an excessive request rate\..*?The ban expires in (.*?)$/;
const GUEST_RE = /<p class="pcen"><b>Welcome Guest<\/b>/;
const LOGGED_IN_RE = /<p class="home"><b>Logged in as:\s*<a[^>]*>(.*?)<\/a>/;
const BOUNCE_LOGIN_RE = /\/bounce_login\.php/;
const ACCOUNT_SUSPENDED_FORUMS_RE =
  /<div class="errorwrap">\s*<h4>The error returned was:<\/h4>\s*<p>Your account has been temporarily suspended\. This suspension is due to end on (.*?)\.<\/p>/;
const ACCOUNT_SUSPENDED_RE = /This page is currently not available, as your account has been suspended\./;
const EXHENTAI_BROWSING_COUNTRY_RE = /<p>You appear to be browsing the site from <strong>(.*?)<\/strong>/;
const EHENTAI_BROWSING_COUNTRY_RE = /<p>You appear to be located in <strong>(.*?)<\/strong>/;

// Azure Function handler
export async function index(context, req) {
  context.res = {
    headers: {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  };

  if (req.method === "OPTIONS") {
    context.res.status = 204;
    return;
  }

  try {
    const { method, query, body } = req;
    const ipbMemberId = method === "GET" ? query.ipb_member_id : body.ipb_member_id;
    const ipbPassHash = method === "GET" ? query.ipb_pass_hash : body.ipb_pass_hash;

    if (!ipbMemberId || !ipbPassHash) {
      context.res.status = 400;
      context.res.body = { error: "Missing required parameters" };
      return;
    }

    const cookie = `ipb_member_id=${ipbMemberId}; ipb_pass_hash=${ipbPassHash}`;
    const headers = { Cookie: cookie };

    const forumsUrl = "https://forums.e-hentai.org";
    const forumsResponse = await fetch(forumsUrl, { headers });
    const forumsHtml = await forumsResponse.text();

    const loggedInMatch = forumsHtml.match(LOGGED_IN_RE);

    if (!loggedInMatch && GUEST_RE.test(forumsHtml)) {
      context.res.body = { accountStatus: "unauthenticated" };
      return;
    }

    const loginName = loggedInMatch ? loggedInMatch[1] : undefined;
    const suspendedMatch = forumsHtml.match(ACCOUNT_SUSPENDED_FORUMS_RE);

    if (suspendedMatch) {
      context.res.body = {
        accountStatus: "suspended",
        loginName: loginName,
        suspendedUntil: suspendedMatch[1],
      };
      return;
    }

    // e-hentai.org only checks account credentials (no IP-auth), so its
    // bounce_login.php redirect is the fastest definite "these credentials
    // don't authenticate" signal available - no reason to wait on
    // exhentai's response first to learn that. Both origin checks run
    // concurrently; exhentai is still the one that has to run regardless,
    // since it's the only one that sets igneous.
    async function queryExhentai() {
      const targetUrl = "https://exhentai.org/uconfig.php";
      const response = await fetch(targetUrl, { headers });
      const headersObject = {};
      response.headers.forEach((value, key) => (headersObject[key] = value));
      const body = await response.text();

      const rateLimitMatch = body.match(RATE_LIMIT_RE);
      if (rateLimitMatch) {
        return { headersObject, browsingCountry: "Unknown", rateLimitExpiresIn: rateLimitMatch[1] };
      }
      if (ACCOUNT_SUSPENDED_RE.test(body)) {
        return { headersObject, browsingCountry: "Unknown", accountSuspended: true };
      }
      const match = body.match(EXHENTAI_BROWSING_COUNTRY_RE);
      return { headersObject, browsingCountry: match ? match[1] : "Unknown" };
    }

    async function queryEhentai() {
      const uconfigUrl = "https://e-hentai.org/uconfig.php";
      const uconfigResponse = await fetch(uconfigUrl, { headers, redirect: 'manual' });
      if (uconfigResponse.status >= 300 && uconfigResponse.status < 400 && BOUNCE_LOGIN_RE.test(uconfigResponse.headers.get('location') || "")) {
        return { unauthenticatedConfirmed: true };
      }
      const body = await uconfigResponse.text();
      const rateLimitMatch = body.match(RATE_LIMIT_RE);
      if (rateLimitMatch) {
        return { rateLimitExpiresIn: rateLimitMatch[1] };
      }
      if (ACCOUNT_SUSPENDED_RE.test(body)) {
        return { accountSuspended: true };
      }
      const match = body.match(EHENTAI_BROWSING_COUNTRY_RE);
      return { browsingCountry: match ? match[1] : undefined };
    }

    const [exhentaiResult, ehentaiResult] = await Promise.all([queryExhentai(), queryEhentai()]);

    const headersObject = exhentaiResult.headersObject;
    const unauthenticatedConfirmed = ehentaiResult.unauthenticatedConfirmed;
    const accountSuspended = exhentaiResult.accountSuspended || ehentaiResult.accountSuspended;
    // exhentai's browsing-country string only appears once the spoofed IP
    // has also passed exhentai's IP-auth check; if it hasn't, use
    // e-hentai's country instead (it only checks account credentials).
    const browsingCountry = exhentaiResult.browsingCountry !== "Unknown" ? exhentaiResult.browsingCountry : (ehentaiResult.browsingCountry ?? "Unknown");
    const rateLimitExpiresIn = exhentaiResult.rateLimitExpiresIn || ehentaiResult.rateLimitExpiresIn;

    context.res.body = {
      accountStatus: unauthenticatedConfirmed
        ? "unauthenticated"
        : accountSuspended
        ? "suspended"
        : loggedInMatch || browsingCountry !== "Unknown"
        ? "not suspended"
        : "Unknown",
      loginName: loginName,
      ipStatus: rateLimitExpiresIn ? "rateLimited" : "OK",
      ...(rateLimitExpiresIn ? { rateLimitExpiresIn } : {}),
      headers: headersObject,
      browsingCountry: browsingCountry,
    };
  } catch (error) {
    context.log.error(error);
    context.res.status = 500;
    context.res.body = { error: error.message };
  }
};
