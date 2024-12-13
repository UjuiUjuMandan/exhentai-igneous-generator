import fetch from 'node-fetch';

export default async function handler(req, res) {
  try {
    const { method, query, body } = req;
    const ipbMemberId = method === "GET" ? query.ipb_member_id : body.ipb_member_id;
    const ipbPassHash = method === "GET" ? query.ipb_pass_hash : body.ipb_pass_hash;

    if (!ipbMemberId || !ipbPassHash) {
      return res.status(400).json({ error: "Missing required parameters" });
    }

    const cookie = `ipb_member_id=${ipbMemberId}; ipb_pass_hash=${ipbPassHash}`;
    const headers = { Cookie: cookie };

    const forumsUrl = "https://forums.e-hentai.org";
    const forumsResponse = await fetch(forumsUrl, { headers });
    const forumsHtml = await forumsResponse.text();

    const banMatch = forumsHtml.match(
      /<div class="errorwrap">\s*<h4>The error returned was:<\/h4>\s*<p>Your account has been temporarily suspended\. This suspension is due to end on (.*?)\.<\/p>/
    );

    if (banMatch) {
      return res.json({
        accountStatus: "banned",
        banEndDate: banMatch[1],
      });
    }

    const targetUrl = "https://exhentai.org/";
    const response = await fetch(targetUrl, { headers });
    const headersObject = {};
    response.headers.forEach((value, key) => (headersObject[key] = value));

    const uconfigUrl = "https://e-hentai.org/uconfig.php";
    const uconfigResponse = await fetch(uconfigUrl, { headers });
    const html = await uconfigResponse.text();
    const match = html.match(/<p>You appear to be browsing the site from <strong>(.*?)<\/strong>/);
    const browsingCountry = match ? match[1] : "Unknown";

    return res.json({
      accountStatus: "Unknown",
      headers: headersObject,
      browsingCountry: browsingCountry,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message });
  }
}

