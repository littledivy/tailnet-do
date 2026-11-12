import { TailnetObject } from "../../../src/index.js";

// One Durable Object = one tailnet device that answers on
// https://<hostname>.<tailnet>.ts.net/ with a certificate Tailscale issues
// through Let's Encrypt. The tailnet needs HTTPS Certificates enabled (admin
// console, DNS page).
//
// Vars:
//   TS_AUTHKEY             Tailscale auth key.
//   TS_HOSTNAME            Device name, default "https-node".
//   TS_ACME_DIRECTORY_URL  Another ACME directory. Without it certificates
//                          come from Let's Encrypt production, which issues
//                          about five a week for one name and publishes
//                          every name. Use the staging directory,
//                          https://acme-staging-v02.api.letsencrypt.org/directory,
//                          while you experiment.
//   ACCESS_TOKEN           Protects this Worker's own URL; see below.
export class HttpsNode extends TailnetObject {
  tailnetOptions() {
    return { ...super.tailnetOptions(), hostname: this.env.TS_HOSTNAME ?? "https-node" };
  }

  async onTailnet(tailnet) {
    const hello = (request, who) => new Response(`hello ${who?.loginName ?? "stranger"}\n`);

    const https = tailnet.serveHTTPS(443, hello);
    https.ready.then(
      (cert) => console.log(`serving https://${cert.domain}/, certificate expires ${cert.expiry}`),
      (err) => console.log(`HTTPS is not ready: ${err.message}`),
    );

    // Plain HTTP keeps working next to it.
    tailnet.serve(80, hello);
  }

  async fetch(request) {
    const tailnet = await this.tailnet();
    // POST /renew replaces the certificate now, to try the renewal path.
    // Every call issues a certificate, so it always needs the token.
    if (request.method === "POST" && new URL(request.url).pathname === "/renew") {
      if (!this.env.ACCESS_TOKEN || !hasToken(request, this.env)) {
        return new Response("set ACCESS_TOKEN and send it as a bearer token\n", { status: 401 });
      }
      return Response.json(await tailnet.renewCertificate());
    }
    return Response.json(tailnet.status());
  }
}

function hasToken(request, env) {
  return request.headers.get("authorization") === `Bearer ${env.ACCESS_TOKEN}`;
}

export default {
  async fetch(request, env) {
    // The node's status (and login URL) is private: requests need
    // ACCESS_TOKEN as a bearer token. Only localhost may read it without.
    const url = new URL(request.url);
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (env.ACCESS_TOKEN || !local) {
      if (!env.ACCESS_TOKEN || !hasToken(request, env)) {
        return new Response("unauthorized", { status: 401 });
      }
    }
    return env.NODE.getByName("main").fetch(request);
  },
};
