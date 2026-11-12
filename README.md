# tailnet-do

Put a Cloudflare Durable Object on your Tailscale tailnet. The object becomes a normal tailnet device with its own `100.x` address. It can serve HTTP, HTTPS or TCP to your other devices, dial into private machines, and act as an exit node or subnet router.

Under the hood this is Tailscale's own userspace client (WireGuard, netstack, DERP) compiled to WebAssembly. The control plane and DERP relays are reached over outbound WebSockets. Traffic that leaves an exit node goes out through `cloudflare:sockets`.

```js
import { TailnetObject } from "tailnet-do";

export class Node extends TailnetObject {
  async onTailnet(tailnet) {
    // Tailnet-only HTTP. `who` says which user and device is calling.
    tailnet.serve(80, (req, who) => new Response(`hi ${who.loginName}`));
  }
}

export default {
  async fetch(req, env) {
    const node = env.NODE.getByName("main");
    // Reach a private machine from a plain Worker, through the DO.
    return node.tailnetFetch("http://homelab:8080/status");
  },
};
```

Set `TS_AUTHKEY` (and optionally `TS_HOSTNAME`, `TS_CONTROL_URL`, `TS_ACME_DIRECTORY_URL`) as secrets. Without an auth key, the node starts an interactive login and puts the URL in `status().loginURL`.

## API

Inside a Durable Object, `Tailnet.start(ctx, options)` returns a node. `TailnetObject` wraps it for you.

- `connect("host:port")` opens TCP to a tailnet host. It returns a socket shaped like `cloudflare:sockets`, and MagicDNS names work.
- `fetch(url, init)` is HTTP over the tailnet.
- `serve(port, (request, who) => Response)` is an HTTP server on the node's tailnet address.
- `serveHTTPS(port, (request, who) => Response)` is the same over TLS, with a certificate for the node's MagicDNS name. See [HTTPS](#https).
- `listen(port, (socket, who) => {})` accepts raw TCP.
- `whois("ip:port")`, `status()`, `ready()` and `logout()` do what their names say.

Options: `authKey`, `hostname`, `controlURL`, `ephemeral`, `tags`, `exitNode`, `advertiseRoutes`, `dohURL`, `acmeDirectoryURL`, `keepAlive`, `statePrefix`, `onLog`.

`TailnetObject` also exposes `tailnetConnect`, `tailnetFetch` and `tailnetStatus` as RPC methods, so Workers without their own node can use the tailnet through a DO stub.

## HTTPS

```js
async onTailnet(tailnet) {
  const https = tailnet.serveHTTPS(443, (req, who) => new Response(`hi ${who.loginName}`));
  https.ready.then(
    ({ domain, expiry }) => console.log(`serving https://${domain}/ until ${expiry}`),
    (err) => console.log(`no certificate yet: ${err.message}`),
  );
}
```

The node then answers on `https://<hostname>.<tailnet>.ts.net/` with a certificate that browsers and curl accept. Tailscale's client gets it from Let's Encrypt, the same way `tailscale cert` does: the control server publishes the DNS record that proves ownership of the name, so the node needs no public address.

- Turn on **HTTPS Certificates** for the tailnet first (admin console, DNS page). Without it `ready` rejects and `status().certError` says so. The node checks again every minute, so there is nothing to restart once it is on.
- Do not `await` `ready` inside `onTailnet()`. It stays pending until the node is running, and `TailnetObject` waits for `onTailnet()` before it answers anything, including `tailnetStatus()` with the login URL.
- The first certificate is issued when the node first comes up, which takes a moment. The port accepts connections right away, and TLS handshakes wait for the certificate.
- The certificate, its key and the ACME account key are stored with the node's state in Durable Object storage. A restart or deploy reuses them and does not issue again. Renewal is automatic.
- `status()` reports `certDomain` (absent until the node is running, and while HTTPS is disabled for the tailnet), `certExpiry`, and `certError` if the last attempt to get the certificate failed. After a failure the node retries with a delay that grows from five minutes to one hour. A renewal that fails in the background is only logged, and is tried again every hour while the old certificate keeps working, so monitor `certExpiry` too.
- `renewCertificate()` issues a replacement now. You only need it to test renewal. Each call issues a certificate, so keep it away from untrusted callers.
- Let's Encrypt limits how many certificates it issues per name (about five identical ones a week), and every certificate, with its hostname, is published in Certificate Transparency logs. While developing, pass `acmeDirectoryURL: LETSENCRYPT_STAGING_URL` (exported by this package), or set `TS_ACME_DIRECTORY_URL` when using `TailnetObject`. Staging certificates are not trusted by clients, so test with `curl -k`. Tailscale has one ACME directory per process, so all nodes that serve HTTPS in an isolate must use the same one; `serveHTTPS` throws on a node that asks for another. When you switch from staging to production, the stored staging certificate is replaced by itself. The other way round it is not: a production certificate stays in use, so clear the node's storage to go back to staging.
- A node with a new name or wiped storage gets a new certificate, so keep the Durable Object's storage, and use a stable `hostname`.

## Limits

- An exit node only forwards TCP, plus DNS answered over DoH. Workers have no UDP sockets, so QUIC falls back to TCP. Outbound port 25 is blocked, and outbound sockets to Cloudflare IP ranges may be blocked.
- A Durable Object lives in one location, so traffic exits from where the object was created. Use `locationHint` to place exit nodes in specific regions.

## Layout and building

- `go/` holds the Go engine: a js/wasm main built against the vendored Tailscale tree.
- `vendor/tailscale` is a git submodule pinned to the tested commit.
- `patches/tailscale/` holds our changes to Tailscale as `git format-patch` files.
- `src/` is the JS library. `src/tailnet.wasm` is a build output.
- `examples/exit-node/` is an exit node that also serves a page on the tailnet.
- `examples/https-node/` serves `hello <loginName>` over HTTPS on port 443, and over HTTP on port 80.
- `test/local-tailnet/` is an end-to-end test of HTTPS serving that needs no tailnet and no Let's Encrypt. It runs the https-node example against a control server, DERP relay and ACME CA from Tailscale's test packages, all on loopback.

```sh
git submodule update --init --depth 1
npm run build                      # apply patches, then build src/tailnet.wasm
npm test                           # tests of the Tailscale patches, and of the engine as wasm under Node
npm run test:e2e                   # test/local-tailnet/run.sh
cd examples/exit-node && npx wrangler dev
```

To change Tailscale, start from a clean pinned checkout, run `git -C vendor/tailscale am ../../patches/tailscale/*.patch`, and add your commits on top. Then run `./scripts/update-patches.sh tailscale` to regenerate `patches/tailscale/`.
