// tailnet-do: put a Durable Object on a Tailscale tailnet.
//
// The Go engine (Tailscale's userspace client compiled to wasm) is loaded once
// per isolate and can host several nodes, one per Durable Object instance.

import { DurableObject } from "cloudflare:workers";
import { connect as cfConnect } from "cloudflare:sockets";
import "./wasm_exec.js";
import engineWasm from "./tailnet.wasm";

const DEFAULT_DOH = "https://cloudflare-dns.com/dns-query";

/**
 * Let's Encrypt's staging directory, for the acmeDirectoryURL option. Staging
 * certificates are not trusted by clients, and staging has far higher rate
 * limits: use it while developing.
 */
export const LETSENCRYPT_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";
const KEEPALIVE_MS = 20_000;

// ---- engine (one per isolate) ------------------------------------------

let enginePromise = null;
const logSinks = new Set();

function loadEngine(options = {}) {
  if (enginePromise) return enginePromise;
  enginePromise = (async () => {
    const go = new Go();
    // Go's stdout/stderr: forward to console. Engine logs use host.log instead.
    const decoder = new TextDecoder();
    let partial = "";
    globalThis.fs.writeSync = (fd, buf) => {
      partial += decoder.decode(buf);
      const nl = partial.lastIndexOf("\n");
      if (nl !== -1) {
        for (const line of partial.slice(0, nl).split("\n")) emitLog(line);
        partial = partial.slice(nl + 1);
      }
      return buf.length;
    };
    const instance = await WebAssembly.instantiate(engineWasm, go.importObject);
    go.run(instance).catch((e) => emitLog(`tailnet engine crashed: ${e}`));
    const api = globalThis.__tailnet;
    if (!api) throw new Error("tailnet engine failed to start");
    const doh = options.dohURL ?? DEFAULT_DOH;
    api.init({
      log: emitLog,
      dialTCP: hostDialTCP,
      dnsQuery: (q) => dohQuery(doh, q),
    });
    return api;
  })();
  return enginePromise;
}

function emitLog(line) {
  if (logSinks.size === 0) {
    console.log(line);
    return;
  }
  for (const sink of logSinks) sink(line);
}

async function hostDialTCP(hostname, port) {
  const sock = cfConnect({ hostname, port }, { allowHalfOpen: true });
  await sock.opened;
  return streamsToSock(sock.readable, sock.writable, () => sock.close());
}

async function dohQuery(url, q) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
    body: q,
  });
  if (!r.ok) throw new Error(`DoH ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

// ---- socket adapters ------------------------------------------------------

// JS streams -> engine sock object.
function streamsToSock(readable, writable, close) {
  const reader = readable.getReader();
  const writer = writable.getWriter();
  return {
    async read() {
      const { value, done } = await reader.read();
      return done ? null : value;
    },
    write: (bytes) => writer.write(bytes),
    closeWrite: () => writer.close().catch(() => {}),
    close: () => {
      try {
        close();
      } catch {}
    },
  };
}

// Engine sock object -> Socket shaped like cloudflare:sockets.
function sockToSocket(sock) {
  let resolveClosed;
  const closed = new Promise((r) => (resolveClosed = r));
  let done = false;
  const finish = () => {
    if (!done) {
      done = true;
      sock.close();
      resolveClosed();
    }
  };
  const readable = new ReadableStream({
    async pull(controller) {
      try {
        const chunk = await sock.read();
        if (chunk === null) {
          controller.close();
        } else if (chunk.byteLength > 0) {
          controller.enqueue(chunk);
        }
      } catch (e) {
        controller.error(e);
        finish();
      }
    },
    cancel: finish,
  });
  const writable = new WritableStream({
    write: (chunk) => sock.write(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)),
    close: () => sock.closeWrite(),
    abort: finish,
  });
  return {
    readable,
    writable,
    opened: Promise.resolve({ remoteAddress: sock.remoteAddress, localAddress: sock.localAddress }),
    closed,
    close: async () => finish(),
  };
}

// Response-returning handler -> engine HTTP handler.
function engineHandler(handler) {
  return async (req, who) => {
    const request = new Request(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body ?? null,
    });
    const res = await handler(request, who);
    const body = res.body ? new Uint8Array(await res.arrayBuffer()) : null;
    return { status: res.status, headers: [...res.headers], body };
  };
}

async function requestToEngine(request) {
  const body = request.body ? new Uint8Array(await request.arrayBuffer()) : null;
  return { method: request.method, url: request.url, headers: [...request.headers], body };
}

// ---- Tailnet ------------------------------------------------------------

const nodes = new WeakMap(); // DurableObjectState -> Promise<Tailnet>

export class Tailnet {
  /**
   * Join the tailnet from a Durable Object. Repeated calls with the same ctx
   * return the same node.
   *
   * options:
   *   authKey         Tailscale auth key. Omit to use interactive login
   *                   (the URL shows up in status().loginURL).
   *   hostname        Device name on the tailnet.
   *   controlURL      Control server (Headscale etc.). Defaults to Tailscale.
   *   ephemeral       Remove the device when it goes offline.
   *   tags            ACL tags to advertise, e.g. ["tag:do"].
   *   exitNode        Advertise as an exit node.
   *   advertiseRoutes Extra subnet routes to advertise.
   *   dohURL          DoH upstream for exit-node DNS.
   *   acmeDirectoryURL  ACME directory that issues the serveHTTPS certificate.
   *                   Defaults to Let's Encrypt; set LETSENCRYPT_STAGING_URL
   *                   while developing. All nodes that call serveHTTPS in
   *                   an isolate must use the same one.
   *   keepAlive       Keep the object in memory with an alarm (default true).
   *                   Your alarm() must call tailnet.alarm() if you set your own.
   *   statePrefix     Storage key prefix for Tailscale state (default "tailnet:").
   *   onLog(line)     Receive engine logs.
   */
  static start(ctx, options = {}) {
    let p = nodes.get(ctx);
    if (!p) {
      p = Tailnet.#create(ctx, options);
      nodes.set(ctx, p);
      p.catch(() => nodes.delete(ctx));
    }
    return p;
  }

  static async #create(ctx, options) {
    const api = await loadEngine(options);
    if (options.onLog) logSinks.add(options.onLog);
    const kv = ctx.storage.kv;
    const prefix = options.statePrefix ?? "tailnet:";
    const t = new Tailnet(ctx, options);
    t.#engine = api;
    t.#node = api.newNode({
      authKey: options.authKey ?? "",
      hostname: options.hostname ?? "",
      controlURL: options.controlURL ?? "",
      ephemeral: !!options.ephemeral,
      exitNode: !!options.exitNode,
      advertiseRoutes: options.advertiseRoutes ?? [],
      tags: options.tags ?? [],
      getState: (k) => kv.get(prefix + k) ?? null,
      setState: (k, v) => kv.put(prefix + k, v),
      onStatus: (s) => {
        Object.assign(t.#status, s);
        for (const fn of t.#statusListeners) fn(t.status());
      },
    });
    await t.#node.started;
    if (t.#keepAlive) await t.alarm();
    return t;
  }

  #ctx;
  #engine;
  #node;
  #acmeDirectoryURL;
  #status = {};
  #statusListeners = new Set();
  #keepAlive;

  constructor(ctx, options) {
    this.#ctx = ctx;
    this.#keepAlive = options.keepAlive ?? true;
    this.#acmeDirectoryURL = options.acmeDirectoryURL ?? "";
  }

  /**
   * Current state: { state, name, addrs, peers, loginURL?, certDomain?,
   * certExpiry?, certError? }.
   *
   * certDomain is the name serveHTTPS gets a certificate for. It is absent
   * until the node is running, and while HTTPS certificates are disabled for
   * the tailnet. certExpiry (ISO 8601) is set once serveHTTPS has a
   * certificate. certError says why the last attempt to get it failed. A
   * renewal that fails in the background is only logged, so watch
   * certExpiry as well.
   */
  status() {
    return { ...this.#status, ...this.#node.status() };
  }

  /** Resolves once the node is Running (or rejects after timeoutMs). */
  ready(timeoutMs = 30_000) {
    if (this.status().state === "Running") return Promise.resolve(this.status());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#statusListeners.delete(check);
        reject(new Error(`tailnet not running: ${JSON.stringify(this.status())}`));
      }, timeoutMs);
      const check = (s) => {
        if (s.state === "Running") {
          clearTimeout(timer);
          this.#statusListeners.delete(check);
          resolve(s);
        }
      };
      this.#statusListeners.add(check);
    });
  }

  /** Open a TCP connection to a tailnet host ("host:port", MagicDNS names work). */
  async connect(address) {
    const addr = typeof address === "string" ? address : `${address.hostname}:${address.port}`;
    return sockToSocket(await this.#node.dial(addr));
  }

  /** fetch() over the tailnet. Bodies are buffered. */
  async fetch(input, init) {
    const request = new Request(input, init);
    const res = await this.#node.fetch(await requestToEngine(request));
    return new Response(res.body.byteLength ? res.body : null, { status: res.status, headers: res.headers });
  }

  /** Accept raw TCP connections on a tailnet port: onSocket(socket, whois). */
  listen(port, onSocket) {
    this.#node.listen(port, (sock, who) => onSocket(sockToSocket(sock), who));
    return { close: () => this.#node.unlisten(port) };
  }

  /**
   * Serve HTTP on a tailnet port. handler(request, whois) returns a Response.
   * whois is { loginName, displayName, nodeName, tags, addr } for the caller.
   */
  serve(port, handler) {
    this.#node.serveHTTP(port, engineHandler(handler));
    return { close: () => this.#node.unlisten(port) };
  }

  /**
   * Serve HTTPS on a tailnet port, like serve(), with the certificate
   * Tailscale issues for the node's MagicDNS name (status().certDomain). The
   * tailnet needs HTTPS Certificates enabled in the admin console.
   *
   * The certificate is stored with the node's state, so it is issued once and
   * reused across restarts, and it renews on its own.
   *
   * Returns { ready, close }. ready resolves with { domain, expiry } once a
   * certificate is in place, which takes a while if it has to be issued. It
   * rejects if the attempt to get one fails, e.g. because the tailnet has
   * HTTPS disabled; the node keeps retrying, and status() has the current
   * state. ready stays pending for as long as the node is not running, so
   * do not await it in TailnetObject.onTailnet(): that would hold up
   * everything else the object does, including the login it may be waiting
   * for.
   *
   * Throws if another node in the isolate serves HTTPS with a different
   * acmeDirectoryURL.
   */
  serveHTTPS(port, handler) {
    // Tailscale takes the ACME directory from the process environment: one
    // for the isolate, picked by the first node that serves HTTPS.
    const conflict = this.#engine.useACMEDirectory(this.#acmeDirectoryURL);
    if (conflict) throw new Error(conflict);
    const ready = this.#node.serveHTTPS(port, engineHandler(handler));
    ready.catch(() => {}); // callers may ignore ready; the error is in status().certError
    return { ready, close: () => this.#node.unlisten(port) };
  }

  /**
   * Replace the serveHTTPS certificate with a newly issued one now. Renewal
   * is automatic; this is for testing it, or for replacing a certificate
   * early. Resolves with { domain, expiry }. Every call issues a certificate
   * and counts against the CA's rate limits (Let's Encrypt: about five a
   * week for one name), so do not expose it to callers you do not trust.
   */
  renewCertificate() {
    return this.#node.renewCert();
  }

  /** Identity of a tailnet peer by "ip:port", or null. */
  whois(addr) {
    return this.#node.whois(addr);
  }

  async logout() {
    await this.#node.logout();
  }

  /** Call from your Durable Object's alarm() if you define one. */
  async alarm() {
    if (this.#keepAlive) await this.#ctx.storage.setAlarm(Date.now() + KEEPALIVE_MS);
  }
}

// ---- TailnetObject ----------------------------------------------------------

/**
 * A Durable Object base class that joins the tailnet on first use, keeps
 * itself alive, and exposes RPC methods so plain Workers can use it:
 *
 *   const sock = await env.TAILNET.getByName("main").tailnetConnect("db:5432");
 *   const res  = await env.TAILNET.getByName("main").tailnetFetch(request);
 *
 * Override tailnetOptions() to configure, and onTailnet(tailnet) to serve.
 */
export class TailnetObject extends DurableObject {
  /** Options for Tailnet.start(). Defaults read TS_* vars from env. */
  tailnetOptions() {
    const env = this.env ?? {};
    return {
      authKey: env.TS_AUTHKEY,
      hostname: env.TS_HOSTNAME,
      controlURL: env.TS_CONTROL_URL,
      acmeDirectoryURL: env.TS_ACME_DIRECTORY_URL,
    };
  }

  /** Called once after the node is created. Set up serve()/listen() here. */
  async onTailnet(tailnet) {}

  async tailnet() {
    if (!this.__tailnetPromise) {
      this.__tailnetPromise = Tailnet.start(this.ctx, this.tailnetOptions()).then(async (t) => {
        await this.onTailnet(t);
        return t;
      });
      this.__tailnetPromise.catch(() => (this.__tailnetPromise = null));
    }
    return this.__tailnetPromise;
  }

  async alarm() {
    const t = await this.tailnet();
    await t.alarm();
  }

  /** RPC: node status. */
  async tailnetStatus() {
    return (await this.tailnet()).status();
  }

  /** RPC: open a TCP connection into the tailnet; returns { readable, writable }. */
  async tailnetConnect(address) {
    const t = await this.tailnet();
    await t.ready();
    const s = await t.connect(address);
    return { readable: s.readable, writable: s.writable };
  }

  /** RPC: fetch() over the tailnet. */
  async tailnetFetch(input, init) {
    const t = await this.tailnet();
    await t.ready();
    return t.fetch(input, init);
  }
}
