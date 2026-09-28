/**
 * workers-proxy
 *
 * A Cloudflare Gateway middleware Worker that acts as a forward HTTP proxy,
 * routing all traffic through a private network reachable via a Workers VPC
 * Network binding over a Cloudflare Tunnel.
 *
 * It is deployed as a Gateway Custom Action (Programmable Gateway / Gateway
 * Workers). Gateway matches HTTP policy rules, decrypts TLS, and dispatches
 * the plain Request to this Worker's GatewayMiddleware.handle() method.
 *
 * Protocol split:
 *
 *   HTTP  → raw TCP to tinyproxy via env.VPC.connect()
 *           Request: "GET http://host/path HTTP/1.1" (absolute-form)
 *           Tinyproxy forwards to the origin over plain HTTP.
 *
 *   HTTPS → env.VPC.fetch() through the same VPC / Cloudflare Tunnel.
 *           The Workers runtime handles TLS to the origin natively.
 *           Tinyproxy is not involved — but the traffic still routes through
 *           the same private-network tunnel, satisfying the network requirement.
 *           Redirects are followed internally (redirect:"follow") so Gateway
 *           never re-intercepts a 3xx and creates a loop.
 *
 *   Why not send HTTPS through tinyproxy?
 *     - env.VPC.connect() is plaintext-only; startTls() is not available on
 *       VPC-bound sockets, so the Worker cannot do a CONNECT tunnel + TLS.
 *     - Tinyproxy does not transparently fetch https:// absolute-form
 *       requests on behalf of the client; it expects CONNECT for HTTPS.
 *     - Sending GET https://host/path to tinyproxy results in a redirect
 *       loop because tinyproxy redirects to http://, which Gateway
 *       re-intercepts back through the Worker.
 *
 * Flow:
 *   Client → Cloudflare Gateway (TLS termination + policy match)
 *     → GatewayMiddleware.handle(request, context, next)
 *       HTTP:  → VPC connect() → Tunnel → tinyproxy → origin
 *       HTTPS: → VPC fetch()   → Tunnel → origin (TLS by Workers runtime)
 */

import { WorkerEntrypoint } from "cloudflare:workers";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * The VPC Network binding exposes both fetch() (for HTTP) and connect() (for
 * raw TCP). Wrangler's generated types model it as `Fetcher` which only
 * covers fetch(). We extend it here with the connect() signature documented
 * at https://developers.cloudflare.com/workers-vpc/api/
 */
interface VpcNetworkBinding {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  connect(
    address: string | { hostname: string; port: number }
  ): Promise<{
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  }>;
}

interface Env {
  /** VPC Network binding that routes TCP through the mad01-k8s tunnel */
  VPC: VpcNetworkBinding;
  /** Hostname or IP of the HTTP proxy reachable behind the tunnel */
  PROXY_HOST: string;
  /** Port the HTTP proxy listens on */
  PROXY_PORT: string;
  /**
   * Optional HTTP proxy credentials (Proxy-Authorization: Basic ...).
   * If either is absent the request is sent without a Proxy-Authorization header.
   */
  PROXY_USERNAME?: string;
  PROXY_PASSWORD?: string;
  /** Set to "true" to enable verbose debug logging via wrangler tail */
  DEBUG: string;
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

/**
 * A per-request logger. When DEBUG !== "true" every method is a no-op so
 * there is zero runtime cost — no string interpolation, no console calls.
 */
interface Logger {
  debug(msg: string, ...args: unknown[]): void;
  info(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
}

function makeLogger(env: Env, requestId: string): Logger {
  const debug = env.DEBUG === "true";
  const prefix = `[${requestId}]`;

  return {
    debug: debug
      ? (msg, ...args) => console.log(`${prefix} [DEBUG] ${msg}`, ...args)
      : () => {},
    info: debug
      ? (msg, ...args) => console.log(`${prefix} [INFO]  ${msg}`, ...args)
      : () => {},
    error: (msg, ...args) => console.error(`${prefix} [ERROR] ${msg}`, ...args),
  };
}

/** Short random ID to correlate log lines belonging to one request. */
function newRequestId(): string {
  return Math.random().toString(36).slice(2, 8).toUpperCase();
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/**
 * Stateful buffered reader that wraps a ReadableStreamDefaultReader.
 *
 * HTTP proxies write the CONNECT response header and may include bytes of the
 * tunneled response in the same TCP segment. A naïve readUntil that discards
 * leftover bytes from an oversized chunk would lose those bytes.
 *
 * BufferedReader keeps an internal remainder buffer so leftover bytes from
 * one read are preserved and returned by the next call.
 */
class BufferedReader {
  private remainder: Uint8Array = new Uint8Array(0);

  constructor(private inner: ReadableStreamDefaultReader<Uint8Array>) {}

  /** Read exactly n bytes, preserving any excess in the remainder buffer. */
  async readExactly(n: number): Promise<Uint8Array> {
    const out = new Uint8Array(n);
    let offset = 0;

    if (this.remainder.length > 0) {
      const take = Math.min(this.remainder.length, n);
      out.set(this.remainder.subarray(0, take), 0);
      offset += take;
      this.remainder = this.remainder.subarray(take);
    }

    while (offset < n) {
      const { done, value } = await this.inner.read();
      if (done) throw new Error(`Proxy: stream ended after ${offset}/${n} bytes`);
      const chunk = value as Uint8Array;
      const needed = n - offset;
      if (chunk.length <= needed) {
        out.set(chunk, offset);
        offset += chunk.length;
      } else {
        out.set(chunk.subarray(0, needed), offset);
        offset += needed;
        this.remainder = chunk.subarray(needed);
      }
    }

    return out;
  }

  /**
   * Convert the remaining unread data + underlying reader back into a
   * ReadableStream, for handing off to the HTTP response parser.
   */
  toReadableStream(): ReadableStream<Uint8Array> {
    const remainder = this.remainder;
    const inner = this.inner;
    return new ReadableStream<Uint8Array>({
      async start(controller) {
        if (remainder.length > 0) controller.enqueue(remainder);
      },
      async pull(controller) {
        const { done, value } = await inner.read();
        if (done) {
          controller.close();
        } else {
          controller.enqueue(value as Uint8Array);
        }
      },
      cancel() { inner.cancel(); },
    });
  }

  cancel(): void { this.inner.cancel(); }
}

// ---------------------------------------------------------------------------
// Header sets
// ---------------------------------------------------------------------------

/** Headers stripped from outgoing requests to the upstream. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  // Gateway decrypts TLS and may decode the body before the Worker sees it.
  // Forwarding accept-encoding would cause the origin to compress the body
  // and set Content-Encoding, which would then fail to decode in the browser.
  "accept-encoding",
]);

/**
 * Headers stripped from upstream responses before returning to the client.
 *
 * Gateway decrypts TLS and may decode compressed bodies before the Worker
 * receives them. Forwarding Content-Encoding unchanged causes the browser to
 * try to decompress an already-decoded body → ERR_CONTENT_DECODING_FAILED.
 * Content-Length is removed because decoded length ≠ compressed length.
 */
const STRIP_RESPONSE = new Set([
  "content-encoding",
  "content-length",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

// ---------------------------------------------------------------------------
// HTTP request serialisation
// ---------------------------------------------------------------------------

/**
 * Serialise the incoming Request into raw HTTP/1.1 bytes for an HTTP forward
 * proxy. The request-target is always absolute-form (http:// or https://) so
 * the proxy knows where to fetch the resource. Tinyproxy handles TLS to the
 * origin for https:// targets — the Worker never speaks TLS itself.
 *
 * proxyAuth: base64-encoded "user:pass" for Proxy-Authorization, or null.
 */
async function buildRawRequest(
  request: Request,
  url: URL,
  proxyAuth: string | null,
  log: Logger
): Promise<Uint8Array> {
  const lines: string[] = [];
  lines.push(`${request.method} ${url.toString()} HTTP/1.1`);
  lines.push(`Host: ${url.hostname}${url.port ? ":" + url.port : ""}`);

  if (proxyAuth) {
    lines.push(`Proxy-Authorization: Basic ${proxyAuth}`);
  }

  for (const [name, value] of request.headers) {
    if (HOP_BY_HOP.has(name.toLowerCase())) {
      log.debug(`Dropping hop-by-hop header: ${name}`);
      continue;
    }
    lines.push(`${name}: ${value}`);
  }

  lines.push("Connection: close");
  lines.push("", "");

  log.debug(`Request line: ${lines[0]}`);

  const headerBytes = new TextEncoder().encode(lines.join("\r\n"));

  if (request.body) {
    const bodyBytes = new Uint8Array(await request.arrayBuffer());
    log.debug(`Request body: ${bodyBytes.length} bytes`);
    const combined = new Uint8Array(headerBytes.length + bodyBytes.length);
    combined.set(headerBytes, 0);
    combined.set(bodyBytes, headerBytes.length);
    return combined;
  }

  return headerBytes;
}

// ---------------------------------------------------------------------------
// Gateway middleware entry point
// ---------------------------------------------------------------------------

/**
 * Gateway Custom Action middleware.
 *
 * The class name GatewayMiddleware is part of the Gateway contract and must
 * not be renamed. Gateway invokes handle(request, context, next) for every
 * HTTP request that matches the associated policy rule.
 *
 * context carries Gateway request-phase selectors (src_ip, host, uri, etc.).
 */
export class GatewayMiddleware extends WorkerEntrypoint<Env> {
  async handle(
    request: Request,
    context: Record<string, unknown>,
    // next is provided by Gateway but not used — this Worker is the egress.
    _next: (req: Request) => Promise<Response>
  ): Promise<Response> {
    const env = this.env;
    const requestId = newRequestId();
    const log = makeLogger(env, requestId);

    log.info("GatewayMiddleware.handle() invoked");
    log.debug(`Gateway context: ${JSON.stringify(context)}`);

    const url = new URL(request.url);
    const isHttps = url.protocol === "https:";
    const targetHost = url.hostname;
    const defaultPort = isHttps ? 443 : 80;
    const targetPort = url.port ? parseInt(url.port, 10) : defaultPort;

    log.info(`${request.method} ${targetHost}:${targetPort}`);
    log.debug(`Full URL: ${url.toString()}`);
    log.debug(`Incoming headers: ${[...request.headers.entries()].map(([k, v]) => `${k}: ${v}`).join(", ")}`);

    if (!targetHost) {
      log.error("Missing host in request URL");
      return new Response("Bad Request: missing host", { status: 400 });
    }

    // Build Proxy-Authorization header value if credentials are configured.
    const proxyAuth = (env.PROXY_USERNAME && env.PROXY_PASSWORD)
      ? btoa(`${env.PROXY_USERNAME}:${env.PROXY_PASSWORD}`)
      : null;
    if (proxyAuth) log.debug("Proxy-Authorization header will be sent");

    // ── HTTPS ────────────────────────────────────────────────────────────────
    // env.VPC.fetch() routes through the same Cloudflare Tunnel as connect(),
    // so traffic stays on the private network. The Workers runtime handles TLS
    // to the origin natively. redirect:"follow" ensures any origin redirects
    // are resolved internally — Gateway never sees a 3xx and cannot loop.
    if (isHttps) {
      try {
        log.debug("HTTPS — forwarding via env.VPC.fetch() with redirect:follow");
        const outHeaders = new Headers();
        for (const [name, value] of request.headers) {
          if (HOP_BY_HOP.has(name.toLowerCase())) continue;
          outHeaders.set(name, value);
        }
        const upstreamRes = await env.VPC.fetch(url.toString(), {
          method: request.method,
          headers: outHeaders,
          body: request.body,
          redirect: "follow",
        });
        const resHeaders = new Headers();
        for (const [name, value] of upstreamRes.headers) {
          if (STRIP_RESPONSE.has(name.toLowerCase())) continue;
          resHeaders.set(name, value);
        }
        const response = new Response(upstreamRes.body, {
          status: upstreamRes.status,
          statusText: upstreamRes.statusText,
          headers: resHeaders,
        });
        log.info(`Response: ${response.status} ${response.statusText}`);
        return response;
      } catch (err) {
        log.error(`VPC fetch failed: ${err}`);
        return new Response(`Bad Gateway: ${(err as Error).message}`, { status: 502 });
      }
    }

    // ── HTTP ─────────────────────────────────────────────────────────────────
    // Send an absolute-form GET http://host/path request to tinyproxy over a
    // raw TCP socket through the VPC tunnel.
    log.debug(`HTTP — connecting to tinyproxy at ${env.PROXY_HOST}:${env.PROXY_PORT}`);
    let socket: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
    try {
      socket = await env.VPC.connect({
        hostname: env.PROXY_HOST,
        port: parseInt(env.PROXY_PORT, 10),
      });
      log.debug("VPC TCP connection established");
    } catch (err) {
      log.error(`VPC connect failed: ${err}`);
      return new Response("Bad Gateway: could not connect to HTTP proxy", { status: 502 });
    }
    const reader = new BufferedReader(socket.readable.getReader());
    const writer = socket.writable.getWriter();

    try {
      const rawRequest = await buildRawRequest(request, url, proxyAuth, log);
      log.debug(`Writing ${rawRequest.length} bytes to tinyproxy`);
      await writer.write(rawRequest);

      const responseStream = reader.toReadableStream();
      log.debug("Parsing HTTP response");
      const response = await parseHttpResponse(responseStream, writer, log);
      log.info(`Response: ${response.status} ${response.statusText}`);
      return response;
    } catch (err) {
      log.error(`Proxy error: ${err}`);
      try { writer.close(); } catch { /* ignore */ }
      try { reader.cancel(); } catch { /* ignore */ }
      return new Response(`Bad Gateway: ${(err as Error).message}`, { status: 502 });
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 response parser
// ---------------------------------------------------------------------------

/**
 * Reads the HTTP/1.1 status line and headers from `stream`, then returns a
 * `Response` object with the parsed status/headers and the remaining body
 * as a streaming ReadableStream.
 */
async function parseHttpResponse(
  stream: ReadableStream<Uint8Array>,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  log: Logger
): Promise<Response> {
  const CRLF2 = "\r\n\r\n";
  const chunks: Uint8Array[] = [];
  let headerText: string | null = null;
  let bodyRemainder: Uint8Array | null = null;

  const reader = stream.getReader();

  while (headerText === null) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value as Uint8Array);

    const soFar = concat(chunks);
    const text = new TextDecoder("latin1").decode(soFar);
    const sep = text.indexOf(CRLF2);
    if (sep !== -1) {
      headerText = text.substring(0, sep);
      const bodyStart = sep + CRLF2.length;
      if (bodyStart < soFar.length) {
        bodyRemainder = soFar.subarray(bodyStart);
      }
    }
  }

  if (!headerText) {
    throw new Error("Proxy upstream closed connection before sending HTTP headers");
  }

  log.debug(`HTTP response headers:\n${headerText}`);

  const lines = headerText.split("\r\n");
  const statusLine = lines[0];
  const statusMatch = statusLine.match(/^HTTP\/1\.[01] (\d{3})(?: (.*))?$/);
  if (!statusMatch) {
    throw new Error(`Unrecognised HTTP status line: ${statusLine}`);
  }
  const status = parseInt(statusMatch[1], 10);
  const statusText = statusMatch[2] ?? "";

  const responseHeaders = new Headers();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const name = line.substring(0, colon).trim().toLowerCase();
    const value = line.substring(colon + 1).trim();
    if (STRIP_RESPONSE.has(name)) {
      log.debug(`Dropping response header: ${name}`);
      continue;
    }
    responseHeaders.append(name, value);
  }

  log.debug(`Body remainder from header parse: ${bodyRemainder?.length ?? 0} bytes`);

  const bodyStream = new ReadableStream<Uint8Array>({
    async start(controller) {
      if (bodyRemainder && bodyRemainder.length > 0) controller.enqueue(bodyRemainder);
    },
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        controller.close();
        try { writer.close(); } catch { /* ignore */ }
      } else {
        controller.enqueue(value as Uint8Array);
      }
    },
    cancel() { reader.cancel(); },
  });

  const noBody = status === 204 || status === 304;

  return new Response(noBody ? null : bodyStream, {
    status,
    statusText,
    headers: responseHeaders,
  });
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}


