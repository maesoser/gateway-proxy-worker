/**
 * workers-proxy
 *
 * A Cloudflare Gateway middleware Worker that acts as a forward HTTP proxy,
 * routing all traffic through a FortiGate explicit web proxy on a private
 * network reachable via a Workers VPC Network binding over a Cloudflare Tunnel.
 *
 * It is deployed as a Gateway Custom Action (Programmable Gateway / Gateway
 * Workers). Gateway matches HTTP policy rules, decrypts TLS, and dispatches
 * the plain Request to this Worker's GatewayMiddleware.handle() method.
 *
 * Protocol — both HTTP and HTTPS use the same absolute-form request path:
 *
 *   HTTP:  GET http://host/path HTTP/1.1
 *          → FortiGate forwards to the origin over plain HTTP.
 *
 *   HTTPS: GET https://host/path HTTP/1.1
 *          → FortiGate's detect-https-in-http-request detects the https://
 *            scheme and opens a TLS connection to the origin itself, returning
 *            the decrypted response to the Worker over the plain proxy connection.
 *
 * Required FortiGate proxy-policy config:
 *   set detect-https-in-http-request enable
 *   set ssl-ssh-profile "deep-inspection"
 *
 * The Worker never needs to speak TLS — Gateway decrypts the client's TLS,
 * and FortiGate handles TLS to the origin. The VPC plaintext-only limitation
 * of env.VPC.connect() is therefore not a problem.
 *
 * Flow:
 *   Client → Cloudflare Gateway (TLS termination + policy match)
 *     → GatewayMiddleware.handle(request, context, next)
 *       → VPC connect() → Cloudflare Tunnel (mad01-k8s)
 *         → FortiGate explicit proxy (172.18.0.22:8888)
 *           → origin (HTTP or HTTPS, TLS handled by FortiGate)
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
  /** Hostname or IP of the FortiGate explicit proxy reachable behind the tunnel */
  PROXY_HOST: string;
  /** Port the proxy listens on */
  PROXY_PORT: string;
  /**
   * Optional proxy credentials (Proxy-Authorization: Basic ...).
   * If either is absent the request is sent without a Proxy-Authorization header.
   */
  PROXY_USERNAME?: string;
  PROXY_PASSWORD?: string;
  /**
   * When "true", if the proxy is unreachable and the request body has not yet
   * been consumed, the request falls through to Gateway's normal egress via
   * next() instead of returning a 502.
   */
  FAIL_OPEN?: string;
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
// Constants
// ---------------------------------------------------------------------------

const ENC = new TextEncoder();
const DEC = new TextDecoder();
const CRLF = ENC.encode("\r\n");
const CRLFCRLF = ENC.encode("\r\n\r\n");
const MAX_HEADER_BYTES = 64 * 1024;

// ---------------------------------------------------------------------------
// BufferedReader
// ---------------------------------------------------------------------------

/**
 * Stateful buffered reader wrapping a ReadableStreamDefaultReader.
 *
 * Preserves leftover bytes across reads so that oversized chunks (e.g. a TCP
 * segment delivering both the response header and the start of the body) never
 * cause bytes to be silently discarded.
 */
class BufferedReader {
  private buf: Uint8Array = new Uint8Array(0);
  private eof = false;

  constructor(private inner: ReadableStreamDefaultReader<Uint8Array>) {}

  private async fill(): Promise<boolean> {
    if (this.eof) return false;
    const { done, value } = await this.inner.read();
    if (done) { this.eof = true; return false; }
    if (value && value.byteLength > 0) {
      if (this.buf.byteLength === 0) {
        this.buf = value;
      } else {
        const merged = new Uint8Array(this.buf.byteLength + value.byteLength);
        merged.set(this.buf, 0);
        merged.set(value, this.buf.byteLength);
        this.buf = merged;
      }
    }
    return true;
  }

  /**
   * Read bytes up to and including `delim`, returning everything before it.
   * Returns null on EOF before the delimiter is found.
   * Throws if more than `max` bytes are buffered without finding the delimiter.
   */
  async readUntil(delim: Uint8Array, max: number): Promise<Uint8Array | null> {
    let from = 0;
    for (;;) {
      const idx = indexOf(this.buf, delim, from);
      if (idx >= 0) {
        const out = this.buf.subarray(0, idx);
        this.buf = this.buf.subarray(idx + delim.byteLength);
        return out;
      }
      if (this.buf.byteLength > max + delim.byteLength) {
        throw new Error("response header too large");
      }
      from = Math.max(0, this.buf.byteLength - delim.byteLength + 1);
      if (!await this.fill()) return null;
    }
  }

  /** Return up to `max` bytes, or null on EOF. */
  async readSome(max: number): Promise<Uint8Array | null> {
    if (this.buf.byteLength === 0 && !await this.fill()) return null;
    if (this.buf.byteLength === 0) return this.readSome(max);
    const n = Math.min(max, this.buf.byteLength);
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }

  cancel(): void { this.inner.cancel().catch(() => {}); }
}

function indexOf(hay: Uint8Array, needle: Uint8Array, from: number): number {
  outer: for (let i = from; i <= hay.byteLength - needle.byteLength; i++) {
    for (let j = 0; j < needle.byteLength; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Header sets
// ---------------------------------------------------------------------------

/**
 * Headers stripped from outgoing requests.
 *
 * Hop-by-hop headers must not cross a proxy boundary.
 * Cloudflare-internal headers are stripped because Cloudflare-fronted origins
 * reject requests that carry them (403), and they would leak Worker metadata.
 * accept-encoding is stripped because Gateway may have already decoded the
 * body; forwarding it would cause the origin to compress a response that
 * the Worker then passes through undecoded, breaking the browser.
 */
const REQUEST_STRIP = new Set([
  "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
  "expect", "host", "accept-encoding",
  // Cloudflare-reserved — Cloudflare-fronted origins reject these with 403
  "cf-connecting-ip", "cf-connecting-ipv6", "cf-ipcountry", "cf-ray",
  "cf-visitor", "cf-worker", "cf-ew-via", "cdn-loop", "x-real-ip",
]);

/**
 * Headers stripped from upstream responses.
 *
 * content-encoding and content-length are removed because Gateway may have
 * decoded the body before dispatching to the Worker; forwarding them unchanged
 * causes ERR_CONTENT_DECODING_FAILED or body truncation in the browser.
 * Transfer-encoding is managed by the Worker's own body framing logic.
 */
const RESPONSE_STRIP = new Set([
  "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
  "transfer-encoding", "trailer", "upgrade",
  "content-encoding", "content-length",
]);

// ---------------------------------------------------------------------------
// Request serialisation
// ---------------------------------------------------------------------------

/**
 * Write the HTTP request headers and body into the proxy socket stream.
 *
 * The request-target is always absolute-form (http:// or https://) so the
 * proxy knows where to fetch the resource. For HTTPS targets the FortiGate
 * explicit proxy detects the scheme and opens a TLS connection to the origin.
 *
 * Bodies are streamed as chunked transfer-encoding when no Content-Length is
 * available, avoiding the need to buffer the entire body in memory.
 */
async function sendRequest(
  socket: { writable: WritableStream<Uint8Array> },
  request: Request,
  url: URL,
  proxyAuth: string | null,
  log: Logger
): Promise<void> {
  // Collect connection-token header names to also strip (RFC 7230 §6.1)
  const connectionTokens = new Set(
    (request.headers.get("connection") ?? "")
      .split(",").map(t => t.trim().toLowerCase()).filter(Boolean)
  );

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    const lower = name.toLowerCase();
    if (REQUEST_STRIP.has(lower) || connectionTokens.has(lower)) {
      log.debug(`Dropping request header: ${name}`);
      continue;
    }
    headers.set(name, value);
  }

  const hasBody = hasRequestBody(request);
  const body = hasBody ? request.body : null;
  if (!body) headers.delete("content-length");

  let chunked = false;
  if (body) {
    if (!headers.has("content-length")) {
      chunked = true;
      headers.set("transfer-encoding", "chunked");
      log.debug("Request body: streaming as chunked transfer-encoding");
    } else {
      log.debug(`Request body: ${headers.get("content-length")} bytes (content-length known)`);
    }
  } else if (["POST", "PUT", "PATCH"].includes(request.method.toUpperCase())) {
    headers.set("content-length", "0");
  }

  headers.set("connection", "close");
  if (proxyAuth) headers.set("proxy-authorization", `Basic ${proxyAuth}`);

  // Absolute-form request target
  const requestTarget = `${url.protocol}//${url.host}${url.pathname || "/"}${url.search}`;
  let head = `${request.method} ${requestTarget} HTTP/1.1\r\nHost: ${url.host}\r\n`;
  for (const [name, value] of headers) head += `${name}: ${value}\r\n`;
  head += "\r\n";

  log.debug(`Request line: ${request.method} ${requestTarget} HTTP/1.1`);

  const writer = socket.writable.getWriter();
  try {
    await writer.write(ENC.encode(head));

    if (!body) return;

    const reader = body.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      if (chunked) {
        await writer.write(ENC.encode(`${value.byteLength.toString(16)}\r\n`));
        await writer.write(value);
        await writer.write(CRLF);
      } else {
        await writer.write(value);
      }
    }
    if (chunked) await writer.write(ENC.encode("0\r\n\r\n"));
  } finally {
    writer.releaseLock();
  }
}

/** True if the request is expected to carry a body. */
const BODYLESS_METHODS = new Set(["GET", "HEAD", "OPTIONS", "DELETE", "TRACE"]);

function hasRequestBody(request: Request): boolean {
  if (!request.body) return false;
  const cl = request.headers.get("content-length");
  if (cl !== null) return cl.trim() !== "0";
  if (request.headers.has("transfer-encoding")) return true;
  return !BODYLESS_METHODS.has(request.method.toUpperCase());
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/**
 * Read and parse the HTTP/1.1 response from the proxy socket.
 *
 * Handles all three HTTP/1.1 body framing modes:
 *   - chunked transfer-encoding  → decoded chunk by chunk
 *   - known content-length       → exactly N bytes read via FixedLengthStream
 *   - until-close                → reads until socket EOF
 *
 * 1xx informational responses are skipped until a final ≥200 status arrives.
 */
async function readResponse(
  socket: { readable: ReadableStream<Uint8Array>; close(): Promise<void> },
  method: string,
  log: Logger
): Promise<Response> {
  const br = new BufferedReader(socket.readable.getReader());

  const cleanup = () => { br.cancel(); socket.close().catch(() => {}); };

  // Skip 1xx informational responses
  let status!: number;
  let statusText!: string;
  let lines!: string[];

  for (;;) {
    const headBytes = await br.readUntil(CRLFCRLF, MAX_HEADER_BYTES);
    if (headBytes === null) {
      throw new Error("proxy upstream closed connection before sending a response");
    }
    lines = DEC.decode(headBytes).split("\r\n");
    ({ status, statusText } = parseStatusLine(lines[0]));
    log.debug(`Response status: ${status} ${statusText}`);
    if (status === 101) throw new Error("protocol upgrades are not supported");
    if (status >= 200) break;
    // 1xx — loop and read the next response block
  }

  // Parse response headers
  const rawHeaders = new Headers();
  for (const line of lines.slice(1)) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    rawHeaders.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
  }

  log.debug(`Response headers:\n${lines.slice(1).filter(l => l).join("\n")}`);

  const connectionTokens = new Set(
    (rawHeaders.get("connection") ?? "")
      .split(",").map(t => t.trim().toLowerCase()).filter(Boolean)
  );
  const transferEncoding = (rawHeaders.get("transfer-encoding") ?? "").toLowerCase();
  const contentLength = rawHeaders.get("content-length");

  // Build filtered response headers
  const responseHeaders = new Headers();
  for (const [name, value] of rawHeaders) {
    const lower = name.toLowerCase();
    if (RESPONSE_STRIP.has(lower) || connectionTokens.has(lower)) {
      log.debug(`Dropping response header: ${name}`);
      continue;
    }
    // Preserve multiple Set-Cookie headers correctly
    if (lower === "set-cookie") responseHeaders.append(name, value);
    else responseHeaders.set(name, value);
  }

  const noBody = method.toUpperCase() === "HEAD" || status === 204 || status === 304;
  const safeStatus = status >= 200 && status <= 599 ? status : 502;
  const init: ResponseInit & { encodeBody: "manual" } = {
    status: safeStatus,
    statusText,
    headers: responseHeaders,
    encodeBody: "manual",
  };

  if (noBody) {
    cleanup();
    return new Response(null, init);
  }

  let body: ReadableStream<Uint8Array>;

  if (transferEncoding.includes("chunked")) {
    log.debug("Response body: chunked transfer-encoding");
    responseHeaders.delete("content-length");
    body = chunkedBody(br, cleanup);
  } else if (contentLength !== null && /^\d+$/.test(contentLength.trim())) {
    const length = Number(contentLength.trim());
    log.debug(`Response body: fixed length ${length} bytes`);
    responseHeaders.delete("content-length");
    const fixed = new FixedLengthStream(length);
    lengthBody(br, length, cleanup).pipeTo(fixed.writable).catch(() => cleanup());
    body = fixed.readable;
  } else {
    log.debug("Response body: streaming until connection close");
    responseHeaders.delete("content-length");
    body = untilCloseBody(br, cleanup);
  }

  return new Response(body, init);
}

function parseStatusLine(line: string): { status: number; statusText: string } {
  const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$/.exec(line.trim());
  if (!m) throw new Error(`malformed status line: ${JSON.stringify(line.slice(0, 100))}`);
  return { status: Number(m[1]), statusText: m[2] ?? "" };
}

/** Stream a fixed-length response body. */
function lengthBody(
  br: BufferedReader,
  length: number,
  cleanup: () => void
): ReadableStream<Uint8Array> {
  let remaining = length;
  return new ReadableStream({
    async pull(controller) {
      if (remaining === 0) { controller.close(); cleanup(); return; }
      const chunk = await br.readSome(remaining);
      if (chunk === null) {
        cleanup();
        controller.error(new Error(`upstream closed with ${remaining} bytes remaining`));
        return;
      }
      remaining -= chunk.byteLength;
      controller.enqueue(chunk);
      if (remaining === 0) { controller.close(); cleanup(); }
    },
    cancel: cleanup,
  });
}

/** Stream a response body until the connection closes. */
function untilCloseBody(
  br: BufferedReader,
  cleanup: () => void
): ReadableStream<Uint8Array> {
  return new ReadableStream({
    async pull(controller) {
      const chunk = await br.readSome(64 * 1024);
      if (chunk === null) { controller.close(); cleanup(); return; }
      controller.enqueue(chunk);
    },
    cancel: cleanup,
  });
}

/** Decode a chunked transfer-encoding response body. */
function chunkedBody(
  br: BufferedReader,
  cleanup: () => void
): ReadableStream<Uint8Array> {
  let remaining = 0;
  const fail = (controller: ReadableStreamDefaultController, msg: string) => {
    cleanup(); controller.error(new Error(msg));
  };
  return new ReadableStream({
    async pull(controller) {
      if (remaining === 0) {
        const sizeLine = await br.readUntil(CRLF, 1024);
        if (sizeLine === null) return fail(controller, "unexpected EOF reading chunk size");
        const size = Number.parseInt(DEC.decode(sizeLine).split(";", 1)[0].trim(), 16);
        if (!Number.isFinite(size) || size < 0) return fail(controller, "invalid chunk size");
        if (size === 0) {
          // Consume trailing headers
          for (;;) {
            const trailer = await br.readUntil(CRLF, MAX_HEADER_BYTES);
            if (trailer === null || trailer.byteLength === 0) break;
          }
          controller.close(); cleanup(); return;
        }
        remaining = size;
      }
      const chunk = await br.readSome(remaining);
      if (chunk === null) return fail(controller, "unexpected EOF in chunk data");
      remaining -= chunk.byteLength;
      controller.enqueue(chunk);
      if (remaining === 0) {
        const end = await br.readUntil(CRLF, 2);
        if (end === null || end.byteLength !== 0) return fail(controller, "missing CRLF after chunk");
      }
    },
    cancel: cleanup,
  });
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
 * next() is called on FAIL_OPEN when the proxy is unreachable before the
 * request body was consumed, allowing Gateway's normal egress to take over.
 */
export class GatewayMiddleware extends WorkerEntrypoint<Env> {
  async handle(
    request: Request,
    context: Record<string, unknown>,
    next: (req: Request) => Promise<Response>
  ): Promise<Response> {
    const env = this.env;
    const requestId = newRequestId();
    const log = makeLogger(env, requestId);
    const started = Date.now();

    log.info("GatewayMiddleware.handle() invoked");
    log.debug(`Gateway context: ${JSON.stringify(context)}`);

    // Prefer context.uri (normalised by Gateway) over request.url where available
    let url: URL;
    try { url = new URL(request.url); } catch {
      return new Response("Bad Request: invalid URL", { status: 400 });
    }
    if (context?.uri) {
      try {
        const normalized = new URL(context.uri as string);
        if (normalized.protocol !== url.protocol) url.protocol = normalized.protocol;
        if (normalized.host !== url.host) url.host = normalized.host;
      } catch { /* ignore bad context.uri */ }
    }

    // WebSocket upgrades and unsupported schemes fall through to Gateway
    if (request.headers.get("upgrade") || (url.protocol !== "https:" && url.protocol !== "http:")) {
      log.info(`Passing through: upgrade=${request.headers.get("upgrade")} protocol=${url.protocol}`);
      return next(request);
    }

    const targetHost = url.hostname;
    const isHttps = url.protocol === "https:";
    const defaultPort = isHttps ? 443 : 80;
    const targetPort = url.port ? parseInt(url.port, 10) : defaultPort;

    log.info(`${request.method} ${targetHost}:${targetPort}`);
    log.debug(`Full URL: ${url.toString()}`);
    log.debug(`Incoming headers: ${[...request.headers.entries()].map(([k, v]) => `${k}: ${v}`).join(", ")}`);

    // Build Proxy-Authorization value if credentials are configured
    const proxyAuth = (env.PROXY_USERNAME && env.PROXY_PASSWORD)
      ? btoa(`${env.PROXY_USERNAME}:${env.PROXY_PASSWORD}`)
      : null;
    if (proxyAuth) log.debug("Proxy-Authorization header will be sent");

    const failOpen = String(env.FAIL_OPEN) === "true";

    // Open a raw TCP connection to the proxy through the VPC tunnel
    log.debug(`Connecting to proxy at ${env.PROXY_HOST}:${env.PROXY_PORT} via VPC`);
    let socket: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array>; close(): Promise<void> };
    try {
      const raw = await env.VPC.connect({
        hostname: env.PROXY_HOST,
        port: parseInt(env.PROXY_PORT, 10),
      });
      // Attach a no-op close so the shape matches what readResponse expects
      socket = { ...raw, close: async () => {} };
      log.debug("VPC TCP connection established");
    } catch (err) {
      log.error(`VPC connect failed: ${err}`);
      if (failOpen && !hasRequestBody(request)) {
        log.info("FAIL_OPEN: falling through to Gateway egress");
        return next(request);
      }
      return new Response("Bad Gateway: could not connect to proxy", { status: 502 });
    }

    try {
      // Send the HTTP request (headers + streamed body) into the proxy socket.
      // sendRequest releases the writer lock when done, leaving the readable
      // side available for readResponse.
      const sendPromise = sendRequest(socket, request, url, proxyAuth, log).catch(err => {
        log.error(`Request write failed: ${err}`);
        socket.close().catch(() => {});
      });
      // Register the send as a background task so the runtime waits for it
      // even after we start streaming the response back.
      this.ctx.waitUntil(sendPromise);

      const response = await readResponse(socket, request.method, log);
      log.info(`Response: ${response.status} ${response.statusText} (${Date.now() - started}ms)`);
      return response;
    } catch (err) {
      log.error(`Proxy error: ${err}`);
      socket.close().catch(() => {});
      if (failOpen && !hasRequestBody(request)) {
        log.info("FAIL_OPEN: falling through to Gateway egress");
        return next(request);
      }
      return new Response(
        `Bad Gateway: ${(err as Error).message}`,
        { status: 502, headers: { "content-type": "text/plain; charset=utf-8" } }
      );
    }
  }
}
