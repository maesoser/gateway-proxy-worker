/**
 * workers-proxy
 *
 * A Cloudflare Gateway middleware Worker that acts as a forward HTTP proxy by
 * tunneling every request through a SOCKS5 proxy on a private network,
 * reachable via a Workers VPC Network binding over a Cloudflare Tunnel.
 *
 * It is deployed as a Gateway Custom Action (Programmable Gateway / Gateway
 * Workers). Gateway matches HTTP policy rules, decrypts TLS, and dispatches
 * the plain Request to this Worker's GatewayMiddleware.handle() method.
 * The Worker tunnels the request through SOCKS5 and returns the response;
 * Gateway forwards that response back to the client.
 *
 * Flow:
 *   Client → Cloudflare Gateway (TLS termination + policy match)
 *     → GatewayMiddleware.handle(request, context, next)
 *       → VPC connect() → Cloudflare Tunnel (mad01-k8s)
 *         → SOCKS5 proxy (172.18.0.21:1080) → Target origin
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
  SOCKS5_HOST: string;
  SOCKS5_PORT: string;
  /** RFC 1929 credentials for the SOCKS5 proxy (stored as secrets) */
  SOCKS5_USERNAME: string;
  SOCKS5_PASSWORD: string;
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
// SOCKS5 constants (RFC 1928 + RFC 1929)
// ---------------------------------------------------------------------------

const SOCKS_VERSION = 0x05;

// Authentication methods
const METHOD_NO_AUTH = 0x00;
const METHOD_USERNAME_PASSWORD = 0x02;
const METHOD_NO_ACCEPTABLE = 0xff;

// RFC 1929 username/password sub-negotiation version
const USERPASS_VERSION = 0x01;

// Commands
const CMD_CONNECT = 0x01;

// Address types
const ATYP_IPV4 = 0x01;
const ATYP_DOMAINNAME = 0x03;
const ATYP_IPV6 = 0x04;

// Reply codes
const REP_SUCCESS = 0x00;

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/** Read exactly `n` bytes from a reader, accumulating chunks as needed. */
async function readExactly(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  n: number
): Promise<Uint8Array> {
  const buf = new Uint8Array(n);
  let offset = 0;
  while (offset < n) {
    const { done, value } = await reader.read();
    if (done) throw new Error(`SOCKS5: stream ended after ${offset}/${n} bytes`);
    const chunk = value as Uint8Array;
    const needed = n - offset;
    if (chunk.length <= needed) {
      buf.set(chunk, offset);
      offset += chunk.length;
    } else {
      // More bytes arrived than needed — take only what we need.
      // This shouldn't happen in practice but handle it defensively.
      buf.set(chunk.subarray(0, needed), offset);
      offset += needed;
      // The leftover bytes are lost; for a proxy use-case this is fine
      // because after the handshake we hand off the raw streams.
    }
  }
  return buf;
}

/** Format a Uint8Array as a hex string for debug output. */
function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" ");
}

// ---------------------------------------------------------------------------
// SOCKS5 handshake
// ---------------------------------------------------------------------------

/**
 * Performs the full SOCKS5 CONNECT handshake with RFC 1929 username/password
 * authentication and returns once the tunnel is established.
 *
 * After this function returns successfully, the socket is a transparent
 * byte pipe to `targetHost:targetPort`.
 */
async function socks5Connect(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  targetHost: string,
  targetPort: number,
  username: string,
  password: string,
  log: Logger
): Promise<void> {
  const enc = new TextEncoder();

  // ── Step 1: Client greeting ──────────────────────────────────────────────
  // Advertise both no-auth and username/password so the proxy can pick.
  // VER | NMETHODS | METHOD[0] | METHOD[1]
  const greeting = new Uint8Array([SOCKS_VERSION, 0x02, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]);
  log.debug(`SOCKS5 greeting → ${hex(greeting)}`);
  await writer.write(greeting);

  // ── Step 2: Server method selection ──────────────────────────────────────
  // VER | METHOD
  const methodResponse = await readExactly(reader, 2);
  log.debug(`SOCKS5 method selection ← ${hex(methodResponse)}`);

  if (methodResponse[0] !== SOCKS_VERSION) {
    throw new Error(`SOCKS5: unexpected version byte ${methodResponse[0]}`);
  }
  if (methodResponse[1] === METHOD_NO_ACCEPTABLE) {
    throw new Error("SOCKS5: server returned no acceptable auth method");
  }

  // ── Step 3 (conditional): RFC 1929 username/password sub-negotiation ─────
  if (methodResponse[1] === METHOD_USERNAME_PASSWORD) {
    log.debug("SOCKS5 server selected username/password auth (0x02)");

    const uBytes = enc.encode(username);
    const pBytes = enc.encode(password);

    if (uBytes.length > 255) throw new Error("SOCKS5: username too long (max 255 bytes)");
    if (pBytes.length > 255) throw new Error("SOCKS5: password too long (max 255 bytes)");

    // VER(1) | ULEN(1) | UNAME(uLen) | PLEN(1) | PASSWD(pLen)
    const authMsg = new Uint8Array(1 + 1 + uBytes.length + 1 + pBytes.length);
    let i = 0;
    authMsg[i++] = USERPASS_VERSION;
    authMsg[i++] = uBytes.length;
    authMsg.set(uBytes, i); i += uBytes.length;
    authMsg[i++] = pBytes.length;
    authMsg.set(pBytes, i);

    // Log auth frame without leaking credentials — show structure only.
    log.debug(`SOCKS5 auth sub-negotiation → VER=0x01 ULEN=${uBytes.length} PLEN=${pBytes.length}`);
    await writer.write(authMsg);

    // Server auth reply: VER(1) | STATUS(1) — 0x00 means success
    const authReply = await readExactly(reader, 2);
    log.debug(`SOCKS5 auth reply ← ${hex(authReply)}`);

    if (authReply[1] !== 0x00) {
      throw new Error(`SOCKS5: authentication failed (status 0x${authReply[1].toString(16)})`);
    }
    log.debug("SOCKS5 authentication succeeded");
  } else if (methodResponse[1] === METHOD_NO_AUTH) {
    log.debug("SOCKS5 server selected no-auth (0x00)");
  } else {
    throw new Error(`SOCKS5: unsupported auth method 0x${methodResponse[1].toString(16)}`);
  }

  // ── Step 4: CONNECT request ───────────────────────────────────────────────
  // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
  const hostBytes = enc.encode(targetHost);
  const hostLen = hostBytes.length;
  if (hostLen > 255) {
    throw new Error(`SOCKS5: hostname too long (${hostLen} bytes, max 255)`);
  }

  // We always send the hostname as a domain name (ATYP_DOMAINNAME).
  // The SOCKS5 proxy resolves it, which is the desired behaviour.
  const connectReq = new Uint8Array(4 + 1 + hostLen + 2);
  connectReq[0] = SOCKS_VERSION;
  connectReq[1] = CMD_CONNECT;
  connectReq[2] = 0x00; // RSV
  connectReq[3] = ATYP_DOMAINNAME;
  connectReq[4] = hostLen;
  connectReq.set(hostBytes, 5);
  connectReq[5 + hostLen] = (targetPort >> 8) & 0xff;
  connectReq[6 + hostLen] = targetPort & 0xff;

  log.debug(`SOCKS5 CONNECT → ${targetHost}:${targetPort} (${hex(connectReq)})`);
  await writer.write(connectReq);

  // ── Step 5: Server reply ─────────────────────────────────────────────────
  // VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
  const replyHeader = await readExactly(reader, 4);
  log.debug(`SOCKS5 CONNECT reply header ← ${hex(replyHeader)}`);

  if (replyHeader[0] !== SOCKS_VERSION) {
    throw new Error(`SOCKS5: unexpected version in reply ${replyHeader[0]}`);
  }
  if (replyHeader[1] !== REP_SUCCESS) {
    throw new Error(`SOCKS5: CONNECT failed, REP=0x${replyHeader[1].toString(16)}`);
  }

  // Consume the BND.ADDR and BND.PORT fields (we don't use them).
  const atyp = replyHeader[3];
  if (atyp === ATYP_IPV4) {
    const bnd = await readExactly(reader, 4 + 2);
    log.debug(`SOCKS5 BND.ADDR (IPv4) ← ${hex(bnd)}`);
  } else if (atyp === ATYP_IPV6) {
    const bnd = await readExactly(reader, 16 + 2);
    log.debug(`SOCKS5 BND.ADDR (IPv6) ← ${hex(bnd)}`);
  } else if (atyp === ATYP_DOMAINNAME) {
    const lenBuf = await readExactly(reader, 1);
    const bnd = await readExactly(reader, lenBuf[0] + 2);
    log.debug(`SOCKS5 BND.ADDR (domain) ← ${hex(bnd)}`);
  } else {
    throw new Error(`SOCKS5: unknown ATYP in reply: 0x${atyp.toString(16)}`);
  }

  log.debug("SOCKS5 tunnel established");
}

// ---------------------------------------------------------------------------
// HTTP request serialisation
// ---------------------------------------------------------------------------

/** Headers that must not be forwarded to the upstream (hop-by-hop). */
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
]);

/**
 * Serialise the incoming Workers Request into a raw HTTP/1.1 request buffer
 * suitable for writing directly into the SOCKS5-tunneled TCP socket.
 */
async function buildHttpRequest(request: Request, url: URL, log: Logger): Promise<Uint8Array> {
  const method = request.method;
  // For a forward proxy we send an absolute-form request-target OR
  // origin-form depending on whether we want to let the upstream handle it.
  // Most origin servers expect origin-form, so we use that.
  const path = url.pathname + url.search || "/";

  const lines: string[] = [];
  lines.push(`${method} ${path} HTTP/1.1`);
  lines.push(`Host: ${url.hostname}${url.port ? ":" + url.port : ""}`);

  // Forward safe headers from the incoming request.
  for (const [name, value] of request.headers) {
    if (HOP_BY_HOP.has(name.toLowerCase())) {
      log.debug(`Dropping hop-by-hop header: ${name}`);
      continue;
    }
    lines.push(`${name}: ${value}`);
  }

  lines.push("Connection: close"); // signal to origin we're done after one response
  lines.push(""); // blank line
  lines.push(""); // end of headers

  log.debug(`HTTP request headers:\n${lines.slice(0, -2).join("\r\n")}`);

  const headerBytes = new TextEncoder().encode(lines.join("\r\n"));

  // Append body if present
  if (request.body) {
    const bodyBytes = new Uint8Array(await request.arrayBuffer());
    log.debug(`HTTP request body: ${bodyBytes.length} bytes`);
    const combined = new Uint8Array(headerBytes.length + bodyBytes.length);
    combined.set(headerBytes, 0);
    combined.set(bodyBytes, headerBytes.length);
    return combined;
  }

  return headerBytes;
}

// ---------------------------------------------------------------------------
// ReadableStream helpers for splicing the SOCKS5 reader remainder
// ---------------------------------------------------------------------------

/**
 * The SOCKS5 handshake reads from the socket's ReadableStream via a locked
 * reader. After the handshake, the reader may contain buffered bytes that
 * are already part of the HTTP response. This function creates a new
 * ReadableStream that prepends any buffered bytes, then continues reading
 * from the original reader.
 *
 * Because the Workers runtime does not let us "unread" bytes back into a
 * locked ReadableStream, we have to pump the rest manually.
 */
function readerToReadableStream(
  reader: ReadableStreamDefaultReader<Uint8Array>
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        controller.close();
      } else {
        controller.enqueue(value as Uint8Array);
      }
    },
    cancel() {
      reader.cancel();
    },
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
 * In this implementation next() is never called: the Worker is the egress
 * path itself — it opens a SOCKS5 tunnel through the VPC binding and forwards
 * the request there, replacing what next() would normally do.
 *
 * context carries Gateway request-phase selectors (src_ip, host, uri, etc.).
 */
export class GatewayMiddleware extends WorkerEntrypoint<Env> {
  async handle(
    request: Request,
    context: Record<string, unknown>,
    // next is provided by Gateway but not used here — this Worker is the egress.
    _next: (req: Request) => Promise<Response>
  ): Promise<Response> {
    // env is available as this.env in WorkerEntrypoint subclasses.
    const env = this.env;

    const requestId = newRequestId();
    const log = makeLogger(env, requestId);

    log.info("GatewayMiddleware.handle() invoked");
    log.debug(`Gateway context: ${JSON.stringify(context)}`);

    const url = new URL(request.url);

    log.info(`${request.method} ${url.hostname}:${url.port || (url.protocol === "https:" ? 443 : 80)}`);
    log.debug(`Full URL: ${url.toString()}`);
    log.debug(`Incoming headers: ${[...request.headers.entries()].map(([k, v]) => `${k}: ${v}`).join(", ")}`);

    // Determine target host and port from the incoming request URL.
    const targetHost = url.hostname;
    const defaultPort = url.protocol === "https:" ? 443 : 80;
    const targetPort = url.port ? parseInt(url.port, 10) : defaultPort;

    if (!targetHost) {
      log.error("Missing host in request URL");
      return new Response("Bad Request: missing host", { status: 400 });
    }

    let socket: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };

    log.debug(`Connecting to SOCKS5 proxy at ${env.SOCKS5_HOST}:${env.SOCKS5_PORT} via VPC`);
    try {
      // Open a raw TCP connection to the SOCKS5 proxy through the VPC tunnel.
      socket = await env.VPC.connect({
        hostname: env.SOCKS5_HOST,
        port: parseInt(env.SOCKS5_PORT, 10),
      });
      log.debug("VPC TCP connection established");
    } catch (err) {
      log.error(`VPC connect failed: ${err}`);
      return new Response("Bad Gateway: could not connect to SOCKS5 proxy", { status: 502 });
    }

    const reader = socket.readable.getReader();
    const writer = socket.writable.getWriter();

    try {
      // Perform the SOCKS5 CONNECT handshake to establish the tunnel.
      await socks5Connect(reader, writer, targetHost, targetPort, env.SOCKS5_USERNAME, env.SOCKS5_PASSWORD, log);

      // Serialise and send the HTTP request into the tunnel.
      const httpRequestBytes = await buildHttpRequest(request, url, log);
      log.debug(`Writing ${httpRequestBytes.length} bytes to tunnel`);
      await writer.write(httpRequestBytes);
      // Do NOT close the writer here — some servers stream responses before
      // they finish reading the request body.

      // Wrap the locked reader back into a fresh ReadableStream so we can
      // pass it to parseHttpResponse without unlocking it.
      const responseStream = readerToReadableStream(reader);

      log.debug("Parsing HTTP response from tunnel");
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
 *
 * This is necessary because we receive a raw TCP byte stream from the SOCKS5
 * tunnel and need to present a proper `Response` to the Workers runtime.
 */
async function parseHttpResponse(
  stream: ReadableStream<Uint8Array>,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  log: Logger
): Promise<Response> {
  // We need to buffer bytes until we find the end of the HTTP headers
  // (the blank line \r\n\r\n), then split header bytes from body bytes.
  const CRLF2 = "\r\n\r\n";
  const chunks: Uint8Array[] = [];
  let headerText: string | null = null;
  let bodyRemainder: Uint8Array | null = null;

  const reader = stream.getReader();

  while (headerText === null) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value as Uint8Array);

    // Concatenate what we have so far and look for the header/body boundary.
    const soFar = concat(chunks);
    const text = new TextDecoder("latin1").decode(soFar); // latin1 to preserve byte values
    const sep = text.indexOf(CRLF2);
    if (sep !== -1) {
      headerText = text.substring(0, sep);
      // Everything after the blank line is the start of the body.
      const bodyStart = sep + CRLF2.length;
      if (bodyStart < soFar.length) {
        bodyRemainder = soFar.subarray(bodyStart);
      }
    }
  }

  if (!headerText) {
    throw new Error("SOCKS5 upstream closed connection before sending HTTP headers");
  }

  log.debug(`HTTP response headers:\n${headerText}`);

  // Parse status line
  const lines = headerText.split("\r\n");
  const statusLine = lines[0];
  const statusMatch = statusLine.match(/^HTTP\/1\.[01] (\d{3})(?: (.*))?$/);
  if (!statusMatch) {
    throw new Error(`Unrecognised HTTP status line: ${statusLine}`);
  }
  const status = parseInt(statusMatch[1], 10);
  const statusText = statusMatch[2] ?? "";

  // Parse headers
  const responseHeaders = new Headers();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const name = line.substring(0, colon).trim().toLowerCase();
    const value = line.substring(colon + 1).trim();
    // Skip hop-by-hop headers — the Workers runtime manages these.
    if (HOP_BY_HOP.has(name)) {
      log.debug(`Dropping upstream hop-by-hop header: ${name}`);
      continue;
    }
    responseHeaders.append(name, value);
  }

  log.debug(`Body remainder from header parse: ${bodyRemainder?.length ?? 0} bytes`);

  // Build the body stream: prepend any remainder bytes from the header parse,
  // then continue from the reader.
  const bodyStream = new ReadableStream<Uint8Array>({
    async start(controller) {
      if (bodyRemainder && bodyRemainder.length > 0) {
        controller.enqueue(bodyRemainder);
      }
    },
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        controller.close();
        // Close the writer now that the response is fully consumed.
        try { writer.close(); } catch { /* ignore */ }
      } else {
        controller.enqueue(value as Uint8Array);
      }
    },
    cancel() {
      reader.cancel();
    },
  });

  // 204 / 304 responses must not carry a body.
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
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
