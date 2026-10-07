# gateway-proxy-worker

A Cloudflare Worker deployed as a **Gateway Custom Action** middleware that acts as a forward HTTP proxy, routing all traffic through an HTTP proxy on a private network reachable via a [Workers VPC](https://developers.cloudflare.com/workers-vpc/) Network binding over a Cloudflare Tunnel.

## Architecture

```
Client (HTTP/HTTPS)
  │  TLS terminated at Cloudflare Gateway edge
  ▼
Cloudflare Gateway
  │  HTTP policy match → Custom Action
  ▼
GatewayMiddleware.handle()   [this Worker]
  │  Plaintext TCP via Workers VPC Network binding
  ▼
Cloudflare Tunnel
  │  Private LAN
  ▼
HTTP proxy  (<PROXY_HOST>:<PROXY_PORT>)
  │  HTTP:  forwards to origin over plain HTTP
  │  HTTPS: proxy opens TLS to origin on behalf of the Worker
  ▼
Target origin
```

Gateway terminates the client's TLS before dispatching to the Worker. The Worker receives a plain, decrypted `Request` for both HTTP and HTTPS destinations. It forwards this as an absolute-form HTTP proxy request; the proxy handles the outbound TLS to HTTPS origins.

## Protocol

Both HTTP and HTTPS use the same request format — absolute-form URL in the request line:

```
GET http://example.com/path  HTTP/1.1
GET https://example.com/path HTTP/1.1
```

The proxy is expected to handle each differently:

- **HTTP** — forwards the request to the origin over plain HTTP.
- **HTTPS** — the proxy detects the `https://` scheme, opens a TLS connection to the origin itself, and returns the decrypted response to the Worker over the plain proxy connection.

This avoids the need for the Worker to speak TLS, which is not possible via `env.VPC.connect()` (plaintext TCP only).

## Proxy configuration

The Worker sends `GET https://host/path HTTP/1.1` (absolute-form with `https://` scheme) for HTTPS destinations. Not all HTTP proxies support this — see the compatibility notes below.

### FortiGate explicit web proxy ✓

Enable the explicit web proxy and set `detect-https-in-http-request` in the proxy policy. This is the key knob that allows FortiGate to fetch HTTPS resources when the client sends an absolute-form `https://` URL instead of a CONNECT tunnel.

```
config web-proxy explicit
    set status enable
    set http-incoming-port 8888
end

config firewall proxy-policy
    edit <policy-id>
        set proxy explicit-web
        set action accept
        set detect-https-in-http-request enable
        set ssl-ssh-profile "deep-inspection"
        set logtraffic all
    next
end
```

`detect-https-in-http-request` and `ssl-ssh-profile "deep-inspection"` are mandatory — without them FortiGate cannot fetch HTTPS origins on behalf of the Worker.

### Squid ✓

Squid supports absolute-form HTTPS requests natively in forward proxy mode. No special configuration is needed beyond enabling the proxy and allowing the relevant ACLs:

```
# /etc/squid/squid.conf (minimal)
http_port 3128

# Allow connections from the Worker's egress IP (the tunnel exit node)
acl worker_src src <your-tunnel-egress-subnet>
http_access allow worker_src
http_access deny all
```

When Squid receives `GET https://host/path HTTP/1.1` it issues its own TLS connection to the origin and returns the decrypted response to the Worker over the plain proxy connection — the same behaviour as FortiGate with `detect-https-in-http-request`.

### tinyproxy ✗ — not compatible

Tinyproxy will not work with this Worker. By design, tinyproxy is a lightweight HTTP proxy that treats HTTPS traffic strictly as an opaque stream via the `CONNECT` method. When it receives `GET https://host/path HTTP/1.1` in absolute-form, it returns `501 Not Implemented` — it has no capability to fetch HTTPS resources itself. The source code confirms this: only `http://` URLs and `CONNECT` requests are handled; everything else falls into a `501` branch.

The `CONNECT`-based approach (which tinyproxy does support) cannot be used here because `env.VPC.connect()` is plaintext-only and `startTls()` is not available on VPC-bound sockets.

## Worker configuration

### Environment variables (`wrangler.jsonc` → `vars`)

| Variable | Description | Default |
|---|---|---|
| `PROXY_HOST` | Hostname or IP of the HTTP proxy reachable behind the tunnel | — |
| `PROXY_PORT` | Port the proxy listens on | — |
| `FAIL_OPEN` | When `"true"`, falls through to Gateway's normal egress if the proxy is unreachable (and the request body was not yet consumed) instead of returning 502 | `"false"` |
| `DEBUG` | Set to `"true"` to enable verbose per-request logging | `"false"` |

### Secrets (encrypted, set via `wrangler secret put`)

| Secret | Description |
|---|---|
| `PROXY_USERNAME` | HTTP proxy username (`Proxy-Authorization: Basic`) |
| `PROXY_PASSWORD` | HTTP proxy password |

Credentials are optional. If absent, requests are sent without a `Proxy-Authorization` header.

### Workers VPC Network binding (`wrangler.jsonc` → `vpc_networks`)

The binding named `VPC` must be pointed at a Cloudflare Tunnel that has access to the private network where the proxy is reachable. Update `tunnel_id` in `wrangler.jsonc` with your tunnel's ID before deploying.

## Deployment

```bash
# Install dependencies
npm install

# Set the proxy address
# Edit wrangler.jsonc: set PROXY_HOST and PROXY_PORT under vars
# Edit wrangler.jsonc: set tunnel_id under vpc_networks

# Optional: set proxy credentials
printf 'myuser' | wrangler secret put PROXY_USERNAME
printf 'mypass' | wrangler secret put PROXY_PASSWORD

# Deploy
wrangler deploy
```

## Development

```bash
npm run dev        # wrangler dev (VPC binding requires remote: true)
npm run logs       # wrangler tail — live log stream
npm run typecheck  # tsc --noEmit
npm run deploy     # wrangler deploy
```

## Logging

When `DEBUG=true`, every request produces structured JSON log lines, each tagged with a short random request ID:

```json
{"level":"INFO","requestId":"A3X9KQ12","msg":"GatewayMiddleware.handle() invoked"}
{"level":"DEBUG","requestId":"A3X9KQ12","msg":"Gateway context: {\"src_ip\":\"...\",\"host\":\"example.com\",...}"}
{"level":"INFO","requestId":"A3X9KQ12","msg":"GET example.com:443"}
{"level":"DEBUG","requestId":"A3X9KQ12","msg":"Connecting to proxy at <PROXY_HOST>:<PROXY_PORT> via VPC"}
{"level":"DEBUG","requestId":"A3X9KQ12","msg":"VPC TCP connection established"}
{"level":"DEBUG","requestId":"A3X9KQ12","msg":"Request line: GET https://example.com/path HTTP/1.1"}
{"level":"DEBUG","requestId":"A3X9KQ12","msg":"Response status: 200 OK"}
{"level":"DEBUG","requestId":"A3X9KQ12","msg":"Response body: chunked transfer-encoding"}
{"level":"INFO","requestId":"A3X9KQ12","msg":"Response: 200 OK (142ms)"}
```

`log.error()` always emits regardless of `DEBUG`. Credentials are never logged.

## Request body handling

Request bodies are streamed rather than buffered:

- If `Content-Length` is known, the body is forwarded verbatim.
- If `Content-Length` is absent (e.g. a streaming POST), the body is forwarded as `Transfer-Encoding: chunked` — no buffering in Worker memory.

## Response body handling

The Worker correctly handles all three HTTP/1.1 body framing modes:

| Mode | Detection | Handling |
|---|---|---|
| Chunked | `Transfer-Encoding: chunked` | Full chunk decoder — reads size lines, validates CRLF, decodes trailers |
| Fixed-length | `Content-Length: N` | Exactly N bytes via `FixedLengthStream` |
| Until-close | Neither header | Streams until socket EOF |

`Content-Encoding` and `Content-Length` are stripped from responses because Gateway may have already decoded the body before dispatching to the Worker.

## FAIL_OPEN mode

When `FAIL_OPEN=true`, if the proxy TCP connection fails *before* the request body is consumed, the Worker calls `next(request)` to let Gateway handle the request through its normal egress path. This prevents a proxy outage from hard-blocking all traffic.

When the request body has already been partially read (e.g. a large upload mid-stream), FAIL_OPEN is not attempted — the body cannot be replayed.

## Cloudflare header stripping

The following Cloudflare-internal headers are stripped before forwarding to the proxy, because Cloudflare-fronted origins reject requests that carry them (403):

`cf-connecting-ip`, `cf-connecting-ipv6`, `cf-ipcountry`, `cf-ray`, `cf-visitor`, `cf-worker`, `cf-ew-via`, `cdn-loop`, `x-real-ip`

## Known limitations

- **One connection per request** — the Workers runtime ties TCP socket lifetimes to request lifetimes. A new proxy connection is opened for every inbound request; there is no connection pool.
- **WebSocket upgrades** — requests with an `Upgrade` header are passed through to Gateway's normal egress via `next()` and are not proxied.
- **Plaintext Worker-to-proxy leg** — `env.VPC.connect()` supports plaintext TCP only. This is acceptable because the proxy is on a trusted private LAN and handles the HTTPS leg to the origin itself.
