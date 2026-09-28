# workers-proxy

A Cloudflare Worker that acts as a forward HTTP proxy by tunneling requests through a SOCKS5 proxy on a private network, reachable via a [Workers VPC](https://developers.cloudflare.com/workers-vpc/) binding over a Cloudflare Tunnel.

## Problem

There is a SOCKS5 proxy running on a private LAN (`172.18.0.21:1080`) that can reach internal services not exposed to the public internet. Clients that need to route HTTP/HTTPS traffic through that proxy cannot reach it directly — it has no public address.

## Solution

```
Client (HTTP/HTTPS)
  │  TLS terminated at Cloudflare edge
  ▼
Cloudflare Worker  (workers-proxy)
  │  Plaintext TCP via Workers VPC Network binding
  ▼
Cloudflare Tunnel  (mad01-k8s)
  │  Private LAN
  ▼
SOCKS5 proxy  (172.18.0.21:1080)
  │
  ▼
Target origin
```

The Worker:

1. Receives every inbound request as a plain `Request` object (Cloudflare terminates TLS at the edge).
2. Opens a raw TCP socket to the SOCKS5 proxy through a **Workers VPC Network** binding, which routes the connection through a Cloudflare Tunnel into the private network.
3. Performs the full **SOCKS5 CONNECT handshake** (RFC 1928) with **username/password authentication** (RFC 1929).
4. Serialises the incoming HTTP request and writes it into the now-transparent tunnel.
5. Parses the raw HTTP/1.1 response from the socket and streams it back to the client.

Because Cloudflare terminates TLS before the Worker runs, HTTPS clients are handled identically to HTTP clients — the Worker sees a plain, decrypted `Request` in both cases.

## Configuration

### Environment variables (`wrangler.jsonc` → `vars`)

| Variable | Description | Default |
|---|---|---|
| `SOCKS5_HOST` | Hostname or IP of the SOCKS5 proxy | `172.18.0.21` |
| `SOCKS5_PORT` | Port of the SOCKS5 proxy | `1080` |
| `DEBUG` | Set to `"true"` to enable verbose per-request logging | `"true"` |

### Secrets (encrypted, set via `wrangler secret put`)

| Secret | Description |
|---|---|
| `SOCKS5_USERNAME` | RFC 1929 username for SOCKS5 authentication |
| `SOCKS5_PASSWORD` | RFC 1929 password for SOCKS5 authentication |

### Workers VPC Network binding (`wrangler.jsonc` → `vpc_networks`)

The binding named `VPC` is pointed at the `mad01-k8s` Cloudflare Tunnel (`9ab52e82-7276-43c3-8acc-7a5e99556e9f`). Any `connect()` call on this binding is routed through that tunnel into the private network.

## Deployment

```bash
# Install dependencies
npm install

# Set credentials (interactive prompts — values are never echoed)
wrangler secret put SOCKS5_USERNAME
wrangler secret put SOCKS5_PASSWORD

# Deploy
wrangler deploy
```

## Development

```bash
# Local dev server (note: VPC Network binding requires remote: true)
npm run dev

# Stream live logs from the deployed worker
npm run logs

# Type-check without deploying
npm run typecheck
```

## Usage

Point any HTTP client's proxy at the Worker URL:

```bash
# Explicit proxy flag
curl -x https://workers-proxy.massesos.workers.dev http://internal.example.com/api

# Via environment variables (most tools and runtimes honour these)
export http_proxy=https://workers-proxy.massesos.workers.dev
export https_proxy=https://workers-proxy.massesos.workers.dev
curl http://internal.example.com/api
```

## SOCKS5 handshake

The Worker implements the full protocol:

```
Worker → Proxy:  05 02 00 02          (VER=5, NMETHODS=2, no-auth + user/pass)
Proxy  → Worker: 05 02                (VER=5, METHOD=user/pass chosen)

Worker → Proxy:  01 <ulen> <user> <plen> <pass>   (RFC 1929 sub-negotiation)
Proxy  → Worker: 01 00                             (success)

Worker → Proxy:  05 01 00 03 <hlen> <host> <port>  (CONNECT host:port)
Proxy  → Worker: 05 00 00 ...                       (success + BND address)

-- tunnel is now a transparent byte pipe --
```

Both `0x00` (no-auth) and `0x02` (user/pass) are advertised in the greeting. If the proxy selects no-auth the RFC 1929 exchange is skipped.

## Logging

When `DEBUG=true`, every request produces structured log lines prefixed with a short random request ID (e.g. `[A3X9KQ]`):

```
[A3X9KQ] [INFO]  GET example.com:80
[A3X9KQ] [DEBUG] Connecting to SOCKS5 proxy at 172.18.0.21:1080 via VPC
[A3X9KQ] [DEBUG] SOCKS5 greeting → 05 02 00 02
[A3X9KQ] [DEBUG] SOCKS5 method selection ← 05 02
[A3X9KQ] [DEBUG] SOCKS5 auth sub-negotiation → VER=0x01 ULEN=4 PLEN=4
[A3X9KQ] [DEBUG] SOCKS5 auth reply ← 01 00
[A3X9KQ] [DEBUG] SOCKS5 authentication succeeded
[A3X9KQ] [DEBUG] SOCKS5 CONNECT → example.com:80
[A3X9KQ] [DEBUG] SOCKS5 tunnel established
[A3X9KQ] [INFO]  Response: 200 OK
```

Credentials are never logged — only the field lengths (`ULEN`, `PLEN`) appear in debug output.

Errors are always logged regardless of `DEBUG`.

## Known limitations

- **No worker-level authentication**: any client that can reach the Worker URL can use it as a proxy. Place it behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/self-hosted-public-app/) if unauthenticated access is a concern.
- **Chunked Transfer-Encoding**: response bodies are streamed verbatim from the socket, so chunked framing bytes are forwarded as-is. Add a `TransformStream` to decode them if this causes issues with specific clients.
- **One connection per request**: the Workers runtime does not allow socket reuse across requests, so a new SOCKS5 connection is opened for every inbound request.
- **Plaintext Worker-to-proxy leg**: `connect()` over VPC Networks currently supports plaintext TCP only. This is acceptable because the tunnel runs over the trusted private LAN; the public leg (client-to-Worker) is always HTTPS.
