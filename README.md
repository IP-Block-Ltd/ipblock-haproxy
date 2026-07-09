> ⚠️ **Status: untested.** This extension is provided as-is and has **not been tested in production**. Please feel free to fork, modify, improve, and open pull requests.
>
> Licensed under **GNU GPLv3** (see [LICENSE](LICENSE)).

# IP Block for HAProxy

A HAProxy Lua action that consults the [ip-block.com](https://www.ip-block.com)
decision API and sets a transaction variable; `haproxy.cfg` then blocks or
redirects based on that variable.

- **Tested against:** HAProxy **3.4 LTS** (latest LTS, 2026). Requires HAProxy built
  with Lua and the Lua HTTP client (`core.httpclient`, available since 2.5).
- **Approach:** Lua `http-req` action + `http-request` rules (as requested). A
  SPOE variant is possible but the Lua httpclient approach is simpler and
  self-contained.

## Files

| File | Purpose |
|------|---------|
| `ip_block.lua` | Registers the `ipblock_check` action; calls the API; sets `txn.ipblock`. |
| `haproxy.cfg` | Example config: `setenv` config, `lua-load`, and enforcement rules. |

## Install

1. Confirm Lua support: `haproxy -vv | grep -i lua` should show it is enabled.
2. Copy `ip_block.lua` to e.g. `/etc/haproxy/ip-block/ip_block.lua`.
3. In the `global` section add:
   ```
   httpclient.ssl.ca-file /etc/ssl/certs/ca-certificates.crt
   lua-load /etc/haproxy/ip-block/ip_block.lua
   ```
   and the `setenv IPB_*` lines (see `haproxy.cfg`).
4. In your `frontend` add:
   ```
   http-request lua.ipblock_check
   http-request redirect location https://www.ip-block.com/blocked.php if { var(txn.ipblock) -m str block }
   # or, for a bare 403:
   # http-request deny deny_status 403 if { var(txn.ipblock) -m str block }
   ```
5. Validate and reload: `haproxy -c -f /etc/haproxy/haproxy.cfg` then reload the
   service.

## Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `IPB_ENABLED` | `1` | Master switch. |
| `IPB_SITE_ID` | — | Site id. |
| `IPB_API_KEY` | — | API key (JSON body). |
| `IPB_API_URL` | `https://api.ip-block.com/v1/check` | Endpoint. |
| `IPB_FAIL_OPEN` | `1` | `1` allow on error, `0` sets `block` on error. |
| `IPB_CACHE_TTL` | `300` | Per-IP cache seconds (`0` disables). |
| `IPB_TIMEOUT_MS` | `1000` | API timeout. |
| `IPB_BEHIND_PROXY` | `0` | If `1`, read client IP from `IPB_REAL_IP_HEADER`. |
| `IPB_REAL_IP_HEADER` | `x-forwarded-for` | Header for the client IP (lower-case). |
| `IPB_WHITELIST` | — | Comma-separated IPs never checked. |

Set these with `setenv` in the `global` section (shown in `haproxy.cfg`) or via the
service environment.

## Behaviour

- The action always defaults `txn.ipblock` to `allow`, so a Lua error can never
  accidentally block traffic.
- Only `{"action":"block"}` yields `block`; anything else is `allow` (subject to
  `IPB_FAIL_OPEN`).
- API errors are not cached; the next request retries. `allow`/`block` decisions are
  cached for `IPB_CACHE_TTL`.
- Whitelisted IPs short-circuit before the cache/API.

## Real client IP

By default `txn.f:src()` (the connection source) is used. When HAProxy is behind a
CDN/LB, set `IPB_BEHIND_PROXY=1` and `IPB_REAL_IP_HEADER` to the header carrying the
client IP; the left-most token of that header is used.

## Caching notes

The cache is a Lua table in HAProxy's shared Lua state, so it is shared across the
threads of a single HAProxy process (the normal multi-threaded deployment). It is
not shared across separate HAProxy processes or nodes; each keeps its own short-TTL
cache, which is fine for idempotent decisions.
