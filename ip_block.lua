--[[
  ip_block.lua — HAProxy Lua action for ip-block.com.

  Registers an http-request action "ipblock_check" that:
    * resolves the real client IP,
    * skips whitelisted IPs,
    * consults an in-memory per-IP decision cache,
    * on a miss, POSTs to https://api.ip-block.com/v1/check (api_key in the BODY)
      using HAProxy's built-in Lua HTTP client (core.httpclient), 1s timeout,
    * sets the transaction variable txn.ipblock to "block" or "allow",
    * FAILS OPEN (sets "allow") on any error/timeout unless IPB_FAIL_OPEN=0.

  haproxy.cfg then does the actual blocking based on txn.ipblock (see haproxy.cfg).

  Requires HAProxy with Lua + the Lua httpclient (HAProxy >= 2.5; tested on 3.4 LTS).
  Load with:  lua-load /etc/haproxy/ip-block/ip_block.lua

  Configuration is read from environment variables (set via `setenv` in the global
  section of haproxy.cfg, or the service environment):
    IPB_ENABLED, IPB_SITE_ID, IPB_API_KEY, IPB_API_URL, IPB_FAIL_OPEN,
    IPB_CACHE_TTL, IPB_TIMEOUT_MS, IPB_BEHIND_PROXY, IPB_REAL_IP_HEADER,
    IPB_WHITELIST
]]

-- ---- configuration (read once at load) ------------------------------------

local function env(name, default)
  local v = os.getenv(name)
  if v == nil or v == "" then return default end
  return v
end

local CONFIG = {
  enabled        = env("IPB_ENABLED", "1") == "1",
  site_id        = env("IPB_SITE_ID", ""),
  api_key        = env("IPB_API_KEY", ""),
  api_url        = env("IPB_API_URL", "https://api.ip-block.com/v1/check"),
  fail_open      = env("IPB_FAIL_OPEN", "1") == "1",
  cache_ttl      = tonumber(env("IPB_CACHE_TTL", "300")) or 300,
  timeout_ms     = tonumber(env("IPB_TIMEOUT_MS", "1000")) or 1000,
  behind_proxy   = env("IPB_BEHIND_PROXY", "0") == "1",
  real_ip_header = string.lower(env("IPB_REAL_IP_HEADER", "x-forwarded-for")),
}

-- whitelist as a set
local WHITELIST = {}
for ip in string.gmatch(env("IPB_WHITELIST", ""), "[^,%s]+") do
  WHITELIST[ip] = true
end

-- ---- in-memory per-IP cache -----------------------------------------------
-- The action runs in HAProxy's shared Lua state (loaded via lua-load), so this
-- table is shared across threads of a single HAProxy process.
local CACHE = {} -- ip -> { expires = epoch, decision = "block"|"allow" }

local function cache_get(ip)
  local e = CACHE[ip]
  if e and os.time() < e.expires then
    return e.decision
  end
  return nil
end

local function cache_set(ip, decision)
  if CONFIG.cache_ttl > 0 then
    CACHE[ip] = { expires = os.time() + CONFIG.cache_ttl, decision = decision }
  end
end

-- ---- JSON helpers (dependency-free) ---------------------------------------

local function json_escape(s)
  s = tostring(s or "")
  s = s:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t')
  s = s:gsub('[%z\1-\8\11\12\14-\31]', '')
  return s
end

local function build_body(ip, ua, ref)
  return string.format(
    '{"api_key":"%s","site_id":"%s","ip":"%s","user_agent":"%s","referrer":"%s"}',
    json_escape(CONFIG.api_key), json_escape(CONFIG.site_id), json_escape(ip),
    json_escape(ua), json_escape(ref))
end

local function parse_action(body)
  if not body then return nil end
  return body:match('"action"%s*:%s*"([^"]*)"')
end

-- ---- API call --------------------------------------------------------------
-- Returns "block" | "allow" | nil (nil == error -> apply fail-open).
local function call_api(ip, ua, ref)
  local httpclient = core.httpclient()
  if not httpclient then return nil end

  local res = httpclient:post{
    url     = CONFIG.api_url,
    body    = build_body(ip, ua, ref),
    headers = { ["content-type"] = { "application/json" } },
    timeout = CONFIG.timeout_ms, -- milliseconds
  }

  if not res or type(res.status) ~= "number" then return nil end
  if res.status < 200 or res.status >= 300 then return nil end

  local action = parse_action(res.body)
  if action == nil then return nil end
  if action == "block" then return "block" end
  return "allow"
end

-- ---- real client IP --------------------------------------------------------
local function client_ip(txn)
  if CONFIG.behind_proxy then
    local hdrs = txn.http:req_get_headers()
    local h = hdrs[CONFIG.real_ip_header]
    if h then
      -- headers come back as { [0] = "value", ... }; take first, left-most token
      local val = h[0] or h[1]
      if val then
        local first = tostring(val):match("^%s*([^,]+)")
        if first then return (first:gsub("%s+", "")) end
      end
    end
  end
  return txn.f:src()
end

local function header_first(txn, name)
  local hdrs = txn.http:req_get_headers()
  local h = hdrs[name]
  if h then return h[0] or h[1] end
  return nil
end

-- ---- the action ------------------------------------------------------------
local function ipblock_check(txn)
  -- Default to allow so downstream rules never block on a Lua glitch.
  txn:set_var("txn.ipblock", "allow")

  if not CONFIG.enabled then return end

  local ip = client_ip(txn)
  if not ip or ip == "" then
    if not CONFIG.fail_open then txn:set_var("txn.ipblock", "block") end
    return
  end

  if WHITELIST[ip] then return end

  local cached = cache_get(ip)
  if cached ~= nil then
    txn:set_var("txn.ipblock", cached)
    return
  end

  local ua  = header_first(txn, "user-agent") or ""
  local ref = header_first(txn, "referer") or ""

  local decision = call_api(ip, ua, ref)
  if decision == nil then
    -- error: fail-open policy; do not cache
    if not CONFIG.fail_open then txn:set_var("txn.ipblock", "block") end
    return
  end

  cache_set(ip, decision)
  txn:set_var("txn.ipblock", decision)
end

core.register_action("ipblock_check", { "http-req" }, ipblock_check)
