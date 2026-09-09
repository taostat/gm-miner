local slot_env = "__SLOT_ENV__"
os.getenv = function(name)
  if name == slot_env then
    return "test-cloud-key"
  end
  return nil
end

local valid_slot = nil
for slot_id, env_name in pairs(slot_config.__PROVIDER__.slots) do
  valid_slot = slot_id
  assert(env_name == slot_env, "the valid slot must point at the configured key")
end
local slot_count = 0
for _ in pairs(slot_config.__PROVIDER__.slots) do slot_count = slot_count + 1 end
assert(slot_count == 1, "one cloud key must expose exactly one slot")
assert(valid_slot == "__EXPECTED_SLOT__", "slot must be HMAC of the current cloud key")
assert(valid_slot ~= nil, "the qualified cloud slot must be rendered")

local function make_headers(values)
  local headers = {}
  function headers:get(name)
    return self[name]
  end
  function headers:remove(name)
    self[name] = nil
  end
  function headers:add(name, value)
    self[name] = value
  end
  return setmetatable(values, {__index = headers})
end

local function run(node_key, slot)
  local values = {
    [":path"] = "__REQUEST_PATH__",
    ["x-gm-provider"] = "__PROVIDER__",
  }
  if node_key ~= nil then values["x-gm-node-key"] = node_key end
  if slot ~= nil then values["x-gm-upstream-slot"] = slot end
  local headers = make_headers(values)
  local metadata = {}
  function metadata:set(_, _) end
  local stream_info = {}
  function stream_info:dynamicMetadata() return metadata end
  local status = nil
  local body = nil
  local handle = {}
  function handle:headers() return headers end
  function handle:streamInfo() return stream_info end
  function handle:respond(response_headers, response_body)
    status = response_headers[":status"]
    body = response_body
  end
  envoy_on_request(handle)
  return status, body
end

local status, body = run("test-node-secret-0001", valid_slot)
assert(status == nil, "a valid authenticated cloud slot must proceed")
status, body = run(nil, valid_slot)
assert(status == "401", "a missing node key must be rejected before slot selection")
status, body = run("wrong-node-secret", "wrong-slot")
assert(status == "401", "node authentication must precede wrong-slot handling")
assert(body:find("gm_slot_unavailable", 1, true) == nil, "pre-auth request must not receive a slot verdict")
status, body = run("test-node-secret-0001", nil)
assert(status == "421", "a missing cloud slot must be unavailable")
assert(body:find("gm_slot_unavailable", 1, true) ~= nil, "missing slot must use the slot contract")
status, body = run("test-node-secret-0001", "wrong-slot")
assert(status == "421", "a wrong cloud slot must be unavailable")
assert(body:find("wrong-slot", 1, true) ~= nil, "wrong slot response must name the requested slot")
status, body = run("test-node-secret-0001", "__OLD_SLOT__")
assert(status == "421", "a slot retired by key rotation must be unavailable")
assert(body:find("__OLD_SLOT__", 1, true) ~= nil, "rotated slot response must name the retired slot")
