local function make_headers(values)
  local headers = {values = values}
  function headers:get(name)
    return self.values[name]
  end
  function headers:remove(name)
    self.values[name] = nil
  end
  function headers:add(name, value)
    self.values[name] = value
  end
  return headers
end

local function run(slot, node_key)
  local values = {
    [":path"] = "/v1/messages",
    ["x-gm-provider"] = "anthropic",
    ["x-gm-node-key"] = node_key,
  }
  if slot ~= nil then values["x-gm-upstream-slot"] = slot end
  local headers = make_headers(values)
  local metadata = {}
  function metadata:set(_, _, _) end
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

local status, body = run(nil, "test-node-secret-0001")
assert(status == "400", "Bedrock without a slot must remain unqualified")
assert(body:find("gm_unqualified_surface", 1, true) ~= nil, "no-slot body must name the unqualified surface")
status, body = run("bedrock-slot", "test-node-secret-0001")
assert(status == "421", "any supplied Bedrock slot must be unavailable")
assert(body:find("gm_slot_unavailable", 1, true) ~= nil, "supplied-slot body must use the slot contract")
assert(body:find("bedrock-slot", 1, true) ~= nil, "421 must name the supplied slot")
status, body = run("bedrock-slot", nil)
assert(status == "401", "Bedrock must authenticate before slot rejection")
status, body = run(nil, "wrong-secret")
assert(status == "401", "Bedrock must authenticate before qualification rejection")
