-- Models Envoy's request header map: names are case-insensitive (stored
-- lowercase) and a repeated header keeps every value; `get` joins them with
-- "," and `getNumValues` counts them.
local methods = {}
function methods:get(name)
  local value = rawget(self, name:lower())
  if type(value) == "table" then return table.concat(value, ",") end
  return value
end
function methods:getNumValues(name)
  local value = rawget(self, name:lower())
  if value == nil then return 0 end
  if type(value) == "table" then return #value end
  return 1
end
function methods:remove(name) rawset(self, name:lower(), nil) end
function methods:add(name, value) rawset(self, name:lower(), value) end
local collected = {}
for _, pair in ipairs(input_header_list) do
  local name, value = pair[1]:lower(), pair[2]
  local existing = collected[name]
  if existing == nil then
    collected[name] = value
  elseif type(existing) == "table" then
    existing[#existing + 1] = value
  else
    collected[name] = {existing, value}
  end
end
input_headers = collected
local headers = setmetatable(input_headers, {__index = methods})
local metadata = {}
local metadata_api = {}
route_metadata = {}
function metadata_api:set(namespace, name, value)
  if namespace == "gm.route" then
    route_metadata[name] = value
    return
  end
  assert(namespace == "gm.access_log")
  metadata[name] = value
end
local stream = {}
function stream:dynamicMetadata() return metadata_api end
local handle = {}
function handle:headers() return headers end
function handle:streamInfo() return stream end
function handle:body() error("request bodies must pass through unread") end
function handle:respond(response_headers, response_body)
  response_status = response_headers[":status"]
  response_body_text = response_body
end
os.getenv = function(name) return input_env[name] end
envoy_on_request(handle)
output_metadata = metadata
