local methods = {}
function methods:get(name) return self[name] end
function methods:remove(name) self[name] = nil end
function methods:add(name, value) self[name] = value end
local headers = setmetatable(input_headers, {__index = methods})
local metadata = {}
local metadata_api = {}
function metadata_api:set(namespace, name, value)
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
