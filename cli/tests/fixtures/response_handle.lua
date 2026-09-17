local methods = {}
function methods:get(name) return self[name] end
local headers = setmetatable(input_headers, {__index = methods})
local metadata_api = {}
function metadata_api:get(namespace)
  assert(namespace == "gm.access_log")
  return input_metadata
end
local stream = {}
function stream:dynamicMetadata() return metadata_api end
local handle = {}
function handle:headers() return headers end
function handle:streamInfo() return stream end
function handle:body() error("response bodies must pass through unread") end
-- Chunks are handed out one at a time and never retained, as Envoy does.
-- When the stream ends the fixture records whether a hand-off had already
-- been made: one made here was made before the broker could have written
-- the record the auditor reads.
local chunks_seen = 0
function handle:bodyChunks()
  local chunks = input_body_chunks or {}
  local index = 0
  return function()
    index = index + 1
    if index > #chunks then
      http_call_before_body_end = http_call ~= nil
      return nil
    end
    chunks_seen = chunks_seen + 1
    return chunks[index]
  end
end
function handle:logWarn(message) log_warn = message end
function handle:httpCall(cluster, call_headers, body, timeout, asynchronous)
  http_call = {
    cluster = cluster,
    method = call_headers[":method"],
    path = call_headers[":path"],
    body = body,
    timeout = timeout,
    asynchronous = asynchronous,
  }
end
envoy_on_response(handle)
body_chunks_seen = chunks_seen
