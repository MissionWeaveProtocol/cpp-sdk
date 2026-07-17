#include <missionweaveprotocol/frame.hpp>

#include <missionweaveprotocol/canonical.hpp>

#include <string>

namespace missionweaveprotocol {
namespace {

void require_valid(const ValidationResult& result, const std::string_view label) {
  if (result.valid) {
    return;
  }
  std::string message{label};
  message += " failed schema validation";
  if (result.issue) {
    if (!result.issue->instance_location.empty()) {
      message += " at " + result.issue->instance_location;
    }
    message += ": " + result.issue->message;
  }
  throw FrameError(message);
}

} // namespace

FrameCodec::FrameCodec() = default;

Json FrameCodec::decode(const std::string_view document) const {
  auto frame = parse_strict_json(document);
  if (!frame.is_object()) {
    throw FrameError("WebSocket frame must be a JSON object");
  }
  require_valid(catalog_.validate("websocket-frame.schema.json", frame), "WebSocket frame");
  return frame;
}

Json FrameCodec::decode(const AssetBytes document) const {
  return decode({reinterpret_cast<const char*>(document.data()), document.size()});
}

std::string FrameCodec::encode(const Json& frame) const {
  if (!frame.is_object()) {
    throw FrameError("WebSocket frame must be a JSON object");
  }
  require_valid(catalog_.validate("websocket-frame.schema.json", frame), "WebSocket frame");
  return canonical_json(frame);
}

void FrameCodec::validate_document(const std::string_view schema_name, const Json& document) const {
  require_valid(catalog_.validate(schema_name, document), "protocol document");
}

} // namespace missionweaveprotocol
