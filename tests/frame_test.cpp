#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/frame.hpp>

#include <cassert>
#include <exception>
#include <string>
#include <string_view>

namespace {

void expect_decode_error(const missionweaveprotocol::FrameCodec& codec,
                         const std::string_view document) {
  try {
    static_cast<void>(codec.decode(document));
    assert(false && "invalid frame decoded");
  } catch (const std::exception&) {
  }
}

} // namespace

int main() {
  const missionweaveprotocol::FrameCodec codec;
  const auto bytes =
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/websocket-frame.json");
  assert(bytes);
  const auto frame = codec.decode(*bytes);
  const auto encoded = codec.encode(frame);
  assert(encoded == missionweaveprotocol::canonical_json(frame));
  assert(codec.decode(encoded) == frame);

  expect_decode_error(
      codec,
      R"({"protocolVersion":"0.1","protocolVersion":"0.1","frameId":"urn:x:1","frameType":"UNKNOWN"})");
  expect_decode_error(codec,
                      R"({"protocolVersion":"0.1","frameId":"urn:x:1","frameType":"UNKNOWN"})");

  std::string invalid_utf8 = R"({"protocolVersion":"0.1","frameId":"urn:x:1","frameType":")";
  invalid_utf8.push_back(static_cast<char>(0xFF));
  expect_decode_error(codec, invalid_utf8);
}
