#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/conformance.hpp>
#include <missionweaveprotocol/frame.hpp>
#include <missionweaveprotocol/version.hpp>

#include <iostream>

int main() {
  const auto bundle = missionweaveprotocol::ProtocolBundle::verify();
  const auto conformance = missionweaveprotocol::ConformanceRunner{}.run();
  const missionweaveprotocol::FrameCodec codec;
  const auto frame_bytes =
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/websocket-frame.json");
  const auto frame = codec.decode(*frame_bytes);
  const auto encoded_frame = codec.encode(frame);
  std::cout << "MissionWeaveProtocol C++ SDK " << missionweaveprotocol::version() << '\n';
  std::cout << bundle.schema_files << " schemas and " << bundle.conformance_files
            << " conformance artifacts verified\n";
  std::cout << conformance.summary() << '\n';
  std::cout << missionweaveprotocol::canonical_sha256(frame) << '\n';
  std::cout << encoded_frame.size() << " canonical frame bytes\n";
  return conformance.passed() ? 0 : 1;
}
