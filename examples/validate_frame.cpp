#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/frame.hpp>

#include <exception>
#include <iostream>

int main() {
  try {
    const auto bytes =
        missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/websocket-frame.json");
    if (!bytes) {
      std::cerr << "embedded frame example is missing\n";
      return 1;
    }

    const missionweaveprotocol::FrameCodec codec;
    const auto frame = codec.decode(*bytes);
    const auto canonical = codec.encode(frame);

    std::cout << "validated canonical frame: " << canonical.size() << " bytes\n";
    std::cout << missionweaveprotocol::canonical_sha256(frame) << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "frame example failed: " << error.what() << '\n';
    return 1;
  }
}
