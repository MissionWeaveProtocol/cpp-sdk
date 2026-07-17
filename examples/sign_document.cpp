#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>
#include <missionweaveprotocol/json.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>

int main() {
  try {
    missionweaveprotocol::Ed25519Seed seed{};
    for (std::size_t index = 0; index < seed.size(); ++index) {
      seed[index] = static_cast<std::uint8_t>(index + 1);
    }

    const auto document = missionweaveprotocol::parse_strict_json(R"({
      "frameId":"urn:missionweaveprotocol:frame:example",
      "frameType":"PING",
      "protocolVersion":"0.1",
      "sentAt":"2026-07-17T00:00:00Z"
    })");
    const auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
    const auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
    if (!missionweaveprotocol::Ed25519::verify_document(public_key, document, signature)) {
      std::cerr << "signature verification failed\n";
      return 1;
    }

    std::cout << "signature: " << signature << '\n';
    std::cout << "content id: " << missionweaveprotocol::canonical_sha256(document) << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "signing example failed: " << error.what() << '\n';
    return 1;
  }
}
