#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/conformance.hpp>
#include <missionweaveprotocol/frame.hpp>
#include <missionweaveprotocol/signed_document.hpp>
#include <missionweaveprotocol/version.hpp>

#include <cstdint>
#include <iostream>
#include <utility>
#include <vector>

namespace {

class GoldenResolver final : public missionweaveprotocol::KeyResolver {
public:
  explicit GoldenResolver(std::vector<std::uint8_t> registry) : registry_(std::move(registry)) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest&) const override {
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
  }

private:
  std::vector<std::uint8_t> registry_;
};

} // namespace

int main() {
  const auto bundle = missionweaveprotocol::ProtocolBundle::verify();
  const auto conformance = missionweaveprotocol::ConformanceRunner{}.run();
  const missionweaveprotocol::FrameCodec codec;
  const auto frame_bytes =
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/websocket-frame.json");
  const auto frame = codec.decode(*frame_bytes);
  const auto encoded_frame = codec.encode(frame);
  const auto command = missionweaveprotocol::ProtocolBundle::cryptography(
      "vectors/signed-documents/valid/command.json");
  const auto registry =
      missionweaveprotocol::ProtocolBundle::cryptography("keys/registry-valid.json");
  if (!command || !registry) {
    return 1;
  }
  const GoldenResolver resolver(std::vector<std::uint8_t>{registry->begin(), registry->end()});
  const auto verified = missionweaveprotocol::SignedDocumentCodec{}.verify(
      missionweaveprotocol::SignedDocumentKind::command, *command, resolver);
  if (verified.signing_hash() !=
      "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695") {
    return 1;
  }
  if (verified.resolved_key().organization_id != "urn:missionweaveprotocol:organization:acme") {
    return 1;
  }
  std::cout << "MissionWeaveProtocol C++ SDK " << missionweaveprotocol::version() << '\n';
  std::cout << bundle.schema_files << " schemas and " << bundle.conformance_files
            << " conformance artifacts verified\n";
  std::cout << conformance.summary() << '\n';
  std::cout << missionweaveprotocol::canonical_sha256(frame) << '\n';
  std::cout << encoded_frame.size() << " canonical frame bytes\n";
  std::cout << verified.signing_hash() << " verified golden Command\n";
  return conformance.passed() ? 0 : 1;
}
