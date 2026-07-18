#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/conformance.hpp>
#include <missionweaveprotocol/frame.hpp>
#include <missionweaveprotocol/signed_document.hpp>
#include <missionweaveprotocol/version.hpp>

#include <iostream>
#include <optional>

namespace {

class GoldenResolver final : public missionweaveprotocol::KeyResolver {
public:
  [[nodiscard]] std::optional<missionweaveprotocol::ResolvedKey>
  resolve(const missionweaveprotocol::KeyResolutionRequest& request) const override {
    return missionweaveprotocol::ResolvedKey{
        .key_id = request.key_id,
        .principal = *request.expected_principal,
        .algorithm = "Ed25519",
        .public_key = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        .valid_from = "2026-07-15T08:00:00+08:00",
        .valid_until = "2026-07-16T00:00:00Z",
        .revoked_at = std::nullopt,
    };
  }
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
  if (!command) {
    return 1;
  }
  const auto verified = missionweaveprotocol::SignedDocumentCodec{}.verify(
      missionweaveprotocol::SignedDocumentKind::command, *command, GoldenResolver{});
  if (verified.signing_hash() !=
      "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695") {
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
