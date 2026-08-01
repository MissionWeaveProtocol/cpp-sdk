#include <missionweaveprotocol/admission.hpp>
#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/conformance.hpp>
#include <missionweaveprotocol/frame.hpp>
#include <missionweaveprotocol/signed_document.hpp>
#include <missionweaveprotocol/version.hpp>

#include <cstdint>
#include <iostream>
#include <string_view>
#include <utility>
#include <vector>

namespace {

class GoldenResolver final : public missionweaveprotocol::KeyResolver,
                             public missionweaveprotocol::AdmissionCurrentKeyResolver {
public:
  explicit GoldenResolver(std::vector<std::uint8_t> registry) : registry_(std::move(registry)) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest&) const override {
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
  }

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve_current(const missionweaveprotocol::KeyResolutionRequest&) const override {
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
  }

private:
  std::vector<std::uint8_t> registry_;
};

class FixedTrustedContext final : public missionweaveprotocol::TrustedAdmissionContext {
public:
  [[nodiscard]] missionweaveprotocol::AdmissionContextValue issue(std::string_view,
                                                                  std::string_view) const override {
    return missionweaveprotocol::AdmissionContextValue{
        .admission_record_id = "urn:missionweaveprotocol:admission-record:crypto-vector-command",
        .trusted_accepted_at = "2026-07-15T00:05:00Z",
        .accepted_by =
            missionweaveprotocol::Principal{
                .type = "service",
                .id = "urn:missionweaveprotocol:service:admission",
            },
    };
  }
};

class PackageAdmissionLog final : public missionweaveprotocol::AdmissionLog {
public:
  explicit PackageAdmissionLog(std::vector<std::uint8_t> committed)
      : committed_(std::move(committed)) {}

  [[nodiscard]] missionweaveprotocol::AdmissionLookup lookup(std::string_view,
                                                             std::string_view) const override {
    return missionweaveprotocol::AdmissionLookup::authoritative_absence();
  }

  [[nodiscard]] missionweaveprotocol::AuthenticatedAdmissionRecord
  append_or_return_existing(std::string_view, std::string_view,
                            missionweaveprotocol::AssetBytes) const override {
    return missionweaveprotocol::AuthenticatedAdmissionRecord{
        committed_, missionweaveprotocol::Principal{
                        .type = "service",
                        .id = "urn:missionweaveprotocol:service:admission",
                    }};
  }

private:
  std::vector<std::uint8_t> committed_;
};

} // namespace

int main() {
  const auto pin = missionweaveprotocol::ProtocolBundle::pin();
  const auto bundle = missionweaveprotocol::ProtocolBundle::verify();
  const auto cryptography = missionweaveprotocol::ProtocolBundle::verify_cryptography();
  const auto admission = missionweaveprotocol::ProtocolBundle::verify_admission();
  if (pin.commit != "f7e70a72c76bbeb5014c186cd820aac2112f0dde" ||
      cryptography.source_commit != "f7e70a72c76bbeb5014c186cd820aac2112f0dde" ||
      cryptography.artifact_digest !=
          "sha256:5eade516e4bc5dcf04477727ebcccd11f33348b2d9135fb6fe0365c6e6cc2ea3" ||
      cryptography.artifact_count != 98 || cryptography.case_count != 22 ||
      cryptography.evaluation_count != 62 ||
      admission.artifact_digest !=
          "sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0" ||
      admission.artifact_count != 19 || admission.case_count != 5 ||
      admission.evaluation_count != 30) {
    return 1;
  }
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
  const auto committed =
      missionweaveprotocol::ProtocolBundle::admission("records/valid/command.json");
  if (!committed) {
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
  const PackageAdmissionLog log(std::vector<std::uint8_t>{committed->begin(), committed->end()});
  const auto admitted = missionweaveprotocol::AdmissionService{}.admit_first(
      missionweaveprotocol::SignedDocumentKind::command, *command, resolver, log,
      FixedTrustedContext{});
  if (admitted.record().signing_hash() != verified.signing_hash()) {
    return 1;
  }
  std::cout << "MissionWeaveProtocol C++ SDK " << missionweaveprotocol::version() << '\n';
  std::cout << bundle.schema_files << " schemas and " << bundle.conformance_files
            << " conformance artifacts verified\n";
  std::cout << conformance.summary() << '\n';
  std::cout << missionweaveprotocol::canonical_sha256(frame) << '\n';
  std::cout << encoded_frame.size() << " canonical frame bytes\n";
  std::cout << verified.signing_hash() << " verified golden Command\n";
  std::cout << admitted.record().signing_hash() << " admitted golden Command\n";
  return conformance.passed() ? 0 : 1;
}
