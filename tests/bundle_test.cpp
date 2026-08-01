#include <missionweaveprotocol/bundle.hpp>

#include "bundle_internal.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  assert(input);
  return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

void assert_pin_rejected(std::string pin) {
  const std::vector<std::uint8_t> bytes{pin.begin(), pin.end()};
  bool rejected = false;
  try {
    static_cast<void>(missionweaveprotocol::detail::parse_protocol_pin(bytes));
  } catch (const missionweaveprotocol::BundleError&) {
    rejected = true;
  }
  assert(rejected);
}

} // namespace

int main() {
  using namespace std::string_view_literals;

  const auto pin = missionweaveprotocol::ProtocolBundle::pin();
  assert(pin.commit == "f7e70a72c76bbeb5014c186cd820aac2112f0dde"sv);
  assert(pin.protocol_version == "0.1"sv);
  assert(pin.wire_namespace == "missionweaveprotocol"sv);
  assert(pin.cryptography.source_commit == "f7e70a72c76bbeb5014c186cd820aac2112f0dde"sv);
  assert(pin.cryptography.profile_id == "missionweaveprotocol.signed-document-verification.v0.1"sv);
  assert(pin.cryptography.artifact_count == 98);
  assert(pin.cryptography.case_count == 22);
  assert(pin.cryptography.evaluation_count == 62);
  assert(pin.admission.source_commit == "f7e70a72c76bbeb5014c186cd820aac2112f0dde"sv);
  assert(pin.admission.profile_id ==
         "missionweaveprotocol.first-admission-historical-trust.v0.1"sv);
  assert(pin.admission.cryptography_artifact_digest == pin.cryptography.artifact_digest);
  assert(pin.admission.artifact_count == 19);
  assert(pin.admission.case_count == 5);
  assert(pin.admission.evaluation_count == 30);

  const auto summary = missionweaveprotocol::ProtocolBundle::verify();
  assert(summary.schema_files == 22);
  assert(summary.conformance_files == 59);
  assert(summary.bundle_sha256 ==
         "c95fc8f8334947dacf51a2c6e84d9b13f5b39b7d3827591569a1e2c5acfe47d7");

  const auto names = missionweaveprotocol::ProtocolBundle::schema_names();
  assert(names.size() == 22);
  assert(std::ranges::is_sorted(names));
  assert(std::ranges::find(names, "first-admission-record.schema.json"sv) != names.end());
  assert(std::ranges::find(names, "mission.schema.json"sv) != names.end());

  assert(missionweaveprotocol::ProtocolBundle::schema("mission.schema.json").has_value());
  assert(!missionweaveprotocol::ProtocolBundle::schema("missing.schema.json").has_value());
  assert(missionweaveprotocol::ProtocolBundle::conformance("manifest.json").has_value());
  assert(
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/mission.json").has_value());
  assert(missionweaveprotocol::ProtocolBundle::cryptography("manifest.json").has_value());
  assert(missionweaveprotocol::ProtocolBundle::cryptography(
             "vectors/signed-documents/invalid/command-invalid-utf8.bin")
             .has_value());
  assert(!missionweaveprotocol::ProtocolBundle::cryptography("missing.json").has_value());
  assert(missionweaveprotocol::ProtocolBundle::admission("manifest.json").has_value());
  assert(missionweaveprotocol::ProtocolBundle::admission("records/valid/command.json").has_value());
  assert(!missionweaveprotocol::ProtocolBundle::admission("missing.json").has_value());

  const auto cryptography = missionweaveprotocol::ProtocolBundle::verify_cryptography();
  assert(cryptography.source_commit == "f7e70a72c76bbeb5014c186cd820aac2112f0dde");
  assert(cryptography.profile_id == "missionweaveprotocol.signed-document-verification.v0.1");
  assert(cryptography.manifest_version == 1);
  assert(cryptography.artifact_digest ==
         "sha256:5eade516e4bc5dcf04477727ebcccd11f33348b2d9135fb6fe0365c6e6cc2ea3");
  assert(cryptography.artifact_count == 98);
  assert(cryptography.case_count == 22);
  assert(cryptography.evaluation_count == 62);

  const auto admission = missionweaveprotocol::ProtocolBundle::verify_admission();
  assert(admission.source_commit == "f7e70a72c76bbeb5014c186cd820aac2112f0dde");
  assert(admission.profile_id == "missionweaveprotocol.first-admission-historical-trust.v0.1");
  assert(admission.manifest_version == 1);
  assert(admission.cryptography_artifact_digest == cryptography.artifact_digest);
  assert(admission.artifact_digest ==
         "sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0");
  assert(admission.artifact_count == 19);
  assert(admission.case_count == 5);
  assert(admission.evaluation_count == 30);

  const auto source_pin =
      read_file(std::filesystem::path{MISSIONWEAVEPROTOCOL_SOURCE_DIR} / "PROTOCOL_PIN.json");
  const auto embedded_pin = missionweaveprotocol::ProtocolBundle::protocol_pin_bytes();
  assert(std::ranges::equal(source_pin, embedded_pin));

  const auto packaged_pin =
      std::string{reinterpret_cast<const char*>(embedded_pin.data()), embedded_pin.size()};
  auto drifted_pin = packaged_pin;
  const auto count = drifted_pin.find("\"caseCount\": 22");
  assert(count != std::string::npos);
  drifted_pin.replace(count, std::string_view{"\"caseCount\": 22"}.size(), "\"caseCount\": 23");
  assert_pin_rejected(std::move(drifted_pin));

  auto duplicate_pin = packaged_pin;
  const auto duplicate = duplicate_pin.find("\"caseCount\": 22,");
  assert(duplicate != std::string::npos);
  duplicate_pin.replace(duplicate, std::string_view{"\"caseCount\": 22,"}.size(),
                        "\"caseCount\": 22,\n    \"\\u0063aseCount\": 22,");
  assert_pin_rejected(std::move(duplicate_pin));

  auto unknown_field_pin = packaged_pin;
  const auto evaluation_count = unknown_field_pin.find("\"evaluationCount\": 62");
  assert(evaluation_count != std::string::npos);
  unknown_field_pin.replace(evaluation_count, std::string_view{"\"evaluationCount\": 62"}.size(),
                            "\"evaluationCount\": 62,\n    \"unexpected\": true");
  assert_pin_rejected(std::move(unknown_field_pin));

  const auto source_root = std::filesystem::path{MISSIONWEAVEPROTOCOL_SOURCE_DIR};
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator{source_root / "cryptography"}) {
    if (!entry.is_regular_file()) {
      continue;
    }
    const auto relative = std::filesystem::relative(entry.path(), source_root).generic_string();
    const auto embedded = missionweaveprotocol::ProtocolBundle::cryptography(
        relative.substr(std::string{"cryptography/"}.size()));
    assert(embedded.has_value());
    assert(std::ranges::equal(read_file(entry.path()), *embedded));
  }
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator{source_root / "admission"}) {
    if (!entry.is_regular_file()) {
      continue;
    }
    const auto relative = std::filesystem::relative(entry.path(), source_root).generic_string();
    const auto embedded = missionweaveprotocol::ProtocolBundle::admission(
        relative.substr(std::string{"admission/"}.size()));
    assert(embedded.has_value());
    assert(std::ranges::equal(read_file(entry.path()), *embedded));
  }
}
