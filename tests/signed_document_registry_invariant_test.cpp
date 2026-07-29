#include "signed_document_registry_test_support.hpp"

#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace support = signed_document_registry_test_support;

constexpr std::size_t selected_binding_index = 0;
constexpr std::size_t unselected_binding_index = 1;

[[nodiscard]] missionweaveprotocol::Json registry_fixture(const std::string_view path) {
  const auto bytes = support::packaged_asset(path);
  return missionweaveprotocol::parse_strict_json(
      missionweaveprotocol::AssetBytes{bytes.data(), bytes.size()});
}

[[nodiscard]] std::string fixture_public_key(const std::string_view path) {
  const auto fixture = registry_fixture(path);
  for (const auto& binding : fixture.at("bindings").array_range()) {
    if (binding.at("keyId").as<std::string>() == support::selected_key_id) {
      return binding.at("publicKey").as<std::string>();
    }
  }
  throw std::logic_error("fixture does not contain the selected key ID: " + std::string{path});
}

void assert_reason(const missionweaveprotocol::VerificationDiagnostic& diagnostic,
                   const std::string_view expected) {
  if (std::string_view{diagnostic.reason} != expected) {
    std::cerr << "expected diagnostic: " << expected << '\n'
              << "actual diagnostic:   " << diagnostic.reason << '\n';
  }
  assert(std::string_view{diagnostic.reason} == expected);
}

void assert_reason_starts_with(const missionweaveprotocol::VerificationDiagnostic& diagnostic,
                               const std::string_view expected,
                               const std::string_view fixture_path) {
  if (!std::string_view{diagnostic.reason}.starts_with(expected)) {
    std::cerr << "fixture:                    " << fixture_path << '\n'
              << "expected diagnostic prefix: " << expected << '\n'
              << "actual diagnostic:          " << diagnostic.reason << '\n';
  }
  assert(std::string_view{diagnostic.reason}.starts_with(expected));
}

[[nodiscard]] missionweaveprotocol::VerificationDiagnostic
expect_unknown_command_rejected(const missionweaveprotocol::Json& registry) {
  const support::SnapshotResolver resolver(support::encode_json_bytes(registry));
  const auto diagnostic =
      support::expect_key_resolution_failure(resolver, support::unknown_key_command_bytes());
  assert(resolver.calls == 1);
  return diagnostic;
}

void test_invalid_public_keys_in_unselected_bindings_fail_before_selection() {
  constexpr auto fixtures = std::array{
      std::string_view{"keys/registry-public-key-noncanonical.json"},
      std::string_view{"keys/registry-public-key-off-curve.json"},
      std::string_view{"keys/registry-public-key-identity.json"},
      std::string_view{"keys/registry-public-key-small-order.json"},
      std::string_view{"keys/registry-public-key-mixed-order.json"},
      std::string_view{"keys/registry-public-key-wrong-length.json"},
      std::string_view{"keys/registry-public-key-padded.json"},
      std::string_view{"keys/registry-public-key-negative-zero.json"},
      std::string_view{"keys/registry-public-key-y-equals-p.json"},
      std::string_view{"keys/registry-public-key-nonzero-unused-pad-bits.json"},
  };

  for (const auto fixture : fixtures) {
    auto registry = support::valid_registry_json();
    assert(support::binding(registry, selected_binding_index).at("keyId").as<std::string>() ==
           support::selected_key_id);
    assert(support::binding(registry, unselected_binding_index).at("keyId").as<std::string>() !=
           support::selected_key_id);
    support::binding(registry, unselected_binding_index)["publicKey"] = fixture_public_key(fixture);

    const auto diagnostic = support::expect_registry_rejected(registry);
    assert_reason_starts_with(diagnostic, "resolved public key", fixture);
  }
}

void test_repeated_unselected_key_id_cannot_change_immutable_binding() {
  auto registry = support::valid_registry_json();
  auto rebound = support::binding(registry, unselected_binding_index);
  rebound["principal"]["id"] = "urn:missionweaveprotocol:agent:developer-two";
  registry.at("bindings").push_back(std::move(rebound));

  assert_reason(support::expect_registry_rejected(registry),
                "Registry reuses a key ID for another immutable binding");
}

void test_public_key_cannot_cross_principals() {
  const auto diagnostic = support::expect_registry_rejected(
      support::packaged_asset("keys/registry-public-key-cross-principal-reuse.json"));
  assert_reason(diagnostic, "Registry reuses a public key");
}

void test_public_key_tuple_alias_has_the_specific_diagnostic() {
  const auto diagnostic =
      support::expect_registry_rejected(support::packaged_asset("keys/registry-key-alias.json"));
  assert_reason(diagnostic, "Registry contains a key-ID alias");
}

void test_identical_repeated_declarations_are_accepted() {
  auto registry = support::valid_registry_json();
  registry.at("bindings").push_back(support::binding(registry, unselected_binding_index));
  static_cast<void>(support::verify_accepts(registry));
}

void test_invalid_final_binding_precedes_unknown_key() {
  auto registry = support::valid_registry_json();
  auto invalid = support::binding(registry, unselected_binding_index);
  invalid["keyId"] = "urn:missionweaveprotocol:key:invalid-final-binding";
  invalid["principal"]["id"] = "urn:missionweaveprotocol:agent:invalid-final-binding";
  invalid["publicKey"] = fixture_public_key("keys/registry-public-key-wrong-length.json");
  registry.at("bindings").push_back(std::move(invalid));

  assert_reason(expect_unknown_command_rejected(registry),
                "resolved public key does not decode to 32 bytes");
}

void test_unknown_key_is_reported_after_a_valid_complete_scan() {
  assert_reason(expect_unknown_command_rejected(support::valid_registry_json()),
                "signature.keyId is unknown");
}

void test_sixty_five_bindings_are_accepted() {
  auto registry = support::valid_registry_json();
  const auto repeated = support::binding(registry, unselected_binding_index);
  while (registry.at("bindings").size() < 65) {
    registry.at("bindings").push_back(repeated);
  }
  assert(registry.at("bindings").size() == 65);
  static_cast<void>(support::verify_accepts(registry));
}

class MutatingSourceResolver final : public missionweaveprotocol::KeyResolver {
public:
  explicit MutatingSourceResolver(std::vector<std::uint8_t> source) : source_(std::move(source)) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest&) const override {
    ++calls;
    auto snapshot = missionweaveprotocol::KeyRegistrySnapshot::organization_wide(source_);
    source_.assign(1, static_cast<std::uint8_t>('{'));
    source_mutated = true;
    return snapshot;
  }

  mutable std::size_t calls = 0;
  mutable bool source_mutated = false;

private:
  mutable std::vector<std::uint8_t> source_;
};

void test_snapshot_owns_verification_evidence_bytes() {
  const missionweaveprotocol::SignedDocumentCodec codec;
  const auto command = support::golden_command_bytes();
  const MutatingSourceResolver resolver(support::valid_registry_bytes());

  const auto verified =
      codec.verify(missionweaveprotocol::SignedDocumentKind::command,
                   missionweaveprotocol::AssetBytes{command.data(), command.size()}, resolver);

  assert(resolver.calls == 1);
  assert(resolver.source_mutated);
  assert(verified.resolved_key().organization_id == "urn:missionweaveprotocol:organization:acme");
  assert(verified.resolved_key().key_id == support::selected_key_id);
}

} // namespace

int main() {
  test_invalid_public_keys_in_unselected_bindings_fail_before_selection();
  test_repeated_unselected_key_id_cannot_change_immutable_binding();
  test_public_key_cannot_cross_principals();
  test_public_key_tuple_alias_has_the_specific_diagnostic();
  test_identical_repeated_declarations_are_accepted();
  test_invalid_final_binding_precedes_unknown_key();
  test_unknown_key_is_reported_after_a_valid_complete_scan();
  test_sixty_five_bindings_are_accepted();
  test_snapshot_owns_verification_evidence_bytes();
}
