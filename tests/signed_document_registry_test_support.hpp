#pragma once

#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace signed_document_registry_test_support {

inline constexpr std::string_view selected_key_id =
    "urn:missionweaveprotocol:key:crypto-vector-rfc8032-1";
inline constexpr std::string_view selected_principal_id =
    "urn:missionweaveprotocol:agent:crypto-vector-coordinator";
inline constexpr std::string_view unknown_key_id =
    "urn:missionweaveprotocol:key:crypto-vector-missing";

[[nodiscard]] inline std::vector<std::uint8_t> packaged_asset(const std::string_view path) {
  const auto bytes = missionweaveprotocol::ProtocolBundle::cryptography(path);
  if (!bytes) {
    throw std::runtime_error("missing packaged cryptography asset: " + std::string{path});
  }
  return {bytes->begin(), bytes->end()};
}

[[nodiscard]] inline std::vector<std::uint8_t> golden_command_bytes() {
  return packaged_asset("vectors/signed-documents/valid/command.json");
}

[[nodiscard]] inline missionweaveprotocol::Json golden_command_json() {
  const auto bytes = golden_command_bytes();
  return missionweaveprotocol::parse_strict_json(
      missionweaveprotocol::AssetBytes{bytes.data(), bytes.size()});
}

[[nodiscard]] inline std::vector<std::uint8_t>
encode_json_bytes(const missionweaveprotocol::Json& value) {
  const auto text = value.to_string();
  return {text.begin(), text.end()};
}

[[nodiscard]] inline std::vector<std::uint8_t> unknown_key_command_bytes() {
  return packaged_asset("vectors/signed-documents/invalid/command-unknown-key.json");
}

[[nodiscard]] inline std::vector<std::uint8_t> valid_registry_bytes() {
  return packaged_asset("keys/registry-valid.json");
}

[[nodiscard]] inline missionweaveprotocol::Json valid_registry_json() {
  const auto bytes = valid_registry_bytes();
  return missionweaveprotocol::parse_strict_json(
      missionweaveprotocol::AssetBytes{bytes.data(), bytes.size()});
}

[[nodiscard]] inline missionweaveprotocol::Json& binding(missionweaveprotocol::Json& registry,
                                                         const std::size_t index) {
  return registry.at("bindings").at(index);
}

[[nodiscard]] inline missionweaveprotocol::Json& principal(missionweaveprotocol::Json& registry,
                                                           const std::size_t binding_index) {
  return binding(registry, binding_index).at("principal");
}

[[nodiscard]] inline missionweaveprotocol::Json& history(missionweaveprotocol::Json& registry,
                                                         const std::size_t binding_index) {
  return binding(registry, binding_index).at("validityHistory");
}

[[nodiscard]] inline missionweaveprotocol::Json&
history_status(missionweaveprotocol::Json& registry, const std::size_t binding_index,
               const std::size_t status_index) {
  return history(registry, binding_index).at(status_index);
}

class SnapshotResolver final : public missionweaveprotocol::KeyResolver {
public:
  explicit SnapshotResolver(std::vector<std::uint8_t> registry,
                            const missionweaveprotocol::KeyRegistryCompleteness completeness =
                                missionweaveprotocol::KeyRegistryCompleteness::organization_wide)
      : registry_(std::move(registry)), completeness_(completeness) {}

  explicit SnapshotResolver(std::string failure_reason)
      : failure_reason_(std::move(failure_reason)) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest& request) const override {
    ++calls;
    last_request = request;
    if (failure_reason_) {
      throw std::runtime_error(*failure_reason_);
    }
    return missionweaveprotocol::KeyRegistrySnapshot(registry_, completeness_);
  }

  mutable std::size_t calls = 0;
  mutable std::optional<missionweaveprotocol::KeyResolutionRequest> last_request;

private:
  std::vector<std::uint8_t> registry_;
  missionweaveprotocol::KeyRegistryCompleteness completeness_ =
      missionweaveprotocol::KeyRegistryCompleteness::unspecified;
  std::optional<std::string> failure_reason_;
};

[[nodiscard]] inline missionweaveprotocol::VerifiedSignedDocument
verify_accepts(const std::vector<std::uint8_t>& registry_bytes) {
  const missionweaveprotocol::SignedDocumentCodec codec;
  const auto command = golden_command_bytes();
  const SnapshotResolver resolver(registry_bytes);
  auto verified =
      codec.verify(missionweaveprotocol::SignedDocumentKind::command,
                   missionweaveprotocol::AssetBytes{command.data(), command.size()}, resolver);
  assert(resolver.calls == 1);
  assert(resolver.last_request.has_value());
  assert(resolver.last_request->key_id == selected_key_id);
  assert(verified.resolved_key().key_id == selected_key_id);
  assert(verified.resolved_principal().id == selected_principal_id);
  return verified;
}

[[nodiscard]] inline missionweaveprotocol::VerifiedSignedDocument
verify_accepts(const missionweaveprotocol::Json& registry) {
  return verify_accepts(encode_json_bytes(registry));
}

[[nodiscard]] inline missionweaveprotocol::VerificationDiagnostic expect_key_resolution_failure(
    const missionweaveprotocol::KeyResolver& resolver,
    const std::vector<std::uint8_t>& command_bytes,
    const std::optional<std::string_view> expected_reason = std::nullopt) {
  const missionweaveprotocol::SignedDocumentCodec codec;
  try {
    static_cast<void>(codec.verify(
        missionweaveprotocol::SignedDocumentKind::command,
        missionweaveprotocol::AssetBytes{command_bytes.data(), command_bytes.size()}, resolver));
    assert(false && "Registry evidence was unexpectedly accepted");
  } catch (const missionweaveprotocol::SignedDocumentVerificationError& error) {
    assert(error.diagnostic().stage == missionweaveprotocol::VerificationStage::key_resolution);
    assert(error.wire_code() == "AUTH_INVALID_SIGNATURE");
    assert(std::string_view{error.what()} ==
           "Signed Document verification failed: AUTH_INVALID_SIGNATURE");
    if (expected_reason) {
      assert(error.diagnostic().reason == *expected_reason);
    }
    return error.diagnostic();
  }
  throw std::logic_error("unreachable Registry verification test path");
}

[[nodiscard]] inline missionweaveprotocol::VerificationDiagnostic
expect_registry_rejected(const std::vector<std::uint8_t>& registry_bytes,
                         const missionweaveprotocol::KeyRegistryCompleteness completeness =
                             missionweaveprotocol::KeyRegistryCompleteness::organization_wide,
                         const std::optional<std::string_view> expected_reason = std::nullopt) {
  const SnapshotResolver resolver(registry_bytes, completeness);
  const auto diagnostic =
      expect_key_resolution_failure(resolver, golden_command_bytes(), expected_reason);
  assert(resolver.calls == 1);
  return diagnostic;
}

[[nodiscard]] inline missionweaveprotocol::VerificationDiagnostic
expect_registry_rejected(const missionweaveprotocol::Json& registry) {
  return expect_registry_rejected(encode_json_bytes(registry));
}

} // namespace signed_document_registry_test_support
