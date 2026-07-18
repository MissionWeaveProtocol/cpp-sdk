#pragma once

#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/crypto.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/schema.hpp>

#include <compare>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace missionweaveprotocol {

enum class SignedDocumentKind {
  agent_card,
  approval,
  artifact,
  command,
  context_package,
  event,
  evidence,
  extension_profile,
  group_snapshot,
};

[[nodiscard]] std::string_view signed_document_kind_id(SignedDocumentKind kind) noexcept;

struct Principal {
  std::string type;
  std::string id;

  bool operator==(const Principal&) const = default;
};

struct ExactInstant {
  std::int64_t epoch_second;
  std::string fractional_digits;

  [[nodiscard]] std::strong_ordering operator<=>(const ExactInstant& other) const noexcept;
  bool operator==(const ExactInstant&) const = default;
};

struct KeyResolutionRequest {
  SignedDocumentKind kind;
  std::string key_id;
  std::optional<Principal> expected_principal;
  bool service_principal_required;
  std::string protected_time;
  ExactInstant protected_instant;
};

struct ResolvedKey {
  std::string key_id;
  Principal principal;
  std::string algorithm;
  std::string public_key;
  std::string valid_from;
  std::optional<std::string> valid_until;
  std::optional<std::string> revoked_at;

  bool operator==(const ResolvedKey&) const = default;
};

class SigningKey {
public:
  virtual ~SigningKey() = default;
  [[nodiscard]] virtual std::string key_id() const = 0;
  [[nodiscard]] virtual Ed25519Signature sign(AssetBytes signing_bytes) const = 0;
};

class KeyResolver {
public:
  virtual ~KeyResolver() = default;

  // The adapter must fail closed unless it can establish Organization-wide immutable key-ID,
  // public-key/tuple uniqueness, and append-only validity-history invariants.
  [[nodiscard]] virtual std::optional<ResolvedKey>
  resolve(const KeyResolutionRequest& request) const = 0;
};

enum class VerificationStage {
  parse,
  schema,
  signature_envelope,
  key_resolution,
  canonicalization,
  signature,
  complete,
};

[[nodiscard]] std::string_view verification_stage_id(VerificationStage stage) noexcept;
[[nodiscard]] std::string_view verification_wire_code(VerificationStage stage) noexcept;

struct VerificationDiagnostic {
  VerificationStage stage;
  std::string reason;
};

class SignedDocumentVerificationError final : public std::runtime_error {
public:
  explicit SignedDocumentVerificationError(VerificationDiagnostic diagnostic);

  [[nodiscard]] std::string_view wire_code() const noexcept;
  [[nodiscard]] const VerificationDiagnostic& diagnostic() const noexcept;

private:
  VerificationDiagnostic diagnostic_;
};

struct SignatureMaterial {
  std::string algorithm;
  std::string key_id;
  std::string created_at;
  std::string value;
  Ed25519Signature bytes;
};

class VerifiedSignedDocument final {
public:
  VerifiedSignedDocument(SignedDocumentKind kind, Json document,
                         std::vector<std::uint8_t> received_bytes, std::string signing_bytes,
                         std::string signing_hash, std::string canonical_bytes,
                         std::string canonical_hash, std::string protected_time,
                         ExactInstant protected_instant, SignatureMaterial signature,
                         ResolvedKey resolved_key);

  [[nodiscard]] SignedDocumentKind kind() const noexcept;
  [[nodiscard]] const Json& document() const noexcept;
  [[nodiscard]] const std::vector<std::uint8_t>& received_bytes() const noexcept;
  [[nodiscard]] std::string_view signing_bytes() const noexcept;
  [[nodiscard]] std::string_view signing_hash() const noexcept;
  [[nodiscard]] std::string_view canonical_bytes() const noexcept;
  [[nodiscard]] std::string_view canonical_hash() const noexcept;
  [[nodiscard]] std::string_view protected_time() const noexcept;
  [[nodiscard]] const ExactInstant& protected_instant() const noexcept;
  [[nodiscard]] const SignatureMaterial& signature() const noexcept;
  [[nodiscard]] const ResolvedKey& resolved_key() const noexcept;
  [[nodiscard]] const Principal& resolved_principal() const noexcept;

private:
  SignedDocumentKind kind_;
  Json document_;
  std::vector<std::uint8_t> received_bytes_;
  std::string signing_bytes_;
  std::string signing_hash_;
  std::string canonical_bytes_;
  std::string canonical_hash_;
  std::string protected_time_;
  ExactInstant protected_instant_;
  SignatureMaterial signature_;
  ResolvedKey resolved_key_;
};

class SignedDocumentCodec final {
public:
  SignedDocumentCodec();

  [[nodiscard]] Json sign(SignedDocumentKind kind, const Json& unsigned_document,
                          const SigningKey& signing_key) const;
  [[nodiscard]] VerifiedSignedDocument verify(SignedDocumentKind kind, AssetBytes received_bytes,
                                              const KeyResolver& resolver) const;
  [[nodiscard]] VerifiedSignedDocument verify(SignedDocumentKind kind,
                                              std::string_view received_bytes,
                                              const KeyResolver& resolver) const;

private:
  SchemaCatalog schemas_;
};

} // namespace missionweaveprotocol
