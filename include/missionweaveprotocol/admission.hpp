#pragma once

#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/schema.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace missionweaveprotocol {

enum class AdmissionReason {
  record_missing,
  record_binding_mismatch,
  trusted_time_outside_key_interval,
  malformed_trusted_time,
  record_conflict,
  record_schema_invalid,
  log_authentication_failed,
  append_integrity_not_established,
  log_unavailable,
  log_indeterminate,
  commit_failed,
  event_self_anchoring,
};

[[nodiscard]] std::string_view admission_reason_id(AdmissionReason reason) noexcept;

struct AdmissionDiagnostic {
  std::string_view stage;
  AdmissionReason reason;
};

class AdmissionError final : public std::runtime_error {
public:
  explicit AdmissionError(AdmissionReason reason);

  [[nodiscard]] std::string_view wire_code() const noexcept;
  [[nodiscard]] const AdmissionDiagnostic& diagnostic() const noexcept;

private:
  AdmissionDiagnostic diagnostic_;
};

class AdmissionAdapterError final : public std::runtime_error {
public:
  AdmissionAdapterError(AdmissionReason reason, std::string detail);

  [[nodiscard]] AdmissionReason reason() const noexcept;
  [[nodiscard]] std::string_view detail() const noexcept;

private:
  AdmissionReason reason_;
  std::string detail_;
};

struct AdmissionContextValue {
  std::string admission_record_id;
  std::string trusted_accepted_at;
  Principal accepted_by;
};

class FirstAdmissionRecord final {
public:
  [[nodiscard]] AssetBytes bytes() const noexcept;
  [[nodiscard]] std::string_view protocol_version() const noexcept;
  [[nodiscard]] std::string_view admission_record_id() const noexcept;
  [[nodiscard]] std::string_view organization_id() const noexcept;
  [[nodiscard]] SignedDocumentKind document_kind() const noexcept;
  [[nodiscard]] std::string_view signing_hash() const noexcept;
  [[nodiscard]] std::string_view key_id() const noexcept;
  [[nodiscard]] const Principal& principal() const noexcept;
  [[nodiscard]] std::string_view trusted_accepted_at() const noexcept;
  [[nodiscard]] const ExactInstant& trusted_accepted_instant() const noexcept;
  [[nodiscard]] const Principal& accepted_by() const noexcept;

private:
  FirstAdmissionRecord(std::vector<std::uint8_t> bytes, std::string protocol_version,
                       std::string admission_record_id, std::string organization_id,
                       SignedDocumentKind document_kind, std::string signing_hash,
                       std::string key_id, Principal principal, std::string trusted_accepted_at,
                       ExactInstant trusted_accepted_instant, Principal accepted_by);

  std::vector<std::uint8_t> bytes_;
  std::string protocol_version_;
  std::string admission_record_id_;
  std::string organization_id_;
  SignedDocumentKind document_kind_;
  std::string signing_hash_;
  std::string key_id_;
  Principal principal_;
  std::string trusted_accepted_at_;
  ExactInstant trusted_accepted_instant_;
  Principal accepted_by_;

  friend class AdmissionService;
};

class PreparedFirstAdmission final {
public:
  [[nodiscard]] const VerifiedSignedDocument& verified() const noexcept;
  [[nodiscard]] const FirstAdmissionRecord& record() const noexcept;
  [[nodiscard]] AssetBytes record_bytes() const noexcept;

private:
  PreparedFirstAdmission(VerifiedSignedDocument verified, FirstAdmissionRecord record);

  VerifiedSignedDocument verified_;
  FirstAdmissionRecord record_;

  friend class AdmissionService;
};

class AdmittedSignedDocument final {
public:
  [[nodiscard]] const VerifiedSignedDocument& verified() const noexcept;
  [[nodiscard]] const FirstAdmissionRecord& record() const noexcept;
  [[nodiscard]] AssetBytes record_bytes() const noexcept;

private:
  AdmittedSignedDocument(VerifiedSignedDocument verified, FirstAdmissionRecord record);

  VerifiedSignedDocument verified_;
  FirstAdmissionRecord record_;

  friend class AdmissionService;
};

class AuthenticatedAdmissionRecord final {
public:
  AuthenticatedAdmissionRecord(std::vector<std::uint8_t> record_bytes,
                               Principal authenticated_service);

  [[nodiscard]] AssetBytes record_bytes() const noexcept;
  [[nodiscard]] const Principal& authenticated_service() const noexcept;

private:
  std::vector<std::uint8_t> record_bytes_;
  Principal authenticated_service_;
};

class AdmissionLookup final {
public:
  [[nodiscard]] static AdmissionLookup found(AuthenticatedAdmissionRecord record);
  [[nodiscard]] static AdmissionLookup authoritative_absence();

  [[nodiscard]] bool has_record() const noexcept;
  [[nodiscard]] bool is_authoritative_absence() const noexcept;
  [[nodiscard]] const AuthenticatedAdmissionRecord& record() const;

private:
  explicit AdmissionLookup(std::optional<AuthenticatedAdmissionRecord> record);

  std::optional<AuthenticatedAdmissionRecord> record_;
};

class AdmissionCurrentKeyResolver {
public:
  virtual ~AdmissionCurrentKeyResolver() = default;

  [[nodiscard]] virtual KeyRegistrySnapshot
  resolve_current(const KeyResolutionRequest& request) const = 0;
};

class TrustedAdmissionContext {
public:
  virtual ~TrustedAdmissionContext() = default;

  [[nodiscard]] virtual AdmissionContextValue issue(std::string_view organization_id,
                                                    std::string_view signing_hash) const = 0;
};

class AdmissionLog {
public:
  virtual ~AdmissionLog() = default;

  [[nodiscard]] virtual AdmissionLookup lookup(std::string_view organization_id,
                                               std::string_view signing_hash) const = 0;
  [[nodiscard]] virtual AuthenticatedAdmissionRecord
  append_or_return_existing(std::string_view organization_id, std::string_view signing_hash,
                            AssetBytes candidate_bytes) const = 0;
};

class AdmissionService final {
public:
  AdmissionService();

  [[nodiscard]] PreparedFirstAdmission
  prepare_first_admission(const VerifiedSignedDocument& verified,
                          const TrustedAdmissionContext& trusted_context) const;

  [[nodiscard]] AdmittedSignedDocument
  admit_first(SignedDocumentKind kind, AssetBytes document_bytes,
              const AdmissionCurrentKeyResolver& registry, const AdmissionLog& admission_log,
              const TrustedAdmissionContext& trusted_context) const;

  [[nodiscard]] AdmittedSignedDocument
  verify_historical_admission(SignedDocumentKind kind, AssetBytes document_bytes,
                              const KeyResolver& registry, const AdmissionLog& admission_log) const;

private:
  struct ParsedAdmissionRecord;

  [[nodiscard]] ParsedAdmissionRecord parse_record(AssetBytes bytes) const;
  void validate_bindings(const ParsedAdmissionRecord& parsed,
                         const VerifiedSignedDocument& verified,
                         const Principal& authenticated_service) const;
  [[nodiscard]] AdmittedSignedDocument
  validate_authenticated_record(const AuthenticatedAdmissionRecord& authenticated,
                                const VerifiedSignedDocument& verified) const;

  SchemaCatalog schemas_;
  SignedDocumentCodec codec_;
};

} // namespace missionweaveprotocol
