#include <missionweaveprotocol/admission.hpp>

#include "signed_document_internal.hpp"

#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace missionweaveprotocol {
namespace {

constexpr std::array adapter_reasons{
    AdmissionReason::record_conflict,
    AdmissionReason::log_authentication_failed,
    AdmissionReason::append_integrity_not_established,
    AdmissionReason::log_unavailable,
    AdmissionReason::log_indeterminate,
    AdmissionReason::commit_failed,
};

[[noreturn]] void fail(const AdmissionReason reason) { throw AdmissionError{reason}; }

[[nodiscard]] std::vector<std::uint8_t> vector_bytes(const AssetBytes bytes) {
  return {bytes.begin(), bytes.end()};
}

[[nodiscard]] AssetBytes bytes_of(const std::string_view value) noexcept {
  return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

[[nodiscard]] std::string required_string(const Json& object, const std::string_view field) {
  if (!object.is_object() || !object.contains(field) || !object.at(field).is_string()) {
    throw std::invalid_argument("First-Admission Record field is not text: " + std::string{field});
  }
  return object.at(field).as<std::string>();
}

[[nodiscard]] Principal principal(const Json& value) {
  return Principal{.type = required_string(value, "type"), .id = required_string(value, "id")};
}

[[nodiscard]] SignedDocumentKind document_kind(const std::string_view id) {
  constexpr std::array kinds{
      SignedDocumentKind::agent_card,      SignedDocumentKind::approval,
      SignedDocumentKind::artifact,        SignedDocumentKind::command,
      SignedDocumentKind::context_package, SignedDocumentKind::event,
      SignedDocumentKind::evidence,        SignedDocumentKind::extension_profile,
      SignedDocumentKind::group_snapshot,
  };
  const auto found = std::ranges::find_if(
      kinds, [id](const SignedDocumentKind kind) { return signed_document_kind_id(kind) == id; });
  if (found == kinds.end()) {
    throw std::invalid_argument("unknown First-Admission Record documentKind");
  }
  return *found;
}

[[nodiscard]] Json principal_json(const Principal& value) {
  Json result(jsoncons::json_object_arg);
  result["type"] = value.type;
  result["id"] = value.id;
  return result;
}

[[noreturn]] void remap_adapter_error(const AdmissionAdapterError& error) { fail(error.reason()); }

class CurrentResolverAdapter final : public KeyResolver {
public:
  explicit CurrentResolverAdapter(const AdmissionCurrentKeyResolver& resolver)
      : resolver_(resolver) {}

  [[nodiscard]] KeyRegistrySnapshot resolve(const KeyResolutionRequest& request) const override {
    return resolver_.resolve_current(request);
  }

private:
  const AdmissionCurrentKeyResolver& resolver_;
};

[[nodiscard]] bool exact_bytes_equal(const AssetBytes left, const AssetBytes right) noexcept {
  return left.size() == right.size() && std::ranges::equal(left, right);
}

[[nodiscard]] bool is_event_self_anchoring(const AssetBytes record_bytes,
                                           const VerifiedSignedDocument& verified) {
  if (verified.kind() != SignedDocumentKind::event) {
    return false;
  }
  if (exact_bytes_equal(record_bytes, verified.received_bytes())) {
    return true;
  }
  try {
    return canonical_json(parse_strict_json(record_bytes)) == verified.canonical_bytes();
  } catch (const std::exception&) {
    return false;
  }
}

} // namespace

std::string_view admission_reason_id(const AdmissionReason reason) noexcept {
  switch (reason) {
  case AdmissionReason::record_missing:
    return "record-missing";
  case AdmissionReason::record_binding_mismatch:
    return "record-binding-mismatch";
  case AdmissionReason::trusted_time_outside_key_interval:
    return "trusted-time-outside-key-interval";
  case AdmissionReason::malformed_trusted_time:
    return "malformed-trusted-time";
  case AdmissionReason::record_conflict:
    return "record-conflict";
  case AdmissionReason::record_schema_invalid:
    return "record-schema-invalid";
  case AdmissionReason::log_authentication_failed:
    return "log-authentication-failed";
  case AdmissionReason::append_integrity_not_established:
    return "append-integrity-not-established";
  case AdmissionReason::log_unavailable:
    return "log-unavailable";
  case AdmissionReason::log_indeterminate:
    return "log-indeterminate";
  case AdmissionReason::commit_failed:
    return "commit-failed";
  case AdmissionReason::event_self_anchoring:
    return "event-self-anchoring";
  }
  return {};
}

AdmissionError::AdmissionError(const AdmissionReason reason)
    : std::runtime_error("Signed Document admission failed: AUTH_INVALID_SIGNATURE"),
      diagnostic_{.stage = "admission", .reason = reason} {}

std::string_view AdmissionError::wire_code() const noexcept { return "AUTH_INVALID_SIGNATURE"; }

const AdmissionDiagnostic& AdmissionError::diagnostic() const noexcept { return diagnostic_; }

AdmissionAdapterError::AdmissionAdapterError(const AdmissionReason reason, std::string detail)
    : std::runtime_error("Admission adapter failed: " + detail), reason_(reason),
      detail_(std::move(detail)) {
  if (std::ranges::find(adapter_reasons, reason) == adapter_reasons.end()) {
    throw std::invalid_argument("Admission adapter error uses a non-adapter reason");
  }
}

AdmissionReason AdmissionAdapterError::reason() const noexcept { return reason_; }

std::string_view AdmissionAdapterError::detail() const noexcept { return detail_; }

FirstAdmissionRecord::FirstAdmissionRecord(
    std::vector<std::uint8_t> bytes, std::string protocol_version, std::string admission_record_id,
    std::string organization_id, const SignedDocumentKind document_kind, std::string signing_hash,
    std::string key_id, Principal principal_value, std::string trusted_accepted_at,
    ExactInstant trusted_accepted_instant, Principal accepted_by)
    : bytes_(std::move(bytes)), protocol_version_(std::move(protocol_version)),
      admission_record_id_(std::move(admission_record_id)),
      organization_id_(std::move(organization_id)), document_kind_(document_kind),
      signing_hash_(std::move(signing_hash)), key_id_(std::move(key_id)),
      principal_(std::move(principal_value)), trusted_accepted_at_(std::move(trusted_accepted_at)),
      trusted_accepted_instant_(std::move(trusted_accepted_instant)),
      accepted_by_(std::move(accepted_by)) {}

AssetBytes FirstAdmissionRecord::bytes() const noexcept { return bytes_; }
std::string_view FirstAdmissionRecord::protocol_version() const noexcept {
  return protocol_version_;
}
std::string_view FirstAdmissionRecord::admission_record_id() const noexcept {
  return admission_record_id_;
}
std::string_view FirstAdmissionRecord::organization_id() const noexcept { return organization_id_; }
SignedDocumentKind FirstAdmissionRecord::document_kind() const noexcept { return document_kind_; }
std::string_view FirstAdmissionRecord::signing_hash() const noexcept { return signing_hash_; }
std::string_view FirstAdmissionRecord::key_id() const noexcept { return key_id_; }
const Principal& FirstAdmissionRecord::principal() const noexcept { return principal_; }
std::string_view FirstAdmissionRecord::trusted_accepted_at() const noexcept {
  return trusted_accepted_at_;
}
const ExactInstant& FirstAdmissionRecord::trusted_accepted_instant() const noexcept {
  return trusted_accepted_instant_;
}
const Principal& FirstAdmissionRecord::accepted_by() const noexcept { return accepted_by_; }

PreparedFirstAdmission::PreparedFirstAdmission(VerifiedSignedDocument verified,
                                               FirstAdmissionRecord record)
    : verified_(std::move(verified)), record_(std::move(record)) {}

const VerifiedSignedDocument& PreparedFirstAdmission::verified() const noexcept {
  return verified_;
}
const FirstAdmissionRecord& PreparedFirstAdmission::record() const noexcept { return record_; }
AssetBytes PreparedFirstAdmission::record_bytes() const noexcept { return record_.bytes(); }

AdmittedSignedDocument::AdmittedSignedDocument(VerifiedSignedDocument verified,
                                               FirstAdmissionRecord record)
    : verified_(std::move(verified)), record_(std::move(record)) {}

const VerifiedSignedDocument& AdmittedSignedDocument::verified() const noexcept {
  return verified_;
}
const FirstAdmissionRecord& AdmittedSignedDocument::record() const noexcept { return record_; }
AssetBytes AdmittedSignedDocument::record_bytes() const noexcept { return record_.bytes(); }

AuthenticatedAdmissionRecord::AuthenticatedAdmissionRecord(std::vector<std::uint8_t> record_bytes,
                                                           Principal authenticated_service)
    : record_bytes_(std::move(record_bytes)),
      authenticated_service_(std::move(authenticated_service)) {
  if (authenticated_service_.type != "service") {
    throw std::invalid_argument("authenticated_service must be a service Principal");
  }
}

AssetBytes AuthenticatedAdmissionRecord::record_bytes() const noexcept { return record_bytes_; }
const Principal& AuthenticatedAdmissionRecord::authenticated_service() const noexcept {
  return authenticated_service_;
}

AdmissionLookup::AdmissionLookup(std::optional<AuthenticatedAdmissionRecord> record)
    : record_(std::move(record)) {}

AdmissionLookup AdmissionLookup::found(AuthenticatedAdmissionRecord record) {
  return AdmissionLookup{std::move(record)};
}

AdmissionLookup AdmissionLookup::authoritative_absence() { return AdmissionLookup{std::nullopt}; }

bool AdmissionLookup::has_record() const noexcept { return record_.has_value(); }
bool AdmissionLookup::is_authoritative_absence() const noexcept { return !record_; }
const AuthenticatedAdmissionRecord& AdmissionLookup::record() const {
  if (!record_) {
    throw std::logic_error("Admission lookup has no record");
  }
  return *record_;
}

struct AdmissionService::ParsedAdmissionRecord {
  FirstAdmissionRecord record;
  ExactInstant trusted_accepted_instant;
};

AdmissionService::AdmissionService() = default;

AdmissionService::ParsedAdmissionRecord
AdmissionService::parse_record(const AssetBytes bytes) const {
  try {
    const auto value = parse_strict_json(bytes);
    const auto validation = schemas_.validate("first-admission-record.schema.json", value);
    if (!validation.valid) {
      fail(AdmissionReason::record_schema_invalid);
    }
    const auto accepted_by = principal(value.at("acceptedBy"));
    if (accepted_by.type != "service") {
      fail(AdmissionReason::record_schema_invalid);
    }
    const auto trusted_accepted_at = required_string(value, "trustedAcceptedAt");
    const auto trusted_accepted_instant = detail::parse_protocol_instant(trusted_accepted_at);
    return ParsedAdmissionRecord{
        .record =
            FirstAdmissionRecord{
                vector_bytes(bytes),
                required_string(value, "protocolVersion"),
                required_string(value, "admissionRecordId"),
                required_string(value, "organizationId"),
                document_kind(required_string(value, "documentKind")),
                required_string(value, "signingHash"),
                required_string(value, "keyId"),
                principal(value.at("principal")),
                trusted_accepted_at,
                trusted_accepted_instant,
                accepted_by,
            },
        .trusted_accepted_instant = trusted_accepted_instant,
    };
  } catch (const AdmissionError&) {
    throw;
  } catch (const std::exception&) {
    fail(AdmissionReason::record_schema_invalid);
  }
}

void AdmissionService::validate_bindings(const ParsedAdmissionRecord& parsed,
                                         const VerifiedSignedDocument& verified,
                                         const Principal& authenticated_service) const {
  const auto& record = parsed.record;
  const auto& resolved = verified.resolved_key();
  if (record.organization_id() != resolved.organization_id ||
      record.document_kind() != verified.kind() ||
      record.signing_hash() != verified.signing_hash() || record.key_id() != resolved.key_id ||
      record.principal() != resolved.principal) {
    fail(AdmissionReason::record_binding_mismatch);
  }
  if (record.accepted_by() != authenticated_service) {
    fail(AdmissionReason::log_authentication_failed);
  }
  const auto& accepted = parsed.trusted_accepted_instant;
  if (accepted < resolved.valid_from_instant ||
      (resolved.valid_until_instant && accepted >= *resolved.valid_until_instant) ||
      (resolved.revoked_at_instant && accepted >= *resolved.revoked_at_instant)) {
    fail(AdmissionReason::trusted_time_outside_key_interval);
  }
}

PreparedFirstAdmission
AdmissionService::prepare_first_admission(const VerifiedSignedDocument& verified,
                                          const TrustedAdmissionContext& trusted_context) const {
  AdmissionContextValue context;
  try {
    context =
        trusted_context.issue(verified.resolved_key().organization_id, verified.signing_hash());
  } catch (const AdmissionAdapterError& error) {
    remap_adapter_error(error);
  }

  ExactInstant accepted{};
  try {
    accepted = detail::parse_protocol_instant(context.trusted_accepted_at);
  } catch (const std::exception&) {
    fail(AdmissionReason::malformed_trusted_time);
  }
  const auto& resolved = verified.resolved_key();
  if (accepted < resolved.valid_from_instant ||
      (resolved.valid_until_instant && accepted >= *resolved.valid_until_instant) ||
      (resolved.revoked_at_instant && accepted >= *resolved.revoked_at_instant)) {
    fail(AdmissionReason::trusted_time_outside_key_interval);
  }

  Json value(jsoncons::json_object_arg);
  value["protocolVersion"] = "0.1";
  value["admissionRecordId"] = context.admission_record_id;
  value["organizationId"] = resolved.organization_id;
  value["documentKind"] = signed_document_kind_id(verified.kind());
  value["signingHash"] = verified.signing_hash();
  value["keyId"] = resolved.key_id;
  value["principal"] = principal_json(resolved.principal);
  value["trustedAcceptedAt"] = context.trusted_accepted_at;
  value["acceptedBy"] = principal_json(context.accepted_by);

  std::string canonical;
  try {
    canonical = canonical_json(value);
  } catch (const std::exception&) {
    fail(AdmissionReason::record_schema_invalid);
  }
  auto parsed = parse_record(bytes_of(canonical));
  validate_bindings(parsed, verified, context.accepted_by);
  if (parsed.trusted_accepted_instant != accepted) {
    fail(AdmissionReason::record_schema_invalid);
  }
  return PreparedFirstAdmission{verified, std::move(parsed.record)};
}

AdmittedSignedDocument
AdmissionService::validate_authenticated_record(const AuthenticatedAdmissionRecord& authenticated,
                                                const VerifiedSignedDocument& verified) const {
  if (is_event_self_anchoring(authenticated.record_bytes(), verified)) {
    fail(AdmissionReason::event_self_anchoring);
  }
  auto parsed = parse_record(authenticated.record_bytes());
  validate_bindings(parsed, verified, authenticated.authenticated_service());
  return AdmittedSignedDocument{verified, std::move(parsed.record)};
}

AdmittedSignedDocument
AdmissionService::admit_first(const SignedDocumentKind kind, const AssetBytes document_bytes,
                              const AdmissionCurrentKeyResolver& registry,
                              const AdmissionLog& admission_log,
                              const TrustedAdmissionContext& trusted_context) const {
  const auto verified = codec_.verify(kind, document_bytes, CurrentResolverAdapter{registry});
  AdmissionLookup lookup = AdmissionLookup::authoritative_absence();
  try {
    lookup = admission_log.lookup(verified.resolved_key().organization_id, verified.signing_hash());
  } catch (const AdmissionAdapterError& error) {
    remap_adapter_error(error);
  }
  if (lookup.has_record()) {
    return validate_authenticated_record(lookup.record(), verified);
  }
  if (!lookup.is_authoritative_absence()) {
    fail(AdmissionReason::log_indeterminate);
  }

  const auto prepared = prepare_first_admission(verified, trusted_context);
  try {
    const auto committed = admission_log.append_or_return_existing(
        verified.resolved_key().organization_id, verified.signing_hash(), prepared.record_bytes());
    return validate_authenticated_record(committed, verified);
  } catch (const AdmissionAdapterError& error) {
    remap_adapter_error(error);
  }
}

AdmittedSignedDocument AdmissionService::verify_historical_admission(
    const SignedDocumentKind kind, const AssetBytes document_bytes, const KeyResolver& registry,
    const AdmissionLog& admission_log) const {
  const auto verified = codec_.verify(kind, document_bytes, registry);
  AdmissionLookup lookup = AdmissionLookup::authoritative_absence();
  try {
    lookup = admission_log.lookup(verified.resolved_key().organization_id, verified.signing_hash());
  } catch (const AdmissionAdapterError& error) {
    remap_adapter_error(error);
  }
  if (lookup.has_record()) {
    return validate_authenticated_record(lookup.record(), verified);
  }
  if (lookup.is_authoritative_absence()) {
    fail(AdmissionReason::record_missing);
  }
  fail(AdmissionReason::log_indeterminate);
}

} // namespace missionweaveprotocol
