#include <missionweaveprotocol/admission.hpp>
#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/json.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::string required_text(const missionweaveprotocol::Json& object, const std::string_view field) {
  if (!object.is_object() || !object.contains(field) || !object.at(field).is_string()) {
    throw std::invalid_argument("manifest field is not text: " + std::string{field});
  }
  return object.at(field).as<std::string>();
}

std::vector<std::uint8_t> asset(const std::string_view path) {
  std::optional<missionweaveprotocol::AssetBytes> bytes;
  if (path.starts_with("admission/")) {
    bytes = missionweaveprotocol::ProtocolBundle::admission(path.substr(10));
  } else if (path.starts_with("cryptography/")) {
    bytes = missionweaveprotocol::ProtocolBundle::cryptography(path.substr(13));
  } else if (path.starts_with("schemas/")) {
    bytes = missionweaveprotocol::ProtocolBundle::schema(path.substr(8));
  }
  if (!bytes) {
    throw std::runtime_error("missing embedded asset: " + std::string{path});
  }
  return {bytes->begin(), bytes->end()};
}

missionweaveprotocol::Json asset_json(const std::string_view path) {
  return missionweaveprotocol::parse_strict_json(asset(path));
}

std::vector<std::uint8_t> canonical_bytes(const std::vector<std::uint8_t>& bytes) {
  const auto canonical =
      missionweaveprotocol::canonical_json(missionweaveprotocol::parse_strict_json(bytes));
  return {canonical.begin(), canonical.end()};
}

missionweaveprotocol::SignedDocumentKind signed_document_kind(const std::string_view id) {
  constexpr std::array kinds{
      missionweaveprotocol::SignedDocumentKind::agent_card,
      missionweaveprotocol::SignedDocumentKind::approval,
      missionweaveprotocol::SignedDocumentKind::artifact,
      missionweaveprotocol::SignedDocumentKind::command,
      missionweaveprotocol::SignedDocumentKind::context_package,
      missionweaveprotocol::SignedDocumentKind::event,
      missionweaveprotocol::SignedDocumentKind::evidence,
      missionweaveprotocol::SignedDocumentKind::extension_profile,
      missionweaveprotocol::SignedDocumentKind::group_snapshot,
  };
  const auto found = std::ranges::find_if(kinds, [id](const auto kind) {
    return missionweaveprotocol::signed_document_kind_id(kind) == id;
  });
  if (found == kinds.end()) {
    throw std::invalid_argument("unknown Signed Document kind: " + std::string{id});
  }
  return *found;
}

missionweaveprotocol::AdmissionReason admission_reason(const std::string_view id) {
  constexpr std::array reasons{
      missionweaveprotocol::AdmissionReason::record_missing,
      missionweaveprotocol::AdmissionReason::record_binding_mismatch,
      missionweaveprotocol::AdmissionReason::trusted_time_outside_key_interval,
      missionweaveprotocol::AdmissionReason::malformed_trusted_time,
      missionweaveprotocol::AdmissionReason::record_conflict,
      missionweaveprotocol::AdmissionReason::record_schema_invalid,
      missionweaveprotocol::AdmissionReason::log_authentication_failed,
      missionweaveprotocol::AdmissionReason::append_integrity_not_established,
      missionweaveprotocol::AdmissionReason::log_unavailable,
      missionweaveprotocol::AdmissionReason::log_indeterminate,
      missionweaveprotocol::AdmissionReason::commit_failed,
      missionweaveprotocol::AdmissionReason::event_self_anchoring,
  };
  const auto found = std::ranges::find_if(reasons, [id](const auto reason) {
    return missionweaveprotocol::admission_reason_id(reason) == id;
  });
  if (found == reasons.end()) {
    throw std::invalid_argument("unknown Admission reason: " + std::string{id});
  }
  return *found;
}

missionweaveprotocol::Principal principal(const missionweaveprotocol::Json& value) {
  return missionweaveprotocol::Principal{.type = required_text(value, "type"),
                                         .id = required_text(value, "id")};
}

class ManifestRegistry final : public missionweaveprotocol::KeyResolver,
                               public missionweaveprotocol::AdmissionCurrentKeyResolver {
public:
  ManifestRegistry(std::vector<std::uint8_t> registry, std::vector<std::string>& calls)
      : registry_(std::move(registry)), calls_(calls) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest&) const override {
    calls_.emplace_back("resolve");
    return snapshot();
  }

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve_current(const missionweaveprotocol::KeyResolutionRequest&) const override {
    calls_.emplace_back("resolve_current");
    return snapshot();
  }

private:
  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot snapshot() const {
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
  }

  std::vector<std::uint8_t> registry_;
  std::vector<std::string>& calls_;
};

class ManifestTrustedContext final : public missionweaveprotocol::TrustedAdmissionContext {
public:
  ManifestTrustedContext(missionweaveprotocol::Json trusted_context,
                         std::vector<std::string>& calls)
      : trusted_context_(std::move(trusted_context)), calls_(calls) {}

  [[nodiscard]] missionweaveprotocol::AdmissionContextValue
  issue(const std::string_view organization_id,
        const std::string_view signing_hash) const override {
    calls_.emplace_back("issue");
    organization_id_ = organization_id;
    signing_hash_ = signing_hash;
    if (trusted_context_.is_null()) {
      throw missionweaveprotocol::AdmissionAdapterError{
          missionweaveprotocol::AdmissionReason::commit_failed, "trusted context was not declared"};
    }
    return missionweaveprotocol::AdmissionContextValue{
        .admission_record_id = required_text(trusted_context_, "admissionRecordId"),
        .trusted_accepted_at = required_text(trusted_context_, "trustedAcceptedAt"),
        .accepted_by = principal(trusted_context_.at("acceptedBy")),
    };
  }

  [[nodiscard]] const std::string& organization_id() const noexcept { return organization_id_; }
  [[nodiscard]] const std::string& signing_hash() const noexcept { return signing_hash_; }

private:
  missionweaveprotocol::Json trusted_context_;
  std::vector<std::string>& calls_;
  mutable std::string organization_id_;
  mutable std::string signing_hash_;
};

class ManifestAdmissionLog final : public missionweaveprotocol::AdmissionLog {
public:
  ManifestAdmissionLog(missionweaveprotocol::Json evaluation, std::vector<std::string>& calls)
      : evaluation_(std::move(evaluation)), calls_(calls) {}

  [[nodiscard]] missionweaveprotocol::AdmissionLookup
  lookup(const std::string_view organization_id,
         const std::string_view signing_hash) const override {
    calls_.emplace_back("lookup");
    organization_id_ = organization_id;
    signing_hash_ = signing_hash;
    const auto& outcome = evaluation_.at("lookup");
    const auto status = required_text(outcome, "status");
    if (status == "found") {
      return missionweaveprotocol::AdmissionLookup::found(
          authenticated(required_text(outcome, "record"), outcome.at("authenticatedService")));
    }
    if (status == "authoritative-absence") {
      return missionweaveprotocol::AdmissionLookup::authoritative_absence();
    }
    if (status == "unauthenticated" || status == "integrity-failed") {
      adapter_failure(missionweaveprotocol::AdmissionReason::log_authentication_failed, status);
    }
    if (status == "unavailable") {
      adapter_failure(missionweaveprotocol::AdmissionReason::log_unavailable, status);
    }
    if (status == "indeterminate") {
      adapter_failure(missionweaveprotocol::AdmissionReason::log_indeterminate, status);
    }
    throw std::invalid_argument("unknown lookup outcome: " + status);
  }

  [[nodiscard]] missionweaveprotocol::AuthenticatedAdmissionRecord
  append_or_return_existing(const std::string_view organization_id,
                            const std::string_view signing_hash,
                            const missionweaveprotocol::AssetBytes candidate_bytes) const override {
    calls_.emplace_back("append_or_return_existing");
    assert(organization_id == organization_id_);
    assert(signing_hash == signing_hash_);
    const auto expected_candidate = canonical_bytes(
        asset("admission/records/valid/" + required_text(evaluation_, "profileId") + ".json"));
    assert(candidate_bytes.size() == expected_candidate.size());
    assert(std::ranges::equal(candidate_bytes, expected_candidate));

    const auto& outcome = evaluation_.at("append");
    const auto status = required_text(outcome, "status");
    if (status == "committed" || status == "existing") {
      return authenticated(required_text(outcome, "record"), outcome.at("authenticatedService"));
    }
    if (status == "conflict") {
      adapter_failure(missionweaveprotocol::AdmissionReason::record_conflict, status);
    }
    if (status == "unauthenticated") {
      adapter_failure(missionweaveprotocol::AdmissionReason::log_authentication_failed, status);
    }
    if (status == "integrity-failed") {
      adapter_failure(missionweaveprotocol::AdmissionReason::append_integrity_not_established,
                      status);
    }
    if (status == "unavailable") {
      adapter_failure(missionweaveprotocol::AdmissionReason::log_unavailable, status);
    }
    if (status == "indeterminate") {
      adapter_failure(missionweaveprotocol::AdmissionReason::log_indeterminate, status);
    }
    if (status == "commit-failed") {
      adapter_failure(missionweaveprotocol::AdmissionReason::commit_failed, status);
    }
    throw std::invalid_argument("unknown append outcome: " + status);
  }

  [[nodiscard]] const std::string& organization_id() const noexcept { return organization_id_; }
  [[nodiscard]] const std::string& signing_hash() const noexcept { return signing_hash_; }

private:
  [[noreturn]] static void adapter_failure(const missionweaveprotocol::AdmissionReason reason,
                                           const std::string_view status) {
    throw missionweaveprotocol::AdmissionAdapterError{reason, "manifest adapter outcome: " +
                                                                  std::string{status}};
  }

  static missionweaveprotocol::AuthenticatedAdmissionRecord
  authenticated(const std::string_view path, const missionweaveprotocol::Json& service) {
    return missionweaveprotocol::AuthenticatedAdmissionRecord{asset(path), principal(service)};
  }

  missionweaveprotocol::Json evaluation_;
  std::vector<std::string>& calls_;
  mutable std::string organization_id_;
  mutable std::string signing_hash_;
};

missionweaveprotocol::AdmittedSignedDocument execute(const missionweaveprotocol::Json& evaluation,
                                                     const ManifestRegistry& registry,
                                                     const ManifestAdmissionLog& log,
                                                     const ManifestTrustedContext& context) {
  const auto kind = signed_document_kind(required_text(evaluation, "profileId"));
  const auto document = asset(required_text(evaluation, "document"));
  const missionweaveprotocol::AdmissionService service;
  if (required_text(evaluation, "mode") == "first-admission") {
    return service.admit_first(kind, document, registry, log, context);
  }
  return service.verify_historical_admission(kind, document, registry, log);
}

std::vector<std::string> expected_calls(const missionweaveprotocol::Json& evaluation) {
  if (required_text(evaluation, "mode") == "historical-replay") {
    return {"resolve", "lookup"};
  }
  if (required_text(evaluation.at("lookup"), "status") != "authoritative-absence") {
    return {"resolve_current", "lookup"};
  }
  if (evaluation.at("append").is_null()) {
    return {"resolve_current", "lookup", "issue"};
  }
  return {"resolve_current", "lookup", "issue", "append_or_return_existing"};
}

void satisfies_all_vendored_admission_manifest_evaluations() {
  const auto manifest = asset_json("admission/manifest.json");
  std::size_t evaluations = 0;
  std::size_t complete = 0;
  std::size_t rejected = 0;
  std::map<std::string, std::size_t> call_totals;

  for (const auto& test_case : manifest.at("cases").array_range()) {
    for (const auto& evaluation : test_case.at("evaluations").array_range()) {
      ++evaluations;
      std::vector<std::string> calls;
      const ManifestRegistry registry{asset(required_text(evaluation, "registry")), calls};
      const ManifestAdmissionLog log{evaluation, calls};
      const ManifestTrustedContext context{evaluation.at("trustedContext"), calls};
      try {
        const auto admitted = execute(evaluation, registry, log, context);
        assert(required_text(evaluation.at("expect"), "stage") == "complete");
        const auto expected_record = asset(required_text(evaluation.at("expect"), "record"));
        assert(admitted.record_bytes().size() == expected_record.size());
        assert(std::ranges::equal(admitted.record_bytes(), expected_record));
        ++complete;
      } catch (const missionweaveprotocol::AdmissionError& error) {
        assert(required_text(evaluation.at("expect"), "stage") == "admission");
        assert(error.wire_code() == required_text(evaluation.at("expect"), "wireCode"));
        assert(error.diagnostic().stage == "admission");
        assert(error.diagnostic().reason ==
               admission_reason(required_text(evaluation.at("expect"), "reason")));
        ++rejected;
      }

      assert(calls == expected_calls(evaluation));
      for (const auto& call : calls) {
        ++call_totals[call];
      }
      if (!context.organization_id().empty()) {
        assert(context.organization_id() == log.organization_id());
        assert(context.signing_hash() == log.signing_hash());
      }
    }
  }

  assert(evaluations == 30);
  assert(complete == 12);
  assert(rejected == 18);
  assert(call_totals["resolve_current"] == 18);
  assert(call_totals["resolve"] == 12);
  assert(call_totals["lookup"] == 30);
  assert(call_totals["issue"] == 17);
  assert(call_totals["append_or_return_existing"] == 11);
}

} // namespace

int main() { satisfies_all_vendored_admission_manifest_evaluations(); }
