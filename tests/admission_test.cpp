#include <missionweaveprotocol/admission.hpp>
#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

static_assert(
    !std::is_constructible_v<
        missionweaveprotocol::VerifiedSignedDocument, missionweaveprotocol::SignedDocumentKind,
        missionweaveprotocol::Json, std::vector<std::uint8_t>, std::string, std::string,
        std::string, std::string, std::string, missionweaveprotocol::ExactInstant,
        missionweaveprotocol::SignatureMaterial, missionweaveprotocol::ResolvedKey>);

namespace {

constexpr std::string_view admission_service_id = "urn:missionweaveprotocol:service:admission";

std::vector<std::uint8_t> cryptography_asset(const std::string_view path) {
  const auto bytes = missionweaveprotocol::ProtocolBundle::cryptography(path);
  if (!bytes) {
    throw std::runtime_error("missing cryptography asset: " + std::string{path});
  }
  return {bytes->begin(), bytes->end()};
}

std::vector<std::uint8_t> source_asset(const std::string_view path) {
  const auto absolute = std::filesystem::path{MISSIONWEAVEPROTOCOL_SOURCE_DIR} / path;
  std::ifstream input(absolute, std::ios::binary);
  if (!input) {
    throw std::runtime_error("missing source asset: " + absolute.string());
  }
  const std::vector<char> characters{std::istreambuf_iterator<char>{input},
                                     std::istreambuf_iterator<char>{}};
  return {characters.begin(), characters.end()};
}

std::vector<std::uint8_t> golden_command() {
  return cryptography_asset("vectors/signed-documents/valid/command.json");
}

class StaticRegistry final : public missionweaveprotocol::KeyResolver,
                             public missionweaveprotocol::AdmissionCurrentKeyResolver {
public:
  explicit StaticRegistry(std::vector<std::uint8_t> registry) : registry_(std::move(registry)) {}

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

StaticRegistry current_registry() {
  return StaticRegistry{cryptography_asset("keys/registry-valid.json")};
}

StaticRegistry historical_registry() {
  return StaticRegistry{cryptography_asset("keys/registry-valid.json")};
}

StaticRegistry later_revocation_registry() {
  return StaticRegistry{source_asset("admission/registries/registry-later-revocation.json")};
}

class FixedTrustedContext final : public missionweaveprotocol::TrustedAdmissionContext {
public:
  explicit FixedTrustedContext(std::string trusted_accepted_at)
      : trusted_accepted_at_(std::move(trusted_accepted_at)) {}

  [[nodiscard]] missionweaveprotocol::AdmissionContextValue
  issue(const std::string_view organization_id,
        const std::string_view signing_hash) const override {
    ++issue_calls_;
    assert(organization_id == "urn:missionweaveprotocol:organization:acme");
    assert(signing_hash ==
           "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695");
    return missionweaveprotocol::AdmissionContextValue{
        .admission_record_id = "urn:missionweaveprotocol:admission-record:crypto-vector-command",
        .trusted_accepted_at = trusted_accepted_at_,
        .accepted_by =
            missionweaveprotocol::Principal{
                .type = "service",
                .id = std::string{admission_service_id},
            },
    };
  }

  [[nodiscard]] std::size_t issue_calls() const noexcept { return issue_calls_; }

private:
  std::string trusted_accepted_at_;
  mutable std::size_t issue_calls_ = 0;
};

FixedTrustedContext
fixed_trusted_context(std::string trusted_accepted_at = "2026-07-15T00:05:00Z") {
  return FixedTrustedContext{std::move(trusted_accepted_at)};
}

class RecordingAdmissionLog final : public missionweaveprotocol::AdmissionLog {
public:
  enum class Outcome {
    authoritative_absence_then_commit,
    authoritative_absence,
    found_valid,
    found_key_id_mismatch,
    unavailable,
  };

  explicit RecordingAdmissionLog(const Outcome outcome) : outcome_(outcome) {}

  [[nodiscard]] missionweaveprotocol::AdmissionLookup
  lookup(const std::string_view organization_id,
         const std::string_view signing_hash) const override {
    calls_.emplace_back("lookup");
    assert(organization_id == "urn:missionweaveprotocol:organization:acme");
    assert(signing_hash ==
           "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695");
    switch (outcome_) {
    case Outcome::authoritative_absence_then_commit:
    case Outcome::authoritative_absence:
      return missionweaveprotocol::AdmissionLookup::authoritative_absence();
    case Outcome::found_valid:
      return missionweaveprotocol::AdmissionLookup::found(
          authenticated(source_asset("admission/records/valid/command.json")));
    case Outcome::found_key_id_mismatch:
      return missionweaveprotocol::AdmissionLookup::found(
          authenticated(source_asset("admission/records/invalid/key-id-mismatch.json")));
    case Outcome::unavailable:
      throw missionweaveprotocol::AdmissionAdapterError{
          missionweaveprotocol::AdmissionReason::log_unavailable,
          "fixture Admission Log is unavailable"};
    }
    throw std::logic_error("unknown Admission Log outcome");
  }

  [[nodiscard]] missionweaveprotocol::AuthenticatedAdmissionRecord
  append_or_return_existing(const std::string_view organization_id,
                            const std::string_view signing_hash,
                            const missionweaveprotocol::AssetBytes candidate_bytes) const override {
    calls_.emplace_back("append_or_return_existing");
    assert(organization_id == "urn:missionweaveprotocol:organization:acme");
    assert(signing_hash ==
           "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695");
    appended_candidate_.assign(candidate_bytes.begin(), candidate_bytes.end());
    assert(outcome_ == Outcome::authoritative_absence_then_commit);
    return authenticated(source_asset("admission/records/valid/command.json"));
  }

  [[nodiscard]] const std::vector<std::string>& calls() const noexcept { return calls_; }

  [[nodiscard]] std::size_t append_calls() const noexcept {
    std::size_t count = 0;
    for (const auto& call : calls_) {
      if (call == "append_or_return_existing") {
        ++count;
      }
    }
    return count;
  }

private:
  static missionweaveprotocol::AuthenticatedAdmissionRecord
  authenticated(std::vector<std::uint8_t> record_bytes) {
    return missionweaveprotocol::AuthenticatedAdmissionRecord{
        std::move(record_bytes), missionweaveprotocol::Principal{
                                     .type = "service",
                                     .id = std::string{admission_service_id},
                                 }};
  }

  Outcome outcome_;
  mutable std::vector<std::string> calls_;
  mutable std::vector<std::uint8_t> appended_candidate_;
};

missionweaveprotocol::VerifiedSignedDocument verified_command() {
  const auto registry = historical_registry();
  return missionweaveprotocol::SignedDocumentCodec{}.verify(
      missionweaveprotocol::SignedDocumentKind::command, golden_command(), registry);
}

void assert_admission_error(const missionweaveprotocol::AdmissionError& error,
                            const missionweaveprotocol::AdmissionReason reason) {
  assert(error.wire_code() == "AUTH_INVALID_SIGNATURE");
  assert(error.diagnostic().stage == "admission");
  assert(error.diagnostic().reason == reason);
}

void first_admission_validates_the_committed_record() {
  RecordingAdmissionLog log{RecordingAdmissionLog::Outcome::authoritative_absence_then_commit};
  const auto admitted = missionweaveprotocol::AdmissionService{}.admit_first(
      missionweaveprotocol::SignedDocumentKind::command, golden_command(), current_registry(), log,
      fixed_trusted_context());
  assert(admitted.record().signing_hash() == admitted.verified().signing_hash());
  assert((log.calls() == std::vector<std::string>{"lookup", "append_or_return_existing"}));
}

void historical_replay_never_appends() {
  RecordingAdmissionLog log{RecordingAdmissionLog::Outcome::authoritative_absence};
  try {
    static_cast<void>(missionweaveprotocol::AdmissionService{}.verify_historical_admission(
        missionweaveprotocol::SignedDocumentKind::command, golden_command(), historical_registry(),
        log));
    assert(false);
  } catch (const missionweaveprotocol::AdmissionError& error) {
    assert_admission_error(error, missionweaveprotocol::AdmissionReason::record_missing);
  }
  assert(log.append_calls() == 0);
}

void existing_record_binding_mismatch_fails_admission() {
  RecordingAdmissionLog log{RecordingAdmissionLog::Outcome::found_key_id_mismatch};
  try {
    static_cast<void>(missionweaveprotocol::AdmissionService{}.verify_historical_admission(
        missionweaveprotocol::SignedDocumentKind::command, golden_command(), historical_registry(),
        log));
    assert(false);
  } catch (const missionweaveprotocol::AdmissionError& error) {
    assert_admission_error(error, missionweaveprotocol::AdmissionReason::record_binding_mismatch);
  }
  assert(log.append_calls() == 0);
}

void historical_replay_accepts_retained_later_revocation() {
  RecordingAdmissionLog log{RecordingAdmissionLog::Outcome::found_valid};
  const auto admitted = missionweaveprotocol::AdmissionService{}.verify_historical_admission(
      missionweaveprotocol::SignedDocumentKind::command, golden_command(),
      later_revocation_registry(), log);
  assert(admitted.record().trusted_accepted_at() == "2026-07-15T00:05:00Z");
  assert(admitted.verified().resolved_key().revoked_at == "2026-07-15T01:00:00Z");
  assert(log.append_calls() == 0);
}

void unavailable_log_fails_first_admission() {
  RecordingAdmissionLog log{RecordingAdmissionLog::Outcome::unavailable};
  auto context = fixed_trusted_context();
  try {
    static_cast<void>(missionweaveprotocol::AdmissionService{}.admit_first(
        missionweaveprotocol::SignedDocumentKind::command, golden_command(), current_registry(),
        log, context));
    assert(false);
  } catch (const missionweaveprotocol::AdmissionError& error) {
    assert_admission_error(error, missionweaveprotocol::AdmissionReason::log_unavailable);
  }
  assert(context.issue_calls() == 0);
}

void trusted_time_equal_valid_until_fails_admission() {
  auto context = fixed_trusted_context("2026-07-16T00:00:00Z");
  try {
    static_cast<void>(missionweaveprotocol::AdmissionService{}.prepare_first_admission(
        verified_command(), context));
    assert(false);
  } catch (const missionweaveprotocol::AdmissionError& error) {
    assert_admission_error(
        error, missionweaveprotocol::AdmissionReason::trusted_time_outside_key_interval);
  }
}

} // namespace

int main() {
  first_admission_validates_the_committed_record();
  historical_replay_never_appends();
  existing_record_binding_mismatch_fails_admission();
  historical_replay_accepts_retained_later_revocation();
  unavailable_log_fails_first_admission();
  trusted_time_equal_valid_until_fails_admission();
}
