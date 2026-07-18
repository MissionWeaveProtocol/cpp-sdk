#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/crypto.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace {

class GoldenResolver final : public missionweaveprotocol::KeyResolver {
public:
  [[nodiscard]] std::optional<missionweaveprotocol::ResolvedKey>
  resolve(const missionweaveprotocol::KeyResolutionRequest& request) const override {
    assert(request.kind == missionweaveprotocol::SignedDocumentKind::command);
    assert(request.key_id == "urn:missionweaveprotocol:key:crypto-vector-rfc8032-1");
    assert(request.expected_principal.has_value());
    assert(request.expected_principal->type == "agent");
    assert(request.expected_principal->id ==
           "urn:missionweaveprotocol:agent:crypto-vector-coordinator");
    assert(!request.service_principal_required);
    assert(request.protected_time == "2026-07-15T00:00:00Z");
    return missionweaveprotocol::ResolvedKey{
        .key_id = "urn:missionweaveprotocol:key:crypto-vector-rfc8032-1",
        .principal =
            {
                .type = "agent",
                .id = "urn:missionweaveprotocol:agent:crypto-vector-coordinator",
            },
        .algorithm = "Ed25519",
        .public_key = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        .valid_from = "2026-07-15T08:00:00+08:00",
        .valid_until = "2026-07-16T00:00:00Z",
        .revoked_at = std::nullopt,
    };
  }
};

std::string_view relative_crypto_path(std::string_view path) {
  constexpr std::string_view prefix = "cryptography/";
  return path.starts_with(prefix) ? path.substr(prefix.size()) : path;
}

std::vector<std::uint8_t> asset(const std::string_view path) {
  const auto bytes = missionweaveprotocol::ProtocolBundle::cryptography(relative_crypto_path(path));
  if (!bytes) {
    throw std::runtime_error("missing cryptography asset: " + std::string{path});
  }
  return {bytes->begin(), bytes->end()};
}

std::string asset_text(const std::string_view path) {
  const auto bytes = asset(path);
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

missionweaveprotocol::Json asset_json(const std::string_view path) {
  return missionweaveprotocol::parse_strict_json(asset_text(path));
}

std::string required_text(const missionweaveprotocol::Json& object, const std::string_view field) {
  if (!object.is_object() || !object.contains(field) || !object.at(field).is_string()) {
    throw std::invalid_argument("fixture field is not text: " + std::string{field});
  }
  return object.at(field).as<std::string>();
}

std::vector<std::uint8_t> decode_base64url(const std::string_view encoded) {
  if (encoded.empty() || encoded.size() % 4 == 1 || encoded.find('=') != std::string_view::npos) {
    throw std::invalid_argument("invalid test base64url");
  }
  std::string padded{encoded};
  for (auto& value : padded) {
    if (value == '-') {
      value = '+';
    } else if (value == '_') {
      value = '/';
    }
  }
  const auto padding = (4 - padded.size() % 4) % 4;
  padded.append(padding, '=');
  std::vector<std::uint8_t> decoded((padded.size() / 4) * 3);
  const auto size =
      EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(padded.data()),
                      static_cast<int>(padded.size()));
  if (size < 0 || static_cast<std::size_t>(size) < padding) {
    throw std::invalid_argument("invalid test base64url");
  }
  decoded.resize(static_cast<std::size_t>(size) - padding);
  return decoded;
}

missionweaveprotocol::SignedDocumentKind kind(const std::string_view id) {
  using Kind = missionweaveprotocol::SignedDocumentKind;
  if (id == "agent-card") {
    return Kind::agent_card;
  }
  if (id == "approval") {
    return Kind::approval;
  }
  if (id == "artifact") {
    return Kind::artifact;
  }
  if (id == "command") {
    return Kind::command;
  }
  if (id == "context-package") {
    return Kind::context_package;
  }
  if (id == "event") {
    return Kind::event;
  }
  if (id == "evidence") {
    return Kind::evidence;
  }
  if (id == "extension-profile") {
    return Kind::extension_profile;
  }
  if (id == "group-snapshot") {
    return Kind::group_snapshot;
  }
  throw std::invalid_argument("unknown Signed Document kind: " + std::string{id});
}

struct NormalizedBinding {
  std::string key_id;
  missionweaveprotocol::Principal principal;
  std::string algorithm;
  std::string public_key;
  std::string valid_from;
  std::map<std::uint64_t, missionweaveprotocol::Json> history;

  bool same_immutable(const NormalizedBinding& other) const {
    return principal == other.principal && algorithm == other.algorithm &&
           public_key == other.public_key && valid_from == other.valid_from;
  }
};

class FixtureResolver final : public missionweaveprotocol::KeyResolver {
public:
  explicit FixtureResolver(std::vector<std::uint8_t> registry) : registry_(std::move(registry)) {}

  [[nodiscard]] std::optional<missionweaveprotocol::ResolvedKey>
  resolve(const missionweaveprotocol::KeyResolutionRequest& request) const override {
    const auto registry = missionweaveprotocol::parse_strict_json(
        missionweaveprotocol::AssetBytes{registry_.data(), registry_.size()});
    if (!registry.is_object() || !registry.contains("bindings") ||
        !registry.at("bindings").is_array()) {
      throw std::invalid_argument("Registry fixture has invalid structure");
    }

    std::map<std::string, NormalizedBinding> bindings;
    std::map<std::string, std::string> public_key_owners;
    std::map<std::tuple<std::string, std::string, std::string, std::string>, std::string> tuple_ids;
    for (const auto& raw : registry.at("bindings").array_range()) {
      const auto key_id = required_text(raw, "keyId");
      const auto& raw_principal = raw.at("principal");
      const missionweaveprotocol::Principal principal{.type = required_text(raw_principal, "type"),
                                                      .id = required_text(raw_principal, "id")};
      const auto algorithm = required_text(raw, "algorithm");
      if (algorithm != "Ed25519") {
        throw std::invalid_argument("Registry key algorithm is not Ed25519");
      }
      const auto public_key = required_text(raw, "publicKey");
      const auto valid_from = required_text(raw, "validFrom");
      NormalizedBinding candidate{.key_id = key_id,
                                  .principal = principal,
                                  .algorithm = algorithm,
                                  .public_key = public_key,
                                  .valid_from = valid_from,
                                  .history = {}};
      auto [iterator, inserted] = bindings.try_emplace(key_id, candidate);
      if (!inserted && !iterator->second.same_immutable(candidate)) {
        throw std::invalid_argument("Registry reuses a key ID for another immutable binding");
      }
      auto& binding = iterator->second;

      const auto owner = key_id + '\0' + principal.type + '\0' + principal.id;
      const auto [owner_iterator, owner_inserted] =
          public_key_owners.try_emplace(public_key, owner);
      if (!owner_inserted && owner_iterator->second != owner) {
        throw std::invalid_argument("Registry reuses a public key");
      }
      const auto tuple = std::tuple{principal.type, principal.id, algorithm, public_key};
      const auto [tuple_iterator, tuple_inserted] = tuple_ids.try_emplace(tuple, key_id);
      if (!tuple_inserted && tuple_iterator->second != key_id) {
        throw std::invalid_argument("Registry contains a key-ID alias");
      }

      if (!raw.contains("validityHistory") || !raw.at("validityHistory").is_array()) {
        throw std::invalid_argument("Registry validityHistory is not an array");
      }
      for (const auto& status : raw.at("validityHistory").array_range()) {
        if (!status.contains("sequence") || !status.at("sequence").is_uint64()) {
          throw std::invalid_argument("Registry validity sequence is not an integer");
        }
        const auto sequence = status.at("sequence").as<std::uint64_t>();
        if (sequence == 0 || sequence > 9007199254740991ULL) {
          throw std::invalid_argument("Registry validity sequence is outside the safe range");
        }
        const auto [status_iterator, status_inserted] =
            binding.history.try_emplace(sequence, status);
        if (!status_inserted && status_iterator->second != status) {
          throw std::invalid_argument("Registry rewrites validity history");
        }
      }
    }

    for (const auto& [key_id, binding] : bindings) {
      std::uint64_t expected_sequence = 1;
      for (const auto& [sequence, status] : binding.history) {
        static_cast<void>(status);
        if (sequence != expected_sequence++) {
          throw std::invalid_argument("Registry validity history is not contiguous");
        }
      }
      static_cast<void>(key_id);
    }

    const auto selected = bindings.find(request.key_id);
    if (selected == bindings.end()) {
      return std::nullopt;
    }
    std::optional<std::string> valid_until;
    std::optional<std::string> revoked_at;
    for (const auto& [sequence, status] : selected->second.history) {
      static_cast<void>(sequence);
      if (status.contains("validUntil")) {
        valid_until = required_text(status, "validUntil");
      }
      if (status.contains("revokedAt")) {
        revoked_at = required_text(status, "revokedAt");
      }
    }
    return missionweaveprotocol::ResolvedKey{
        .key_id = selected->second.key_id,
        .principal = selected->second.principal,
        .algorithm = selected->second.algorithm,
        .public_key = selected->second.public_key,
        .valid_from = selected->second.valid_from,
        .valid_until = std::move(valid_until),
        .revoked_at = std::move(revoked_at),
    };
  }

private:
  std::vector<std::uint8_t> registry_;
};

class FixtureSigningKey final : public missionweaveprotocol::SigningKey {
public:
  explicit FixtureSigningKey(const missionweaveprotocol::Json& fixture)
      : key_id_(required_text(fixture, "keyId")) {
    const auto raw = decode_base64url(required_text(fixture, "seed"));
    if (raw.size() != seed_.size()) {
      throw std::invalid_argument("signing fixture seed is not 32 bytes");
    }
    std::ranges::copy(raw, seed_.begin());
  }

  [[nodiscard]] std::string key_id() const override { return key_id_; }

  [[nodiscard]] missionweaveprotocol::Ed25519Signature
  sign(const missionweaveprotocol::AssetBytes signing_bytes) const override {
    return missionweaveprotocol::Ed25519::sign(seed_, signing_bytes);
  }

private:
  std::string key_id_;
  missionweaveprotocol::Ed25519Seed seed_{};
};

class EchoResolver final : public missionweaveprotocol::KeyResolver {
public:
  [[nodiscard]] std::optional<missionweaveprotocol::ResolvedKey>
  resolve(const missionweaveprotocol::KeyResolutionRequest& request) const override {
    called = true;
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

  mutable bool called = false;
};

} // namespace

int main() {
  const auto document = missionweaveprotocol::ProtocolBundle::cryptography(
      "vectors/signed-documents/valid/command.json");
  const auto expected_signing = missionweaveprotocol::ProtocolBundle::cryptography(
      "vectors/canonicalization/command.signing.jcs");
  assert(document && expected_signing);

  const GoldenResolver resolver;
  const missionweaveprotocol::SignedDocumentCodec codec;
  const auto verified =
      codec.verify(missionweaveprotocol::SignedDocumentKind::command, *document, resolver);
  assert(verified.kind() == missionweaveprotocol::SignedDocumentKind::command);
  assert(verified.received_bytes().size() == document->size());
  const auto expected_signing_text = std::string_view{
      reinterpret_cast<const char*>(expected_signing->data()), expected_signing->size()};
  assert(verified.signing_bytes() == expected_signing_text);
  assert(verified.signing_hash() ==
         "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695");
  assert(verified.canonical_hash() ==
         "sha256:1d17d0bd5379e554d48d14a6b328671f12860c6c3278bc1e7ca4e1163a74353f");
  assert(verified.protected_time() == "2026-07-15T00:00:00Z");
  assert(verified.signature().bytes.size() == 64);
  assert(verified.resolved_principal().type == "agent");

  const auto manifest = asset_json("manifest.json");
  std::size_t evaluations = 0;
  std::size_t completed = 0;
  std::size_t rejected = 0;
  for (const auto& test_case : manifest.at("cases").array_range()) {
    if (required_text(test_case, "kind") == "canonicalization") {
      ++evaluations;
      ++completed;
      continue;
    }
    for (const auto& evaluation : test_case.at("evaluations").array_range()) {
      ++evaluations;
      const auto selected_kind = kind(required_text(evaluation, "profileId"));
      const auto raw = asset(required_text(evaluation, "document"));
      const FixtureResolver fixture_resolver(asset(required_text(evaluation, "registry")));
      const auto& expected = evaluation.at("expect");
      const auto expected_stage = required_text(expected, "stage");
      if (expected_stage == "complete") {
        const auto result =
            codec.verify(selected_kind, missionweaveprotocol::AssetBytes{raw.data(), raw.size()},
                         fixture_resolver);
        const auto& evidence = expected.at("verified");
        assert(result.resolved_key().key_id == required_text(evidence, "keyId"));
        assert(result.resolved_principal().type == required_text(evidence.at("principal"), "type"));
        assert(result.resolved_principal().id == required_text(evidence.at("principal"), "id"));
        assert(result.protected_time() == required_text(evidence, "protectedTime"));
        assert(result.signing_bytes() == asset_text(required_text(evidence, "signingBytes")));
        assert(result.signing_hash() == required_text(evidence, "signingHash"));
        assert(result.signature().value == required_text(evidence, "signature"));
        assert(result.canonical_hash() == required_text(evidence, "signedDocumentHash"));

        auto unsigned_document = result.document();
        unsigned_document.erase("signature");
        const FixtureSigningKey signing_key(asset_json(required_text(evaluation, "signingKey")));
        assert(codec.sign(selected_kind, unsigned_document, signing_key) == result.document());
        ++completed;
      } else {
        bool failed = false;
        try {
          static_cast<void>(codec.verify(selected_kind,
                                         missionweaveprotocol::AssetBytes{raw.data(), raw.size()},
                                         fixture_resolver));
        } catch (const missionweaveprotocol::SignedDocumentVerificationError& error) {
          failed = true;
          assert(missionweaveprotocol::verification_stage_id(error.diagnostic().stage) ==
                 expected_stage);
          assert(error.wire_code() == required_text(expected, "wireCode"));
        }
        assert(failed);
        ++rejected;
      }
    }
  }
  assert(evaluations == 58);
  assert(completed == 12);
  assert(rejected == 46);

  auto surrogate_key_id = asset_text("vectors/signed-documents/valid/command.json");
  const auto key_position =
      surrogate_key_id.find("urn:missionweaveprotocol:key:crypto-vector-rfc8032-1");
  assert(key_position != std::string::npos);
  surrogate_key_id.replace(
      key_position, std::string_view{"urn:missionweaveprotocol:key:crypto-vector-rfc8032-1"}.size(),
      "urn:missionweaveprotocol:key:crypto-vector-\\uD800");
  const EchoResolver echo_resolver;
  bool rejected_surrogate = false;
  try {
    static_cast<void>(codec.verify(missionweaveprotocol::SignedDocumentKind::command,
                                   surrogate_key_id, echo_resolver));
  } catch (const missionweaveprotocol::SignedDocumentVerificationError& error) {
    rejected_surrogate = true;
    assert(error.diagnostic().stage == missionweaveprotocol::VerificationStage::canonicalization);
    assert(error.wire_code() == "PROTOCOL_VIOLATION");
  }
  assert(echo_resolver.called);
  assert(rejected_surrogate);
}
