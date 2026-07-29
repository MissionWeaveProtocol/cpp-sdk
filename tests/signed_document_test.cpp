#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <openssl/evp.h>

#include <jsoncons/utility/uri.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

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

class GoldenResolver final : public missionweaveprotocol::KeyResolver {
public:
  GoldenResolver() : registry_(asset("keys/registry-valid.json")) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest& request) const override {
    ++calls;
    assert(request.kind == missionweaveprotocol::SignedDocumentKind::command);
    assert(request.key_id == "urn:missionweaveprotocol:key:crypto-vector-rfc8032-1");
    assert(request.expected_principal.has_value());
    assert(request.expected_principal->type == "agent");
    assert(request.expected_principal->id ==
           "urn:missionweaveprotocol:agent:crypto-vector-coordinator");
    assert(!request.service_principal_required);
    assert(request.protected_time == "2026-07-15T00:00:00Z");
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
  }

  mutable std::size_t calls = 0;

private:
  std::vector<std::uint8_t> registry_;
};

using FixtureSchema = jsoncons::jsonschema::json_schema<missionweaveprotocol::Json>;

FixtureSchema compile_fixture_schema(const std::string_view path) {
  const auto schema = asset_json(path);
  if (!schema.is_object() || !schema.contains("$id") || !schema.at("$id").is_string()) {
    throw std::invalid_argument("fixture schema has no string $id: " + std::string{path});
  }
  const auto identifier = schema.at("$id").as<std::string>();
  const auto resolver = [](const jsoncons::uri&) { return missionweaveprotocol::Json::null(); };
  const auto options = jsoncons::jsonschema::evaluation_options{}.require_format_validation(true);
  return jsoncons::jsonschema::make_json_schema(schema, identifier, resolver, options);
}

bool fixture_schema_accepts(const FixtureSchema& schema,
                            const missionweaveprotocol::Json& fixture) {
  bool valid = true;
  const auto reporter = [&valid](const jsoncons::jsonschema::validation_message&) {
    valid = false;
    return jsoncons::jsonschema::walk_state::abort;
  };
  schema.validate(fixture, reporter);
  return valid;
}

void require_fixture_schema(const FixtureSchema& schema, const std::string_view path) {
  if (!fixture_schema_accepts(schema, asset_json(path))) {
    throw std::invalid_argument("fixture failed its manifest-declared schema: " +
                                std::string{path});
  }
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

class FixtureResolver final : public missionweaveprotocol::KeyResolver {
public:
  explicit FixtureResolver(std::vector<std::uint8_t> registry) : registry_(std::move(registry)) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest&) const override {
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
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
  EchoResolver() : registry_(asset("keys/registry-valid.json")) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest&) const override {
    called = true;
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
  }

  mutable bool called = false;

private:
  std::vector<std::uint8_t> registry_;
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
  assert(resolver.calls == 1);
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
  assert(verified.resolved_key().organization_id == "urn:missionweaveprotocol:organization:acme");
  assert(verified.resolved_principal().type == "agent");

  const auto manifest = asset_json("manifest.json");
  const auto& declared_fixture_schemas = manifest.at("fixtureSchemas");
  const auto registry_fixture_schema =
      compile_fixture_schema(required_text(declared_fixture_schemas, "registry"));
  const auto signing_key_fixture_schema =
      compile_fixture_schema(required_text(declared_fixture_schemas, "signingKey"));
  auto invalid_registry = asset_json("keys/registry-valid.json");
  invalid_registry.erase("organizationId");
  assert(!fixture_schema_accepts(registry_fixture_schema, invalid_registry));
  std::size_t evaluations = 0;
  std::size_t completed = 0;
  std::size_t rejected = 0;
  for (const auto& test_case : manifest.at("cases").array_range()) {
    if (required_text(test_case, "kind") == "canonicalization") {
      for (const auto& evaluation : test_case.at("evaluations").array_range()) {
        ++evaluations;
        const auto input = asset_json(required_text(evaluation, "input"));
        assert(missionweaveprotocol::canonical_json(input) ==
               asset_text(required_text(evaluation, "expectedJcs")));
        assert(missionweaveprotocol::canonical_sha256(input) ==
               required_text(evaluation, "sha256"));
        ++completed;
      }
      continue;
    }
    for (const auto& evaluation : test_case.at("evaluations").array_range()) {
      ++evaluations;
      require_fixture_schema(registry_fixture_schema, required_text(evaluation, "registry"));
      if (evaluation.contains("signingKey")) {
        require_fixture_schema(signing_key_fixture_schema, required_text(evaluation, "signingKey"));
      }
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
    assert(error.diagnostic().stage == missionweaveprotocol::VerificationStage::schema);
    assert(error.wire_code() == "SCHEMA_VALIDATION_FAILED");
  }
  assert(!echo_resolver.called);
  assert(rejected_surrogate);

  auto malformed_action_id = asset_text("vectors/signed-documents/valid/command.json");
  const auto action_position =
      malformed_action_id.find("urn:uuid:11111111-2222-4333-8444-555555555555");
  assert(action_position != std::string::npos);
  malformed_action_id.replace(
      action_position, std::string_view{"urn:uuid:11111111-2222-4333-8444-555555555555"}.size(),
      "example:%ZZ");
  const EchoResolver malformed_action_resolver;
  bool rejected_malformed_action = false;
  try {
    static_cast<void>(codec.verify(missionweaveprotocol::SignedDocumentKind::command,
                                   malformed_action_id, malformed_action_resolver));
  } catch (const missionweaveprotocol::SignedDocumentVerificationError& error) {
    rejected_malformed_action = true;
    assert(error.diagnostic().stage == missionweaveprotocol::VerificationStage::schema);
    assert(error.wire_code() == "SCHEMA_VALIDATION_FAILED");
  }
  assert(!malformed_action_resolver.called);
  assert(rejected_malformed_action);
}
