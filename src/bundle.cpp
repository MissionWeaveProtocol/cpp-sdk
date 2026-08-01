#include <missionweaveprotocol/bundle.hpp>

#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/json.hpp>

#include "bundle_internal.hpp"
#include "embedded_assets.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>

namespace missionweaveprotocol {
namespace {

constexpr ProtocolPin embedded_pin{
    .repository = "https://github.com/missionweaveprotocol/missionweaveprotocol",
    .commit = "f7e70a72c76bbeb5014c186cd820aac2112f0dde",
    .protocol_version = "0.1",
    .wire_namespace = "missionweaveprotocol",
    .artifacts =
        {
            .schemas =
                {
                    .path = "schemas",
                    .files = 22,
                    .sha256 = "941a5a19b8664207f1ff48b799219c2f981ecd491a5cca527d586028d976ec76",
                },
            .conformance =
                {
                    .path = "conformance",
                    .files = 59,
                    .sha256 = "2362acd8345e5860e605ed06984f1673a1ea0a00e76c1fe00fed222326782f24",
                },
        },
    .cryptography =
        {
            .path = "cryptography/manifest.json",
            .source_commit = "f7e70a72c76bbeb5014c186cd820aac2112f0dde",
            .profile_id = "missionweaveprotocol.signed-document-verification.v0.1",
            .manifest_version = 1,
            .artifact_digest =
                "sha256:5eade516e4bc5dcf04477727ebcccd11f33348b2d9135fb6fe0365c6e6cc2ea3",
            .artifact_count = 98,
            .case_count = 22,
            .evaluation_count = 62,
        },
    .admission =
        {
            .path = "admission/manifest.json",
            .source_commit = "f7e70a72c76bbeb5014c186cd820aac2112f0dde",
            .profile_id = "missionweaveprotocol.first-admission-historical-trust.v0.1",
            .manifest_version = 1,
            .cryptography_artifact_digest =
                "sha256:5eade516e4bc5dcf04477727ebcccd11f33348b2d9135fb6fe0365c6e6cc2ea3",
            .artifact_digest =
                "sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0",
            .artifact_count = 19,
            .case_count = 5,
            .evaluation_count = 30,
        },
    .bundle_sha256 = "c95fc8f8334947dacf51a2c6e84d9b13f5b39b7d3827591569a1e2c5acfe47d7",
};

[[nodiscard]] const detail::EmbeddedAsset* find_asset(const std::string_view path) noexcept {
  const auto assets = detail::embedded_assets();
  const auto found =
      std::lower_bound(assets.begin(), assets.end(), path,
                       [](const detail::EmbeddedAsset& asset, const std::string_view wanted) {
                         return asset.path < wanted;
                       });
  return found != assets.end() && found->path == path ? std::addressof(*found) : nullptr;
}

[[nodiscard]] std::vector<const detail::EmbeddedAsset*> json_assets(const std::string_view prefix) {
  std::vector<const detail::EmbeddedAsset*> result;
  for (const auto& asset : detail::embedded_assets()) {
    if (asset.path.starts_with(prefix) && asset.path.ends_with(".json")) {
      result.push_back(std::addressof(asset));
    }
  }
  return result;
}

class DigestContext final {
public:
  DigestContext() : context_(EVP_MD_CTX_new(), &EVP_MD_CTX_free) {
    if (!context_ || EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr) != 1) {
      throw BundleError("unable to initialize SHA-256");
    }
  }

  void update(const std::span<const std::uint8_t> bytes) {
    if (EVP_DigestUpdate(context_.get(), bytes.data(), bytes.size()) != 1) {
      throw BundleError("unable to update SHA-256");
    }
  }

  void update(const std::string_view text) {
    update(std::span{reinterpret_cast<const std::uint8_t*>(text.data()), text.size()});
  }

  void separator() {
    constexpr std::array<std::uint8_t, 1> zero{0};
    update(zero);
  }

  [[nodiscard]] std::string finish() {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (EVP_DigestFinal_ex(context_.get(), digest.data(), &size) != 1) {
      throw BundleError("unable to finalize SHA-256");
    }

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < size; ++index) {
      output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return output.str();
  }

private:
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context_;
};

[[nodiscard]] std::string tree_digest(const std::vector<const detail::EmbeddedAsset*>& assets) {
  DigestContext digest;
  for (const auto* asset : assets) {
    digest.update(asset->path);
    digest.separator();
    digest.update(asset->bytes);
    digest.separator();
  }
  return digest.finish();
}

[[nodiscard]] std::string sha256_identifier(const AssetBytes bytes) {
  DigestContext digest;
  digest.update(bytes);
  return "sha256:" + digest.finish();
}

[[nodiscard]] std::string required_string(const Json& object, const std::string_view key,
                                          const std::string_view label = "cryptography manifest") {
  if (!object.contains(key) || !object.at(key).is_string()) {
    throw BundleError(std::string{label} + " field must be a string: " + std::string{key});
  }
  return object.at(key).as<std::string>();
}

[[nodiscard]] std::size_t required_size(const Json& object, const std::string_view key,
                                        const std::string_view label = "cryptography manifest") {
  if (!object.contains(key) || !object.at(key).is_uint64()) {
    throw BundleError(std::string{label} +
                      " field must be a non-negative integer: " + std::string{key});
  }
  return object.at(key).as<std::size_t>();
}

[[nodiscard]] const Json& required_array(const Json& object, const std::string_view key,
                                         const std::string_view label = "cryptography manifest") {
  if (!object.contains(key) || !object.at(key).is_array()) {
    throw BundleError(std::string{label} + " field must be an array: " + std::string{key});
  }
  return object.at(key);
}

[[nodiscard]] const Json& required_object(const Json& object, const std::string_view key,
                                          const std::string_view label) {
  if (!object.contains(key) || !object.at(key).is_object()) {
    throw BundleError(std::string{label} + " field must be an object: " + std::string{key});
  }
  return object.at(key);
}

void require_equal(const std::string_view label, const std::string_view expected,
                   const std::string_view actual) {
  if (expected != actual) {
    throw BundleError(std::string{label} + " does not match PROTOCOL_PIN.json");
  }
}

void require_equal(const std::string_view label, const std::size_t expected,
                   const std::size_t actual) {
  if (expected != actual) {
    throw BundleError(std::string{label} + " expected " + std::to_string(expected) + ", got " +
                      std::to_string(actual));
  }
}

void require_fields(const Json& object, const std::set<std::string>& expected,
                    const std::string_view label) {
  std::set<std::string> actual;
  for (const auto& member : object.object_range()) {
    actual.emplace(member.key());
  }
  if (actual != expected) {
    throw BundleError(std::string{label} + " has unexpected fields");
  }
}

void validate_artifact_pin(const Json& artifacts, const std::string_view name,
                           const ArtifactPin& expected) {
  const auto& artifact = required_object(artifacts, name, "protocol pin artifacts");
  require_fields(artifact, {"files", "path", "sha256"}, "protocol pin artifact");
  require_equal("protocol pin artifact path", expected.path,
                required_string(artifact, "path", "protocol pin artifact"));
  require_equal("protocol pin artifact files", expected.files,
                required_size(artifact, "files", "protocol pin artifact"));
  require_equal("protocol pin artifact sha256", expected.sha256,
                required_string(artifact, "sha256", "protocol pin artifact"));
}

void validate_protocol_pin(const Json& pin) {
  if (!pin.is_object()) {
    throw BundleError("PROTOCOL_PIN.json must be a JSON object");
  }
  require_fields(pin,
                 {"admission", "artifacts", "bundleSha256", "commit", "cryptography",
                  "protocolVersion", "repository", "wireNamespace"},
                 "protocol pin");
  require_equal("protocol pin repository", embedded_pin.repository,
                required_string(pin, "repository", "protocol pin"));
  require_equal("protocol pin commit", embedded_pin.commit,
                required_string(pin, "commit", "protocol pin"));
  require_equal("protocol pin protocolVersion", embedded_pin.protocol_version,
                required_string(pin, "protocolVersion", "protocol pin"));
  require_equal("protocol pin wireNamespace", embedded_pin.wire_namespace,
                required_string(pin, "wireNamespace", "protocol pin"));
  require_equal("protocol pin bundleSha256", embedded_pin.bundle_sha256,
                required_string(pin, "bundleSha256", "protocol pin"));

  const auto& artifacts = required_object(pin, "artifacts", "protocol pin");
  require_fields(artifacts, {"conformance", "schemas"}, "protocol pin artifacts");
  validate_artifact_pin(artifacts, "schemas", embedded_pin.artifacts.schemas);
  validate_artifact_pin(artifacts, "conformance", embedded_pin.artifacts.conformance);

  const auto& cryptography = required_object(pin, "cryptography", "protocol pin");
  require_fields(cryptography,
                 {"artifactCount", "artifactDigest", "caseCount", "evaluationCount",
                  "manifestVersion", "path", "profileId", "sourceCommit"},
                 "protocol pin cryptography");
  require_equal("protocol pin cryptography path", embedded_pin.cryptography.path,
                required_string(cryptography, "path", "protocol pin cryptography"));
  require_equal("protocol pin cryptography sourceCommit", embedded_pin.cryptography.source_commit,
                required_string(cryptography, "sourceCommit", "protocol pin cryptography"));
  require_equal("protocol pin cryptography profileId", embedded_pin.cryptography.profile_id,
                required_string(cryptography, "profileId", "protocol pin cryptography"));
  require_equal("protocol pin cryptography manifestVersion",
                embedded_pin.cryptography.manifest_version,
                required_size(cryptography, "manifestVersion", "protocol pin cryptography"));
  require_equal("protocol pin cryptography artifactDigest",
                embedded_pin.cryptography.artifact_digest,
                required_string(cryptography, "artifactDigest", "protocol pin cryptography"));
  require_equal("protocol pin cryptography artifactCount", embedded_pin.cryptography.artifact_count,
                required_size(cryptography, "artifactCount", "protocol pin cryptography"));
  require_equal("protocol pin cryptography caseCount", embedded_pin.cryptography.case_count,
                required_size(cryptography, "caseCount", "protocol pin cryptography"));
  require_equal("protocol pin cryptography evaluationCount",
                embedded_pin.cryptography.evaluation_count,
                required_size(cryptography, "evaluationCount", "protocol pin cryptography"));

  const auto& admission = required_object(pin, "admission", "protocol pin");
  require_fields(admission,
                 {"artifactCount", "artifactDigest", "caseCount", "cryptographyArtifactDigest",
                  "evaluationCount", "manifestVersion", "path", "profileId", "sourceCommit"},
                 "protocol pin admission");
  require_equal("protocol pin admission path", embedded_pin.admission.path,
                required_string(admission, "path", "protocol pin admission"));
  require_equal("protocol pin admission sourceCommit", embedded_pin.admission.source_commit,
                required_string(admission, "sourceCommit", "protocol pin admission"));
  require_equal("protocol pin admission profileId", embedded_pin.admission.profile_id,
                required_string(admission, "profileId", "protocol pin admission"));
  require_equal("protocol pin admission manifestVersion", embedded_pin.admission.manifest_version,
                required_size(admission, "manifestVersion", "protocol pin admission"));
  require_equal("protocol pin admission cryptographyArtifactDigest",
                embedded_pin.admission.cryptography_artifact_digest,
                required_string(admission, "cryptographyArtifactDigest", "protocol pin admission"));
  require_equal("protocol pin admission artifactDigest", embedded_pin.admission.artifact_digest,
                required_string(admission, "artifactDigest", "protocol pin admission"));
  require_equal("protocol pin admission artifactCount", embedded_pin.admission.artifact_count,
                required_size(admission, "artifactCount", "protocol pin admission"));
  require_equal("protocol pin admission caseCount", embedded_pin.admission.case_count,
                required_size(admission, "caseCount", "protocol pin admission"));
  require_equal("protocol pin admission evaluationCount", embedded_pin.admission.evaluation_count,
                required_size(admission, "evaluationCount", "protocol pin admission"));
}

[[nodiscard]] bool valid_segment(const std::string_view segment) {
  if (segment.empty()) {
    return false;
  }
  const auto valid_character = [](const char value) {
    return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '.' ||
           value == '_' || value == '-';
  };
  return std::ranges::all_of(segment, valid_character) &&
         ((segment.front() >= 'a' && segment.front() <= 'z') ||
          (segment.front() >= '0' && segment.front() <= '9'));
}

void validate_artifact_path(const std::string_view path, const std::string_view primary_prefix,
                            const std::string_view manifest_path,
                            const std::string_view readme_path) {
  if (path.empty() || path.size() > 512 || path.front() == '/' || path.back() == '/' ||
      path.find('\\') != std::string_view::npos ||
      !(path.starts_with(primary_prefix) || path.starts_with("schemas/")) ||
      path == manifest_path || path == readme_path) {
    throw BundleError("unsafe artifact path: " + std::string{path});
  }
  std::size_t start = 0;
  while (start < path.size()) {
    const auto end = path.find('/', start);
    const auto segment =
        path.substr(start, end == std::string_view::npos ? path.size() - start : end - start);
    if (!valid_segment(segment) || segment == "." || segment == "..") {
      throw BundleError("unsafe artifact path: " + std::string{path});
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1;
  }
}

void verify_tree(const std::string_view label,
                 const std::vector<const detail::EmbeddedAsset*>& assets, const ArtifactPin& pin) {
  if (assets.size() != pin.files) {
    throw BundleError(std::string{label} + " contains " + std::to_string(assets.size()) +
                      " JSON files; expected " + std::to_string(pin.files));
  }

  const auto digest = tree_digest(assets);
  if (digest != pin.sha256) {
    throw BundleError(std::string{label} + " digest is " + digest + "; expected " +
                      std::string{pin.sha256});
  }
}

} // namespace

ProtocolPin detail::parse_protocol_pin(const AssetBytes bytes) {
  try {
    validate_protocol_pin(parse_strict_json(bytes));
  } catch (const BundleError&) {
    throw;
  } catch (const std::exception& error) {
    throw BundleError(std::string{"embedded PROTOCOL_PIN.json is invalid: "} + error.what());
  }
  return embedded_pin;
}

ProtocolPin ProtocolBundle::pin() { return detail::parse_protocol_pin(protocol_pin_bytes()); }

AssetBytes ProtocolBundle::protocol_pin_bytes() noexcept {
  const auto* asset = find_asset("PROTOCOL_PIN.json");
  return asset == nullptr ? AssetBytes{} : asset->bytes;
}

std::optional<AssetBytes> ProtocolBundle::schema(const std::string_view name) noexcept {
  const auto* asset = find_asset(std::string{"schemas/"} + std::string{name});
  return asset == nullptr ? std::nullopt : std::optional<AssetBytes>{asset->bytes};
}

std::vector<std::string_view> ProtocolBundle::schema_names() {
  constexpr std::string_view prefix = "schemas/";
  std::vector<std::string_view> names;
  for (const auto* asset : json_assets(prefix)) {
    names.push_back(asset->path.substr(prefix.size()));
  }
  return names;
}

std::optional<AssetBytes> ProtocolBundle::conformance(const std::string_view path) noexcept {
  const auto* asset = find_asset(std::string{"conformance/"} + std::string{path});
  return asset == nullptr ? std::nullopt : std::optional<AssetBytes>{asset->bytes};
}

std::optional<AssetBytes> ProtocolBundle::cryptography(const std::string_view path) noexcept {
  const auto* asset = find_asset(std::string{"cryptography/"} + std::string{path});
  return asset == nullptr ? std::nullopt : std::optional<AssetBytes>{asset->bytes};
}

std::optional<AssetBytes> ProtocolBundle::admission(const std::string_view path) noexcept {
  const auto* asset = find_asset(std::string{"admission/"} + std::string{path});
  return asset == nullptr ? std::nullopt : std::optional<AssetBytes>{asset->bytes};
}

BundleSummary ProtocolBundle::verify() {
  const auto pin = ProtocolBundle::pin();
  const auto schemas = json_assets("schemas/");
  const auto conformance_assets = json_assets("conformance/");

  verify_tree("schemas", schemas, pin.artifacts.schemas);
  verify_tree("conformance", conformance_assets, pin.artifacts.conformance);

  std::vector<const detail::EmbeddedAsset*> bundle;
  bundle.reserve(schemas.size() + conformance_assets.size());
  bundle.insert(bundle.end(), conformance_assets.begin(), conformance_assets.end());
  bundle.insert(bundle.end(), schemas.begin(), schemas.end());
  std::sort(bundle.begin(), bundle.end(),
            [](const auto* left, const auto* right) { return left->path < right->path; });

  const auto bundle_digest = tree_digest(bundle);
  if (bundle_digest != pin.bundle_sha256) {
    throw BundleError("bundle digest is " + bundle_digest + "; expected " +
                      std::string{pin.bundle_sha256});
  }

  return BundleSummary{
      .schema_files = schemas.size(),
      .conformance_files = conformance_assets.size(),
      .bundle_sha256 = bundle_digest,
  };
}

CryptographyBundleSummary ProtocolBundle::verify_cryptography() {
  const auto pin = ProtocolBundle::pin();
  const auto* manifest_asset = find_asset(pin.cryptography.path);
  if (manifest_asset == nullptr) {
    throw BundleError("embedded cryptography manifest is missing");
  }
  const auto manifest = parse_strict_json(manifest_asset->bytes);
  if (!manifest.is_object()) {
    throw BundleError("cryptography manifest must be a JSON object");
  }
  require_fields(manifest,
                 {"$schema", "artifactDigest", "artifacts", "cases", "fixtureSchemas",
                  "manifestVersion", "profileId", "profiles", "protocolVersion", "semanticStages"},
                 "cryptography manifest");

  require_equal("cryptography manifest manifestVersion", pin.cryptography.manifest_version,
                required_size(manifest, "manifestVersion"));
  require_equal("cryptography manifest protocolVersion", pin.protocol_version,
                required_string(manifest, "protocolVersion"));
  require_equal("cryptography manifest profileId", pin.cryptography.profile_id,
                required_string(manifest, "profileId"));
  require_equal("cryptography manifest artifactDigest", pin.cryptography.artifact_digest,
                required_string(manifest, "artifactDigest"));

  const auto& artifacts = required_array(manifest, "artifacts");
  const auto& cases = required_array(manifest, "cases");
  require_equal("cryptography artifact count", pin.cryptography.artifact_count, artifacts.size());
  require_equal("cryptography case count", pin.cryptography.case_count, cases.size());

  std::size_t evaluation_count = 0;
  for (const auto& test_case : cases.array_range()) {
    if (!test_case.is_object()) {
      throw BundleError("cryptography manifest case must be an object");
    }
    evaluation_count += required_array(test_case, "evaluations").size();
  }
  require_equal("cryptography evaluation count", pin.cryptography.evaluation_count,
                evaluation_count);

  std::set<std::string> paths;
  for (const auto& item : artifacts.array_range()) {
    if (!item.is_object() || item.size() != 3 || !item.contains("path") ||
        !item.contains("byteLength") || !item.contains("sha256")) {
      throw BundleError("cryptography manifest artifact has invalid fields");
    }
    const auto artifact_path = required_string(item, "path");
    validate_artifact_path(artifact_path, "cryptography/", "cryptography/manifest.json",
                           "cryptography/README.md");
    if (!paths.insert(artifact_path).second) {
      throw BundleError("duplicate cryptography artifact path: " + artifact_path);
    }
    const auto byte_length = required_size(item, "byteLength");
    const auto expected_digest = required_string(item, "sha256");
    const auto* asset = find_asset(artifact_path);
    if (asset == nullptr) {
      throw BundleError("embedded cryptography artifact is missing: " + artifact_path);
    }
    require_equal("cryptography artifact byteLength", byte_length, asset->bytes.size());
    require_equal("cryptography artifact sha256", expected_digest, sha256_identifier(asset->bytes));
  }

  auto digest_input = manifest;
  digest_input.erase("artifactDigest");
  const auto actual_digest = canonical_sha256(digest_input);
  require_equal("cryptography manifest artifactDigest", pin.cryptography.artifact_digest,
                actual_digest);

  return CryptographyBundleSummary{
      .source_commit = std::string{pin.cryptography.source_commit},
      .profile_id = std::string{pin.cryptography.profile_id},
      .manifest_version = pin.cryptography.manifest_version,
      .artifact_digest = actual_digest,
      .artifact_count = artifacts.size(),
      .case_count = cases.size(),
      .evaluation_count = evaluation_count,
  };
}

AdmissionBundleSummary ProtocolBundle::verify_admission() {
  const auto pin = ProtocolBundle::pin();
  const auto* manifest_asset = find_asset(pin.admission.path);
  if (manifest_asset == nullptr) {
    throw BundleError("embedded admission manifest is missing");
  }
  const auto manifest = parse_strict_json(manifest_asset->bytes);
  if (!manifest.is_object()) {
    throw BundleError("admission manifest must be a JSON object");
  }
  require_fields(manifest,
                 {"$schema", "artifactDigest", "artifacts", "cases", "cryptography",
                  "fixtureSchemas", "manifestVersion", "profileId", "protocolVersion",
                  "semanticStage", "wireCode"},
                 "admission manifest");

  require_equal("admission manifest manifestVersion", pin.admission.manifest_version,
                required_size(manifest, "manifestVersion", "admission manifest"));
  require_equal("admission manifest protocolVersion", pin.protocol_version,
                required_string(manifest, "protocolVersion", "admission manifest"));
  require_equal("admission manifest profileId", pin.admission.profile_id,
                required_string(manifest, "profileId", "admission manifest"));
  require_equal("admission manifest semanticStage", "admission",
                required_string(manifest, "semanticStage", "admission manifest"));
  require_equal("admission manifest wireCode", "AUTH_INVALID_SIGNATURE",
                required_string(manifest, "wireCode", "admission manifest"));
  require_equal("admission manifest artifactDigest", pin.admission.artifact_digest,
                required_string(manifest, "artifactDigest", "admission manifest"));

  const auto& cryptography = required_object(manifest, "cryptography", "admission manifest");
  require_fields(cryptography, {"artifactDigest", "manifest"}, "admission manifest cryptography");
  require_equal("admission manifest cryptography manifest", pin.cryptography.path,
                required_string(cryptography, "manifest", "admission manifest cryptography"));
  const auto cryptography_digest =
      required_string(cryptography, "artifactDigest", "admission manifest cryptography");
  require_equal("admission manifest cryptography artifactDigest",
                pin.admission.cryptography_artifact_digest, cryptography_digest);
  require_equal("admission manifest pinned cryptography artifactDigest",
                pin.cryptography.artifact_digest, cryptography_digest);

  const auto& artifacts = required_array(manifest, "artifacts", "admission manifest");
  const auto& cases = required_array(manifest, "cases", "admission manifest");
  require_equal("admission artifact count", pin.admission.artifact_count, artifacts.size());
  require_equal("admission case count", pin.admission.case_count, cases.size());

  std::size_t evaluation_count = 0;
  for (const auto& test_case : cases.array_range()) {
    if (!test_case.is_object()) {
      throw BundleError("admission manifest case must be an object");
    }
    evaluation_count += required_array(test_case, "evaluations", "admission manifest").size();
  }
  require_equal("admission evaluation count", pin.admission.evaluation_count, evaluation_count);

  std::set<std::string> paths;
  for (const auto& item : artifacts.array_range()) {
    if (!item.is_object() || item.size() != 3 || !item.contains("path") ||
        !item.contains("byteLength") || !item.contains("sha256")) {
      throw BundleError("admission manifest artifact has invalid fields");
    }
    const auto artifact_path = required_string(item, "path", "admission manifest artifact");
    validate_artifact_path(artifact_path, "admission/", "admission/manifest.json",
                           "admission/README.md");
    if (!paths.insert(artifact_path).second) {
      throw BundleError("duplicate admission artifact path: " + artifact_path);
    }
    const auto byte_length = required_size(item, "byteLength", "admission manifest artifact");
    const auto expected_digest = required_string(item, "sha256", "admission manifest artifact");
    const auto* asset = find_asset(artifact_path);
    if (asset == nullptr) {
      throw BundleError("embedded admission artifact is missing: " + artifact_path);
    }
    require_equal("admission artifact byteLength", byte_length, asset->bytes.size());
    require_equal("admission artifact sha256", expected_digest, sha256_identifier(asset->bytes));
  }

  auto digest_input = manifest;
  digest_input.erase("artifactDigest");
  const auto actual_digest = canonical_sha256(digest_input);
  require_equal("admission manifest artifactDigest", pin.admission.artifact_digest, actual_digest);

  return AdmissionBundleSummary{
      .source_commit = std::string{pin.admission.source_commit},
      .profile_id = std::string{pin.admission.profile_id},
      .manifest_version = pin.admission.manifest_version,
      .cryptography_artifact_digest = cryptography_digest,
      .artifact_digest = actual_digest,
      .artifact_count = artifacts.size(),
      .case_count = cases.size(),
      .evaluation_count = evaluation_count,
  };
}

} // namespace missionweaveprotocol
