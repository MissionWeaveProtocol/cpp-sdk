#include <missionweaveprotocol/bundle.hpp>

#include "embedded_assets.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>

namespace missionweaveprotocol {
namespace {

constexpr ProtocolPin embedded_pin{
    .repository = "https://github.com/missionweaveprotocol/missionweaveprotocol",
    .commit = "6f10987627d62fb296e3490ceceb5539b1e94b70",
    .protocol_version = "0.1",
    .wire_namespace = "missionweaveprotocol",
    .artifacts =
        {
            .schemas =
                {
                    .path = "schemas",
                    .files = 21,
                    .sha256 = "a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413",
                },
            .conformance =
                {
                    .path = "conformance",
                    .files = 53,
                    .sha256 = "21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da",
                },
        },
    .bundle_sha256 = "b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7",
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

ProtocolPin ProtocolBundle::pin() noexcept { return embedded_pin; }

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

BundleSummary ProtocolBundle::verify() {
  const auto schemas = json_assets("schemas/");
  const auto conformance_assets = json_assets("conformance/");

  verify_tree("schemas", schemas, embedded_pin.artifacts.schemas);
  verify_tree("conformance", conformance_assets, embedded_pin.artifacts.conformance);

  std::vector<const detail::EmbeddedAsset*> bundle;
  bundle.reserve(schemas.size() + conformance_assets.size());
  bundle.insert(bundle.end(), conformance_assets.begin(), conformance_assets.end());
  bundle.insert(bundle.end(), schemas.begin(), schemas.end());
  std::sort(bundle.begin(), bundle.end(),
            [](const auto* left, const auto* right) { return left->path < right->path; });

  const auto bundle_digest = tree_digest(bundle);
  if (bundle_digest != embedded_pin.bundle_sha256) {
    throw BundleError("bundle digest is " + bundle_digest + "; expected " +
                      std::string{embedded_pin.bundle_sha256});
  }

  return BundleSummary{
      .schema_files = schemas.size(),
      .conformance_files = conformance_assets.size(),
      .bundle_sha256 = bundle_digest,
  };
}

} // namespace missionweaveprotocol
