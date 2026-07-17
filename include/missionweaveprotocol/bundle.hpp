#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace missionweaveprotocol {

using AssetBytes = std::span<const std::uint8_t>;

struct ArtifactPin {
  std::string_view path;
  std::size_t files;
  std::string_view sha256;
};

struct ProtocolArtifacts {
  ArtifactPin schemas;
  ArtifactPin conformance;
};

struct ProtocolPin {
  std::string_view repository;
  std::string_view commit;
  std::string_view protocol_version;
  std::string_view wire_namespace;
  ProtocolArtifacts artifacts;
  std::string_view bundle_sha256;
};

struct BundleSummary {
  std::size_t schema_files;
  std::size_t conformance_files;
  std::string bundle_sha256;
};

class BundleError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class ProtocolBundle final {
public:
  [[nodiscard]] static ProtocolPin pin() noexcept;
  [[nodiscard]] static AssetBytes protocol_pin_bytes() noexcept;
  [[nodiscard]] static std::optional<AssetBytes> schema(std::string_view name) noexcept;
  [[nodiscard]] static std::vector<std::string_view> schema_names();
  [[nodiscard]] static std::optional<AssetBytes> conformance(std::string_view path) noexcept;
  [[nodiscard]] static BundleSummary verify();
};

} // namespace missionweaveprotocol
