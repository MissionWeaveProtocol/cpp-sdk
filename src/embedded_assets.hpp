#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace missionweaveprotocol::detail {

struct EmbeddedAsset {
  std::string_view path;
  std::span<const std::uint8_t> bytes;
};

[[nodiscard]] std::span<const EmbeddedAsset> embedded_assets() noexcept;

} // namespace missionweaveprotocol::detail
