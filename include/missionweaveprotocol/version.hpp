#pragma once

#include <string_view>

namespace missionweaveprotocol {

inline constexpr std::string_view sdk_version = "0.1.0";
inline constexpr std::string_view protocol_version = "0.1";
inline constexpr std::string_view wire_namespace = "missionweaveprotocol";

[[nodiscard]] std::string_view version() noexcept;

} // namespace missionweaveprotocol
