#pragma once

#include <missionweaveprotocol/signed_document.hpp>

#include <string_view>

namespace missionweaveprotocol::detail {

[[nodiscard]] ExactInstant parse_protocol_instant(std::string_view text);

[[nodiscard]] Ed25519PublicKey decode_strict_ed25519_public_key(std::string_view encoded);

} // namespace missionweaveprotocol::detail
