#pragma once

#include <missionweaveprotocol/signed_document.hpp>

#include <string_view>

namespace missionweaveprotocol::detail {

struct RegistryKeyResolution {
  ResolvedKey resolved_key;
  Ed25519PublicKey public_key;
};

[[nodiscard]] RegistryKeyResolution resolve_agent_registry_key(AssetBytes registry_bytes,
                                                               const KeyResolutionRequest& request);

[[nodiscard]] ExactInstant parse_protocol_instant(std::string_view text);

[[nodiscard]] Ed25519PublicKey decode_strict_ed25519_public_key(std::string_view encoded);

} // namespace missionweaveprotocol::detail
