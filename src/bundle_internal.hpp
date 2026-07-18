#pragma once

#include <missionweaveprotocol/bundle.hpp>

namespace missionweaveprotocol::detail {

[[nodiscard]] ProtocolPin parse_protocol_pin(AssetBytes bytes);

} // namespace missionweaveprotocol::detail
