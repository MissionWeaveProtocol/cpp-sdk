#pragma once

#include <string_view>

#if defined(MISSIONWEAVEPROTOCOL_SCHEMA_TEST_HOOKS)
#include <cstddef>
#endif

namespace missionweaveprotocol::detail {

[[nodiscard]] bool is_protocol_uri(std::string_view value) noexcept;

#if defined(MISSIONWEAVEPROTOCOL_SCHEMA_TEST_HOOKS)
struct SchemaValidationMetrics {
  std::size_t uri_prevalidation_walks;
  std::size_t jsoncons_validations;
};

void reset_schema_validation_metrics() noexcept;
[[nodiscard]] SchemaValidationMetrics schema_validation_metrics() noexcept;
#endif

} // namespace missionweaveprotocol::detail
