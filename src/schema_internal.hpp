#pragma once

#if defined(MISSIONWEAVEPROTOCOL_SCHEMA_TEST_HOOKS)
#include <cstddef>

namespace missionweaveprotocol::detail {

struct SchemaValidationMetrics {
  std::size_t uri_prevalidation_walks;
  std::size_t jsoncons_validations;
};

void reset_schema_validation_metrics() noexcept;
[[nodiscard]] SchemaValidationMetrics schema_validation_metrics() noexcept;

} // namespace missionweaveprotocol::detail
#endif
