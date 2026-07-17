#pragma once

#include <missionweaveprotocol/json.hpp>

#include <stdexcept>
#include <string>
#include <string_view>

namespace missionweaveprotocol {

class CanonicalError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] std::string canonical_json(const Json& value);
[[nodiscard]] std::string canonicalize_json(std::string_view document);
[[nodiscard]] std::string canonical_sha256(const Json& value);
[[nodiscard]] std::string canonical_sha256_document(std::string_view document);

} // namespace missionweaveprotocol
