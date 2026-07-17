#pragma once

#include <missionweaveprotocol/bundle.hpp>

#include <jsoncons/json.hpp>

#include <stdexcept>
#include <string_view>

namespace missionweaveprotocol {

using Json = jsoncons::json;

class StrictJsonError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] Json parse_strict_json(std::string_view text);
[[nodiscard]] Json parse_strict_json(AssetBytes bytes);

} // namespace missionweaveprotocol
