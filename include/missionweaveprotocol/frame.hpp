#pragma once

#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/schema.hpp>

#include <stdexcept>
#include <string>
#include <string_view>

namespace missionweaveprotocol {

class FrameError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class FrameCodec final {
public:
  FrameCodec();

  [[nodiscard]] Json decode(std::string_view document) const;
  [[nodiscard]] Json decode(AssetBytes document) const;
  [[nodiscard]] std::string encode(const Json& frame) const;
  void validate_document(std::string_view schema_name, const Json& document) const;

private:
  SchemaCatalog catalog_;
};

} // namespace missionweaveprotocol
