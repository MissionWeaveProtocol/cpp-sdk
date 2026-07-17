#pragma once

#include <missionweaveprotocol/json.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace missionweaveprotocol {

class SchemaError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

struct ValidationIssue {
  std::string keyword;
  std::string instance_location;
  std::string schema_location;
  std::string message;
};

struct ValidationResult {
  bool valid;
  std::optional<ValidationIssue> issue;

  [[nodiscard]] explicit operator bool() const noexcept { return valid; }
};

class SchemaCatalog final {
public:
  SchemaCatalog();
  ~SchemaCatalog();

  SchemaCatalog(SchemaCatalog&&) noexcept;
  SchemaCatalog& operator=(SchemaCatalog&&) noexcept;

  SchemaCatalog(const SchemaCatalog&) = delete;
  SchemaCatalog& operator=(const SchemaCatalog&) = delete;

  [[nodiscard]] ValidationResult validate(std::string_view schema_name, const Json& instance) const;

private:
  class Impl;
  std::unique_ptr<Impl> implementation_;
};

} // namespace missionweaveprotocol
