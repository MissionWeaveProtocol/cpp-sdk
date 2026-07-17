#pragma once

#include <missionweaveprotocol/schema.hpp>

#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace missionweaveprotocol {

class ConformanceError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

struct VectorResult {
  std::string name;
  bool expected_valid;
  bool actual_valid;
  std::string error;

  [[nodiscard]] bool passed() const noexcept { return expected_valid == actual_valid; }
};

struct ConformanceReport {
  std::vector<VectorResult> results;

  [[nodiscard]] bool passed() const noexcept;
  [[nodiscard]] std::size_t passed_count() const noexcept;
  [[nodiscard]] std::size_t expected_valid_count() const noexcept;
  [[nodiscard]] std::string summary() const;
};

class ConformanceRunner final {
public:
  ConformanceRunner();

  [[nodiscard]] ConformanceReport run() const;

private:
  SchemaCatalog catalog_;
};

} // namespace missionweaveprotocol
