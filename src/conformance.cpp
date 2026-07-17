#include <missionweaveprotocol/conformance.hpp>

#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/json.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <string_view>

namespace missionweaveprotocol {
namespace {

[[nodiscard]] std::string_view safe_relative_path(const std::string_view path,
                                                  const std::string_view prefix) {
  if (!path.starts_with(prefix)) {
    throw ConformanceError("unexpected conformance path: " + std::string{path});
  }
  const auto relative = path.substr(prefix.size());
  if (relative.empty() || relative.starts_with('/') ||
      relative.find('\\') != std::string_view::npos) {
    throw ConformanceError("unsafe conformance path: " + std::string{path});
  }

  std::size_t start = 0;
  while (start <= relative.size()) {
    const auto end = relative.find('/', start);
    const auto segment = relative.substr(
        start, end == std::string_view::npos ? relative.size() - start : end - start);
    if (segment.empty() || segment == "..") {
      throw ConformanceError("unsafe conformance path: " + std::string{path});
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1;
  }
  return relative;
}

[[nodiscard]] std::string required_string(const Json& object, const std::string_view key) {
  if (!object.contains(key) || !object.at(key).is_string()) {
    throw ConformanceError("manifest field must be a string: " + std::string{key});
  }
  return object.at(key).as<std::string>();
}

} // namespace

bool ConformanceReport::passed() const noexcept {
  return std::ranges::all_of(results, &VectorResult::passed);
}

std::size_t ConformanceReport::passed_count() const noexcept {
  return static_cast<std::size_t>(std::ranges::count_if(results, &VectorResult::passed));
}

std::size_t ConformanceReport::expected_valid_count() const noexcept {
  return static_cast<std::size_t>(std::ranges::count(results, true, &VectorResult::expected_valid));
}

std::string ConformanceReport::summary() const {
  return std::to_string(passed_count()) + "/" + std::to_string(results.size()) +
         " conformance vectors passed (" + std::to_string(expected_valid_count()) + " valid, " +
         std::to_string(results.size() - expected_valid_count()) + " invalid)";
}

ConformanceRunner::ConformanceRunner() = default;

ConformanceReport ConformanceRunner::run() const {
  const auto manifest_bytes = ProtocolBundle::conformance("manifest.json");
  if (!manifest_bytes) {
    throw ConformanceError("embedded conformance manifest is missing");
  }

  const auto manifest = parse_strict_json(*manifest_bytes);
  if (!manifest.is_array()) {
    throw ConformanceError("embedded conformance manifest must be an array");
  }

  std::set<std::string> names;
  ConformanceReport report;
  report.results.reserve(manifest.size());

  for (const auto& entry : manifest.array_range()) {
    if (!entry.is_object()) {
      throw ConformanceError("conformance manifest entry must be an object");
    }
    const auto name = required_string(entry, "name");
    if (!names.insert(name).second) {
      throw ConformanceError("duplicate conformance vector name: " + name);
    }
    const auto schema_path = required_string(entry, "schema");
    const auto instance_path = required_string(entry, "instance");
    if (!entry.contains("valid") || !entry.at("valid").is_bool()) {
      throw ConformanceError("manifest field must be a boolean: valid");
    }
    const auto expected_valid = entry.at("valid").as<bool>();

    const auto schema_name = safe_relative_path(schema_path, "schemas/");
    const auto instance_name = safe_relative_path(instance_path, "conformance/");
    const auto instance_bytes = ProtocolBundle::conformance(instance_name);
    if (!instance_bytes) {
      throw ConformanceError("embedded conformance vector is missing: " + instance_path);
    }
    const auto instance = parse_strict_json(*instance_bytes);
    const auto validation = catalog_.validate(schema_name, instance);
    report.results.push_back(VectorResult{
        .name = name,
        .expected_valid = expected_valid,
        .actual_valid = validation.valid,
        .error = validation.issue ? validation.issue->message : std::string{},
    });
  }

  return report;
}

} // namespace missionweaveprotocol
