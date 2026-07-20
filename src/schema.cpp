#include <missionweaveprotocol/schema.hpp>

#include <missionweaveprotocol/bundle.hpp>

#include "schema_internal.hpp"

#include <jsoncons/utility/uri.hpp>
#include <jsoncons_ext/jsonpointer/jsonpointer.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace missionweaveprotocol {
namespace detail {
#if defined(MISSIONWEAVEPROTOCOL_SCHEMA_TEST_HOOKS)
namespace {

thread_local SchemaValidationMetrics validation_metrics{};

} // namespace

void reset_schema_validation_metrics() noexcept { validation_metrics = {}; }

SchemaValidationMetrics schema_validation_metrics() noexcept { return validation_metrics; }

void record_uri_prevalidation_walk() noexcept { ++validation_metrics.uri_prevalidation_walks; }

void record_jsoncons_validation() noexcept { ++validation_metrics.jsoncons_validations; }
#endif

} // namespace detail

namespace {

constexpr std::string_view identifier_format_location =
    "https://missionweaveprotocol.dev/schemas/0.1/common.schema.json#/$defs/id/format";

[[nodiscard]] bool is_alpha(const char value) noexcept {
  return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

[[nodiscard]] bool is_scheme_character(const char value) noexcept {
  return is_alpha(value) || (value >= '0' && value <= '9') || value == '+' || value == '-' ||
         value == '.';
}

[[nodiscard]] bool is_hex_digit(const char value) noexcept {
  return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'F') ||
         (value >= 'a' && value <= 'f');
}

[[nodiscard]] bool has_valid_percent_triplets(const std::string_view value) noexcept {
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (value[index] != '%') {
      continue;
    }
    if (index + 2 >= value.size() || !is_hex_digit(value[index + 1]) ||
        !is_hex_digit(value[index + 2])) {
      return false;
    }
    index += 2;
  }
  return true;
}

[[nodiscard]] bool is_empty_hier_part_absolute_uri(const std::string_view value) noexcept {
  return value.size() >= 2 && value.back() == ':' && is_alpha(value.front()) &&
         std::ranges::all_of(value.begin() + 1, value.end() - 1, is_scheme_character);
}

struct IdentifierRepair {
  std::string instance_location;
  std::string value;
};

struct IdentifierPrevalidation {
  std::optional<ValidationIssue> issue;
  std::vector<IdentifierRepair> repairs;
  std::set<std::string> identifier_values;
};

template <typename Schema>
[[nodiscard]] IdentifierPrevalidation prevalidate_identifier_uris(const Schema& schema,
                                                                  const Json& document) {
  // jsoncons 1.8.1 accepts malformed percent escapes, so supplement the shared identifier URI
  // format before delegating the rest of RFC 3986 validation to jsoncons. It also rejects legal
  // absolute URIs with an empty hier-part, so collect those locations for a validator-only copy.
#if defined(MISSIONWEAVEPROTOCOL_SCHEMA_TEST_HOOKS)
  detail::record_uri_prevalidation_walk();
#endif
  IdentifierPrevalidation result;
  const auto reporter = [&result](const jsoncons::jsonschema::schema_property<Json>& property,
                                  const Json& instance,
                                  const jsoncons::jsonpointer::json_pointer& instance_location,
                                  jsoncons::optional<Json>&) {
    if (property.keyword() != "format" ||
        property.schema_location().string() != identifier_format_location ||
        !instance.is_string()) {
      return jsoncons::jsonschema::walk_state::advance;
    }

    const auto value = instance.as<std::string>();
    result.identifier_values.insert(value);
    if (!has_valid_percent_triplets(value)) {
      result.issue = ValidationIssue{
          .keyword = property.keyword(),
          .instance_location = instance_location.to_string(),
          .schema_location = property.schema_location().string(),
          .message = "'" + value + "': Invalid percent-encoded octet",
      };
      return jsoncons::jsonschema::walk_state::abort;
    }
    if (is_empty_hier_part_absolute_uri(value)) {
      result.repairs.push_back(IdentifierRepair{
          .instance_location = instance_location.to_string(),
          .value = value,
      });
    }
    return jsoncons::jsonschema::walk_state::advance;
  };
  schema.walk(document, reporter);
  return result;
}

} // namespace

class SchemaCatalog::Impl final {
public:
  using CompiledSchema = jsoncons::jsonschema::json_schema<Json>;

  Impl() {
    std::map<std::string, Json> documents;
    std::map<std::string, Json> documents_by_id;

    for (const auto name : ProtocolBundle::schema_names()) {
      const auto bytes = ProtocolBundle::schema(name);
      if (!bytes) {
        throw SchemaError("embedded schema is missing: " + std::string{name});
      }
      auto document = parse_strict_json(*bytes);
      if (!document.is_object() || !document.contains("$id") || !document.at("$id").is_string()) {
        throw SchemaError("embedded schema has no string $id: " + std::string{name});
      }
      const auto id = document.at("$id").as<std::string>();
      if (!documents_by_id.emplace(id, document).second) {
        throw SchemaError("duplicate embedded schema $id: " + id);
      }
      documents.emplace(name, std::move(document));
    }

    const auto resolver = [&documents_by_id](const jsoncons::uri& uri) -> Json {
      const auto found = documents_by_id.find(uri.base().string());
      return found == documents_by_id.end() ? Json::null() : found->second;
    };
    const auto options = jsoncons::jsonschema::evaluation_options{}.require_format_validation(true);

    for (const auto& [name, document] : documents) {
      const auto id = document.at("$id").as<std::string>();
      try {
        compiled_.emplace(name,
                          jsoncons::jsonschema::make_json_schema(document, id, resolver, options));
      } catch (const std::exception& error) {
        throw SchemaError("unable to compile " + name + ": " + error.what());
      }
    }
  }

  [[nodiscard]] ValidationResult validate(const std::string_view schema_name,
                                          const Json& instance) const {
    const auto found = compiled_.find(std::string{schema_name});
    if (found == compiled_.end()) {
      throw SchemaError("unknown embedded schema: " + std::string{schema_name});
    }

    auto prevalidation = prevalidate_identifier_uris(found->second, instance);
    if (prevalidation.issue) {
      return ValidationResult{.valid = false, .issue = std::move(prevalidation.issue)};
    }

    const Json* document = &instance;
    std::optional<Json> adjusted;
    if (!prevalidation.repairs.empty()) {
      adjusted.emplace(instance);
      std::map<std::string, std::string> replacements;
      auto occupied_values = std::move(prevalidation.identifier_values);
      std::size_t replacement_index = 0;
      for (const auto& repair : prevalidation.repairs) {
        auto replacement = replacements.find(repair.value);
        if (replacement == replacements.end()) {
          std::string candidate;
          do {
            candidate = "x-missionweaveprotocol-validator:" + std::to_string(replacement_index++);
          } while (occupied_values.contains(candidate));
          occupied_values.insert(candidate);
          replacement = replacements.emplace(repair.value, std::move(candidate)).first;
        }

        std::error_code error;
        jsoncons::jsonpointer::replace(*adjusted, repair.instance_location, replacement->second,
                                       error);
        if (error) {
          throw SchemaError("unable to prepare identifier URI validation at " +
                            repair.instance_location + ": " + error.message());
        }
      }
      document = &*adjusted;
    }

    std::optional<ValidationIssue> issue;
    const auto reporter = [&issue](const jsoncons::jsonschema::validation_message& message) {
      issue = ValidationIssue{
          .keyword = message.keyword(),
          .instance_location = message.instance_location().to_string(),
          .schema_location = message.schema_location().string(),
          .message = message.message(),
      };
      return jsoncons::jsonschema::walk_state::abort;
    };
#if defined(MISSIONWEAVEPROTOCOL_SCHEMA_TEST_HOOKS)
    detail::record_jsoncons_validation();
#endif
    found->second.validate(*document, reporter);
    return ValidationResult{.valid = !issue.has_value(), .issue = std::move(issue)};
  }

private:
  std::map<std::string, CompiledSchema> compiled_;
};

SchemaCatalog::SchemaCatalog() : implementation_(std::make_unique<Impl>()) {}

SchemaCatalog::~SchemaCatalog() = default;

SchemaCatalog::SchemaCatalog(SchemaCatalog&&) noexcept = default;

SchemaCatalog& SchemaCatalog::operator=(SchemaCatalog&&) noexcept = default;

ValidationResult SchemaCatalog::validate(const std::string_view schema_name,
                                         const Json& instance) const {
  return implementation_->validate(schema_name, instance);
}

} // namespace missionweaveprotocol
