#include <missionweaveprotocol/schema.hpp>

#include <missionweaveprotocol/bundle.hpp>

#include "schema_internal.hpp"

#include <openssl/x509v3.h>

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

[[nodiscard]] bool is_digit(const char value) noexcept { return value >= '0' && value <= '9'; }

[[nodiscard]] bool is_scheme_character(const char value) noexcept {
  return is_alpha(value) || is_digit(value) || value == '+' || value == '-' || value == '.';
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

[[nodiscard]] bool has_valid_scheme(const std::string_view value,
                                    const std::size_t colon) noexcept {
  return colon != std::string_view::npos && colon != 0 && is_alpha(value.front()) &&
         std::ranges::all_of(value.begin() + 1, value.begin() + colon, is_scheme_character);
}

[[nodiscard]] bool is_empty_hier_part_absolute_uri(const std::string_view value) noexcept {
  const auto colon = value.find(':');
  return colon != std::string_view::npos && colon + 1 == value.size() &&
         has_valid_scheme(value, colon);
}

[[nodiscard]] bool has_visible_ascii_only(const std::string_view value) noexcept {
  return std::ranges::all_of(value, [](const char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte >= 0x21 && byte <= 0x7e;
  });
}

[[nodiscard]] bool is_unreserved(const char value) noexcept {
  return is_alpha(value) || is_digit(value) || value == '-' || value == '.' || value == '_' ||
         value == '~';
}

[[nodiscard]] bool is_sub_delimiter(const char value) noexcept {
  switch (value) {
  case '!':
  case '$':
  case '&':
  case '\'':
  case '(':
  case ')':
  case '*':
  case '+':
  case ',':
  case ';':
  case '=':
    return true;
  default:
    return false;
  }
}

[[nodiscard]] bool is_pchar(const char value) noexcept {
  return is_unreserved(value) || is_sub_delimiter(value) || value == ':' || value == '@';
}

template <typename Allowed>
[[nodiscard]] bool component_matches(const std::string_view value, Allowed allowed) noexcept {
  for (std::size_t index = 0; index < value.size();) {
    if (value[index] == '%') {
      if (index + 2 >= value.size() || !is_hex_digit(value[index + 1]) ||
          !is_hex_digit(value[index + 2])) {
        return false;
      }
      index += 3;
      continue;
    }
    if (!allowed(value[index])) {
      return false;
    }
    ++index;
  }
  return true;
}

[[nodiscard]] bool is_ipv_future(const std::string_view value) noexcept {
  if (value.size() < 4 || (value.front() != 'v' && value.front() != 'V')) {
    return false;
  }
  const auto dot = value.find('.', 1);
  if (dot == std::string_view::npos || dot == 1 || dot + 1 == value.size() ||
      !std::ranges::all_of(value.begin() + 1, value.begin() + dot, is_hex_digit)) {
    return false;
  }
  return std::ranges::all_of(value.begin() + dot + 1, value.end(), [](const char character) {
    return is_unreserved(character) || is_sub_delimiter(character) || character == ':';
  });
}

[[nodiscard]] bool is_ipv6_address(const std::string_view value) noexcept {
  try {
    const std::string address{value};
    auto* encoded = a2i_IPADDRESS(address.c_str());
    if (encoded == nullptr) {
      return false;
    }
    const auto is_ipv6 = ASN1_STRING_length(encoded) == 16;
    ASN1_OCTET_STRING_free(encoded);
    return is_ipv6;
  } catch (...) {
    return false;
  }
}

[[nodiscard]] bool is_ip_literal(const std::string_view value) noexcept {
  return is_ipv_future(value) || is_ipv6_address(value);
}

[[nodiscard]] bool is_valid_port(const std::string_view value) noexcept {
  return std::ranges::all_of(value, is_digit);
}

[[nodiscard]] bool is_valid_authority(const std::string_view authority) noexcept {
  auto host_port = authority;
  const auto at = authority.find('@');
  if (at != std::string_view::npos) {
    if (authority.find('@', at + 1) != std::string_view::npos ||
        !component_matches(authority.substr(0, at), [](const char character) {
          return is_unreserved(character) || is_sub_delimiter(character) || character == ':';
        })) {
      return false;
    }
    host_port = authority.substr(at + 1);
  }

  if (host_port.starts_with('[')) {
    const auto close = host_port.find(']');
    if (close == std::string_view::npos || close == 1 ||
        host_port.find('[', 1) != std::string_view::npos ||
        host_port.find(']', close + 1) != std::string_view::npos ||
        !is_ip_literal(host_port.substr(1, close - 1))) {
      return false;
    }
    const auto remainder = host_port.substr(close + 1);
    return remainder.empty() || (remainder.front() == ':' && is_valid_port(remainder.substr(1)));
  }

  if (host_port.find_first_of("[]") != std::string_view::npos) {
    return false;
  }

  auto host = host_port;
  std::string_view port;
  const auto colon = host_port.find(':');
  if (colon != std::string_view::npos) {
    if (host_port.find(':', colon + 1) != std::string_view::npos) {
      return false;
    }
    host = host_port.substr(0, colon);
    port = host_port.substr(colon + 1);
  }
  return component_matches(host,
                           [](const char character) {
                             return is_unreserved(character) || is_sub_delimiter(character);
                           }) &&
         is_valid_port(port);
}

[[nodiscard]] bool is_valid_path_abempty(const std::string_view path) noexcept {
  return (path.empty() || path.front() == '/') && component_matches(path, [](const char character) {
           return is_pchar(character) || character == '/';
         });
}

[[nodiscard]] bool is_valid_path_absolute(const std::string_view path) noexcept {
  if (path.empty() || path.front() != '/') {
    return false;
  }
  if (path.size() == 1) {
    return true;
  }
  return path[1] != '/' && component_matches(path.substr(1), [](const char character) {
           return is_pchar(character) || character == '/';
         });
}

[[nodiscard]] bool is_valid_path_rootless(const std::string_view path) noexcept {
  if (path.empty() || path.front() == '/') {
    return false;
  }
  const auto first_is_pchar = path.front() == '%' || is_pchar(path.front());
  return first_is_pchar && component_matches(path, [](const char character) {
           return is_pchar(character) || character == '/';
         });
}

[[nodiscard]] bool is_valid_hier_part(const std::string_view hier_part) noexcept {
  if (hier_part.starts_with("//")) {
    const auto path_start = hier_part.find('/', 2);
    const auto authority = hier_part.substr(2, path_start - 2);
    const auto path =
        path_start == std::string_view::npos ? std::string_view{} : hier_part.substr(path_start);
    return is_valid_authority(authority) && is_valid_path_abempty(path);
  }
  if (hier_part.empty()) {
    return true;
  }
  return hier_part.front() == '/' ? is_valid_path_absolute(hier_part)
                                  : is_valid_path_rootless(hier_part);
}

[[nodiscard]] bool is_valid_query_or_fragment(const std::string_view value) noexcept {
  return component_matches(value, [](const char character) {
    return is_pchar(character) || character == '/' || character == '?';
  });
}

[[nodiscard]] bool is_protocol_uri_impl(const std::string_view value) noexcept {
  if (value.empty() || !has_visible_ascii_only(value) || !has_valid_percent_triplets(value)) {
    return false;
  }
  const auto colon = value.find(':');
  if (!has_valid_scheme(value, colon)) {
    return false;
  }

  const auto fragment_delimiter = value.find('#', colon + 1);
  const auto before_fragment_end =
      fragment_delimiter == std::string_view::npos ? value.size() : fragment_delimiter;
  const auto query_delimiter = value.find('?', colon + 1);
  const auto has_query =
      query_delimiter != std::string_view::npos && query_delimiter < before_fragment_end;
  const auto hier_part_end = has_query ? query_delimiter : before_fragment_end;
  if (!is_valid_hier_part(value.substr(colon + 1, hier_part_end - colon - 1))) {
    return false;
  }
  if (has_query && !is_valid_query_or_fragment(value.substr(
                       query_delimiter + 1, before_fragment_end - query_delimiter - 1))) {
    return false;
  }
  return fragment_delimiter == std::string_view::npos ||
         is_valid_query_or_fragment(value.substr(fragment_delimiter + 1));
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

namespace detail {

bool is_protocol_uri(const std::string_view value) noexcept { return is_protocol_uri_impl(value); }

} // namespace detail

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
