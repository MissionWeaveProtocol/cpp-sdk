#include <missionweaveprotocol/schema.hpp>

#include <missionweaveprotocol/bundle.hpp>

#include <jsoncons/utility/uri.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <map>
#include <string>
#include <utility>

namespace missionweaveprotocol {

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
    found->second.validate(instance, reporter);
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
