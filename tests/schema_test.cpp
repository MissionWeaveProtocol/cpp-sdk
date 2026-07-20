#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/schema.hpp>

#include "schema_internal.hpp"

#include <array>
#include <cassert>
#include <string_view>

int main() {
  const missionweaveprotocol::SchemaCatalog catalog;

  const auto valid_bytes =
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/mission.json");
  const auto invalid_bytes = missionweaveprotocol::ProtocolBundle::conformance(
      "vectors/invalid/mission-without-final-human-approval.json");
  assert(valid_bytes && invalid_bytes);
  assert(catalog.validate("mission.schema.json",
                          missionweaveprotocol::parse_strict_json(*valid_bytes)));

  const auto invalid = catalog.validate("mission.schema.json",
                                        missionweaveprotocol::parse_strict_json(*invalid_bytes));
  assert(!invalid);
  assert(invalid.issue.has_value());

  const auto presence_bytes =
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/presence-record.json");
  assert(presence_bytes);
  auto presence = missionweaveprotocol::parse_strict_json(*presence_bytes);
  presence["lastHeartbeat"] = "not-a-date-time";
  const auto bad_format = catalog.validate("presence-record.schema.json", presence);
  assert(!bad_format);
  assert(bad_format.issue.has_value());
  assert(bad_format.issue->keyword == "format");

  const auto empty_hier_part = missionweaveprotocol::ProtocolBundle::conformance(
      "vectors/valid/command-action-id-empty-hier-part.json");
  assert(empty_hier_part);
  assert(catalog.validate("command.schema.json",
                          missionweaveprotocol::parse_strict_json(*empty_hier_part)));

  const auto command_bytes =
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/command.json");
  assert(command_bytes);
  auto percent_encoded = missionweaveprotocol::parse_strict_json(*command_bytes);
  percent_encoded["actionId"] = "https://example.test/actions/%E4%BE%8B";
  assert(catalog.validate("command.schema.json", percent_encoded));

  for (const auto malformed :
       std::array{std::string_view{"example:%"}, std::string_view{"example:%Z"},
                  std::string_view{"example:%ZZ"},
                  std::string_view{"https://example.test/action?bad=%GG"}}) {
    auto command = missionweaveprotocol::parse_strict_json(*command_bytes);
    command["actionId"] = malformed;
    const auto result = catalog.validate("command.schema.json", command);
    assert(!result);
    assert(result.issue.has_value());
    assert(result.issue->keyword == "format");
    if (malformed == "example:%ZZ") {
      assert(result.issue->instance_location == "/actionId");
      assert(result.issue->schema_location ==
             "https://missionweaveprotocol.dev/schemas/0.1/common.schema.json#/$defs/id/format");
      assert(result.issue->message == "'example:%ZZ': Invalid percent-encoded octet");
    }
  }

  const auto snapshot_bytes =
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/group-snapshot.json");
  assert(snapshot_bytes);
  auto snapshot = missionweaveprotocol::parse_strict_json(*snapshot_bytes);
  snapshot["snapshotId"] = "snapshot:";
  snapshot["groupId"] = "group:";
  snapshot["eventIds"].at(0) = "event:";
  snapshot["eventIds"].at(1) = "example:";

  auto duplicate_snapshot = snapshot;
  duplicate_snapshot["eventIds"].at(1) = "event:";
  missionweaveprotocol::detail::reset_schema_validation_metrics();
  const auto duplicate_result = catalog.validate("group-snapshot.schema.json", duplicate_snapshot);
  assert(!duplicate_result);
  assert(duplicate_result.issue.has_value());
  assert(duplicate_result.issue->keyword == "uniqueItems");
  const auto duplicate_metrics = missionweaveprotocol::detail::schema_validation_metrics();
  assert(duplicate_metrics.uri_prevalidation_walks == 1);
  assert(duplicate_metrics.jsoncons_validations == 1);

  missionweaveprotocol::detail::reset_schema_validation_metrics();
  const auto snapshot_result = catalog.validate("group-snapshot.schema.json", snapshot);
  const auto metrics = missionweaveprotocol::detail::schema_validation_metrics();
  assert(metrics.uri_prevalidation_walks == 1);
  assert(metrics.jsoncons_validations == 1);
  assert(snapshot_result);

  const auto assert_invalid_identifier = [&catalog](const std::string_view path) {
    const auto bytes = missionweaveprotocol::ProtocolBundle::conformance(path);
    assert(bytes);
    assert(
        !catalog.validate("command.schema.json", missionweaveprotocol::parse_strict_json(*bytes)));
  };
  assert_invalid_identifier("vectors/invalid/command-action-id-trailing-line-feed.json");
  assert_invalid_identifier("vectors/invalid/command-action-id-relative-reference.json");
  assert_invalid_identifier("vectors/invalid/command-action-id-iri-only.json");

  try {
    static_cast<void>(catalog.validate("missing.schema.json", presence));
    assert(false && "unknown schema was accepted");
  } catch (const missionweaveprotocol::SchemaError&) {
  }
}
