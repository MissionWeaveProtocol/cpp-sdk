#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/schema.hpp>

#include <cassert>

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

  try {
    static_cast<void>(catalog.validate("missing.schema.json", presence));
    assert(false && "unknown schema was accepted");
  } catch (const missionweaveprotocol::SchemaError&) {
  }
}
