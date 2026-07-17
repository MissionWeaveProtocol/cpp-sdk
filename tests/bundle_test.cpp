#include <missionweaveprotocol/bundle.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  assert(input);
  return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

} // namespace

int main() {
  using namespace std::string_view_literals;

  const auto pin = missionweaveprotocol::ProtocolBundle::pin();
  assert(pin.commit == "00964ea9064cbf1f0eca8af21a0c57367ee14752"sv);
  assert(pin.protocol_version == "0.1"sv);
  assert(pin.wire_namespace == "missionweaveprotocol"sv);

  const auto summary = missionweaveprotocol::ProtocolBundle::verify();
  assert(summary.schema_files == 21);
  assert(summary.conformance_files == 44);
  assert(summary.bundle_sha256 ==
         "281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda");

  const auto names = missionweaveprotocol::ProtocolBundle::schema_names();
  assert(names.size() == 21);
  assert(std::ranges::is_sorted(names));
  assert(std::ranges::find(names, "mission.schema.json"sv) != names.end());

  assert(missionweaveprotocol::ProtocolBundle::schema("mission.schema.json").has_value());
  assert(!missionweaveprotocol::ProtocolBundle::schema("missing.schema.json").has_value());
  assert(missionweaveprotocol::ProtocolBundle::conformance("manifest.json").has_value());
  assert(
      missionweaveprotocol::ProtocolBundle::conformance("vectors/valid/mission.json").has_value());

  const auto source_pin =
      read_file(std::filesystem::path{MISSIONWEAVEPROTOCOL_SOURCE_DIR} / "PROTOCOL_PIN.json");
  const auto embedded_pin = missionweaveprotocol::ProtocolBundle::protocol_pin_bytes();
  assert(std::ranges::equal(source_pin, embedded_pin));
}
