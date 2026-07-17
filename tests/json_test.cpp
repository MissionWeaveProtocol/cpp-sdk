#include <missionweaveprotocol/json.hpp>

#include <cassert>
#include <string>
#include <string_view>

namespace {

void expect_rejected(const std::string_view text) {
  try {
    static_cast<void>(missionweaveprotocol::parse_strict_json(text));
    assert(false && "strict JSON parser accepted invalid input");
  } catch (const missionweaveprotocol::StrictJsonError&) {
  }
}

} // namespace

int main() {
  const auto value = missionweaveprotocol::parse_strict_json(
      R"({"name":"MissionWeaveProtocol","nested":{"ok":true},"number":1.25e2})");
  assert(value.at("name").as<std::string>() == "MissionWeaveProtocol");
  assert(value.at("nested").at("ok").as<bool>());

  expect_rejected(R"({"duplicate":1,"duplicate":2})");
  expect_rejected(R"({"same":1,"\u0073ame":2})");
  expect_rejected(R"({"nested":{"x":1,"x":2}})");
  expect_rejected(R"({"leading":01})");
  expect_rejected(R"({"surrogate":"\uD800"})");
  expect_rejected(R"({"trailing":true} false)");

  std::string invalid_utf8{"{\"value\":\""};
  invalid_utf8.push_back(static_cast<char>(0xC0));
  invalid_utf8 += "\"}";
  expect_rejected(invalid_utf8);
}
