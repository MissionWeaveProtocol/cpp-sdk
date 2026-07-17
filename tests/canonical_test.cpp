#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/json.hpp>

#include <array>
#include <bit>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

int main() {
  using namespace std::string_view_literals;

  const auto input = missionweaveprotocol::parse_strict_json(R"({
    "numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],
    "string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
    "literals":[null,true,false]
  })");
  const auto canonical = missionweaveprotocol::canonical_json(input);
  const std::string expected =
      R"JCS({"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"})JCS";
  if (canonical != expected) {
    std::cerr << "canonical mismatch\nexpected: " << expected << "\nactual:   " << canonical
              << '\n';
    return 1;
  }

  const auto thresholds =
      missionweaveprotocol::parse_strict_json(R"([1e20,1e21,1e-6,1e-7,-0.0,1000000000000000100])");
  assert(missionweaveprotocol::canonical_json(thresholds) ==
         "[100000000000000000000,1e+21,0.000001,1e-7,0,1000000000000000100]");

  constexpr std::array number_samples{
      std::pair{0x0000000000000000ULL, "0"sv},
      std::pair{0x8000000000000000ULL, "0"sv},
      std::pair{0x0000000000000001ULL, "5e-324"sv},
      std::pair{0x8000000000000001ULL, "-5e-324"sv},
      std::pair{0x7fefffffffffffffULL, "1.7976931348623157e+308"sv},
      std::pair{0xffefffffffffffffULL, "-1.7976931348623157e+308"sv},
      std::pair{0x4340000000000000ULL, "9007199254740992"sv},
      std::pair{0xc340000000000000ULL, "-9007199254740992"sv},
      std::pair{0x4430000000000000ULL, "295147905179352830000"sv},
      std::pair{0x44b52d02c7e14af5ULL, "9.999999999999997e+22"sv},
      std::pair{0x44b52d02c7e14af6ULL, "1e+23"sv},
      std::pair{0x44b52d02c7e14af7ULL, "1.0000000000000001e+23"sv},
      std::pair{0x444b1ae4d6e2ef4eULL, "999999999999999700000"sv},
      std::pair{0x444b1ae4d6e2ef4fULL, "999999999999999900000"sv},
      std::pair{0x444b1ae4d6e2ef50ULL, "1e+21"sv},
      std::pair{0x3eb0c6f7a0b5ed8cULL, "9.999999999999997e-7"sv},
      std::pair{0x3eb0c6f7a0b5ed8dULL, "0.000001"sv},
      std::pair{0x41b3de4355555553ULL, "333333333.3333332"sv},
      std::pair{0x41b3de4355555554ULL, "333333333.33333325"sv},
      std::pair{0x41b3de4355555555ULL, "333333333.3333333"sv},
      std::pair{0x41b3de4355555556ULL, "333333333.3333334"sv},
      std::pair{0x41b3de4355555557ULL, "333333333.33333343"sv},
      std::pair{0xbecbf647612f3696ULL, "-0.0000033333333333333333"sv},
      std::pair{0x43143ff3c1cb0959ULL, "1424953923781206.2"sv},
  };
  for (const auto& [bits, expected] : number_samples) {
    missionweaveprotocol::Json value = std::bit_cast<double>(bits);
    assert(missionweaveprotocol::canonical_json(value) == expected);
  }

  const auto ordered = missionweaveprotocol::canonicalize_json(
      R"({"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"})");
  const std::vector<std::string> values{
      "Carriage Return",
      "One",
      "Control",
      "Latin Small Letter O With Diaeresis",
      "Euro Sign",
      "Emoji: Grinning Face",
      "Hebrew Letter Dalet With Dagesh",
  };
  std::size_t previous = 0;
  for (const auto& value : values) {
    const auto position = ordered.find(value);
    assert(position != std::string::npos);
    assert(position >= previous);
    previous = position;
  }

  const auto left = missionweaveprotocol::canonical_sha256_document(R"({"z":2,"a":true})");
  const auto right = missionweaveprotocol::canonical_sha256_document(R"({"a":true,"z":2})");
  assert(left == right);
  assert(left.starts_with("sha256:"));
  assert(left.size() == 71);

  missionweaveprotocol::Json infinity = std::numeric_limits<double>::infinity();
  try {
    static_cast<void>(missionweaveprotocol::canonical_json(infinity));
    assert(false && "non-finite number was canonicalized");
  } catch (const missionweaveprotocol::CanonicalError&) {
  }
}
