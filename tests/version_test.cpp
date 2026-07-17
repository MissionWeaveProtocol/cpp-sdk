#include <missionweaveprotocol/version.hpp>

#include <cassert>

int main() {
  using namespace std::string_view_literals;

  assert(missionweaveprotocol::version() == "0.1.0"sv);
  assert(missionweaveprotocol::protocol_version == "0.1"sv);
  assert(missionweaveprotocol::wire_namespace == "missionweaveprotocol"sv);
}
