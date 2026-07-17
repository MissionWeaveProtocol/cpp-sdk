#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/version.hpp>

#include <iostream>

int main() {
  const auto bundle = missionweaveprotocol::ProtocolBundle::verify();
  std::cout << "MissionWeaveProtocol C++ SDK " << missionweaveprotocol::version() << '\n';
  std::cout << bundle.schema_files << " schemas and " << bundle.conformance_files
            << " conformance artifacts verified\n";
}
