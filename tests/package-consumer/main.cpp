#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/conformance.hpp>
#include <missionweaveprotocol/version.hpp>

#include <iostream>

int main() {
  const auto bundle = missionweaveprotocol::ProtocolBundle::verify();
  const auto conformance = missionweaveprotocol::ConformanceRunner{}.run();
  std::cout << "MissionWeaveProtocol C++ SDK " << missionweaveprotocol::version() << '\n';
  std::cout << bundle.schema_files << " schemas and " << bundle.conformance_files
            << " conformance artifacts verified\n";
  std::cout << conformance.summary() << '\n';
  return conformance.passed() ? 0 : 1;
}
