#include <missionweaveprotocol/conformance.hpp>

#include <exception>
#include <iostream>

int main() {
  try {
    const auto report = missionweaveprotocol::ConformanceRunner{}.run();
    std::cout << report.summary() << '\n';
    if (report.passed()) {
      return 0;
    }

    for (const auto& result : report.results) {
      if (!result.passed()) {
        std::cerr << "FAIL: " << result.name << " expected "
                  << (result.expected_valid ? "valid" : "invalid") << " but observed "
                  << (result.actual_valid ? "valid" : "invalid");
        if (!result.error.empty()) {
          std::cerr << ": " << result.error;
        }
        std::cerr << '\n';
      }
    }
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "MissionWeaveProtocol conformance error: " << error.what() << '\n';
    return 2;
  }
}
