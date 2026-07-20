#include <missionweaveprotocol/conformance.hpp>

#include <cassert>

int main() {
  const auto report = missionweaveprotocol::ConformanceRunner{}.run();
  assert(report.passed());
  assert(report.results.size() == 56);
  assert(report.passed_count() == 56);
  assert(report.expected_valid_count() == 26);
  assert(report.summary() == "56/56 conformance vectors passed (26 valid, 30 invalid)");
}
