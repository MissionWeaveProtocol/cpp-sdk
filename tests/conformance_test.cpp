#include <missionweaveprotocol/conformance.hpp>

#include <cassert>

int main() {
  const auto report = missionweaveprotocol::ConformanceRunner{}.run();
  assert(report.passed());
  assert(report.results.size() == 43);
  assert(report.passed_count() == 43);
  assert(report.expected_valid_count() == 22);
  assert(report.summary() == "43/43 conformance vectors passed (22 valid, 21 invalid)");
}
