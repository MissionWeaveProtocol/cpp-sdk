#include <missionweaveprotocol/conformance.hpp>

#include <cassert>

int main() {
  const auto report = missionweaveprotocol::ConformanceRunner{}.run();
  assert(report.passed());
  assert(report.results.size() == 52);
  assert(report.passed_count() == 52);
  assert(report.expected_valid_count() == 25);
  assert(report.summary() == "52/52 conformance vectors passed (25 valid, 27 invalid)");
}
