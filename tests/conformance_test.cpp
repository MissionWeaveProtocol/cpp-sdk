#include <missionweaveprotocol/conformance.hpp>

#include <cassert>

int main() {
  const auto report = missionweaveprotocol::ConformanceRunner{}.run();
  assert(report.passed());
  assert(report.results.size() == 58);
  assert(report.passed_count() == 58);
  assert(report.expected_valid_count() == 27);
  assert(report.summary() == "58/58 conformance vectors passed (27 valid, 31 invalid)");
}
