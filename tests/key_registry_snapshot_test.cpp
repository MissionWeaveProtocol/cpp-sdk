#include <missionweaveprotocol/signed_document.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
  std::vector<std::uint8_t> source{1, 2, 3};
  const missionweaveprotocol::KeyRegistrySnapshot snapshot(
      source, missionweaveprotocol::KeyRegistryCompleteness::partial);

  source.assign({9, 8, 7});

  constexpr std::array<std::uint8_t, 3> expected_partial{1, 2, 3};
  assert(std::ranges::equal(snapshot.registry_bytes(), expected_partial));
  assert(snapshot.completeness() == missionweaveprotocol::KeyRegistryCompleteness::partial);

  const auto organization_wide =
      missionweaveprotocol::KeyRegistrySnapshot::organization_wide({4, 5, 6});
  constexpr std::array<std::uint8_t, 3> expected_organization_wide{4, 5, 6};
  assert(std::ranges::equal(organization_wide.registry_bytes(), expected_organization_wide));
  assert(organization_wide.completeness() ==
         missionweaveprotocol::KeyRegistryCompleteness::organization_wide);
}
