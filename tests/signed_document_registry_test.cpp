#include "signed_document_registry_test_support.hpp"

#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace support = signed_document_registry_test_support;

constexpr std::size_t unselected_binding_index = 1;

template <typename Mutation> void expect_mutation_rejected(Mutation mutation) {
  auto registry = support::valid_registry_json();
  mutation(registry);
  static_cast<void>(support::expect_registry_rejected(registry));
}

template <typename Mutation> void expect_mutation_accepted(Mutation mutation) {
  auto registry = support::valid_registry_json();
  mutation(registry);
  static_cast<void>(support::verify_accepts(registry));
}

void add_unselected_history_status(missionweaveprotocol::Json& registry) {
  support::history(registry, unselected_binding_index)
      .push_back(missionweaveprotocol::parse_strict_json(
          R"({"sequence":1,"recordedAt":"2026-07-02T00:00:00Z"})"));
}

void test_completeness_precedes_registry_parsing() {
  const std::vector<std::uint8_t> malformed{'{'};
  for (const auto completeness : {missionweaveprotocol::KeyRegistryCompleteness::partial,
                                  missionweaveprotocol::KeyRegistryCompleteness::unspecified}) {
    static_cast<void>(support::expect_registry_rejected(
        malformed, completeness, "Registry evidence is not Organization-wide complete"));
  }

  static_cast<void>(support::expect_registry_rejected(
      malformed, missionweaveprotocol::KeyRegistryCompleteness::organization_wide));

  const support::SnapshotResolver unavailable("Registry unavailable");
  static_cast<void>(support::expect_key_resolution_failure(
      unavailable, support::golden_command_bytes(), "Registry unavailable"));
  assert(unavailable.calls == 1);
}

void test_registry_bytes_are_strict_json() {
  auto invalid_utf8 = support::valid_registry_bytes();
  invalid_utf8.push_back(0xff);
  static_cast<void>(support::expect_registry_rejected(invalid_utf8));

  auto bom = support::valid_registry_bytes();
  bom.insert(bom.begin(), {0xef, 0xbb, 0xbf});
  static_cast<void>(support::expect_registry_rejected(bom));

  const auto valid = support::valid_registry_bytes();
  std::string duplicate{reinterpret_cast<const char*>(valid.data()), valid.size()};
  duplicate.insert(duplicate.find('{') + 1,
                   "\"organization\\u0049d\":\"urn:missionweaveprotocol:organization:duplicate\",");
  const auto* duplicate_begin = reinterpret_cast<const std::uint8_t*>(duplicate.data());
  const std::vector<std::uint8_t> duplicate_bytes(duplicate_begin,
                                                  duplicate_begin + duplicate.size());
  static_cast<void>(support::expect_registry_rejected(duplicate_bytes));

  auto trailing = support::valid_registry_bytes();
  constexpr std::string_view extra = " true";
  trailing.insert(trailing.end(), extra.begin(), extra.end());
  static_cast<void>(support::expect_registry_rejected(trailing));
}

void test_registry_root_shape_is_exact() {
  static_cast<void>(
      support::expect_registry_rejected(missionweaveprotocol::parse_strict_json("[]")));

  for (const auto field :
       std::array{std::string_view{"organizationId"}, std::string_view{"bindings"}}) {
    expect_mutation_rejected(
        [field](missionweaveprotocol::Json& registry) { registry.erase(field); });
  }

  expect_mutation_rejected(
      [](missionweaveprotocol::Json& registry) { registry["unexpected"] = true; });
  expect_mutation_rejected(
      [](missionweaveprotocol::Json& registry) { registry["bindings"] = true; });
  expect_mutation_rejected([](missionweaveprotocol::Json& registry) {
    registry["bindings"] = missionweaveprotocol::parse_strict_json("[]");
  });
}

void test_registry_binding_shape_is_exact_even_when_unselected() {
  expect_mutation_rejected([](missionweaveprotocol::Json& registry) {
    support::binding(registry, unselected_binding_index) = missionweaveprotocol::Json::null();
  });

  for (const auto field :
       std::array{std::string_view{"keyId"}, std::string_view{"principal"},
                  std::string_view{"algorithm"}, std::string_view{"publicKey"},
                  std::string_view{"validFrom"}, std::string_view{"validityHistory"}}) {
    expect_mutation_rejected([field](missionweaveprotocol::Json& registry) {
      support::binding(registry, unselected_binding_index).erase(field);
    });
  }

  expect_mutation_rejected([](missionweaveprotocol::Json& registry) {
    support::binding(registry, unselected_binding_index)["unexpected"] = true;
  });
}

void test_registry_principal_shape_and_type_are_exact_even_when_unselected() {
  for (const auto field : std::array{std::string_view{"type"}, std::string_view{"id"}}) {
    expect_mutation_rejected([field](missionweaveprotocol::Json& registry) {
      support::principal(registry, unselected_binding_index).erase(field);
    });
  }

  expect_mutation_rejected([](missionweaveprotocol::Json& registry) {
    support::principal(registry, unselected_binding_index)["unexpected"] = true;
  });
  expect_mutation_rejected([](missionweaveprotocol::Json& registry) {
    support::principal(registry, unselected_binding_index)["type"] = "organization";
  });

  for (const auto type : std::array{std::string_view{"agent"}, std::string_view{"human"},
                                    std::string_view{"service"}}) {
    expect_mutation_accepted([type](missionweaveprotocol::Json& registry) {
      support::principal(registry, unselected_binding_index)["type"] = type;
    });
  }
}

void test_registry_history_shape_is_exact_even_when_unselected() {
  for (const auto field :
       std::array{std::string_view{"sequence"}, std::string_view{"recordedAt"}}) {
    expect_mutation_rejected([field](missionweaveprotocol::Json& registry) {
      add_unselected_history_status(registry);
      support::history_status(registry, unselected_binding_index, 0).erase(field);
    });
  }

  expect_mutation_rejected([](missionweaveprotocol::Json& registry) {
    add_unselected_history_status(registry);
    support::history_status(registry, unselected_binding_index, 0)["unexpected"] = true;
  });
  expect_mutation_rejected([](missionweaveprotocol::Json& registry) {
    support::history(registry, unselected_binding_index).push_back(true);
  });

  expect_mutation_accepted([](missionweaveprotocol::Json& registry) {
    add_unselected_history_status(registry);
    auto& status = support::history_status(registry, unselected_binding_index, 0);
    status["validUntil"] = "2026-07-20T00:00:00Z";
    status["revokedAt"] = "2026-07-19T00:00:00Z";
  });
}

enum class IdentifierPosition { organization, binding_key, principal_id };

void set_identifier(missionweaveprotocol::Json& registry, const IdentifierPosition position,
                    const std::string_view value) {
  switch (position) {
  case IdentifierPosition::organization:
    registry["organizationId"] = value;
    return;
  case IdentifierPosition::binding_key:
    support::binding(registry, unselected_binding_index)["keyId"] = value;
    return;
  case IdentifierPosition::principal_id:
    support::principal(registry, unselected_binding_index)["id"] = value;
    return;
  }
}

void test_registry_identifiers_use_protocol_uri_rules() {
  constexpr auto positions =
      std::array{IdentifierPosition::organization, IdentifierPosition::binding_key,
                 IdentifierPosition::principal_id};
  constexpr auto valid = std::array{std::string_view{"example:"},
                                    std::string_view{"example:/path"},
                                    std::string_view{"example:rootless/path"},
                                    std::string_view{"https://example.test/actions/%E4%BE%8B"},
                                    std::string_view{"https://example.test/?q=%5Bx%5D"},
                                    std::string_view{"https://[2001:db8::1]/actions/run"},
                                    std::string_view{"https://user@[2001:db8::1]/actions/run"},
                                    std::string_view{"https://[v1.fe80]/actions/run"},
                                    std::string_view{"https://host:/"},
                                    std::string_view{"https://@/"},
                                    std::string_view{"scheme://"},
                                    std::string_view{"https://[::ffff:192.0.2.128]/"}};
  constexpr auto invalid = std::array{std::string_view{"actions/run"},
                                      std::string_view{"1:"},
                                      std::string_view{"//"},
                                      std::string_view{"urn:example:key\n"},
                                      std::string_view{"https://例え.テスト/actions/run"},
                                      std::string_view{"example:%"},
                                      std::string_view{"example:%Z"},
                                      std::string_view{"example:%ZZ"},
                                      std::string_view{"https://example.test/?q=%GG"},
                                      std::string_view{"https://example.test/?q=[x]"},
                                      std::string_view{"https://[not-an-ip]/"},
                                      std::string_view{"https://[::1]:abc/"},
                                      std::string_view{"https://example.test/?q=^"},
                                      std::string_view{"https://example.test/#fragment^"},
                                      std::string_view{"https://user@@example.test/"},
                                      std::string_view{"https://exa[mple].test/"},
                                      std::string_view{"https://[::ffff:192.0.2.999]/"},
                                      std::string_view{"scheme:##"}};
  for (const auto value : invalid) {
    for (const auto position : positions) {
      expect_mutation_rejected([position, value](missionweaveprotocol::Json& registry) {
        set_identifier(registry, position, value);
      });
    }
  }

  for (const auto value : valid) {
    for (const auto position : positions) {
      expect_mutation_accepted([position, value](missionweaveprotocol::Json& registry) {
        set_identifier(registry, position, value);
      });
    }
  }
}

void test_registry_runtime_has_no_fixture_size_caps() {
  auto long_identifiers = support::valid_registry_json();
  const auto long_component = std::string(600, 'a');
  long_identifiers["organizationId"] = "example:" + long_component;
  support::binding(long_identifiers, unselected_binding_index)["keyId"] =
      "example:" + long_component;
  support::principal(long_identifiers, unselected_binding_index)["id"] =
      "example:" + long_component;
  static_cast<void>(support::verify_accepts(long_identifiers));

  auto many_bindings = support::valid_registry_json();
  const auto repeated = support::binding(many_bindings, unselected_binding_index);
  while (many_bindings.at("bindings").size() <= 64) {
    many_bindings.at("bindings").push_back(repeated);
  }
  static_cast<void>(support::verify_accepts(many_bindings));
}

} // namespace

int main() {
  const auto unknown_command = support::unknown_key_command_bytes();
  assert(missionweaveprotocol::parse_strict_json(
             missionweaveprotocol::AssetBytes{unknown_command.data(), unknown_command.size()})
             .at("signature")
             .at("keyId")
             .as<std::string>() == support::unknown_key_id);

  test_completeness_precedes_registry_parsing();
  test_registry_bytes_are_strict_json();
  test_registry_root_shape_is_exact();
  test_registry_binding_shape_is_exact_even_when_unselected();
  test_registry_principal_shape_and_type_are_exact_even_when_unselected();
  test_registry_history_shape_is_exact_even_when_unselected();
  test_registry_identifiers_use_protocol_uri_rules();
  test_registry_runtime_has_no_fixture_size_caps();
}
