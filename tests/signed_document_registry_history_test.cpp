#include "signed_document_registry_test_support.hpp"

#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace {

namespace support = signed_document_registry_test_support;

constexpr std::size_t selected_binding_index = 0;
constexpr std::size_t unselected_binding_index = 1;
constexpr std::size_t late_unselected_binding_index = 6;

[[nodiscard]] missionweaveprotocol::Json status(const std::uint64_t sequence,
                                                const std::string_view recorded_at) {
  return missionweaveprotocol::parse_strict_json("{\"sequence\":" + std::to_string(sequence) +
                                                 ",\"recordedAt\":\"" + std::string{recorded_at} +
                                                 "\"}");
}

[[nodiscard]] missionweaveprotocol::Json
status_with_sequence_literal(const std::string_view sequence, const std::string_view recorded_at) {
  return missionweaveprotocol::parse_strict_json("{\"sequence\":" + std::string{sequence} +
                                                 ",\"recordedAt\":\"" + std::string{recorded_at} +
                                                 "\"}");
}

void replace_history(missionweaveprotocol::Json& binding,
                     const std::initializer_list<missionweaveprotocol::Json> statuses) {
  auto history = missionweaveprotocol::parse_strict_json("[]");
  for (const auto& item : statuses) {
    history.push_back(item);
  }
  binding["validityHistory"] = std::move(history);
}

void clear_history(missionweaveprotocol::Json& binding) {
  binding["validityHistory"] = missionweaveprotocol::parse_strict_json("[]");
}

void append_history(missionweaveprotocol::Json& binding, missionweaveprotocol::Json item) {
  binding.at("validityHistory").push_back(std::move(item));
}

void assert_reason(const missionweaveprotocol::VerificationDiagnostic& diagnostic,
                   const std::string_view expected) {
  if (std::string_view{diagnostic.reason} != expected) {
    std::cerr << "expected diagnostic: " << expected << '\n'
              << "actual diagnostic:   " << diagnostic.reason << '\n';
  }
  assert(std::string_view{diagnostic.reason} == expected);
}

void expect_rejected(const missionweaveprotocol::Json& registry,
                     const std::string_view expected_reason) {
  assert_reason(support::expect_registry_rejected(registry), expected_reason);
}

[[nodiscard]] missionweaveprotocol::VerificationDiagnostic
expect_unknown_command_rejected(const missionweaveprotocol::Json& registry) {
  const support::SnapshotResolver resolver(support::encode_json_bytes(registry));
  const auto diagnostic =
      support::expect_key_resolution_failure(resolver, support::unknown_key_command_bytes());
  assert(resolver.calls == 1);
  return diagnostic;
}

void test_semantic_duplicate_aliases_preserve_first_lexical_text() {
  auto registry = support::valid_registry_json();
  auto& selected = support::binding(registry, selected_binding_index);
  support::history_status(registry, selected_binding_index, 0)["revokedAt"] =
      "2026-07-17T00:00:00Z";

  auto duplicate = selected;
  duplicate["validFrom"] = "2026-07-15T00:00:00.000Z";
  auto& duplicate_status = duplicate.at("validityHistory").at(0);
  duplicate_status["recordedAt"] = "2026-07-15T16:00:00-08:00";
  duplicate_status["validUntil"] = "2026-07-15T16:00:00-08:00";
  duplicate_status["revokedAt"] = "2026-07-16T16:00:00-08:00";
  registry.at("bindings").push_back(std::move(duplicate));

  const auto verified = [&registry] {
    try {
      return support::verify_accepts(registry);
    } catch (const missionweaveprotocol::SignedDocumentVerificationError& error) {
      std::cerr << "semantic timestamp aliases were rejected: " << error.diagnostic().reason
                << '\n';
      throw;
    }
  }();
  const auto& resolved = verified.resolved_key();
  assert(resolved.valid_from == "2026-07-15T08:00:00+08:00");
  assert(resolved.valid_until == "2026-07-16T00:00:00Z");
  assert(resolved.revoked_at == "2026-07-17T00:00:00Z");
}

void test_sequences_are_positive_safe_integers() {
  struct InvalidSequence {
    std::string_view literal;
    std::string_view reason;
  };
  constexpr auto cases = std::array{
      InvalidSequence{"0", "Registry validity sequence is outside the safe range"},
      InvalidSequence{"9007199254740992", "Registry validity sequence is outside the safe range"},
      InvalidSequence{"-1", "Registry validity sequence is not an integer"},
      InvalidSequence{"1.5", "Registry validity sequence is not an integer"},
      InvalidSequence{"\"1\"", "Registry validity sequence is not an integer"},
  };

  for (const auto& item : cases) {
    auto registry = support::valid_registry_json();
    replace_history(support::binding(registry, unselected_binding_index),
                    {status_with_sequence_literal(item.literal, "2026-07-02T00:00:00Z")});
    expect_rejected(registry, item.reason);
  }
}

void test_cross_declaration_history_is_contiguous_from_one() {
  auto accepted = support::valid_registry_json();
  auto& first = support::binding(accepted, unselected_binding_index);
  replace_history(first, {status(1, "2026-07-02T00:00:00Z")});
  auto second = first;
  replace_history(second, {status(2, "2026-07-03T00:00:00Z")});
  accepted.at("bindings").push_back(std::move(second));
  static_cast<void>(support::verify_accepts(accepted));

  auto rejected = support::valid_registry_json();
  auto& gap_first = support::binding(rejected, unselected_binding_index);
  replace_history(gap_first, {status(1, "2026-07-02T00:00:00Z")});
  auto gap_second = gap_first;
  replace_history(gap_second, {status(3, "2026-07-04T00:00:00Z")});
  rejected.at("bindings").push_back(std::move(gap_second));
  expect_rejected(rejected, "Registry validity history is not contiguous");
}

void test_recorded_at_order_uses_exact_instants() {
  auto accepted = support::valid_registry_json();
  replace_history(support::binding(accepted, unselected_binding_index),
                  {status(1, "2026-07-03T00:00:00Z"), status(2, "2026-07-02T16:00:00-08:00")});
  static_cast<void>(support::verify_accepts(accepted));

  auto rejected = support::valid_registry_json();
  replace_history(
      support::binding(rejected, unselected_binding_index),
      {status(1, "2026-07-03T00:00:00Z"), status(2, "2026-07-02T23:59:59.999999999999999999Z")});
  expect_rejected(rejected, "Registry validity history is not append ordered");
}

void test_duplicate_sequences_reject_semantic_rewrites() {
  const auto expect_duplicate_rejected = [](missionweaveprotocol::Json first,
                                            missionweaveprotocol::Json second) {
    auto registry = support::valid_registry_json();
    replace_history(support::binding(registry, unselected_binding_index),
                    {std::move(first), std::move(second)});
    expect_rejected(registry, "Registry rewrites validity history");
  };

  expect_duplicate_rejected(status(1, "2026-07-02T00:00:00Z"), status(1, "2026-07-03T00:00:00Z"));

  auto valid_until = status(1, "2026-07-02T00:00:00Z");
  valid_until["validUntil"] = "2026-07-10T00:00:00Z";
  auto rewritten_valid_until = valid_until;
  rewritten_valid_until["validUntil"] = "2026-07-09T00:00:00Z";
  expect_duplicate_rejected(valid_until, rewritten_valid_until);

  auto revoked_at = status(1, "2026-07-02T00:00:00Z");
  revoked_at["revokedAt"] = "2026-07-10T00:00:00Z";
  auto rewritten_revoked_at = revoked_at;
  rewritten_revoked_at["revokedAt"] = "2026-07-09T00:00:00Z";
  expect_duplicate_rejected(revoked_at, rewritten_revoked_at);

  auto missing_valid_until = status(1, "2026-07-02T00:00:00Z");
  auto present_valid_until = missing_valid_until;
  present_valid_until["validUntil"] = "2026-07-10T00:00:00Z";
  expect_duplicate_rejected(missing_valid_until, present_valid_until);

  auto missing_revoked_at = status(1, "2026-07-02T00:00:00Z");
  auto present_revoked_at = missing_revoked_at;
  present_revoked_at["revokedAt"] = "2026-07-10T00:00:00Z";
  expect_duplicate_rejected(missing_revoked_at, present_revoked_at);
}

void test_repeated_bindings_compare_valid_from_by_instant() {
  auto accepted = support::valid_registry_json();
  auto selected_alias = support::binding(accepted, selected_binding_index);
  selected_alias["validFrom"] = "2026-07-15T00:00:00.000Z";
  accepted.at("bindings").push_back(std::move(selected_alias));
  auto unselected_alias = support::binding(accepted, unselected_binding_index);
  unselected_alias["validFrom"] = "2026-06-30T16:00:00-08:00";
  accepted.at("bindings").push_back(std::move(unselected_alias));

  const auto resolved = support::verify_accepts(accepted).resolved_key();
  assert(resolved.valid_from == "2026-07-15T08:00:00+08:00");

  auto rejected = support::valid_registry_json();
  auto changed = support::binding(rejected, unselected_binding_index);
  changed["validFrom"] = "2026-07-02T00:00:00Z";
  rejected.at("bindings").push_back(std::move(changed));
  expect_rejected(rejected, "Registry reuses a key ID for another immutable binding");
}

void test_complementary_histories_merge_across_repeated_declarations() {
  auto registry = support::valid_registry_json();

  auto selected_second = support::binding(registry, selected_binding_index);
  auto selected_status = status(2, "2026-07-17T00:00:00Z");
  selected_status["revokedAt"] = "2026-07-17T00:00:00Z";
  replace_history(selected_second, {std::move(selected_status)});
  registry.at("bindings").push_back(std::move(selected_second));

  auto& unselected_first = support::binding(registry, unselected_binding_index);
  replace_history(unselected_first, {status(1, "2026-07-02T00:00:00Z")});
  auto unselected_second = unselected_first;
  replace_history(unselected_second, {status(2, "2026-07-03T00:00:00Z")});
  registry.at("bindings").push_back(std::move(unselected_second));

  const auto resolved = support::verify_accepts(registry).resolved_key();
  assert(resolved.valid_until == "2026-07-16T00:00:00Z");
  assert(resolved.revoked_at == "2026-07-17T00:00:00Z");
}

void test_boundaries_preserve_the_first_text_for_the_earliest_instant() {
  auto registry = support::valid_registry_json();
  auto& selected = support::binding(registry, selected_binding_index);
  clear_history(selected);
  append_history(selected, status(1, "2026-07-16T00:00:00Z"));

  auto added = status(2, "2026-07-17T00:00:00Z");
  added["validUntil"] = "2026-07-20T00:00:00Z";
  added["revokedAt"] = "2026-07-19T00:00:00Z";
  append_history(selected, std::move(added));

  append_history(selected, status(3, "2026-07-18T00:00:00Z"));

  auto earlier = status(4, "2026-07-19T00:00:00Z");
  earlier["validUntil"] = "2026-07-18T00:00:00Z";
  earlier["revokedAt"] = "2026-07-17T00:00:00Z";
  append_history(selected, std::move(earlier));

  auto equal_alias = status(5, "2026-07-20T00:00:00Z");
  equal_alias["validUntil"] = "2026-07-17T16:00:00-08:00";
  equal_alias["revokedAt"] = "2026-07-16T16:00:00-08:00";
  append_history(selected, std::move(equal_alias));
  append_history(selected, status(6, "2026-07-21T00:00:00Z"));

  const auto resolved = support::verify_accepts(registry).resolved_key();
  assert(resolved.valid_until == "2026-07-18T00:00:00Z");
  assert(resolved.revoked_at == "2026-07-17T00:00:00Z");
}

void test_omission_does_not_remove_boundaries_or_allow_later_values() {
  const auto expect_later_rejected = [](const std::string_view field,
                                        const std::string_view expected_reason) {
    auto registry = support::valid_registry_json();
    auto& unselected = support::binding(registry, unselected_binding_index);
    auto first = status(1, "2026-07-02T00:00:00Z");
    first[field] = "2026-07-10T00:00:00Z";
    auto later = status(3, "2026-07-04T00:00:00Z");
    later[field] = "2026-07-11T00:00:00Z";
    replace_history(unselected,
                    {std::move(first), status(2, "2026-07-03T00:00:00Z"), std::move(later)});
    expect_rejected(registry, expected_reason);
  };

  expect_later_rejected("validUntil", "Registry moves validUntil later");
  expect_later_rejected("revokedAt", "Registry moves revokedAt later");
}

void test_sixty_five_history_records_are_accepted() {
  auto registry = support::valid_registry_json();
  auto& selected = support::binding(registry, selected_binding_index);
  clear_history(selected);
  for (std::uint64_t sequence = 1; sequence <= 65; ++sequence) {
    auto item = status(sequence, "2026-07-16T00:00:00Z");
    if (sequence == 65) {
      item["revokedAt"] = "2026-07-17T00:00:00Z";
    }
    append_history(selected, std::move(item));
  }
  assert(selected.at("validityHistory").size() == 65);

  const auto resolved = support::verify_accepts(registry).resolved_key();
  assert(!resolved.valid_until.has_value());
  assert(resolved.revoked_at == "2026-07-17T00:00:00Z");
}

void test_invalid_late_unselected_history_precedes_selection_and_unknown_key() {
  auto registry = support::valid_registry_json();
  assert(support::binding(registry, late_unselected_binding_index).at("keyId").as<std::string>() >
         support::binding(registry, selected_binding_index).at("keyId").as<std::string>());
  support::binding(registry, selected_binding_index)["validFrom"] = "2026-07-16T00:00:00Z";
  replace_history(support::binding(registry, late_unselected_binding_index),
                  {status(2, "2026-07-02T00:00:00Z")});

  constexpr std::string_view expected = "Registry validity history is not contiguous";
  expect_rejected(registry, expected);
  assert_reason(expect_unknown_command_rejected(registry), expected);
}

} // namespace

int main() {
  test_semantic_duplicate_aliases_preserve_first_lexical_text();
  test_sequences_are_positive_safe_integers();
  test_cross_declaration_history_is_contiguous_from_one();
  test_recorded_at_order_uses_exact_instants();
  test_duplicate_sequences_reject_semantic_rewrites();
  test_repeated_bindings_compare_valid_from_by_instant();
  test_complementary_histories_merge_across_repeated_declarations();
  test_boundaries_preserve_the_first_text_for_the_earliest_instant();
  test_omission_does_not_remove_boundaries_or_allow_later_values();
  test_sixty_five_history_records_are_accepted();
  test_invalid_late_unselected_history_precedes_selection_and_unknown_key();
}
