#include "schema_internal.hpp"
#include "signed_document_internal.hpp"

#include <missionweaveprotocol/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace missionweaveprotocol::detail {
namespace {

constexpr std::array root_fields{std::string_view{"organizationId"}, std::string_view{"bindings"}};
constexpr std::array binding_fields{
    std::string_view{"keyId"},     std::string_view{"principal"},
    std::string_view{"algorithm"}, std::string_view{"publicKey"},
    std::string_view{"validFrom"}, std::string_view{"validityHistory"}};
constexpr std::array principal_fields{std::string_view{"type"}, std::string_view{"id"}};
constexpr std::array status_required_fields{std::string_view{"sequence"},
                                            std::string_view{"recordedAt"}};
constexpr std::array status_allowed_fields{
    std::string_view{"sequence"}, std::string_view{"recordedAt"}, std::string_view{"validUntil"},
    std::string_view{"revokedAt"}};
constexpr std::array principal_types{std::string_view{"agent"}, std::string_view{"human"},
                                     std::string_view{"service"}};

template <std::size_t RequiredSize, std::size_t AllowedSize>
void require_exact_object(const Json& value,
                          const std::array<std::string_view, RequiredSize>& required,
                          const std::array<std::string_view, AllowedSize>& allowed,
                          const std::string_view label) {
  if (!value.is_object()) {
    throw std::invalid_argument("Registry " + std::string{label} + " is not an object");
  }
  for (const auto field : required) {
    if (!value.contains(field)) {
      throw std::invalid_argument("Registry " + std::string{label} +
                                  " is missing field: " + std::string{field});
    }
  }
  for (const auto& member : value.object_range()) {
    if (std::ranges::find(allowed, member.key()) == allowed.end()) {
      throw std::invalid_argument("Registry " + std::string{label} +
                                  " has unknown field: " + std::string{member.key()});
    }
  }
}

[[nodiscard]] std::string required_text(const Json& object, const std::string_view field) {
  if (!object.is_object() || !object.contains(field) || !object.at(field).is_string()) {
    throw std::invalid_argument("Registry field is not text: " + std::string{field});
  }
  return object.at(field).as<std::string>();
}

[[nodiscard]] std::string required_protocol_uri(const Json& object, const std::string_view field) {
  auto value = required_text(object, field);
  if (!is_protocol_uri(value)) {
    throw std::invalid_argument("Registry field is not a protocol URI: " + std::string{field});
  }
  return value;
}

struct ParsedBoundary {
  std::string text;
  ExactInstant instant;

  bool operator==(const ParsedBoundary&) const = default;
};

struct ValidityStatus {
  ExactInstant recorded_at;
  std::optional<ParsedBoundary> valid_until;
  std::optional<ParsedBoundary> revoked_at;

  bool operator==(const ValidityStatus&) const = default;
};

struct NormalizedBinding {
  std::string key_id;
  Principal principal;
  std::string algorithm;
  std::string public_key;
  Ed25519PublicKey public_key_bytes;
  std::string valid_from;
  ExactInstant valid_from_instant;
  std::map<std::uint64_t, ValidityStatus> history;
  std::optional<ParsedBoundary> effective_valid_until;
  std::optional<ParsedBoundary> effective_revoked_at;

  [[nodiscard]] bool same_immutable(const NormalizedBinding& other) const {
    return principal == other.principal && algorithm == other.algorithm &&
           public_key_bytes == other.public_key_bytes &&
           valid_from_instant == other.valid_from_instant;
  }
};

[[nodiscard]] std::optional<ParsedBoundary> boundary(const Json& status,
                                                     const std::string_view name) {
  if (!status.contains(name)) {
    return std::nullopt;
  }
  auto text = required_text(status, name);
  return ParsedBoundary{.text = text, .instant = parse_protocol_instant(text)};
}

void fold_history(NormalizedBinding& binding) {
  std::uint64_t expected_sequence = 1;
  std::optional<ExactInstant> previous_recorded_at;
  for (const auto& [sequence, status] : binding.history) {
    if (sequence != expected_sequence++) {
      throw std::invalid_argument("Registry validity history is not contiguous");
    }
    if (previous_recorded_at && status.recorded_at < *previous_recorded_at) {
      throw std::invalid_argument("Registry validity history is not append ordered");
    }
    previous_recorded_at = status.recorded_at;
    const auto apply_boundary = [](const std::optional<ParsedBoundary>& candidate,
                                   std::optional<ParsedBoundary>& effective,
                                   const std::string_view name) {
      if (!candidate) {
        return;
      }
      if (effective && candidate->instant > effective->instant) {
        throw std::invalid_argument("Registry moves " + std::string{name} + " later");
      }
      if (!effective || candidate->instant < effective->instant) {
        effective = candidate;
      }
    };
    apply_boundary(status.valid_until, binding.effective_valid_until, "validUntil");
    apply_boundary(status.revoked_at, binding.effective_revoked_at, "revokedAt");
  }
}

} // namespace

RegistryKeyResolution resolve_agent_registry_key(const AssetBytes registry_bytes,
                                                 const KeyResolutionRequest& request) {
  const auto registry = parse_strict_json(registry_bytes);
  require_exact_object(registry, root_fields, root_fields, "root");
  const auto organization_id = required_protocol_uri(registry, "organizationId");
  if (!registry.at("bindings").is_array() || registry.at("bindings").empty()) {
    throw std::invalid_argument("Registry bindings is not a non-empty array");
  }

  std::map<std::string, NormalizedBinding> bindings;
  std::map<Ed25519PublicKey, std::string> public_key_owners;
  std::map<std::tuple<std::string, std::string, std::string, Ed25519PublicKey>, std::string>
      tuple_ids;
  for (const auto& raw : registry.at("bindings").array_range()) {
    require_exact_object(raw, binding_fields, binding_fields, "binding");
    const auto key_id = required_protocol_uri(raw, "keyId");
    const auto& raw_principal = raw.at("principal");
    require_exact_object(raw_principal, principal_fields, principal_fields, "Principal");
    const Principal principal{.type = required_text(raw_principal, "type"),
                              .id = required_protocol_uri(raw_principal, "id")};
    if (std::ranges::find(principal_types, principal.type) == principal_types.end()) {
      throw std::invalid_argument("Registry Principal type is unsupported");
    }
    const auto algorithm = required_text(raw, "algorithm");
    if (algorithm != "Ed25519") {
      throw std::invalid_argument("Registry key algorithm is not Ed25519");
    }
    const auto public_key = required_text(raw, "publicKey");
    const auto public_key_bytes = decode_strict_ed25519_public_key(public_key);
    const auto valid_from = required_text(raw, "validFrom");
    const auto valid_from_instant = parse_protocol_instant(valid_from);
    NormalizedBinding candidate{.key_id = key_id,
                                .principal = principal,
                                .algorithm = algorithm,
                                .public_key = public_key,
                                .public_key_bytes = public_key_bytes,
                                .valid_from = valid_from,
                                .valid_from_instant = valid_from_instant,
                                .history = {},
                                .effective_valid_until = std::nullopt,
                                .effective_revoked_at = std::nullopt};
    auto [iterator, inserted] = bindings.try_emplace(key_id, candidate);
    if (!inserted && !iterator->second.same_immutable(candidate)) {
      throw std::invalid_argument("Registry reuses a key ID for another immutable binding");
    }
    auto& binding = iterator->second;

    const auto owner = key_id + '\0' + principal.type + '\0' + principal.id;
    const auto [owner_iterator, owner_inserted] =
        public_key_owners.try_emplace(public_key_bytes, owner);
    if (!owner_inserted && owner_iterator->second != owner) {
      throw std::invalid_argument("Registry reuses a public key");
    }
    const auto tuple = std::tuple{principal.type, principal.id, algorithm, public_key_bytes};
    const auto [tuple_iterator, tuple_inserted] = tuple_ids.try_emplace(tuple, key_id);
    if (!tuple_inserted && tuple_iterator->second != key_id) {
      throw std::invalid_argument("Registry contains a key-ID alias");
    }

    if (!raw.contains("validityHistory") || !raw.at("validityHistory").is_array()) {
      throw std::invalid_argument("Registry validityHistory is not an array");
    }
    for (const auto& status : raw.at("validityHistory").array_range()) {
      require_exact_object(status, status_required_fields, status_allowed_fields,
                           "validity status");
      if (!status.contains("sequence") || !status.at("sequence").is_uint64()) {
        throw std::invalid_argument("Registry validity sequence is not an integer");
      }
      const auto sequence = status.at("sequence").as<std::uint64_t>();
      if (sequence == 0 || sequence > 9007199254740991ULL) {
        throw std::invalid_argument("Registry validity sequence is outside the safe range");
      }
      const ValidityStatus parsed{
          .recorded_at = parse_protocol_instant(required_text(status, "recordedAt")),
          .valid_until = boundary(status, "validUntil"),
          .revoked_at = boundary(status, "revokedAt"),
      };
      const auto [status_iterator, status_inserted] = binding.history.try_emplace(sequence, parsed);
      if (!status_inserted && status_iterator->second != parsed) {
        throw std::invalid_argument("Registry rewrites validity history");
      }
    }
  }

  for (auto& [key_id, binding] : bindings) {
    fold_history(binding);
    static_cast<void>(key_id);
  }

  const auto selected = bindings.find(request.key_id);
  if (selected == bindings.end()) {
    throw std::invalid_argument("signature.keyId is unknown");
  }
  const auto& binding = selected->second;
  if (request.service_principal_required) {
    if (binding.principal.type != "service") {
      throw std::invalid_argument("Agent Card signer is not a service Principal");
    }
  } else if (!request.expected_principal || binding.principal != *request.expected_principal) {
    throw std::invalid_argument("resolved key is bound to the wrong Principal");
  }
  if (request.protected_instant < binding.valid_from_instant) {
    throw std::invalid_argument("signing key is not yet valid at the protected time");
  }
  if (binding.effective_valid_until &&
      request.protected_instant >= binding.effective_valid_until->instant) {
    throw std::invalid_argument("signing key is expired at the protected time");
  }
  if (binding.effective_revoked_at &&
      request.protected_instant >= binding.effective_revoked_at->instant) {
    throw std::invalid_argument("signing key is revoked at the protected time");
  }

  return RegistryKeyResolution{
      .resolved_key =
          ResolvedKey{
              .organization_id = organization_id,
              .key_id = binding.key_id,
              .principal = binding.principal,
              .algorithm = binding.algorithm,
              .public_key = binding.public_key,
              .valid_from = binding.valid_from,
              .valid_until = binding.effective_valid_until
                                 ? std::optional{binding.effective_valid_until->text}
                                 : std::nullopt,
              .revoked_at = binding.effective_revoked_at
                                ? std::optional{binding.effective_revoked_at->text}
                                : std::nullopt,
          },
      .public_key = binding.public_key_bytes,
  };
}

} // namespace missionweaveprotocol::detail
