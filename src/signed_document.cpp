#include <missionweaveprotocol/signed_document.hpp>

#include <missionweaveprotocol/canonical.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace missionweaveprotocol {
namespace {

enum class SignerRule { service, principal, agent_id };

struct Profile {
  SignedDocumentKind kind;
  std::string_view id;
  std::string_view schema;
  std::string_view protected_time;
  SignerRule signer_rule;
  std::string_view signer;
};

constexpr std::array profiles{
    Profile{SignedDocumentKind::agent_card, "agent-card", "agent-card.schema.json", "issuedAt",
            SignerRule::service, ""},
    Profile{SignedDocumentKind::approval, "approval", "approval.schema.json", "occurredAt",
            SignerRule::principal, "approver"},
    Profile{SignedDocumentKind::artifact, "artifact", "artifact.schema.json", "createdAt",
            SignerRule::agent_id, "producer"},
    Profile{SignedDocumentKind::command, "command", "command.schema.json", "issuedAt",
            SignerRule::principal, "actor"},
    Profile{SignedDocumentKind::context_package, "context-package", "context-package.schema.json",
            "generatedAt", SignerRule::principal, "generatedBy"},
    Profile{SignedDocumentKind::event, "event", "event.schema.json", "occurredAt",
            SignerRule::principal, "acceptedBy"},
    Profile{SignedDocumentKind::evidence, "evidence", "evidence.schema.json", "createdAt",
            SignerRule::principal, "generatedBy"},
    Profile{SignedDocumentKind::extension_profile, "extension-profile",
            "extension-profile.schema.json", "approvedAt", SignerRule::principal, "approvedBy"},
    Profile{SignedDocumentKind::group_snapshot, "group-snapshot", "group-snapshot.schema.json",
            "createdAt", SignerRule::principal, "createdBy"},
};

[[nodiscard]] const Profile& profile(const SignedDocumentKind kind) {
  const auto found = std::ranges::find(profiles, kind, &Profile::kind);
  if (found == profiles.end()) {
    throw std::invalid_argument("unknown Signed Document kind");
  }
  return *found;
}

[[noreturn]] void fail(const VerificationStage stage, std::string reason) {
  throw SignedDocumentVerificationError(
      VerificationDiagnostic{.stage = stage, .reason = std::move(reason)});
}

[[nodiscard]] std::string exception_reason(const std::exception& error) {
  return *error.what() == '\0' ? "unknown verification failure" : error.what();
}

[[nodiscard]] bool is_hex(const char value) noexcept {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
         (value >= 'A' && value <= 'F');
}

[[nodiscard]] std::uint16_t hex_quad(const std::string_view value) {
  std::uint16_t result = 0;
  for (const auto digit : value) {
    result = static_cast<std::uint16_t>(result << 4U);
    if (digit >= '0' && digit <= '9') {
      result = static_cast<std::uint16_t>(result + digit - '0');
    } else if (digit >= 'a' && digit <= 'f') {
      result = static_cast<std::uint16_t>(result + digit - 'a' + 10);
    } else {
      result = static_cast<std::uint16_t>(result + digit - 'A' + 10);
    }
  }
  return result;
}

struct SanitizedJson {
  std::string text;
  bool unpaired_surrogate = false;
};

[[nodiscard]] SanitizedJson sanitize_unpaired_surrogates(const std::string_view input) {
  SanitizedJson result;
  result.text.reserve(input.size());
  bool in_string = false;
  for (std::size_t index = 0; index < input.size();) {
    const auto value = input[index];
    if (!in_string) {
      result.text.push_back(value);
      ++index;
      if (value == '"') {
        in_string = true;
      }
      continue;
    }
    if (value == '"') {
      result.text.push_back(value);
      ++index;
      in_string = false;
      continue;
    }
    if (value != '\\') {
      result.text.push_back(value);
      ++index;
      continue;
    }
    if (index + 1 >= input.size() || input[index + 1] != 'u' || index + 6 > input.size() ||
        !std::ranges::all_of(input.substr(index + 2, 4), is_hex)) {
      result.text.push_back(value);
      ++index;
      if (index < input.size()) {
        result.text.push_back(input[index++]);
      }
      continue;
    }

    const auto first = hex_quad(input.substr(index + 2, 4));
    if (first >= 0xD800U && first <= 0xDBFFU) {
      const bool pair = index + 12 <= input.size() && input[index + 6] == '\\' &&
                        input[index + 7] == 'u' &&
                        std::ranges::all_of(input.substr(index + 8, 4), is_hex) &&
                        hex_quad(input.substr(index + 8, 4)) >= 0xDC00U &&
                        hex_quad(input.substr(index + 8, 4)) <= 0xDFFFU;
      if (pair) {
        result.text.append(input.substr(index, 12));
        index += 12;
      } else {
        result.text += "\\uE000";
        result.unpaired_surrogate = true;
        index += 6;
      }
      continue;
    }
    if (first >= 0xDC00U && first <= 0xDFFFU) {
      result.text += "\\uE000";
      result.unpaired_surrogate = true;
      index += 6;
      continue;
    }
    result.text.append(input.substr(index, 6));
    index += 6;
  }
  return result;
}

[[nodiscard]] std::int64_t days_from_civil(const int year, const int month, const int day) {
  const auto adjusted_year = year - (month <= 2 ? 1 : 0);
  const auto era = adjusted_year / 400;
  const auto year_of_era = adjusted_year - era * 400;
  const auto adjusted_month = month + (month > 2 ? -3 : 9);
  const auto day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
  const auto day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  return static_cast<std::int64_t>(era) * 146097 + day_of_era - 719468;
}

[[nodiscard]] bool leap_year(const int year) noexcept {
  return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

[[nodiscard]] ExactInstant parse_instant(const std::string_view text) {
  static const std::regex expression(
      R"(^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})$)",
      std::regex::ECMAScript);
  std::match_results<std::string_view::const_iterator> match;
  if (!std::regex_match(text.begin(), text.end(), match, expression)) {
    throw std::invalid_argument("not an RFC 3339 timestamp");
  }
  const auto number = [&match](const std::size_t index) {
    return std::stoi(std::string{match[index].first, match[index].second});
  };
  const auto year = number(1);
  const auto month = number(2);
  const auto day = number(3);
  const auto hour = number(4);
  const auto minute = number(5);
  const auto second = number(6);
  if (year == 0) {
    throw std::invalid_argument("year 0000 is not supported");
  }
  constexpr std::array month_lengths{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12) {
    throw std::invalid_argument("month is outside protocol bounds");
  }
  auto maximum_day = month_lengths[static_cast<std::size_t>(month - 1)];
  if (month == 2 && leap_year(year)) {
    ++maximum_day;
  }
  if (day < 1 || day > maximum_day || hour > 23 || minute > 59 || second > 59) {
    throw std::invalid_argument("timestamp is outside Gregorian protocol bounds");
  }

  const auto offset = std::string{match[8].first, match[8].second};
  if (offset == "-00:00") {
    throw std::invalid_argument("unknown local offset -00:00 is not an instant");
  }
  auto offset_seconds = 0;
  if (offset != "Z" && offset != "z") {
    const auto offset_hour = std::stoi(offset.substr(1, 2));
    const auto offset_minute = std::stoi(offset.substr(4, 2));
    if (offset_hour > 23 || offset_minute > 59) {
      throw std::invalid_argument("numeric offset is outside RFC 3339 bounds");
    }
    offset_seconds = (offset.front() == '+' ? 1 : -1) * (offset_hour * 3600 + offset_minute * 60);
  }
  auto fraction = match[7].matched ? std::string{match[7].first, match[7].second} : std::string{};
  while (!fraction.empty() && fraction.back() == '0') {
    fraction.pop_back();
  }
  const auto local_second =
      days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
  return ExactInstant{.epoch_second = local_second - offset_seconds,
                      .fractional_digits = std::move(fraction)};
}

[[nodiscard]] std::vector<std::uint8_t> base64url_decode(const std::string_view text,
                                                         const std::string_view label) {
  if (text.empty() || text.size() % 4 == 1 || text.find('=') != std::string_view::npos) {
    throw std::invalid_argument(std::string{label} + " is not unpadded base64url");
  }
  std::string padded{text};
  for (auto& value : padded) {
    if (value == '-') {
      value = '+';
    } else if (value == '_') {
      value = '/';
    } else if (!std::isalnum(static_cast<unsigned char>(value))) {
      throw std::invalid_argument(std::string{label} + " is not unpadded base64url");
    }
  }
  const auto padding = (4 - padded.size() % 4) % 4;
  padded.append(padding, '=');
  std::vector<std::uint8_t> decoded((padded.size() / 4) * 3);
  const auto size =
      EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(padded.data()),
                      static_cast<int>(padded.size()));
  if (size < 0 || static_cast<std::size_t>(size) < padding) {
    throw std::invalid_argument(std::string{label} + " cannot be decoded");
  }
  decoded.resize(static_cast<std::size_t>(size) - padding);
  std::string canonical(((decoded.size() + 2) / 3) * 4, '\0');
  const auto canonical_size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(canonical.data()),
                                              decoded.data(), static_cast<int>(decoded.size()));
  canonical.resize(static_cast<std::size_t>(canonical_size));
  std::ranges::replace(canonical, '+', '-');
  std::ranges::replace(canonical, '/', '_');
  while (!canonical.empty() && canonical.back() == '=') {
    canonical.pop_back();
  }
  if (canonical != text) {
    throw std::invalid_argument(std::string{label} + " is not canonical base64url");
  }
  return decoded;
}

[[nodiscard]] std::string base64url_encode(const AssetBytes bytes) {
  std::string result(((bytes.size() + 2) / 3) * 4, '\0');
  const auto size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()), bytes.data(),
                                    static_cast<int>(bytes.size()));
  result.resize(static_cast<std::size_t>(size));
  std::ranges::replace(result, '+', '-');
  std::ranges::replace(result, '/', '_');
  while (!result.empty() && result.back() == '=') {
    result.pop_back();
  }
  return result;
}

class Big final {
public:
  Big() : value_(BN_new(), &BN_free) {
    if (!value_) {
      throw std::runtime_error("unable to allocate Ed25519 integer");
    }
    BN_zero(value_.get());
  }

  explicit Big(BIGNUM* value) : value_(value, &BN_free) {
    if (!value_) {
      throw std::runtime_error("unable to create Ed25519 integer");
    }
  }

  Big(const Big& other) : Big(BN_dup(other.get())) {}
  Big(Big&&) noexcept = default;
  Big& operator=(Big other) noexcept {
    value_.swap(other.value_);
    return *this;
  }

  [[nodiscard]] BIGNUM* get() noexcept { return value_.get(); }
  [[nodiscard]] const BIGNUM* get() const noexcept { return value_.get(); }

private:
  std::unique_ptr<BIGNUM, decltype(&BN_free)> value_;
};

class BigContext final {
public:
  BigContext() : value_(BN_CTX_new(), &BN_CTX_free) {
    if (!value_) {
      throw std::runtime_error("unable to allocate Ed25519 arithmetic context");
    }
  }

  [[nodiscard]] BN_CTX* get() const noexcept { return value_.get(); }

private:
  std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> value_;
};

[[nodiscard]] Big decimal(const char* text) {
  BIGNUM* value = nullptr;
  if (BN_dec2bn(&value, text) == 0) {
    BN_free(value);
    throw std::runtime_error("unable to initialize Ed25519 constant");
  }
  return Big(value);
}

[[nodiscard]] const Big& field() {
  static const Big value =
      decimal("57896044618658097711785492504343953926634992332820282019728792003956564819949");
  return value;
}

[[nodiscard]] const Big& order() {
  static const Big value =
      decimal("7237005577332262213973186563042994240857116359379907606001950938285454250989");
  return value;
}

[[nodiscard]] const Big& curve_d() {
  static const Big value =
      decimal("37095705934669439343138083508754565189542113879843219016388785533085940283555");
  return value;
}

[[nodiscard]] const Big& sqrt_m1() {
  static const Big value =
      decimal("19681161376707505956807079304988542015446066515923890162744021073123829784752");
  return value;
}

[[nodiscard]] const Big& field_minus_two() {
  static const Big value = [] {
    Big result(field());
    if (BN_sub_word(result.get(), 2) != 1) {
      throw std::runtime_error("unable to initialize Ed25519 exponent");
    }
    return result;
  }();
  return value;
}

[[nodiscard]] const Big& square_root_exponent() {
  static const Big value = [] {
    Big result(field());
    if (BN_add_word(result.get(), 3) != 1 || BN_rshift(result.get(), result.get(), 3) != 1) {
      throw std::runtime_error("unable to initialize Ed25519 square-root exponent");
    }
    return result;
  }();
  return value;
}

[[nodiscard]] Big word(const unsigned long value) {
  Big result;
  if (BN_set_word(result.get(), value) != 1) {
    throw std::runtime_error("unable to initialize Ed25519 integer");
  }
  return result;
}

[[nodiscard]] Big add(const Big& left, const Big& right) {
  Big result;
  BigContext context;
  if (BN_mod_add(result.get(), left.get(), right.get(), field().get(), context.get()) != 1) {
    throw std::runtime_error("Ed25519 modular addition failed");
  }
  return result;
}

[[nodiscard]] Big subtract(const Big& left, const Big& right) {
  Big result;
  BigContext context;
  if (BN_mod_sub(result.get(), left.get(), right.get(), field().get(), context.get()) != 1) {
    throw std::runtime_error("Ed25519 modular subtraction failed");
  }
  return result;
}

[[nodiscard]] Big multiply(const Big& left, const Big& right) {
  Big result;
  BigContext context;
  if (BN_mod_mul(result.get(), left.get(), right.get(), field().get(), context.get()) != 1) {
    throw std::runtime_error("Ed25519 modular multiplication failed");
  }
  return result;
}

[[nodiscard]] Big exponentiate(const Big& value, const Big& exponent) {
  Big result;
  BigContext context;
  if (BN_mod_exp(result.get(), value.get(), exponent.get(), field().get(), context.get()) != 1) {
    throw std::runtime_error("Ed25519 modular exponentiation failed");
  }
  return result;
}

[[nodiscard]] Big little_integer(const AssetBytes bytes) {
  return Big(BN_lebin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr));
}

struct Point {
  Big x;
  Big y;
  Big z;
  Big t;
};

[[nodiscard]] Point point_add(const Point& left, const Point& right) {
  const auto a = multiply(subtract(left.y, left.x), subtract(right.y, right.x));
  const auto b = multiply(add(left.y, left.x), add(right.y, right.x));
  const auto c = multiply(multiply(multiply(word(2), curve_d()), left.t), right.t);
  const auto d = multiply(multiply(word(2), left.z), right.z);
  const auto e = subtract(b, a);
  const auto f = subtract(d, c);
  const auto g = add(d, c);
  const auto h = add(b, a);
  return Point{.x = multiply(e, f), .y = multiply(g, h), .z = multiply(f, g), .t = multiply(e, h)};
}

[[nodiscard]] bool identity(const Point& point) {
  return BN_is_zero(point.x.get()) != 0 && BN_cmp(point.y.get(), point.z.get()) == 0;
}

[[nodiscard]] Point scalar_multiply(Point point, const Big& scalar) {
  Point result{.x = word(0), .y = word(1), .z = word(1), .t = word(0)};
  const auto bits = BN_num_bits(scalar.get());
  for (int bit = 0; bit < bits; ++bit) {
    if (BN_is_bit_set(scalar.get(), bit) != 0) {
      result = point_add(result, point);
    }
    point = point_add(point, point);
  }
  return result;
}

void validate_point(const AssetBytes encoded, const bool allow_identity,
                    const std::string_view label) {
  if (encoded.size() != 32) {
    throw std::invalid_argument(std::string{label} + " is not a 32-byte Ed25519 point");
  }
  std::array<std::uint8_t, 32> y_bytes{};
  std::ranges::copy(encoded, y_bytes.begin());
  const auto x_sign = y_bytes.back() >> 7U;
  y_bytes.back() &= 0x7FU;
  const auto y = little_integer(y_bytes);
  if (BN_cmp(y.get(), field().get()) >= 0) {
    throw std::invalid_argument(std::string{label} + " is not canonically encoded");
  }
  const auto y_squared = multiply(y, y);
  const auto numerator = subtract(y_squared, word(1));
  const auto denominator = add(multiply(curve_d(), y_squared), word(1));
  const auto x_squared = multiply(numerator, exponentiate(denominator, field_minus_two()));
  auto x = exponentiate(x_squared, square_root_exponent());
  if (!BN_is_zero(subtract(multiply(x, x), x_squared).get())) {
    x = multiply(x, sqrt_m1());
  }
  if (!BN_is_zero(subtract(multiply(x, x), x_squared).get())) {
    throw std::invalid_argument(std::string{label} + " is off the Edwards25519 curve");
  }
  if (BN_is_zero(x.get()) != 0 && x_sign != 0) {
    throw std::invalid_argument(std::string{label} + " uses negative-zero encoding");
  }
  if (static_cast<unsigned>(BN_is_odd(x.get())) != static_cast<unsigned>(x_sign)) {
    x = subtract(field(), x);
  }
  const Point point{.x = x, .y = y, .z = word(1), .t = multiply(x, y)};
  if (identity(point) && !allow_identity) {
    throw std::invalid_argument(std::string{label} + " is the Ed25519 identity point");
  }
  if (!identity(scalar_multiply(point, order()))) {
    throw std::invalid_argument(std::string{label} + " is not in the prime-order subgroup");
  }
}

void validate_signature_encoding(const Ed25519Signature& signature) {
  validate_point({signature.data(), 32}, true, "signature R");
  if (BN_cmp(little_integer({signature.data() + 32, 32}).get(), order().get()) >= 0) {
    throw std::invalid_argument("signature S is outside the Ed25519 scalar range");
  }
}

[[nodiscard]] std::string sha256(const std::string_view bytes) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int size = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1) {
    throw std::runtime_error("unable to calculate SHA-256");
  }
  constexpr char hexadecimal[] = "0123456789abcdef";
  std::string result = "sha256:";
  result.reserve(7 + size * 2);
  for (unsigned int index = 0; index < size; ++index) {
    result.push_back(hexadecimal[digest[index] >> 4U]);
    result.push_back(hexadecimal[digest[index] & 0x0FU]);
  }
  return result;
}

[[nodiscard]] std::string required_string(const Json& object, const std::string_view field_name) {
  if (!object.is_object() || !object.contains(field_name) || !object.at(field_name).is_string()) {
    throw std::invalid_argument("required field is not a string: " + std::string{field_name});
  }
  return object.at(field_name).as<std::string>();
}

[[nodiscard]] Principal principal(const Json& value) {
  auto result =
      Principal{.type = required_string(value, "type"), .id = required_string(value, "id")};
  if (result.type != "agent" && result.type != "human" && result.type != "service") {
    throw std::invalid_argument("expected signer has an unsupported Principal type");
  }
  return result;
}

[[nodiscard]] std::optional<Principal> expected_principal(const Profile& selected,
                                                          const Json& document) {
  if (selected.signer_rule == SignerRule::service) {
    return std::nullopt;
  }
  if (!document.contains(selected.signer)) {
    throw std::invalid_argument("expected signer field is absent");
  }
  if (selected.signer_rule == SignerRule::agent_id) {
    const auto& producer = document.at(selected.signer);
    return Principal{.type = "agent", .id = required_string(producer, "agentId")};
  }
  return principal(document.at(selected.signer));
}

void require_schema(const SchemaCatalog& schemas, const std::string_view name, const Json& value) {
  const auto result = schemas.validate(name, value);
  if (result.valid) {
    return;
  }
  auto reason = std::string{name} + " validation failed";
  if (result.issue) {
    reason += ": " + result.issue->message;
  }
  throw std::invalid_argument(std::move(reason));
}

[[nodiscard]] std::vector<std::uint8_t> vector_bytes(const AssetBytes bytes) {
  return {bytes.begin(), bytes.end()};
}

[[nodiscard]] AssetBytes bytes_of(const std::string_view value) noexcept {
  return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

} // namespace

std::string_view signed_document_kind_id(const SignedDocumentKind kind) noexcept {
  for (const auto& item : profiles) {
    if (item.kind == kind) {
      return item.id;
    }
  }
  return {};
}

std::strong_ordering ExactInstant::operator<=>(const ExactInstant& other) const noexcept {
  if (const auto seconds = epoch_second <=> other.epoch_second; seconds != 0) {
    return seconds;
  }
  const auto width = std::max(fractional_digits.size(), other.fractional_digits.size());
  for (std::size_t index = 0; index < width; ++index) {
    const auto left = index < fractional_digits.size() ? fractional_digits[index] : '0';
    const auto right =
        index < other.fractional_digits.size() ? other.fractional_digits[index] : '0';
    if (left < right) {
      return std::strong_ordering::less;
    }
    if (left > right) {
      return std::strong_ordering::greater;
    }
  }
  return std::strong_ordering::equal;
}

std::string_view verification_stage_id(const VerificationStage stage) noexcept {
  switch (stage) {
  case VerificationStage::parse:
    return "parse";
  case VerificationStage::schema:
    return "schema";
  case VerificationStage::signature_envelope:
    return "signature-envelope";
  case VerificationStage::key_resolution:
    return "key-resolution";
  case VerificationStage::canonicalization:
    return "canonicalization";
  case VerificationStage::signature:
    return "signature";
  case VerificationStage::complete:
    return "complete";
  }
  return {};
}

std::string_view verification_wire_code(const VerificationStage stage) noexcept {
  switch (stage) {
  case VerificationStage::parse:
  case VerificationStage::canonicalization:
    return "PROTOCOL_VIOLATION";
  case VerificationStage::schema:
    return "SCHEMA_VALIDATION_FAILED";
  case VerificationStage::signature_envelope:
  case VerificationStage::key_resolution:
  case VerificationStage::signature:
    return "AUTH_INVALID_SIGNATURE";
  case VerificationStage::complete:
    return {};
  }
  return {};
}

SignedDocumentVerificationError::SignedDocumentVerificationError(VerificationDiagnostic diagnostic)
    : std::runtime_error("Signed Document verification failed: " +
                         std::string{verification_wire_code(diagnostic.stage)}),
      diagnostic_(std::move(diagnostic)) {}

std::string_view SignedDocumentVerificationError::wire_code() const noexcept {
  return verification_wire_code(diagnostic_.stage);
}

const VerificationDiagnostic& SignedDocumentVerificationError::diagnostic() const noexcept {
  return diagnostic_;
}

VerifiedSignedDocument::VerifiedSignedDocument(
    const SignedDocumentKind kind, Json document, std::vector<std::uint8_t> received_bytes,
    std::string signing_bytes, std::string signing_hash, std::string canonical_bytes,
    std::string canonical_hash, std::string protected_time, ExactInstant protected_instant,
    SignatureMaterial signature, ResolvedKey resolved_key)
    : kind_(kind), document_(std::move(document)), received_bytes_(std::move(received_bytes)),
      signing_bytes_(std::move(signing_bytes)), signing_hash_(std::move(signing_hash)),
      canonical_bytes_(std::move(canonical_bytes)), canonical_hash_(std::move(canonical_hash)),
      protected_time_(std::move(protected_time)), protected_instant_(std::move(protected_instant)),
      signature_(std::move(signature)), resolved_key_(std::move(resolved_key)) {}

SignedDocumentKind VerifiedSignedDocument::kind() const noexcept { return kind_; }
const Json& VerifiedSignedDocument::document() const noexcept { return document_; }
const std::vector<std::uint8_t>& VerifiedSignedDocument::received_bytes() const noexcept {
  return received_bytes_;
}
std::string_view VerifiedSignedDocument::signing_bytes() const noexcept { return signing_bytes_; }
std::string_view VerifiedSignedDocument::signing_hash() const noexcept { return signing_hash_; }
std::string_view VerifiedSignedDocument::canonical_bytes() const noexcept {
  return canonical_bytes_;
}
std::string_view VerifiedSignedDocument::canonical_hash() const noexcept { return canonical_hash_; }
std::string_view VerifiedSignedDocument::protected_time() const noexcept { return protected_time_; }
const ExactInstant& VerifiedSignedDocument::protected_instant() const noexcept {
  return protected_instant_;
}
const SignatureMaterial& VerifiedSignedDocument::signature() const noexcept { return signature_; }
const ResolvedKey& VerifiedSignedDocument::resolved_key() const noexcept { return resolved_key_; }
const Principal& VerifiedSignedDocument::resolved_principal() const noexcept {
  return resolved_key_.principal;
}

SignedDocumentCodec::SignedDocumentCodec() = default;

Json SignedDocumentCodec::sign(const SignedDocumentKind kind, const Json& unsigned_document,
                               const SigningKey& signing_key) const {
  const auto& selected = profile(kind);
  if (!unsigned_document.is_object()) {
    throw std::invalid_argument("Unsigned Signed Document must be a JSON object");
  }
  if (unsigned_document.contains("signature")) {
    throw std::invalid_argument("Unsigned Signed Document already has a signature");
  }
  const auto protected_time = required_string(unsigned_document, selected.protected_time);
  static_cast<void>(parse_instant(protected_time));
  if (!protected_time.ends_with('Z')) {
    throw std::invalid_argument("Protected signed time must use uppercase Z");
  }
  auto signed_document = unsigned_document;
  Json envelope(jsoncons::json_object_arg);
  envelope["algorithm"] = "Ed25519";
  envelope["keyId"] = signing_key.key_id();
  envelope["createdAt"] = protected_time;
  Ed25519Signature placeholder{};
  envelope["value"] = base64url_encode(placeholder);
  signed_document["signature"] = std::move(envelope);
  require_schema(schemas_, selected.schema, signed_document);
  const auto signing_bytes = canonical_json(unsigned_document);
  const auto signature = signing_key.sign(bytes_of(signing_bytes));
  validate_signature_encoding(signature);
  signed_document["signature"]["value"] = base64url_encode(signature);
  return signed_document;
}

VerifiedSignedDocument SignedDocumentCodec::verify(const SignedDocumentKind kind,
                                                   const AssetBytes received_bytes,
                                                   const KeyResolver& resolver) const {
  const auto& selected = profile(kind);
  const auto received_text =
      std::string_view{reinterpret_cast<const char*>(received_bytes.data()), received_bytes.size()};
  Json document;
  bool unpaired_surrogate = false;
  try {
    auto sanitized = sanitize_unpaired_surrogates(received_text);
    unpaired_surrogate = sanitized.unpaired_surrogate;
    document = parse_strict_json(sanitized.text);
  } catch (const std::exception& error) {
    fail(VerificationStage::parse, exception_reason(error));
  }
  try {
    require_schema(schemas_, selected.schema, document);
    if (!document.is_object()) {
      throw std::invalid_argument("Signed Document is not a JSON object");
    }
    static_cast<void>(parse_instant(required_string(document, selected.protected_time)));
    static_cast<void>(parse_instant(required_string(document.at("signature"), "createdAt")));
  } catch (const std::exception& error) {
    fail(VerificationStage::schema, exception_reason(error));
  }

  std::string protected_time;
  ExactInstant protected_instant{};
  std::optional<Principal> expected;
  SignatureMaterial signature;
  try {
    protected_time = required_string(document, selected.protected_time);
    protected_instant = parse_instant(protected_time);
    const auto& envelope = document.at("signature");
    const auto created_at = required_string(envelope, "createdAt");
    static_cast<void>(parse_instant(created_at));
    if (!protected_time.ends_with('Z') || !created_at.ends_with('Z')) {
      throw std::invalid_argument("protected time and signature.createdAt must use uppercase Z");
    }
    if (protected_time != created_at) {
      throw std::invalid_argument("protected time and signature.createdAt are not byte-equal");
    }
    expected = expected_principal(selected, document);
    const auto value = required_string(envelope, "value");
    const auto decoded = base64url_decode(value, "signature.value");
    if (decoded.size() != 64) {
      throw std::invalid_argument("signature.value does not decode to 64 bytes");
    }
    Ed25519Signature raw{};
    std::ranges::copy(decoded, raw.begin());
    validate_signature_encoding(raw);
    signature = SignatureMaterial{.algorithm = required_string(envelope, "algorithm"),
                                  .key_id = required_string(envelope, "keyId"),
                                  .created_at = created_at,
                                  .value = value,
                                  .bytes = raw};
  } catch (const std::exception& error) {
    fail(VerificationStage::signature_envelope, exception_reason(error));
  }

  ResolvedKey resolved;
  Ed25519PublicKey public_key{};
  try {
    const KeyResolutionRequest request{.kind = kind,
                                       .key_id = signature.key_id,
                                       .expected_principal = expected,
                                       .service_principal_required =
                                           selected.signer_rule == SignerRule::service,
                                       .protected_time = protected_time,
                                       .protected_instant = protected_instant};
    auto candidate = resolver.resolve(request);
    if (!candidate) {
      throw std::invalid_argument("signature.keyId is unknown");
    }
    resolved = std::move(*candidate);
    if (resolved.key_id != request.key_id) {
      throw std::invalid_argument("resolver returned another key ID");
    }
    if (resolved.algorithm != "Ed25519") {
      throw std::invalid_argument("resolved key algorithm is not Ed25519");
    }
    const auto decoded = base64url_decode(resolved.public_key, "resolved public key");
    if (decoded.size() != 32) {
      throw std::invalid_argument("resolved public key does not decode to 32 bytes");
    }
    validate_point(decoded, false, "resolved public key");
    std::ranges::copy(decoded, public_key.begin());
    if (selected.signer_rule == SignerRule::service) {
      if (resolved.principal.type != "service") {
        throw std::invalid_argument("Agent Card signer is not a service Principal");
      }
    } else if (!expected || resolved.principal != *expected) {
      throw std::invalid_argument("resolved key is bound to the wrong Principal");
    }
    const auto valid_from = parse_instant(resolved.valid_from);
    const auto valid_until =
        resolved.valid_until ? std::optional{parse_instant(*resolved.valid_until)} : std::nullopt;
    const auto revoked_at =
        resolved.revoked_at ? std::optional{parse_instant(*resolved.revoked_at)} : std::nullopt;
    if (protected_instant < valid_from) {
      throw std::invalid_argument("signing key is not yet valid at the protected time");
    }
    if (valid_until && protected_instant >= *valid_until) {
      throw std::invalid_argument("signing key is expired at the protected time");
    }
    if (revoked_at && protected_instant >= *revoked_at) {
      throw std::invalid_argument("signing key is revoked at the protected time");
    }
  } catch (const std::exception& error) {
    fail(VerificationStage::key_resolution, exception_reason(error));
  }

  std::string signing_bytes;
  std::string canonical_bytes;
  try {
    if (unpaired_surrogate) {
      throw std::invalid_argument("document contains an unpaired Unicode surrogate");
    }
    auto unsigned_document = document;
    unsigned_document.erase("signature");
    signing_bytes = canonical_json(unsigned_document);
    canonical_bytes = canonical_json(document);
  } catch (const std::exception& error) {
    fail(VerificationStage::canonicalization, exception_reason(error));
  }
  try {
    if (!Ed25519::verify(public_key, bytes_of(signing_bytes), signature.bytes)) {
      throw std::invalid_argument("Ed25519 signature does not verify");
    }
  } catch (const std::exception& error) {
    fail(VerificationStage::signature, exception_reason(error));
  }
  return VerifiedSignedDocument(kind, document, vector_bytes(received_bytes), signing_bytes,
                                sha256(signing_bytes), canonical_bytes, sha256(canonical_bytes),
                                protected_time, protected_instant, signature, resolved);
}

VerifiedSignedDocument SignedDocumentCodec::verify(const SignedDocumentKind kind,
                                                   const std::string_view received_bytes,
                                                   const KeyResolver& resolver) const {
  return verify(kind, bytes_of(received_bytes), resolver);
}

} // namespace missionweaveprotocol
