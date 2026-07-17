#include <missionweaveprotocol/canonical.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace missionweaveprotocol {
namespace {

struct CodePoint {
  std::uint32_t value;
  std::size_t width;
};

[[noreturn]] void unicode_error(const std::size_t position) {
  throw CanonicalError("invalid UTF-8 at byte " + std::to_string(position));
}

[[nodiscard]] CodePoint decode_code_point(const std::string_view text, const std::size_t position) {
  const auto lead = static_cast<std::uint8_t>(text[position]);
  std::size_t width = 0;
  std::uint32_t code_point = 0;
  if (lead < 0x80) {
    return {.value = lead, .width = 1};
  }
  if (lead >= 0xC2 && lead <= 0xDF) {
    width = 2;
    code_point = lead & 0x1FU;
  } else if (lead >= 0xE0 && lead <= 0xEF) {
    width = 3;
    code_point = lead & 0x0FU;
  } else if (lead >= 0xF0 && lead <= 0xF4) {
    width = 4;
    code_point = lead & 0x07U;
  } else {
    unicode_error(position);
  }

  if (text.size() - position < width) {
    unicode_error(position);
  }
  for (std::size_t index = 1; index < width; ++index) {
    const auto continuation = static_cast<std::uint8_t>(text[position + index]);
    if ((continuation & 0xC0U) != 0x80U) {
      unicode_error(position + index);
    }
    code_point = (code_point << 6U) | (continuation & 0x3FU);
  }
  if ((width == 3 && code_point < 0x800U) || (width == 4 && code_point < 0x10000U) ||
      (code_point >= 0xD800U && code_point <= 0xDFFFU) || code_point > 0x10FFFFU) {
    unicode_error(position);
  }
  return {.value = code_point, .width = width};
}

[[nodiscard]] std::vector<std::uint16_t> utf16_units(const std::string_view text) {
  std::vector<std::uint16_t> units;
  for (std::size_t position = 0; position < text.size();) {
    const auto decoded = decode_code_point(text, position);
    if (decoded.value <= 0xFFFFU) {
      units.push_back(static_cast<std::uint16_t>(decoded.value));
    } else {
      const auto supplementary = decoded.value - 0x10000U;
      units.push_back(static_cast<std::uint16_t>(0xD800U + (supplementary >> 10U)));
      units.push_back(static_cast<std::uint16_t>(0xDC00U + (supplementary & 0x3FFU)));
    }
    position += decoded.width;
  }
  return units;
}

void append_escaped_string(std::string& output, const std::string_view text) {
  constexpr char hexadecimal[] = "0123456789abcdef";
  output.push_back('"');
  for (std::size_t position = 0; position < text.size();) {
    const auto value = static_cast<std::uint8_t>(text[position]);
    if (value >= 0x80) {
      const auto decoded = decode_code_point(text, position);
      output.append(text.substr(position, decoded.width));
      position += decoded.width;
      continue;
    }

    ++position;
    switch (value) {
    case '"':
      output += "\\\"";
      break;
    case '\\':
      output += "\\\\";
      break;
    case '\b':
      output += "\\b";
      break;
    case '\t':
      output += "\\t";
      break;
    case '\n':
      output += "\\n";
      break;
    case '\f':
      output += "\\f";
      break;
    case '\r':
      output += "\\r";
      break;
    default:
      if (value < 0x20) {
        output += "\\u00";
        output.push_back(hexadecimal[value >> 4U]);
        output.push_back(hexadecimal[value & 0x0FU]);
      } else {
        output.push_back(static_cast<char>(value));
      }
    }
  }
  output.push_back('"');
}

[[nodiscard]] int parse_exponent(const std::string_view value) {
  std::size_t position = 0;
  int sign = 1;
  if (!value.empty() && (value.front() == '+' || value.front() == '-')) {
    sign = value.front() == '-' ? -1 : 1;
    position = 1;
  }
  if (position == value.size()) {
    throw CanonicalError("invalid floating-point exponent");
  }
  int exponent = 0;
  for (; position < value.size(); ++position) {
    if (value[position] < '0' || value[position] > '9') {
      throw CanonicalError("invalid floating-point exponent");
    }
    exponent = exponent * 10 + (value[position] - '0');
  }
  return sign * exponent;
}

[[nodiscard]] std::string canonical_number(const double number) {
  if (!std::isfinite(number)) {
    throw CanonicalError("RFC 8785 cannot encode a non-finite number");
  }
  if (number == 0.0) {
    return "0";
  }

  std::array<char, 128> buffer{};
  const auto [end, error] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), number,
                                          std::chars_format::general);
  if (error != std::errc{}) {
    throw CanonicalError("unable to serialize a JSON number");
  }

  std::string representation{buffer.data(), end};
  const bool negative = representation.front() == '-';
  if (negative) {
    representation.erase(representation.begin());
  }

  const auto exponent_marker = representation.find_first_of("eE");
  const auto mantissa = representation.substr(0, exponent_marker);
  const auto exponent = exponent_marker == std::string::npos
                            ? 0
                            : parse_exponent(representation.substr(exponent_marker + 1));
  const auto point = mantissa.find('.');
  const auto decimal_position =
      static_cast<long>(point == std::string::npos ? mantissa.size() : point) + exponent;

  std::string digits;
  digits.reserve(mantissa.size());
  for (const auto value : mantissa) {
    if (value != '.') {
      digits.push_back(value);
    }
  }

  const auto first_nonzero = digits.find_first_not_of('0');
  if (first_nonzero == std::string::npos) {
    return "0";
  }
  const auto n = decimal_position - static_cast<long>(first_nonzero);
  digits.erase(0, first_nonzero);
  while (digits.size() > 1 && digits.back() == '0') {
    digits.pop_back();
  }

  const auto k = static_cast<long>(digits.size());
  std::string result;
  if (k <= n && n <= 21) {
    result = digits;
    result.append(static_cast<std::size_t>(n - k), '0');
  } else if (0 < n && n <= 21) {
    result = digits.substr(0, static_cast<std::size_t>(n));
    result.push_back('.');
    result += digits.substr(static_cast<std::size_t>(n));
  } else if (-6 < n && n <= 0) {
    result = "0.";
    result.append(static_cast<std::size_t>(-n), '0');
    result += digits;
  } else {
    result.push_back(digits.front());
    if (digits.size() > 1) {
      result.push_back('.');
      result += digits.substr(1);
    }
    const auto scientific_exponent = n - 1;
    result.push_back('e');
    result.push_back(scientific_exponent < 0 ? '-' : '+');
    result += std::to_string(std::abs(scientific_exponent));
  }

  if (negative) {
    result.insert(result.begin(), '-');
  }
  return result;
}

struct ObjectMember {
  std::string key;
  std::vector<std::uint16_t> order;
  const Json* value;
};

void serialize(const Json& value, std::string& output) {
  if (value.is_null()) {
    output += "null";
  } else if (value.is_bool()) {
    output += value.as<bool>() ? "true" : "false";
  } else if (value.is_number()) {
    output += canonical_number(value.as<double>());
  } else if (value.is_string()) {
    append_escaped_string(output, value.as<std::string>());
  } else if (value.is_array()) {
    output.push_back('[');
    bool first = true;
    for (const auto& element : value.array_range()) {
      if (!first) {
        output.push_back(',');
      }
      first = false;
      serialize(element, output);
    }
    output.push_back(']');
  } else if (value.is_object()) {
    std::vector<ObjectMember> members;
    members.reserve(value.size());
    for (const auto& member : value.object_range()) {
      auto key = std::string{member.key()};
      members.push_back(
          {.key = key, .order = utf16_units(key), .value = std::addressof(member.value())});
    }
    std::ranges::sort(members, [](const ObjectMember& left, const ObjectMember& right) {
      if (left.order == right.order) {
        return left.key < right.key;
      }
      return left.order < right.order;
    });

    output.push_back('{');
    bool first = true;
    for (const auto& member : members) {
      if (!first) {
        output.push_back(',');
      }
      first = false;
      append_escaped_string(output, member.key);
      output.push_back(':');
      serialize(*member.value, output);
    }
    output.push_back('}');
  } else {
    throw CanonicalError("value is outside the RFC 8785 JSON data model");
  }
}

[[nodiscard]] std::string sha256_hex(const std::string_view bytes) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int size = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1) {
    throw CanonicalError("unable to calculate SHA-256");
  }

  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (unsigned int index = 0; index < size; ++index) {
    output << std::setw(2) << static_cast<unsigned int>(digest[index]);
  }
  return output.str();
}

} // namespace

std::string canonical_json(const Json& value) {
  std::string result;
  serialize(value, result);
  return result;
}

std::string canonicalize_json(const std::string_view document) {
  return canonical_json(parse_strict_json(document));
}

std::string canonical_sha256(const Json& value) {
  return "sha256:" + sha256_hex(canonical_json(value));
}

std::string canonical_sha256_document(const std::string_view document) {
  return canonical_sha256(parse_strict_json(document));
}

} // namespace missionweaveprotocol
