#include <missionweaveprotocol/json.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>

namespace missionweaveprotocol {
namespace {

class StrictScanner final {
public:
  explicit StrictScanner(const std::string_view input) : input_(input) {}

  void scan() {
    skip_whitespace();
    parse_value(0);
    skip_whitespace();
    if (position_ != input_.size()) {
      fail("unexpected trailing content");
    }
  }

private:
  static constexpr std::size_t maximum_depth = 512;

  [[noreturn]] void fail(const std::string_view message) const {
    throw StrictJsonError(std::string{message} + " at byte " + std::to_string(position_));
  }

  [[nodiscard]] bool at_end() const noexcept { return position_ >= input_.size(); }

  [[nodiscard]] char current() const {
    if (at_end()) {
      fail("unexpected end of JSON");
    }
    return input_[position_];
  }

  void skip_whitespace() noexcept {
    while (!at_end()) {
      const auto value = input_[position_];
      if (value != ' ' && value != '\t' && value != '\n' && value != '\r') {
        return;
      }
      ++position_;
    }
  }

  void expect(const char expected) {
    if (current() != expected) {
      fail("unexpected character");
    }
    ++position_;
  }

  void parse_value(const std::size_t depth) {
    if (depth > maximum_depth) {
      fail("JSON nesting exceeds the supported limit");
    }
    skip_whitespace();
    switch (current()) {
    case '{':
      parse_object(depth + 1);
      return;
    case '[':
      parse_array(depth + 1);
      return;
    case '"':
      static_cast<void>(parse_string());
      return;
    case 't':
      parse_literal("true");
      return;
    case 'f':
      parse_literal("false");
      return;
    case 'n':
      parse_literal("null");
      return;
    default:
      parse_number();
    }
  }

  void parse_object(const std::size_t depth) {
    expect('{');
    skip_whitespace();
    if (!at_end() && current() == '}') {
      ++position_;
      return;
    }

    std::unordered_set<std::string> names;
    while (true) {
      skip_whitespace();
      if (current() != '"') {
        fail("object member name must be a string");
      }
      auto name = parse_string();
      if (!names.insert(std::move(name)).second) {
        fail("duplicate object member");
      }
      skip_whitespace();
      expect(':');
      parse_value(depth);
      skip_whitespace();
      if (current() == '}') {
        ++position_;
        return;
      }
      expect(',');
    }
  }

  void parse_array(const std::size_t depth) {
    expect('[');
    skip_whitespace();
    if (!at_end() && current() == ']') {
      ++position_;
      return;
    }

    while (true) {
      parse_value(depth);
      skip_whitespace();
      if (current() == ']') {
        ++position_;
        return;
      }
      expect(',');
    }
  }

  void parse_literal(const std::string_view literal) {
    if (input_.substr(position_, literal.size()) != literal) {
      fail("invalid JSON literal");
    }
    position_ += literal.size();
  }

  void parse_number() {
    if (current() == '-') {
      ++position_;
    }
    if (at_end()) {
      fail("incomplete JSON number");
    }

    if (current() == '0') {
      ++position_;
      if (!at_end() && current() >= '0' && current() <= '9') {
        fail("JSON number has a leading zero");
      }
    } else if (current() >= '1' && current() <= '9') {
      while (!at_end() && current() >= '0' && current() <= '9') {
        ++position_;
      }
    } else {
      fail("invalid JSON number");
    }

    if (!at_end() && current() == '.') {
      ++position_;
      if (at_end() || current() < '0' || current() > '9') {
        fail("JSON fraction requires a digit");
      }
      while (!at_end() && current() >= '0' && current() <= '9') {
        ++position_;
      }
    }

    if (!at_end() && (current() == 'e' || current() == 'E')) {
      ++position_;
      if (!at_end() && (current() == '+' || current() == '-')) {
        ++position_;
      }
      if (at_end() || current() < '0' || current() > '9') {
        fail("JSON exponent requires a digit");
      }
      while (!at_end() && current() >= '0' && current() <= '9') {
        ++position_;
      }
    }
  }

  [[nodiscard]] std::string parse_string() {
    expect('"');
    std::string decoded;
    while (true) {
      if (at_end()) {
        fail("unterminated JSON string");
      }

      const auto value = static_cast<std::uint8_t>(input_[position_]);
      if (value == '"') {
        ++position_;
        return decoded;
      }
      if (value == '\\') {
        ++position_;
        parse_escape(decoded);
        continue;
      }
      if (value < 0x20) {
        fail("unescaped control character in JSON string");
      }
      if (value < 0x80) {
        decoded.push_back(static_cast<char>(value));
        ++position_;
        continue;
      }

      append_utf8(decoded, parse_utf8_code_point());
    }
  }

  void parse_escape(std::string& decoded) {
    if (at_end()) {
      fail("incomplete JSON escape");
    }
    const auto escape = input_[position_++];
    switch (escape) {
    case '"':
    case '\\':
    case '/':
      decoded.push_back(escape);
      return;
    case 'b':
      decoded.push_back('\b');
      return;
    case 'f':
      decoded.push_back('\f');
      return;
    case 'n':
      decoded.push_back('\n');
      return;
    case 'r':
      decoded.push_back('\r');
      return;
    case 't':
      decoded.push_back('\t');
      return;
    case 'u':
      parse_unicode_escape(decoded);
      return;
    default:
      fail("invalid JSON escape");
    }
  }

  [[nodiscard]] std::uint16_t parse_hex_quad() {
    if (input_.size() - position_ < 4) {
      fail("incomplete Unicode escape");
    }
    std::uint16_t value = 0;
    for (int count = 0; count < 4; ++count) {
      const auto digit = input_[position_++];
      value = static_cast<std::uint16_t>(value << 4U);
      if (digit >= '0' && digit <= '9') {
        value = static_cast<std::uint16_t>(value + digit - '0');
      } else if (digit >= 'a' && digit <= 'f') {
        value = static_cast<std::uint16_t>(value + digit - 'a' + 10);
      } else if (digit >= 'A' && digit <= 'F') {
        value = static_cast<std::uint16_t>(value + digit - 'A' + 10);
      } else {
        fail("invalid Unicode escape");
      }
    }
    return value;
  }

  void parse_unicode_escape(std::string& decoded) {
    const auto first = parse_hex_quad();
    std::uint32_t code_point = first;
    if (first >= 0xD800 && first <= 0xDBFF) {
      if (input_.size() - position_ < 6 || input_[position_] != '\\' ||
          input_[position_ + 1] != 'u') {
        fail("high surrogate requires a low surrogate");
      }
      position_ += 2;
      const auto second = parse_hex_quad();
      if (second < 0xDC00 || second > 0xDFFF) {
        fail("invalid low surrogate");
      }
      code_point = 0x10000U + ((static_cast<std::uint32_t>(first) - 0xD800U) << 10U) +
                   (static_cast<std::uint32_t>(second) - 0xDC00U);
    } else if (first >= 0xDC00 && first <= 0xDFFF) {
      fail("isolated low surrogate");
    }
    append_utf8(decoded, code_point);
  }

  [[nodiscard]] std::uint32_t parse_utf8_code_point() {
    const auto lead = static_cast<std::uint8_t>(input_[position_]);
    std::size_t width = 0;
    std::uint32_t code_point = 0;
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
      fail("invalid UTF-8 leading byte");
    }

    if (input_.size() - position_ < width) {
      fail("truncated UTF-8 sequence");
    }
    for (std::size_t index = 1; index < width; ++index) {
      const auto continuation = static_cast<std::uint8_t>(input_[position_ + index]);
      if ((continuation & 0xC0U) != 0x80U) {
        fail("invalid UTF-8 continuation byte");
      }
      code_point = (code_point << 6U) | (continuation & 0x3FU);
    }

    if ((width == 3 && code_point < 0x800U) || (width == 4 && code_point < 0x10000U) ||
        (code_point >= 0xD800U && code_point <= 0xDFFFU) || code_point > 0x10FFFFU) {
      fail("non-canonical UTF-8 sequence");
    }
    position_ += width;
    return code_point;
  }

  static void append_utf8(std::string& output, const std::uint32_t code_point) {
    if (code_point <= 0x7FU) {
      output.push_back(static_cast<char>(code_point));
    } else if (code_point <= 0x7FFU) {
      output.push_back(static_cast<char>(0xC0U | (code_point >> 6U)));
      output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    } else if (code_point <= 0xFFFFU) {
      output.push_back(static_cast<char>(0xE0U | (code_point >> 12U)));
      output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
      output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    } else {
      output.push_back(static_cast<char>(0xF0U | (code_point >> 18U)));
      output.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
      output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
      output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    }
  }

  std::string_view input_;
  std::size_t position_ = 0;
};

} // namespace

Json parse_strict_json(const std::string_view text) {
  StrictScanner{text}.scan();
  try {
    return Json::parse(std::string{text});
  } catch (const std::exception& error) {
    throw StrictJsonError(std::string{"unable to decode strict JSON: "} + error.what());
  }
}

Json parse_strict_json(const AssetBytes bytes) {
  return parse_strict_json({reinterpret_cast<const char*>(bytes.data()), bytes.size()});
}

} // namespace missionweaveprotocol
