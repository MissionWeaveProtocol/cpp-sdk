#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::string required_text(const missionweaveprotocol::Json& object, const std::string_view field) {
  if (!object.is_object() || !object.contains(field) || !object.at(field).is_string()) {
    throw std::invalid_argument("signing fixture field is not text: " + std::string{field});
  }
  return object.at(field).as<std::string>();
}

std::vector<std::uint8_t> decode_base64url(const std::string_view encoded) {
  if (encoded.empty() || encoded.size() % 4 == 1 || encoded.find('=') != std::string_view::npos) {
    throw std::invalid_argument("signing fixture seed is not unpadded base64url");
  }
  std::string padded{encoded};
  for (auto& value : padded) {
    if (value == '-') {
      value = '+';
    } else if (value == '_') {
      value = '/';
    }
  }
  const auto padding = (4 - padded.size() % 4) % 4;
  padded.append(padding, '=');
  std::vector<std::uint8_t> decoded((padded.size() / 4) * 3);
  const auto size =
      EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(padded.data()),
                      static_cast<int>(padded.size()));
  if (size < 0 || static_cast<std::size_t>(size) < padding) {
    throw std::invalid_argument("signing fixture seed cannot be decoded");
  }
  decoded.resize(static_cast<std::size_t>(size) - padding);
  return decoded;
}

class ExampleSigningKey final : public missionweaveprotocol::SigningKey {
public:
  explicit ExampleSigningKey(const missionweaveprotocol::Json& fixture)
      : key_id_(required_text(fixture, "keyId")) {
    const auto raw = decode_base64url(required_text(fixture, "seed"));
    if (raw.size() != seed_.size()) {
      throw std::invalid_argument("signing fixture seed is not 32 bytes");
    }
    std::ranges::copy(raw, seed_.begin());
  }

  [[nodiscard]] std::string key_id() const override { return key_id_; }

  [[nodiscard]] missionweaveprotocol::Ed25519Signature
  sign(const missionweaveprotocol::AssetBytes signing_bytes) const override {
    return missionweaveprotocol::Ed25519::sign(seed_, signing_bytes);
  }

private:
  std::string key_id_;
  missionweaveprotocol::Ed25519Seed seed_{};
};

class ExampleResolver final : public missionweaveprotocol::KeyResolver {
public:
  explicit ExampleResolver(std::vector<std::uint8_t> registry) : registry_(std::move(registry)) {}

  [[nodiscard]] missionweaveprotocol::KeyRegistrySnapshot
  resolve(const missionweaveprotocol::KeyResolutionRequest&) const override {
    return missionweaveprotocol::KeyRegistrySnapshot::organization_wide(registry_);
  }

private:
  std::vector<std::uint8_t> registry_;
};

} // namespace

int main() {
  try {
    const auto command_bytes = missionweaveprotocol::ProtocolBundle::cryptography(
        "vectors/signed-documents/valid/command.json");
    const auto signing_key_bytes =
        missionweaveprotocol::ProtocolBundle::cryptography("keys/signing-coordinator.json");
    const auto registry_bytes =
        missionweaveprotocol::ProtocolBundle::cryptography("keys/registry-valid.json");
    if (!command_bytes || !signing_key_bytes || !registry_bytes) {
      throw std::runtime_error("packaged signing cryptography assets are missing");
    }
    auto document = missionweaveprotocol::parse_strict_json(*command_bytes);
    document.erase("signature");
    const ExampleSigningKey signing_key(
        missionweaveprotocol::parse_strict_json(*signing_key_bytes));
    const ExampleResolver resolver(
        std::vector<std::uint8_t>{registry_bytes->begin(), registry_bytes->end()});
    const missionweaveprotocol::SignedDocumentCodec codec;
    const auto signed_document =
        codec.sign(missionweaveprotocol::SignedDocumentKind::command, document, signing_key);
    const auto encoded = missionweaveprotocol::canonical_json(signed_document);
    const auto verified =
        codec.verify(missionweaveprotocol::SignedDocumentKind::command, encoded, resolver);

    std::cout << "signature: " << verified.signature().value << '\n';
    std::cout << "content id: " << verified.canonical_hash() << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "signing example failed: " << error.what() << '\n';
    return 1;
  }
}
