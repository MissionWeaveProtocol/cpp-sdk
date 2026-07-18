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
#include <optional>
#include <string>

namespace {

std::string base64url(const missionweaveprotocol::AssetBytes bytes) {
  std::string encoded(((bytes.size() + 2) / 3) * 4, '\0');
  const auto size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()), bytes.data(),
                                    static_cast<int>(bytes.size()));
  encoded.resize(static_cast<std::size_t>(size));
  std::ranges::replace(encoded, '+', '-');
  std::ranges::replace(encoded, '/', '_');
  while (!encoded.empty() && encoded.back() == '=') {
    encoded.pop_back();
  }
  return encoded;
}

class ExampleSigningKey final : public missionweaveprotocol::SigningKey {
public:
  explicit ExampleSigningKey(missionweaveprotocol::Ed25519Seed seed) : seed_(seed) {}

  [[nodiscard]] std::string key_id() const override {
    return "urn:missionweaveprotocol:key:example";
  }

  [[nodiscard]] missionweaveprotocol::Ed25519Signature
  sign(const missionweaveprotocol::AssetBytes signing_bytes) const override {
    return missionweaveprotocol::Ed25519::sign(seed_, signing_bytes);
  }

private:
  missionweaveprotocol::Ed25519Seed seed_;
};

class ExampleResolver final : public missionweaveprotocol::KeyResolver {
public:
  explicit ExampleResolver(std::string public_key) : public_key_(std::move(public_key)) {}

  [[nodiscard]] std::optional<missionweaveprotocol::ResolvedKey>
  resolve(const missionweaveprotocol::KeyResolutionRequest& request) const override {
    return missionweaveprotocol::ResolvedKey{
        .key_id = request.key_id,
        .principal = *request.expected_principal,
        .algorithm = "Ed25519",
        .public_key = public_key_,
        .valid_from = "2026-01-01T00:00:00Z",
        .valid_until = std::nullopt,
        .revoked_at = std::nullopt,
    };
  }

private:
  std::string public_key_;
};

} // namespace

int main() {
  try {
    missionweaveprotocol::Ed25519Seed seed{};
    for (std::size_t index = 0; index < seed.size(); ++index) {
      seed[index] = static_cast<std::uint8_t>(index + 1);
    }

    const auto command_bytes = missionweaveprotocol::ProtocolBundle::cryptography(
        "vectors/signed-documents/valid/command.json");
    if (!command_bytes) {
      throw std::runtime_error("packaged command cryptography vector is missing");
    }
    auto document = missionweaveprotocol::parse_strict_json(*command_bytes);
    document.erase("signature");
    const auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
    const ExampleSigningKey signing_key(seed);
    const ExampleResolver resolver(base64url(public_key));
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
