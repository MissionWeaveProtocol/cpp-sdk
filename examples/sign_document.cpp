#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>
#include <missionweaveprotocol/json.hpp>
#include <missionweaveprotocol/signed_document.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr auto example_key_id = "urn:missionweaveprotocol:key:example";

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

missionweaveprotocol::Ed25519Seed random_seed() {
  missionweaveprotocol::Ed25519Seed seed{};
  if (RAND_priv_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
    throw std::runtime_error("OpenSSL could not generate an Ed25519 seed");
  }
  return seed;
}

missionweaveprotocol::Json example_command() {
  return missionweaveprotocol::parse_strict_json(R"({
    "protocolVersion": "0.1",
    "actionId": "urn:uuid:00000000-0000-4000-8000-000000000011",
    "actor": {
      "type": "agent",
      "id": "urn:missionweaveprotocol:agent:coordinator"
    },
    "sessionEpoch": 7,
    "membershipEpoch": 3,
    "groupId": "urn:missionweaveprotocol:group:mission-one",
    "conversationId": "urn:missionweaveprotocol:conversation:planning",
    "kind": "message.post",
    "expectedRevision": 4,
    "correlationId": "urn:uuid:00000000-0000-4000-8000-000000000012",
    "issuedAt": "2026-07-17T08:00:00Z",
    "payload": {
      "messageId": "urn:missionweaveprotocol:message:one",
      "authority": false
    }
  })");
}

std::vector<std::uint8_t>
example_registry(const missionweaveprotocol::Ed25519PublicKey& public_key) {
  auto registry = missionweaveprotocol::parse_strict_json(R"({
    "organizationId": "urn:missionweaveprotocol:organization:example",
    "bindings": [
      {
        "keyId": "urn:missionweaveprotocol:key:example",
        "principal": {
          "type": "agent",
          "id": "urn:missionweaveprotocol:agent:coordinator"
        },
        "algorithm": "Ed25519",
        "publicKey": "replace-at-runtime",
        "validFrom": "2026-01-01T00:00:00Z",
        "validityHistory": []
      }
    ]
  })");
  registry.at("bindings").at(0).at("publicKey") = base64url(public_key);
  const auto encoded = missionweaveprotocol::canonical_json(registry);
  return {encoded.begin(), encoded.end()};
}

class ExampleSigningKey final : public missionweaveprotocol::SigningKey {
public:
  explicit ExampleSigningKey(missionweaveprotocol::Ed25519Seed seed) : seed_(seed) {}

  [[nodiscard]] std::string key_id() const override { return example_key_id; }

  [[nodiscard]] missionweaveprotocol::Ed25519Signature
  sign(const missionweaveprotocol::AssetBytes signing_bytes) const override {
    return missionweaveprotocol::Ed25519::sign(seed_, signing_bytes);
  }

private:
  missionweaveprotocol::Ed25519Seed seed_;
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
    const auto seed = random_seed();
    const auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
    const auto document = example_command();
    const ExampleSigningKey signing_key(seed);
    const ExampleResolver resolver(example_registry(public_key));
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
