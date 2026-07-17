#pragma once

#include <missionweaveprotocol/bundle.hpp>
#include <missionweaveprotocol/json.hpp>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace missionweaveprotocol {

using Ed25519Seed = std::array<std::uint8_t, 32>;
using Ed25519PublicKey = std::array<std::uint8_t, 32>;
using Ed25519Signature = std::array<std::uint8_t, 64>;

class CryptoError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class Ed25519 final {
public:
  [[nodiscard]] static Ed25519PublicKey public_key_from_seed(const Ed25519Seed& seed);
  [[nodiscard]] static Ed25519Signature sign(const Ed25519Seed& seed, AssetBytes message);
  [[nodiscard]] static bool verify(const Ed25519PublicKey& public_key, AssetBytes message,
                                   const Ed25519Signature& signature);
  [[nodiscard]] static std::string sign_base64url(const Ed25519Seed& seed, AssetBytes message);
  [[nodiscard]] static bool verify_base64url(const Ed25519PublicKey& public_key, AssetBytes message,
                                             std::string_view signature);
  [[nodiscard]] static std::string sign_document(const Ed25519Seed& seed, const Json& document);
  [[nodiscard]] static bool verify_document(const Ed25519PublicKey& public_key,
                                            const Json& document, std::string_view signature);
};

[[nodiscard]] std::string document_signing_payload(const Json& document);

} // namespace missionweaveprotocol
