#include <missionweaveprotocol/crypto.hpp>

#include <missionweaveprotocol/canonical.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace missionweaveprotocol {
namespace {

using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

[[nodiscard]] Key private_key(const Ed25519Seed& seed) {
  Key key{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()),
          &EVP_PKEY_free};
  if (!key) {
    throw CryptoError("unable to create Ed25519 private key");
  }
  return key;
}

[[nodiscard]] Key public_key(const Ed25519PublicKey& bytes) {
  Key key{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, bytes.data(), bytes.size()),
          &EVP_PKEY_free};
  if (!key) {
    throw CryptoError("unable to create Ed25519 public key");
  }
  return key;
}

[[nodiscard]] Context context() {
  Context result{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
  if (!result) {
    throw CryptoError("unable to create Ed25519 operation context");
  }
  return result;
}

[[nodiscard]] std::string base64url_encode(const AssetBytes bytes) {
  std::string encoded(((bytes.size() + 2) / 3) * 4, '\0');
  const auto size = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()), bytes.data(),
                                    static_cast<int>(bytes.size()));
  if (size < 0) {
    throw CryptoError("unable to encode Ed25519 signature");
  }
  encoded.resize(static_cast<std::size_t>(size));
  std::ranges::replace(encoded, '+', '-');
  std::ranges::replace(encoded, '/', '_');
  while (!encoded.empty() && encoded.back() == '=') {
    encoded.pop_back();
  }
  return encoded;
}

[[nodiscard]] std::vector<std::uint8_t> base64url_decode(const std::string_view encoded) {
  if (encoded.size() % 4 == 1 || encoded.find('=') != std::string_view::npos) {
    throw CryptoError("invalid unpadded base64url signature");
  }
  std::string padded{encoded};
  for (auto& value : padded) {
    if (value == '-') {
      value = '+';
    } else if (value == '_') {
      value = '/';
    } else if (!((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
                 (value >= '0' && value <= '9'))) {
      throw CryptoError("invalid unpadded base64url signature");
    }
  }
  const auto padding = (4 - padded.size() % 4) % 4;
  padded.append(padding, '=');

  std::vector<std::uint8_t> decoded((padded.size() / 4) * 3);
  const auto size =
      EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(padded.data()),
                      static_cast<int>(padded.size()));
  if (size < 0 || static_cast<std::size_t>(size) < padding) {
    throw CryptoError("invalid unpadded base64url signature");
  }
  decoded.resize(static_cast<std::size_t>(size) - padding);
  return decoded;
}

[[nodiscard]] AssetBytes bytes_of(const std::string_view value) noexcept {
  return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

} // namespace

Ed25519PublicKey Ed25519::public_key_from_seed(const Ed25519Seed& seed) {
  auto key = private_key(seed);
  Ed25519PublicKey result{};
  std::size_t size = result.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), result.data(), &size) != 1 || size != result.size()) {
    throw CryptoError("unable to derive Ed25519 public key");
  }
  return result;
}

Ed25519Signature Ed25519::sign(const Ed25519Seed& seed, const AssetBytes message) {
  auto key = private_key(seed);
  auto operation = context();
  if (EVP_DigestSignInit(operation.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    throw CryptoError("unable to initialize Ed25519 signing");
  }

  Ed25519Signature signature{};
  std::size_t size = signature.size();
  if (EVP_DigestSign(operation.get(), signature.data(), &size, message.data(), message.size()) !=
          1 ||
      size != signature.size()) {
    throw CryptoError("unable to sign with Ed25519");
  }
  return signature;
}

bool Ed25519::verify(const Ed25519PublicKey& public_key_bytes, const AssetBytes message,
                     const Ed25519Signature& signature) {
  auto key = public_key(public_key_bytes);
  auto operation = context();
  if (EVP_DigestVerifyInit(operation.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    throw CryptoError("unable to initialize Ed25519 verification");
  }
  const auto result = EVP_DigestVerify(operation.get(), signature.data(), signature.size(),
                                       message.data(), message.size());
  if (result < 0) {
    throw CryptoError("unable to verify Ed25519 signature");
  }
  return result == 1;
}

std::string Ed25519::sign_base64url(const Ed25519Seed& seed, const AssetBytes message) {
  const auto signature = sign(seed, message);
  return base64url_encode(signature);
}

bool Ed25519::verify_base64url(const Ed25519PublicKey& public_key_bytes, const AssetBytes message,
                               const std::string_view signature) {
  std::vector<std::uint8_t> decoded;
  try {
    decoded = base64url_decode(signature);
  } catch (const CryptoError&) {
    return false;
  }
  if (decoded.size() != Ed25519Signature{}.size()) {
    return false;
  }
  Ed25519Signature raw{};
  std::ranges::copy(decoded, raw.begin());
  return verify(public_key_bytes, message, raw);
}

std::string document_signing_payload(const Json& document) {
  if (!document.is_object()) {
    throw CryptoError("signed protocol document must be a JSON object");
  }
  auto unsigned_document = document;
  unsigned_document.erase("signature");
  return canonical_json(unsigned_document);
}

std::string Ed25519::sign_document(const Ed25519Seed& seed, const Json& document) {
  const auto payload = document_signing_payload(document);
  return sign_base64url(seed, bytes_of(payload));
}

bool Ed25519::verify_document(const Ed25519PublicKey& public_key_bytes, const Json& document,
                              const std::string_view signature) {
  const auto payload = document_signing_payload(document);
  return verify_base64url(public_key_bytes, bytes_of(payload), signature);
}

} // namespace missionweaveprotocol
