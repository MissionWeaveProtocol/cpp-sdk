#include <missionweaveprotocol/crypto.hpp>
#include <missionweaveprotocol/json.hpp>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace {

template <std::size_t Size>
std::array<std::uint8_t, Size> decode_hex(const std::string_view value) {
  assert(value.size() == Size * 2);
  std::array<std::uint8_t, Size> output{};
  for (std::size_t index = 0; index < Size; ++index) {
    const auto byte = value.substr(index * 2, 2);
    output[index] = static_cast<std::uint8_t>(std::stoul(std::string{byte}, nullptr, 16));
  }
  return output;
}

missionweaveprotocol::AssetBytes bytes(const std::string_view value) {
  return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

} // namespace

int main() {
  const auto seed =
      decode_hex<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const auto expected_public =
      decode_hex<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const auto expected_signature =
      decode_hex<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

  const auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
  assert(public_key == expected_public);
  const auto signature = missionweaveprotocol::Ed25519::sign(seed, {});
  assert(signature == expected_signature);
  assert(missionweaveprotocol::Ed25519::verify(public_key, {}, signature));

  missionweaveprotocol::Ed25519Seed document_seed{};
  for (std::size_t index = 0; index < document_seed.size(); ++index) {
    document_seed[index] = static_cast<std::uint8_t>(index + 1);
  }
  const auto document_public = missionweaveprotocol::Ed25519::public_key_from_seed(document_seed);
  const auto first = missionweaveprotocol::parse_strict_json(
      R"({"payload":{"signature":"nested"},"signature":{"value":"old"},"value":1})");
  const auto second = missionweaveprotocol::parse_strict_json(
      R"({"signature":{"value":"different"},"value":1,"payload":{"signature":"nested"}})");
  const auto left = missionweaveprotocol::Ed25519::sign_document(document_seed, first);
  const auto right = missionweaveprotocol::Ed25519::sign_document(document_seed, second);
  assert(left == right);
  assert(missionweaveprotocol::Ed25519::verify_document(document_public, second, left));

  const auto tampered =
      missionweaveprotocol::parse_strict_json(R"({"value":2,"payload":{"signature":"nested"}})");
  assert(!missionweaveprotocol::Ed25519::verify_document(document_public, tampered, left));
  assert(
      !missionweaveprotocol::Ed25519::verify_base64url(document_public, bytes("message"), "short"));
}
