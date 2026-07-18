**English** | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

Official C++20 protocol SDK for MissionWeaveProtocol. It provides strict JSON handling, an offline
Draft 2020-12 schema registry, the canonical conformance vectors, RFC 8785 canonical JSON and
`sha256:` identifiers, Ed25519 signing, and a schema-validating frame codec.

The current release demonstrates **schema-and-vector conformance**. It is not a port of the full
Python reference runtime: Core, Worker execution, cross-Group scheduling, storage, replay, and a
WebSocket connection client remain outside this SDK's initial scope.

## Capabilities

- Exact, byte-preserving `PROTOCOL_PIN.json`, 21 schemas, and 53 conformance JSON artifacts.
- Strict UTF-8 JSON parsing with decoded duplicate-member rejection.
- Offline `$id` resolution for all embedded Draft 2020-12 schemas, with format assertions enabled.
- An installed `missionweaveprotocol-conformance` CLI that passes all 52/52 vectors: 25 valid and
  27 invalid.
- RFC 8785 canonical JSON, including UTF-16 property ordering and ECMAScript number formatting.
- Lowercase SHA-256 content identifiers in `sha256:<hex>` form.
- Ed25519 signing and verification, tested against RFC 8032 test vector 1.
- `FrameCodec` for strict parsing, schema validation, and canonical WebSocket frame encoding.
- An installable CMake package exposed as `MissionWeaveProtocol::sdk`.

## Requirements

- A C++20 compiler.
- CMake 3.24 or newer.
- OpenSSL 3.0 or newer.
- Ninja is recommended but not required.

The build uses an installed jsoncons 1.8.1 package when available. Otherwise CMake downloads the
pinned jsoncons 1.8.1 source during configuration; runtime validation remains fully offline.

## Build from source

No registry package or release tag is advertised yet. Clone the repository and build the protected
`main` branch:

```console
git clone https://github.com/MissionWeaveProtocol/cpp-sdk.git
cd cpp-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/missionweaveprotocol-conformance
```

Install to a private prefix:

```console
cmake --install build --prefix /path/to/prefix
```

Consume the installed package:

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

Point `CMAKE_PREFIX_PATH` at the chosen prefix when configuring the consumer.

## Quick start

Strictly decode and validate a frame, then emit canonical bytes:

```cpp
#include <missionweaveprotocol/frame.hpp>

missionweaveprotocol::FrameCodec codec;
auto frame = codec.decode(input_bytes);
std::string canonical = codec.encode(frame);
```

Create a stable content identifier:

```cpp
#include <missionweaveprotocol/canonical.hpp>

std::string content_id = missionweaveprotocol::canonical_sha256(frame);
```

Sign and verify a protocol document. The document helpers omit only the top-level `signature`
member from the canonical signing payload; nested members with that name remain covered:

```cpp
#include <missionweaveprotocol/crypto.hpp>

missionweaveprotocol::Ed25519Seed seed{}; // Load 32 protected random bytes in production.
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

For the complete six-stage profile, use
`SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` and
`verify(kind, received_bytes, key_resolver)`. The kind is always explicit; `SigningKey` and the
Organization-controlled `KeyResolver` are the only external adapters, and verification returns
immutable received, signing, canonical, signature, and resolved-Principal evidence.

Validate any embedded protocol document:

```cpp
#include <missionweaveprotocol/schema.hpp>

missionweaveprotocol::SchemaCatalog schemas;
auto result = schemas.validate("mission.schema.json", document);
if (!result.valid && result.issue) {
  // result.issue contains the keyword, instance location, schema location, and message.
}
```

See `examples/validate_frame.cpp` and `examples/sign_document.cpp` for complete runnable programs.

## Pinned protocol bundle

This SDK embeds assets from the following exact MissionWeaveProtocol revision:

| Item | Value |
| --- | --- |
| Protocol commit | `6f10987627d62fb296e3490ceceb5539b1e94b70` |
| Schema files | `21` |
| Schema tree SHA-256 | `a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413` |
| Conformance JSON files | `53` |
| Conformance tree SHA-256 | `21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da` |
| Combined bundle SHA-256 | `b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7` |

`ProtocolBundle::verify()` checks the counts and path-and-byte-sensitive digests at runtime.

## Conformance scope

The CLI and library runner validate the 52 manifest cases against the exact embedded schemas:

```console
missionweaveprotocol-conformance
# 52/52 conformance vectors passed (25 valid, 27 invalid)
```

This result is intentionally limited to schema-and-vector conformance. It does not claim full
behavioral conformance for coordination, scheduling, leasing, replay, persistence, or transport
lifecycle behavior.

## Security notes

- Keep Ed25519 seeds outside source code and load them from an appropriate secret store.
- Verify schema validity before treating a decoded document as an authorized command or event.
- Extension data remains data; it cannot replace core protocol fields or grant authority by itself.
- The embedded schema resolver performs no network access.

## License

Apache-2.0. Third-party notices are listed in `THIRD_PARTY_NOTICES.md`.
