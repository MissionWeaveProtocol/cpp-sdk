**English** | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

Official C++20 protocol SDK for MissionWeaveProtocol. It provides strict JSON handling, an offline
Draft 2020-12 schema registry, the canonical conformance vectors, RFC 8785 canonical JSON and
`sha256:` identifiers, Ed25519 signing, First-Admission and historical-trust verification, and a
schema-validating frame codec.

The current release demonstrates **schema-and-vector conformance**. It is not a port of the full
Python reference runtime: Core, Worker execution, cross-Group scheduling, storage, replay, and a
WebSocket connection client remain outside this SDK's initial scope.

## Capabilities

- Exact, byte-preserving `PROTOCOL_PIN.json`, 22 schemas, and 59 conformance JSON artifacts.
- Strict UTF-8 JSON parsing with decoded duplicate-member rejection.
- Offline `$id` resolution for all embedded Draft 2020-12 schemas, with format assertions enabled.
- An installed `missionweaveprotocol-conformance` CLI that passes all 58/58 vectors: 27 valid and
  31 invalid.
- RFC 8785 canonical JSON, including UTF-16 property ordering and ECMAScript number formatting.
- Lowercase SHA-256 content identifiers in `sha256:<hex>` form.
- Ed25519 signing and verification, tested against RFC 8032 test vector 1.
- `AdmissionService` for fail-closed first admission and historical replay over an authenticated,
  append-only Admission Log adapter.
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

These direct Ed25519 helpers are lower-level cryptographic primitives; they do not perform complete
MissionWeaveProtocol verification.

For the complete six-stage profile, use
`SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` and
`verify(kind, received_bytes, key_resolver)`. The kind is always explicit. A `KeyResolver` receives
a `KeyResolutionRequest` and returns
`KeyRegistrySnapshot::organization_wide(registry_bytes)`, never a selected `ResolvedKey`.
`organization_wide` is a trusted adapter assertion, not a completeness proof: the bytes must cover
one coherent, authoritative Registry revision applicable to the verification decision for exactly
one Organization, including all Organization-wide bindings and complete retained validity history.
`request.key_id` is routing context only and must not authorize filtering or a partial projection.

The codec treats the Registry bytes as untrusted and validates every binding and its complete
retained history before selecting the key. `KeyRegistryCompleteness::partial`,
`KeyRegistryCompleteness::unspecified`, unavailable, empty, or malformed evidence fails closed at
key resolution. Codec-produced evidence retains `organization_id`. That Registry-evidence migration
is intentionally source- and ABI-breaking.

For First Admission, include `missionweaveprotocol/admission.hpp`. `AdmissionService::admit_first`
uses a separate `AdmissionCurrentKeyResolver`, consults the Admission Log only after six-stage
verification, and validates the committed record before returning. `verify_historical_admission`
requires an existing authenticated record and never appends. See the
[Admission bundle](admission/README.md) for the exact failure and adapter model.

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
| Protocol commit | `f7e70a72c76bbeb5014c186cd820aac2112f0dde` |
| Schema files | `22` |
| Schema tree SHA-256 | `941a5a19b8664207f1ff48b799219c2f981ecd491a5cca527d586028d976ec76` |
| Conformance JSON files | `59` |
| Conformance tree SHA-256 | `2362acd8345e5860e605ed06984f1673a1ea0a00e76c1fe00fed222326782f24` |
| Combined bundle SHA-256 | `c95fc8f8334947dacf51a2c6e84d9b13f5b39b7d3827591569a1e2c5acfe47d7` |
| Admission digest | `sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0` |

`ProtocolBundle::verify()` checks the counts and path-and-byte-sensitive digests at runtime.

## Conformance scope

The CLI and library runner validate the 58 manifest cases against the exact embedded schemas.

The pinned cryptography manifest contains 62 cryptography evaluations. The layered Admission
manifest contains 30 admission evaluations: 12 complete and 18 rejected.

```console
missionweaveprotocol-conformance
# 58/58 conformance vectors passed (27 valid, 31 invalid)
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
