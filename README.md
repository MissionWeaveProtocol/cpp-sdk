# MissionWeaveProtocol C++ SDK

Official C++20 protocol SDK for MissionWeaveProtocol.

The SDK embeds the exact protocol bundle pinned by `PROTOCOL_PIN.json`: 21
Draft 2020-12 schemas and 44 conformance JSON artifacts. Asset access and digest
verification work without a source checkout or network connection.

Validation, canonical identifiers, signing, frame encoding, conformance tooling,
examples, and the complete translated documentation set follow in subsequent
reviewed changes.

## Build and test

```console
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

OpenSSL 3.0 or newer is required.

## Install and consume

```console
cmake --install build --prefix /path/to/prefix
```

Consumers can then use:

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

## License

Apache-2.0.
