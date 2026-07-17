# MissionWeaveProtocol C++ SDK

Official C++20 protocol SDK for MissionWeaveProtocol.

The SDK embeds the exact protocol bundle pinned by `PROTOCOL_PIN.json`: 21
Draft 2020-12 schemas and 44 conformance JSON artifacts. It provides strict
UTF-8 JSON parsing with duplicate-member rejection, an offline `$id` schema
registry with format assertions, and a 43-vector conformance runner.

Canonical identifiers, signing, frame encoding, examples, and the complete
translated documentation set follow in subsequent reviewed changes.

## Build and test

```console
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

OpenSSL 3.0 or newer is required.

Run the embedded schema-and-vector conformance suite with:

```console
./build/missionweaveprotocol-conformance
```

Passing this suite demonstrates schema-and-vector conformance, not full
behavioral protocol conformance.

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
