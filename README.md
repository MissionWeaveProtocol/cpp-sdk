# MissionWeaveProtocol C++ SDK

Official C++20 protocol SDK for MissionWeaveProtocol.

This repository is being built through a sequence of reviewed pull requests. The
initial foundation provides an installable CMake package and the stable
`missionweaveprotocol` C++ namespace. Protocol assets, validation, canonical
identifiers, signing, frame encoding, conformance tooling, examples, and the
complete translated documentation set follow in subsequent changes.

## Build and test

```console
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

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
