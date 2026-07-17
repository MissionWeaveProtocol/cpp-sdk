[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | **Deutsch**

# MissionWeaveProtocol C++ SDK

Offizielles C++20-Protokoll-SDK für MissionWeaveProtocol. Es bietet strikte JSON-Verarbeitung,
eine Offline-Registry für Draft-2020-12-Schema, die normativen Konformitätsvektoren, kanonisches
JSON nach RFC 8785 und `sha256:`-Inhaltskennungen, Ed25519-Signaturen sowie einen Schema-prüfenden
Frame-Codec.

Die aktuelle Version weist **Schema- und Vektorkonformität** nach. Sie ist keine Portierung der
vollständigen Python-Referenz-Runtime: Core, Worker-Ausführung, Group-übergreifendes Scheduling,
Speicherung, Replay und ein WebSocket-Verbindungsclient liegen außerhalb des ersten Umfangs.

## Funktionen

- Exakte, bytegetreue `PROTOCOL_PIN.json`, 21 Schema und 44 Konformitäts-JSON-Dateien.
- Striktes UTF-8-JSON-Parsing mit Ablehnung dekodierter doppelter Member-Namen.
- Vollständig offline ausgeführte `$id`-Auflösung mit aktivierten Draft-2020-12-Formatprüfungen.
- CLI `missionweaveprotocol-conformance`: 43/43 Vektoren, davon 22 gültig und 21 ungültig.
- RFC 8785 mit UTF-16-Property-Sortierung, ECMAScript-Zahlen und `sha256:<hex>`-Kennungen.
- Ed25519-Signatur und -Prüfung, getestet mit RFC-8032-Testvektor 1.
- `FrameCodec` für striktes Parsing, WebSocket-Frame-Schema-Prüfung und kanonische Kodierung.
- Installierbares CMake-Package mit dem Target `MissionWeaveProtocol::sdk`.

## Voraussetzungen und Build

Erforderlich sind ein C++20-Compiler, CMake ab 3.24 und OpenSSL ab 3.0. Ninja wird empfohlen. Falls
jsoncons 1.8.1 nicht installiert ist, lädt CMake die festgelegte Version während der Konfiguration;
die Runtime-Validierung bleibt vollständig offline.

Ein Registry-Package oder Release-Tag wird noch nicht als veröffentlicht angegeben. Baue den
geschützten Branch `main`:

```console
git clone https://github.com/MissionWeaveProtocol/cpp-sdk.git
cd cpp-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/missionweaveprotocol-conformance
cmake --install build --prefix /path/to/prefix
```

Im nutzenden CMake-Projekt:

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

Setze `CMAKE_PREFIX_PATH` auf das Installationspräfix.

## Verwendung

Einen Frame strikt dekodieren und kanonisch kodieren:

```cpp
#include <missionweaveprotocol/frame.hpp>

missionweaveprotocol::FrameCodec codec;
auto frame = codec.decode(input_bytes);
std::string canonical = codec.encode(frame);
```

Eine Inhaltskennung erzeugen und ein Dokument signieren:

```cpp
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>

auto content_id = missionweaveprotocol::canonical_sha256(document);
missionweaveprotocol::Ed25519Seed seed{}; // In Produktion aus einem sicheren Secret Store laden.
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

Beim Signieren wird nur das oberste `signature`-Member aus dem kanonischen Payload entfernt;
verschachtelte Member desselben Namens bleiben signiert. Vollständige Programme stehen in
`examples/validate_frame.cpp` und `examples/sign_document.cpp`.

## Festgelegtes Protokoll-Bundle

| Element | Wert |
| --- | --- |
| Protokoll-Commit | `00964ea9064cbf1f0eca8af21a0c57367ee14752` |
| Schema | `21` |
| SHA-256 des Schema-Baums | `cbb37b7d55ad1a21a01370d6c09677b05dcd1383d6d77fa60b9c58b0fd85c624` |
| Konformitäts-JSON | `44` |
| SHA-256 des Konformitätsbaums | `100d2d2104d07bd7dcfbde354555a85d244f4b7c20c1c5dda0136ce36b4b8675` |
| SHA-256 des kombinierten Bundles | `281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda` |

`ProtocolBundle::verify()` prüft zur Runtime die Dateianzahlen und die pfad- und bytesensitiven
Hashes.

## Konformitätsumfang

```console
missionweaveprotocol-conformance
# 43/43 conformance vectors passed (22 valid, 21 invalid)
```

Das Ergebnis gilt nur für Schema- und Vektorkonformität. Es behauptet keine vollständige
Verhaltenskonformität für Koordination, Scheduling, Leases, Replay, Persistenz oder den
Transportlebenszyklus. Erfolgreiche Validierung erteilt auch keine Autorität; die Anwendung muss
Regeln der Organization und menschliche Freigaben durchsetzen.

## Lizenz

Apache-2.0. Hinweise zu Drittsoftware stehen in `THIRD_PARTY_NOTICES.md`.
