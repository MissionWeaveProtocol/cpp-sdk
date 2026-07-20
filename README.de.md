[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | **Deutsch**

# MissionWeaveProtocol C++ SDK

Offizielles C++20-Protokoll-SDK für MissionWeaveProtocol. Es bietet strikte JSON-Verarbeitung,
eine Offline-Registry für Draft-2020-12-Schemata, die normativen Konformitätsvektoren, kanonisches
JSON nach RFC 8785 und `sha256:`-Inhaltskennungen, Ed25519-Signaturen sowie einen Schema-prüfenden
Frame-Codec.

Die aktuelle Version weist ausschließlich **Schema- und Vektorkonformität** nach. Sie ist keine
Portierung der vollständigen Python-Referenzlaufzeit: Core, Worker-Ausführung, Group-übergreifende
Planung, Speicherung, Replay-Verarbeitung und ein WebSocket-Verbindungsclient liegen außerhalb des ersten
Umfangs.

## Funktionen

- Exakte, bytegetreue `PROTOCOL_PIN.json`, 21 Schemata und 57 Konformitäts-JSON-Dateien.
- Striktes UTF-8-JSON-Parsing mit Ablehnung dekodierter doppelter Member-Namen.
- Vollständig offline ausgeführte `$id`-Auflösung mit aktivierten Draft-2020-12-Formatprüfungen.
- CLI `missionweaveprotocol-conformance`: 56/56 Vektoren, davon 26 gültig und 30 ungültig.
- RFC 8785 mit UTF-16-Property-Sortierung, ECMAScript-Zahlen und `sha256:<hex>`-Kennungen.
- Ed25519-Signatur und -Prüfung, getestet mit RFC-8032-Testvektor 1.
- `FrameCodec` für striktes Parsing, WebSocket-Frame-Schema-Prüfung und kanonische Kodierung.
- Installierbares CMake-Package mit dem Target `MissionWeaveProtocol::sdk`.

## Voraussetzungen und Build

Erforderlich sind ein C++20-Compiler, CMake ab 3.24 und OpenSSL ab 3.0. Ninja wird empfohlen. Falls
jsoncons 1.8.1 nicht installiert ist, lädt CMake die festgelegte Version während der Konfiguration;
die Validierung zur Laufzeit bleibt vollständig offline.

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
verschachtelte Member desselben Namens bleiben signiert.

Für das vollständige sechsstufige Profil verwende `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` und
`verify(kind, received_bytes, key_resolver)`. Der Typ bleibt explizit; `SigningKey` und der organisationskontrollierte
`KeyResolver` sind die einzigen externen Adapter, und das Ergebnis bewahrt unveränderliche Prüfnachweise.

Ein beliebiges eingebettetes Protokolldokument validieren:

```cpp
#include <missionweaveprotocol/schema.hpp>

missionweaveprotocol::SchemaCatalog schemas;
auto result = schemas.validate("mission.schema.json", document);
if (!result.valid && result.issue) {
  // result.issue contains the keyword, instance location, schema location, and message.
}
```

Vollständige Programme stehen in
`examples/validate_frame.cpp` und `examples/sign_document.cpp`.

## Festgelegtes Protokoll-Bundle

| Element | Wert |
| --- | --- |
| Protokoll-Commit | `33e47ad8a7318f942de77fb72dbb054d85881b40` |
| Schemadateien | `21` |
| SHA-256 des Schema-Baums | `de90adb6a84995ce6e7e35f20c58f74293546ad2aca61796429c8b1d8d269c42` |
| Konformitäts-JSON | `57` |
| SHA-256 des Konformitätsbaums | `fc7d6b2005b4cdebcb9d47efd0a3ce991fea111776c4271beaf8945e11b5d7df` |
| SHA-256 des kombinierten Bundles | `eed30aeb0a6d39575b6ab2f3121de27cef34d27dd9659ee4e5a7204ec5deeea7` |

`ProtocolBundle::verify()` prüft zur Laufzeit die Dateianzahlen und die pfad- und bytesensitiven
Hashes.

## Konformitätsumfang

```console
missionweaveprotocol-conformance
# 56/56 conformance vectors passed (26 valid, 30 invalid)
```

Das Ergebnis gilt nur für Schema- und Vektorkonformität. Es behauptet keine vollständige
Verhaltenskonformität für Koordination, Planung, Execution Leases, Replay-Verarbeitung, Persistenz oder den
Transportlebenszyklus. Erfolgreiche Validierung erteilt auch keine Autorität; die Anwendung muss
Regeln der Organization und menschliche Freigaben durchsetzen.

## Sicherheitshinweise

- Halte Ed25519-Seeds aus dem Quellcode heraus und lade sie aus einem geeigneten Geheimnisspeicher.
- Prüfe die Schema-Gültigkeit, bevor ein dekodiertes Dokument als autorisierter `Command` oder
  `Event` behandelt wird.
- Erweiterungsdaten bleiben Daten; sie können weder Kernfelder des Protokolls ersetzen noch selbst
  Autorität gewähren.
- Der eingebettete Schema-Resolver führt keinen Netzwerkzugriff aus.

## Lizenz

Apache-2.0. Hinweise zu Drittsoftware stehen in `THIRD_PARTY_NOTICES.md`.
