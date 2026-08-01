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

- Exakte, bytegetreue `PROTOCOL_PIN.json`, 22 Schemata und 59 Konformitäts-JSON-Dateien.
- Striktes UTF-8-JSON-Parsing mit Ablehnung dekodierter doppelter Member-Namen.
- Vollständig offline ausgeführte `$id`-Auflösung mit aktivierten Draft-2020-12-Formatprüfungen.
- CLI `missionweaveprotocol-conformance`: 58/58 Vektoren, davon 27 gültig und 31 ungültig.
- RFC 8785 mit UTF-16-Property-Sortierung, ECMAScript-Zahlen und `sha256:<hex>`-Kennungen.
- Ed25519-Signatur und -Prüfung, getestet mit RFC-8032-Testvektor 1.
- `AdmissionService` für First Admission und historischen Replay über ein authentifiziertes,
  nur anhängendes Admission Log.
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
Diese direkten Ed25519-Hilfsfunktionen sind kryptografische Primitive auf niedriger Ebene; sie führen
keine vollständige MissionWeaveProtocol-Verifikation aus.

Für das vollständige sechsstufige Profil verwende `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` und
`verify(kind, received_bytes, key_resolver)`; der Typ bleibt explizit. Ein `KeyResolver` erhält einen
`KeyResolutionRequest` und gibt `KeyRegistrySnapshot::organization_wide(registry_bytes)` zurück,
niemals einen bereits ausgewählten `ResolvedKey`. `organization_wide` ist die Zusicherung eines
vertrauenswürdigen Adapters, kein Vollständigkeitsnachweis: Die Bytes müssen eine kohärente,
maßgebliche und für die Prüfentscheidung anwendbare Registry-Revision genau einer Organization mit
allen organisationsweiten Bindungen und der vollständigen aufbewahrten Gültigkeitshistorie abdecken.
`request.key_id` ist nur Routing-Kontext und darf weder das Filtern der Registry noch eine
Teilprojektion autorisieren.

Der Codec behandelt die Registry-Bytes als nicht vertrauenswürdig und validiert vor der
Schlüsselauswahl jede Bindung und ihre vollständige aufbewahrte Gültigkeitshistorie. Nachweise mit
`KeyRegistryCompleteness::partial`, `KeyRegistryCompleteness::unspecified`, nicht verfügbare, leere
oder fehlerhafte Nachweise werden bei der Schlüsselauflösung nach dem Fail-Closed-Prinzip abgelehnt;
vom Codec erzeugte Nachweise behalten `organization_id`. Diese Registry-Evidenz-Migration bricht
bewusst die Quell- und ABI-Kompatibilität.

Für First Admission wird `missionweaveprotocol/admission.hpp` eingebunden.
`AdmissionService::admit_first` greift erst nach der sechsstufigen Prüfung auf das Admission Log zu
und validiert den festgeschriebenen Record vor der Rückgabe erneut. `verify_historical_admission`
verlangt einen vorhandenen authentifizierten Record und hängt nie an. Siehe
[Admission bundle](admission/README.md).

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
| Protokoll-Commit | `f7e70a72c76bbeb5014c186cd820aac2112f0dde` |
| Schemadateien | `22` |
| SHA-256 des Schema-Baums | `941a5a19b8664207f1ff48b799219c2f981ecd491a5cca527d586028d976ec76` |
| Konformitäts-JSON | `59` |
| SHA-256 des Konformitätsbaums | `2362acd8345e5860e605ed06984f1673a1ea0a00e76c1fe00fed222326782f24` |
| SHA-256 des kombinierten Bundles | `c95fc8f8334947dacf51a2c6e84d9b13f5b39b7d3827591569a1e2c5acfe47d7` |
| Admission-Digest | `sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0` |

`ProtocolBundle::verify()` prüft zur Laufzeit die Dateianzahlen und die pfad- und bytesensitiven
Hashes.

## Konformitätsumfang

```console
missionweaveprotocol-conformance
# 58/58 conformance vectors passed (27 valid, 31 invalid)
```

Das festgelegte Kryptografie-Manifest enthält `62 cryptography evaluations`; das Admission-Manifest
enthält `30 admission evaluations`, davon 12 abgeschlossen und 18 abgelehnt.

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
