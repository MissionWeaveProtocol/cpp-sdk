[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | **Español** | [Français](README.fr.md) | [Deutsch](README.de.md)

# SDK de C++ de MissionWeaveProtocol

SDK oficial del protocolo MissionWeaveProtocol para C++20. Incluye JSON estricto, un registro
offline de Schema Draft 2020-12, los vectores normativos, JSON canónico RFC 8785 e identificadores
`sha256:`, firmas Ed25519 y un codec de frames con validación de Schema.

La versión actual demuestra únicamente **conformidad con esquemas y vectores**. No es un port del
runtime de referencia completo en Python: Core, ejecución de Worker, planificación entre Group,
almacenamiento, replay y el cliente de conexión WebSocket quedan fuera del alcance inicial.

## Capacidades

- `PROTOCOL_PIN.json` exacto y conservado byte a byte, 21 Schema y 53 archivos JSON de conformidad.
- Análisis JSON UTF-8 estricto que rechaza miembros duplicados después de decodificar sus nombres.
- Resolución `$id` completamente offline con assertions de format para Draft 2020-12.
- CLI `missionweaveprotocol-conformance`: 52/52 vectores, 25 válidos y 27 inválidos.
- RFC 8785 con orden UTF-16, números ECMAScript e identificadores `sha256:<hex>`.
- Firma y verificación Ed25519 comprobadas con el vector 1 de RFC 8032.
- `FrameCodec` para análisis estricto, validación del Schema de WebSocket y codificación canónica.
- Paquete CMake instalable con el target `MissionWeaveProtocol::sdk`.

## Requisitos y compilación

Se requiere un compilador C++20, CMake 3.24 o posterior y OpenSSL 3.0 o posterior. Se recomienda
Ninja. Si jsoncons 1.8.1 no está instalado, CMake descarga la versión fijada durante la configuración;
la validación en runtime no usa la red.

Todavía no se anuncia ningún paquete de registro ni tag de release. Compila la rama protegida `main`:

```console
git clone https://github.com/MissionWeaveProtocol/cpp-sdk.git
cd cpp-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/missionweaveprotocol-conformance
cmake --install build --prefix /path/to/prefix
```

En el proyecto consumidor:

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

Configura `CMAKE_PREFIX_PATH` con el prefijo de instalación.

## Uso

Decodifica un frame estrictamente y vuelve a codificarlo de forma canónica:

```cpp
#include <missionweaveprotocol/frame.hpp>

missionweaveprotocol::FrameCodec codec;
auto frame = codec.decode(input_bytes);
std::string canonical = codec.encode(frame);
```

Crea un identificador de contenido y firma un documento:

```cpp
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>

auto content_id = missionweaveprotocol::canonical_sha256(document);
missionweaveprotocol::Ed25519Seed seed{}; // En producción, cargar desde un almacén seguro.
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

La firma documental elimina únicamente el miembro `signature` de nivel superior del payload
canónico; los miembros anidados con el mismo nombre siguen firmados. Consulta
`examples/validate_frame.cpp` y `examples/sign_document.cpp`.

## Bundle de protocolo fijado

| Elemento | Valor |
| --- | --- |
| Commit del protocolo | `6f10987627d62fb296e3490ceceb5539b1e94b70` |
| Schema | `21` |
| SHA-256 del árbol de Schema | `a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413` |
| JSON de conformidad | `53` |
| SHA-256 del árbol de conformidad | `21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da` |
| SHA-256 del bundle combinado | `b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7` |

`ProtocolBundle::verify()` comprueba en runtime los recuentos y los hashes sensibles a ruta y bytes.

## Alcance de la conformidad

```console
missionweaveprotocol-conformance
# 52/52 conformance vectors passed (25 valid, 27 invalid)
```

El resultado se limita a la conformidad con esquemas y vectores. No afirma conformidad conductual
completa de coordinación, planificación, leases, replay, persistencia ni ciclo de vida del
transporte. Una validación correcta tampoco concede autorización: la aplicación debe aplicar las
políticas de la Organization y la aprobación humana.

## Notas de seguridad

- Mantén las semillas Ed25519 fuera del código fuente y cárgalas desde un almacén de secretos
  adecuado.
- Verifica la validez del Schema antes de tratar un documento decodificado como un `Command` o
  `Event` autorizado.
- Los datos de extensión siguen siendo datos; no pueden sustituir campos centrales del protocolo ni
  conceder autoridad por sí solos.
- El resolvedor de Schema integrado no realiza acceso de red.

## Licencia

Apache-2.0. Los avisos de terceros están en `THIRD_PARTY_NOTICES.md`.
