[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | **Español** | [Français](README.fr.md) | [Deutsch](README.de.md)

# SDK de C++ de MissionWeaveProtocol

SDK oficial del protocolo MissionWeaveProtocol para C++20. Incluye JSON estricto, un registro
offline de Schema Draft 2020-12, los vectores normativos, JSON canónico RFC 8785 e identificadores
`sha256:`, firmas Ed25519 y un codec de frames con validación de Schema.

La versión actual demuestra únicamente **conformidad con esquemas y vectores**. No es un port del
runtime de referencia completo en Python: Core, ejecución de Worker, planificación entre Group,
almacenamiento, replay y el cliente de conexión WebSocket quedan fuera del alcance inicial.

## Capacidades

- `PROTOCOL_PIN.json` exacto y conservado byte a byte, 21 Schema y 44 archivos JSON de conformidad.
- Análisis JSON UTF-8 estricto que rechaza miembros duplicados después de decodificar sus nombres.
- Resolución `$id` completamente offline con assertions de format para Draft 2020-12.
- CLI `missionweaveprotocol-conformance`: 43/43 vectores, 22 válidos y 21 inválidos.
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
| Commit del protocolo | `00964ea9064cbf1f0eca8af21a0c57367ee14752` |
| Schema | `21` |
| SHA-256 del árbol de Schema | `cbb37b7d55ad1a21a01370d6c09677b05dcd1383d6d77fa60b9c58b0fd85c624` |
| JSON de conformidad | `44` |
| SHA-256 del árbol de conformidad | `100d2d2104d07bd7dcfbde354555a85d244f4b7c20c1c5dda0136ce36b4b8675` |
| SHA-256 del bundle combinado | `281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda` |

`ProtocolBundle::verify()` comprueba en runtime los recuentos y los hashes sensibles a ruta y bytes.

## Alcance de la conformidad

```console
missionweaveprotocol-conformance
# 43/43 conformance vectors passed (22 valid, 21 invalid)
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
