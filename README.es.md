[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | **Español** | [Français](README.fr.md) | [Deutsch](README.de.md)

# SDK de C++ de MissionWeaveProtocol

SDK oficial del protocolo MissionWeaveProtocol para C++20. Incluye JSON estricto, un registro
sin conexión de Schema Draft 2020-12, los vectores normativos, JSON canónico RFC 8785 e
identificadores `sha256:`, firmas Ed25519 y un códec de tramas con validación de Schema.

La versión actual demuestra únicamente **conformidad con esquemas y vectores**. No es una
adaptación del entorno de ejecución de referencia completo en Python: Core, ejecución de Worker,
planificación entre Group, almacenamiento, replay y el cliente de conexión WebSocket quedan
fuera del alcance inicial.

## Capacidades

- `PROTOCOL_PIN.json` exacto y conservado byte a byte, 22 Schema y 59 archivos JSON de conformidad.
- Análisis JSON UTF-8 estricto que rechaza miembros duplicados después de decodificar sus nombres.
- Resolución `$id` completamente sin conexión con aserciones de formato para Draft 2020-12.
- CLI `missionweaveprotocol-conformance`: 58/58 vectores, 27 válidos y 31 inválidos.
- RFC 8785 con orden UTF-16, números ECMAScript e identificadores `sha256:<hex>`.
- Firma y verificación Ed25519 comprobadas con el vector 1 de RFC 8032.
- `AdmissionService` para primera admisión y replay histórico con un Admission Log autenticado y
  de solo anexado.
- `FrameCodec` para análisis estricto, validación del Schema de WebSocket y codificación canónica.
- Paquete CMake instalable con el objetivo `MissionWeaveProtocol::sdk`.

## Requisitos y compilación

Se requiere un compilador C++20, CMake 3.24 o posterior y OpenSSL 3.0 o posterior. Se recomienda
Ninja. Si jsoncons 1.8.1 no está instalado, CMake descarga la versión fijada durante la configuración;
la validación durante la ejecución no usa la red.

Todavía no se anuncia ningún paquete de registro ni etiqueta de versión. Compila la rama protegida `main`:

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

Decodifica una trama estrictamente y vuelve a codificarla de forma canónica:

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

La firma documental elimina únicamente el miembro `signature` de nivel superior del contenido
canónico; los miembros anidados con el mismo nombre siguen firmados.
Estos helpers directos de Ed25519 son primitivas criptográficas de bajo nivel; no realizan la
verificación completa de MissionWeaveProtocol.

Para el perfil completo de seis etapas, usa `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` y
`verify(kind, received_bytes, key_resolver)`; el tipo siempre es explícito. Un `KeyResolver` recibe un
`KeyResolutionRequest` y devuelve `KeyRegistrySnapshot::organization_wide(registry_bytes)`, nunca un
`ResolvedKey` ya seleccionado. `organization_wide` es la afirmación de un adaptador de confianza, no
una prueba de completitud: los bytes deben abarcar una revisión coherente y autoritativa del Registry,
aplicable a la decisión de verificación para exactamente una Organization, con todas las vinculaciones
de la Organization y el historial de validez conservado completo. `request.key_id` es únicamente
contexto de encaminamiento y no autoriza filtrar el Registry ni devolver una proyección parcial.

El códec trata los bytes del Registry como datos no confiables y valida cada vinculación y todo su
historial de validez conservado antes de seleccionar la clave. La evidencia
`KeyRegistryCompleteness::partial`, `KeyRegistryCompleteness::unspecified`, no disponible, vacía o
malformada se rechaza de forma segura durante la resolución de claves; la evidencia producida por el
códec conserva `organization_id`. Esta migración de evidencia del Registry rompe intencionadamente
la compatibilidad de código fuente y ABI.

Para First Admission, incluye `missionweaveprotocol/admission.hpp`. `AdmissionService::admit_first`
consulta el Admission Log solo después de la verificación de seis etapas y vuelve a validar el
registro confirmado antes de devolverlo. `verify_historical_admission` exige un registro autenticado
existente y nunca anexa. Consulta [Admission bundle](admission/README.md).

Valida cualquier documento de protocolo integrado:

```cpp
#include <missionweaveprotocol/schema.hpp>

missionweaveprotocol::SchemaCatalog schemas;
auto result = schemas.validate("mission.schema.json", document);
if (!result.valid && result.issue) {
  // result.issue contiene la palabra clave, la ubicación de instancia, la ubicación de Schema y el mensaje.
}
```

Consulta
`examples/validate_frame.cpp` y `examples/sign_document.cpp`.

## Paquete de protocolo fijado

| Elemento | Valor |
| --- | --- |
| Commit del protocolo | `f7e70a72c76bbeb5014c186cd820aac2112f0dde` |
| Schema | `22` |
| SHA-256 del árbol de Schema | `941a5a19b8664207f1ff48b799219c2f981ecd491a5cca527d586028d976ec76` |
| JSON de conformidad | `59` |
| SHA-256 del árbol de conformidad | `2362acd8345e5860e605ed06984f1673a1ea0a00e76c1fe00fed222326782f24` |
| SHA-256 del paquete combinado | `c95fc8f8334947dacf51a2c6e84d9b13f5b39b7d3827591569a1e2c5acfe47d7` |
| Digest de Admission | `sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0` |

`ProtocolBundle::verify()` comprueba durante la ejecución los recuentos y los hashes sensibles a ruta y bytes.

## Alcance de la conformidad

```console
missionweaveprotocol-conformance
# 58/58 conformance vectors passed (27 valid, 31 invalid)
```

El manifiesto criptográfico fijado contiene `62 cryptography evaluations`; el manifiesto de
Admission contiene `30 admission evaluations`, 12 completas y 18 rechazadas.

El resultado se limita a la conformidad con esquemas y vectores. No afirma conformidad conductual
completa de coordinación, planificación, gestión del ciclo de vida de Execution Lease, protección
contra replay, persistencia ni ciclo de vida del transporte. Una validación correcta tampoco
concede autorización: la aplicación debe aplicar las políticas de la Organization y la aprobación
humana.

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
