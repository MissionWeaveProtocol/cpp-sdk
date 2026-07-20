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

- `PROTOCOL_PIN.json` exacto y conservado byte a byte, 21 Schema y 57 archivos JSON de conformidad.
- Análisis JSON UTF-8 estricto que rechaza miembros duplicados después de decodificar sus nombres.
- Resolución `$id` completamente sin conexión con aserciones de formato para Draft 2020-12.
- CLI `missionweaveprotocol-conformance`: 56/56 vectores, 26 válidos y 30 inválidos.
- RFC 8785 con orden UTF-16, números ECMAScript e identificadores `sha256:<hex>`.
- Firma y verificación Ed25519 comprobadas con el vector 1 de RFC 8032.
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

Para el perfil completo de seis etapas, usa `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` y
`verify(kind, received_bytes, key_resolver)`. El tipo siempre es explícito; `SigningKey` y el `KeyResolver`
controlado por la organización son los únicos adaptadores externos, y el resultado conserva evidencia inmutable.

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
| Commit del protocolo | `33e47ad8a7318f942de77fb72dbb054d85881b40` |
| Schema | `21` |
| SHA-256 del árbol de Schema | `de90adb6a84995ce6e7e35f20c58f74293546ad2aca61796429c8b1d8d269c42` |
| JSON de conformidad | `57` |
| SHA-256 del árbol de conformidad | `fc7d6b2005b4cdebcb9d47efd0a3ce991fea111776c4271beaf8945e11b5d7df` |
| SHA-256 del paquete combinado | `eed30aeb0a6d39575b6ab2f3121de27cef34d27dd9659ee4e5a7204ec5deeea7` |

`ProtocolBundle::verify()` comprueba durante la ejecución los recuentos y los hashes sensibles a ruta y bytes.

## Alcance de la conformidad

```console
missionweaveprotocol-conformance
# 56/56 conformance vectors passed (26 valid, 30 invalid)
```

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
