[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | **Français** | [Deutsch](README.de.md)

# SDK C++ MissionWeaveProtocol

SDK officiel du protocole MissionWeaveProtocol pour C++20. Il fournit un traitement JSON strict,
un registre de Schema Draft 2020-12 hors ligne, les vecteurs normatifs, le JSON canonique RFC 8785
et les identifiants `sha256:`, la signature Ed25519 et un codec de frame validé par Schema.

La version actuelle démontre la **conformité des Schema et des vecteurs**. Elle ne porte pas
l’intégralité du runtime de référence Python : Core, exécution Worker, ordonnancement entre Group,
stockage, replay et client de connexion WebSocket restent hors du périmètre initial.

## Capacités

- `PROTOCOL_PIN.json` exact et préservé octet par octet, 21 Schema et 44 fichiers JSON de conformité.
- Analyse JSON UTF-8 stricte avec rejet des membres dupliqués après décodage de leur nom.
- Résolution `$id` entièrement hors ligne et assertions de format Draft 2020-12 activées.
- CLI `missionweaveprotocol-conformance` : 43/43 vecteurs, dont 22 valides et 21 invalides.
- RFC 8785 avec ordre UTF-16, nombres ECMAScript et identifiants `sha256:<hex>`.
- Signature et vérification Ed25519 testées avec le vecteur 1 de la RFC 8032.
- `FrameCodec` pour l’analyse stricte, la validation du Schema WebSocket et l’encodage canonique.
- Package CMake installable exposant la target `MissionWeaveProtocol::sdk`.

## Prérequis et compilation

Un compilateur C++20, CMake 3.24 ou ultérieur et OpenSSL 3.0 ou ultérieur sont requis. Ninja est
recommandé. Si jsoncons 1.8.1 n’est pas installé, CMake télécharge la version épinglée pendant la
configuration ; la validation au runtime reste totalement hors ligne.

Aucun package de registre ni tag de release n’est encore annoncé. Compilez la branche protégée
`main` :

```console
git clone https://github.com/MissionWeaveProtocol/cpp-sdk.git
cd cpp-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/missionweaveprotocol-conformance
cmake --install build --prefix /path/to/prefix
```

Dans le projet consommateur :

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

Définissez `CMAKE_PREFIX_PATH` sur le préfixe d’installation.

## Utilisation

Décodez strictement un frame puis produisez son encodage canonique :

```cpp
#include <missionweaveprotocol/frame.hpp>

missionweaveprotocol::FrameCodec codec;
auto frame = codec.decode(input_bytes);
std::string canonical = codec.encode(frame);
```

Créez un identifiant de contenu et signez un document :

```cpp
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>

auto content_id = missionweaveprotocol::canonical_sha256(document);
missionweaveprotocol::Ed25519Seed seed{}; // En production, charger depuis un coffre sécurisé.
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

La signature de document retire uniquement le membre `signature` de premier niveau du payload
canonique ; les membres imbriqués du même nom restent couverts. Consultez
`examples/validate_frame.cpp` et `examples/sign_document.cpp`.

## Bundle de protocole épinglé

| Élément | Valeur |
| --- | --- |
| Commit du protocole | `00964ea9064cbf1f0eca8af21a0c57367ee14752` |
| Schema | `21` |
| SHA-256 de l’arbre Schema | `cbb37b7d55ad1a21a01370d6c09677b05dcd1383d6d77fa60b9c58b0fd85c624` |
| JSON de conformité | `44` |
| SHA-256 de l’arbre de conformité | `100d2d2104d07bd7dcfbde354555a85d244f4b7c20c1c5dda0136ce36b4b8675` |
| SHA-256 du bundle combiné | `281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda` |

`ProtocolBundle::verify()` contrôle au runtime les nombres de fichiers et les empreintes sensibles
aux chemins et aux octets.

## Périmètre de conformité

```console
missionweaveprotocol-conformance
# 43/43 conformance vectors passed (22 valid, 21 invalid)
```

Ce résultat se limite à la conformité des Schema et des vecteurs. Il ne revendique pas la
conformité comportementale complète de la coordination, de l’ordonnancement, des leases, du replay,
de la persistance ou du cycle de vie du transport. Une validation réussie n’accorde pas non plus
d’autorité : l’application doit appliquer les règles de l’Organization et l’approbation humaine.

## Licence

Apache-2.0. Les avis relatifs aux tiers figurent dans `THIRD_PARTY_NOTICES.md`.
