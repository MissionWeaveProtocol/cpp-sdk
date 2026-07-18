[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | **Français** | [Deutsch](README.de.md)

# SDK C++ MissionWeaveProtocol

SDK officiel du protocole MissionWeaveProtocol pour C++20. Il fournit un traitement JSON strict,
un registre de Schema Draft 2020-12 hors ligne, les vecteurs normatifs, le JSON canonique RFC 8785
et les identifiants `sha256:`, la signature Ed25519 et un codec de frame validé par Schema.

La version actuelle démontre une **conformité limitée aux schémas et aux vecteurs**. Elle ne porte
pas l’intégralité du runtime de référence Python : Core, exécution Worker, ordonnancement entre
Group, stockage, replay et client de connexion WebSocket restent hors du périmètre initial.

## Capacités

- `PROTOCOL_PIN.json` exact et préservé octet par octet, 21 Schema et 53 fichiers JSON de conformité.
- Analyse JSON UTF-8 stricte avec rejet des membres dupliqués après décodage de leur nom.
- Résolution `$id` entièrement hors ligne et assertions de format Draft 2020-12 activées.
- CLI `missionweaveprotocol-conformance` : 52/52 vecteurs, dont 25 valides et 27 invalides.
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
| Commit du protocole | `6f10987627d62fb296e3490ceceb5539b1e94b70` |
| Schema | `21` |
| SHA-256 de l’arbre Schema | `a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413` |
| JSON de conformité | `53` |
| SHA-256 de l’arbre de conformité | `21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da` |
| SHA-256 du bundle combiné | `b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7` |

`ProtocolBundle::verify()` contrôle au runtime les nombres de fichiers et les empreintes sensibles
aux chemins et aux octets.

## Périmètre de conformité

```console
missionweaveprotocol-conformance
# 52/52 conformance vectors passed (25 valid, 27 invalid)
```

Ce résultat se limite à la conformité des schémas et des vecteurs. Il ne revendique pas la
conformité comportementale complète de la coordination, de l’ordonnancement, des leases, du replay,
de la persistance ou du cycle de vie du transport. Une validation réussie n’accorde pas non plus
d’autorité : l’application doit appliquer les règles de l’Organization et l’approbation humaine.

## Notes de sécurité

- Conservez les graines Ed25519 hors du code source et chargez-les depuis un coffre de secrets
  adapté.
- Vérifiez la validité du Schema avant de traiter un document décodé comme un `Command` ou un
  `Event` autorisé.
- Les données d’extension restent des données ; elles ne peuvent ni remplacer les champs centraux du
  protocole ni accorder une autorité par elles-mêmes.
- Le résolveur de Schema embarqué n’effectue aucun accès réseau.

## Licence

Apache-2.0. Les avis relatifs aux tiers figurent dans `THIRD_PARTY_NOTICES.md`.
