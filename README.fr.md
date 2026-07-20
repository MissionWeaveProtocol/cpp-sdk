[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | **Français** | [Deutsch](README.de.md)

# SDK C++ MissionWeaveProtocol

SDK officiel du protocole MissionWeaveProtocol pour C++20. Il fournit un traitement JSON strict,
un registre de schémas Draft 2020-12 hors ligne, les vecteurs normatifs, le JSON canonique RFC 8785
et les identifiants `sha256:`, la signature Ed25519 et un codec de trames avec validation par schéma.

La version actuelle démontre une **conformité limitée aux schémas et aux vecteurs**. Elle ne porte
pas l’intégralité de l’environnement d’exécution de référence Python : Core, exécution Worker,
ordonnancement entre Group, stockage, rejeu et client de connexion WebSocket restent hors du
périmètre initial.

## Capacités

- `PROTOCOL_PIN.json` exact et préservé octet par octet, 21 schémas et 57 fichiers JSON de conformité.
- Analyse JSON UTF-8 stricte avec rejet des membres dupliqués après décodage de leur nom.
- Résolution `$id` entièrement hors ligne et assertions de format Draft 2020-12 activées.
- CLI `missionweaveprotocol-conformance` : 56/56 vecteurs, dont 26 valides et 30 invalides.
- RFC 8785 avec ordre UTF-16, nombres ECMAScript et identifiants `sha256:<hex>`.
- Signature et vérification Ed25519 testées avec le vecteur 1 de la RFC 8032.
- `FrameCodec` pour l’analyse stricte, la validation du schéma WebSocket et l’encodage canonique.
- Paquet CMake installable exposant la cible `MissionWeaveProtocol::sdk`.

## Prérequis et compilation

Un compilateur C++20, CMake 3.24 ou ultérieur et OpenSSL 3.0 ou ultérieur sont requis. Ninja est
recommandé. Si jsoncons 1.8.1 n’est pas installé, CMake télécharge la version épinglée pendant la
configuration ; la validation à l’exécution reste totalement hors ligne.

Aucun paquet de registre ni étiquette de version n’est encore annoncé. Compilez la branche protégée
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

Décodez strictement une trame puis produisez son encodage canonique :

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

La signature de document retire uniquement le membre `signature` de premier niveau du contenu
canonique ; les membres imbriqués du même nom restent couverts.

Pour le profil complet en six étapes, utilisez `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` et
`verify(kind, received_bytes, key_resolver)`. Le type reste explicite ; `SigningKey` et le `KeyResolver`
contrôlé par l’organisation sont les seuls adaptateurs externes, et le résultat conserve des preuves immuables.

Validez tout document de protocole embarqué :

```cpp
#include <missionweaveprotocol/schema.hpp>

missionweaveprotocol::SchemaCatalog schemas;
auto result = schemas.validate("mission.schema.json", document);
if (!result.valid && result.issue) {
  // result.issue contient le mot-clé, l’emplacement d’instance, l’emplacement de Schema et le message.
}
```

Consultez
`examples/validate_frame.cpp` et `examples/sign_document.cpp`.

## Paquet de protocole épinglé

| Élément | Valeur |
| --- | --- |
| Commit du protocole | `33e47ad8a7318f942de77fb72dbb054d85881b40` |
| Schémas | `21` |
| SHA-256 de l’arbre des schémas | `de90adb6a84995ce6e7e35f20c58f74293546ad2aca61796429c8b1d8d269c42` |
| JSON de conformité | `57` |
| SHA-256 de l’arbre de conformité | `fc7d6b2005b4cdebcb9d47efd0a3ce991fea111776c4271beaf8945e11b5d7df` |
| SHA-256 du paquet combiné | `eed30aeb0a6d39575b6ab2f3121de27cef34d27dd9659ee4e5a7204ec5deeea7` |

`ProtocolBundle::verify()` contrôle à l’exécution les nombres de fichiers et les empreintes sensibles
aux chemins et aux octets.

## Périmètre de conformité

```console
missionweaveprotocol-conformance
# 56/56 conformance vectors passed (26 valid, 30 invalid)
```

Ce résultat se limite à la conformité des schémas et des vecteurs. Il ne revendique pas la
conformité comportementale complète de la coordination, de l’ordonnancement, de la gestion du cycle
de vie d’Execution Lease, du rejeu, de la persistance ou du cycle de vie du transport. Une
validation réussie n’accorde pas non plus d’autorité : l’application doit appliquer les règles de
l’Organization et l’approbation humaine.

## Notes de sécurité

- Conservez les graines Ed25519 hors du code source et chargez-les depuis un coffre de secrets
  adapté.
- Vérifiez la validité du schéma avant de traiter un document décodé comme un `Command` ou un
  `Event` autorisé.
- Les données d’extension restent des données ; elles ne peuvent ni remplacer les champs centraux du
  protocole ni accorder une autorité par elles-mêmes.
- Le résolveur de schémas embarqué n’effectue aucun accès réseau.

## Licence

Apache-2.0. Les avis relatifs aux tiers figurent dans `THIRD_PARTY_NOTICES.md`.
