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

- `PROTOCOL_PIN.json` exact et préservé octet par octet, 22 schémas et 59 fichiers JSON de conformité.
- Analyse JSON UTF-8 stricte avec rejet des membres dupliqués après décodage de leur nom.
- Résolution `$id` entièrement hors ligne et assertions de format Draft 2020-12 activées.
- CLI `missionweaveprotocol-conformance` : 58/58 vecteurs, dont 27 valides et 31 invalides.
- RFC 8785 avec ordre UTF-16, nombres ECMAScript et identifiants `sha256:<hex>`.
- Signature et vérification Ed25519 testées avec le vecteur 1 de la RFC 8032.
- `AdmissionService` pour la première admission et le rejeu historique avec un Admission Log
  authentifié et en ajout seul.
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
Ces helpers Ed25519 directs sont des primitives cryptographiques de bas niveau ; ils n’effectuent pas
la vérification MissionWeaveProtocol complète.

Pour le profil complet en six étapes, utilisez `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` et
`verify(kind, received_bytes, key_resolver)` ; le type reste explicite. Un `KeyResolver` reçoit un
`KeyResolutionRequest` et renvoie `KeyRegistrySnapshot::organization_wide(registry_bytes)`, jamais un
`ResolvedKey` déjà sélectionné. `organization_wide` est l’assertion d’un adaptateur de confiance, pas
une preuve de complétude : les octets doivent couvrir une révision cohérente et faisant autorité du
Registry, applicable à la décision de vérification pour exactement une Organization, avec toutes les
liaisons de l’Organization et l’intégralité de l’historique de validité conservé. `request.key_id`
sert uniquement de contexte de routage et n’autorise ni le filtrage du Registry ni une projection
partielle.

Le codec traite les octets du Registry comme des données non fiables et valide chaque liaison ainsi
que l’intégralité de son historique de validité conservé avant de sélectionner la clé. Une preuve
`KeyRegistryCompleteness::partial`, `KeyRegistryCompleteness::unspecified`, indisponible, vide ou mal
formée est rejetée en mode fermé lors de la résolution de clé ; les preuves produites par le codec
conservent `organization_id`. Cette migration des preuves du Registry rompt volontairement la
compatibilité source et ABI.

Pour First Admission, incluez `missionweaveprotocol/admission.hpp`.
`AdmissionService::admit_first` ne consulte l’Admission Log qu’après la vérification en six étapes
et revalide l’enregistrement validé avant de le renvoyer. `verify_historical_admission` exige un
enregistrement authentifié existant et n’ajoute jamais. Voir [Admission bundle](admission/README.md).

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
| Commit du protocole | `f7e70a72c76bbeb5014c186cd820aac2112f0dde` |
| Schémas | `22` |
| SHA-256 de l’arbre des schémas | `941a5a19b8664207f1ff48b799219c2f981ecd491a5cca527d586028d976ec76` |
| JSON de conformité | `59` |
| SHA-256 de l’arbre de conformité | `2362acd8345e5860e605ed06984f1673a1ea0a00e76c1fe00fed222326782f24` |
| SHA-256 du paquet combiné | `c95fc8f8334947dacf51a2c6e84d9b13f5b39b7d3827591569a1e2c5acfe47d7` |
| Empreinte Admission | `sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0` |

`ProtocolBundle::verify()` contrôle à l’exécution les nombres de fichiers et les empreintes sensibles
aux chemins et aux octets.

## Périmètre de conformité

```console
missionweaveprotocol-conformance
# 58/58 conformance vectors passed (27 valid, 31 invalid)
```

Le manifeste cryptographique épinglé contient `62 cryptography evaluations` ; le manifeste
Admission contient `30 admission evaluations`, dont 12 terminées et 18 rejetées.

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
