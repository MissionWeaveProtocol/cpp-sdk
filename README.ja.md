[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | **日本語** | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

MissionWeaveProtocol の公式 C++20 プロトコル SDK です。厳格な JSON 処理、オフラインの
Draft 2020-12 Schema レジストリ、規範的な適合性ベクトル、RFC 8785 正規 JSON と
`sha256:` コンテンツ ID、Ed25519 署名、および Schema 検証付きフレームコーデックを
提供します。

現在のリリースが示すのは**Schema とベクトルの適合性**です。
完全な Python 参照ランタイム
の移植ではなく、Core、Worker 実行、Group 間スケジューリング、ストレージ、リプレイ、
WebSocket 接続クライアントは初期スコープに含まれません。

## 機能

- バイトを保持した正確な `PROTOCOL_PIN.json`、21 Schema、53 個の適合性 JSON ファイル。
- UTF-8 を厳格に解析し、デコード後の重複メンバーを拒否。
- format アサーションを有効にした、完全オフラインの Draft 2020-12 `$id` 解決。
- `missionweaveprotocol-conformance` CLI。52/52 ベクトル（有効 25、無効 27）に合格。
- UTF-16 プロパティ順序と ECMAScript 数値表現を含む RFC 8785、および `sha256:<hex>` ID。
- RFC 8032 テストベクトル 1 で検証した Ed25519 署名と検証。
- 厳格な解析、WebSocket フレーム Schema 検証、正規エンコードを行う `FrameCodec`。
- `MissionWeaveProtocol::sdk` ターゲットを公開するインストール可能な CMake パッケージ。

## 要件とビルド

C++20 コンパイラ、CMake 3.24 以降、OpenSSL 3.0 以降が必要です。Ninja を推奨します。
jsoncons 1.8.1 が見つからない場合、CMake は設定時に固定バージョンを取得します。実行時
検証はネットワークへアクセスしません。

レジストリパッケージやリリースタグはまだ公開済みとして案内していません。
保護された
`main` ブランチからビルドしてください。

```console
git clone https://github.com/MissionWeaveProtocol/cpp-sdk.git
cd cpp-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/missionweaveprotocol-conformance
cmake --install build --prefix /path/to/prefix
```

利用側の CMake：

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

利用側を設定するときは `CMAKE_PREFIX_PATH` にインストールプレフィックスを指定します。

## 使用例

フレームを厳格にデコードし、正規 JSON へエンコードします。

```cpp
#include <missionweaveprotocol/frame.hpp>

missionweaveprotocol::FrameCodec codec;
auto frame = codec.decode(input_bytes);
std::string canonical = codec.encode(frame);
```

コンテンツ ID を作成し、文書へ署名します。

```cpp
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>

auto content_id = missionweaveprotocol::canonical_sha256(document);
// 本番環境では、安全なシークレットストアから
// 保護された 32 バイトのランダム値を読み込みます。
missionweaveprotocol::Ed25519Seed seed{};
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

文書署名では、正規署名ペイロードからトップレベルの `signature` メンバーだけを
除外します。
同名のネストされたメンバーは署名対象のままです。

6 段階の完全なプロファイルには `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` と
`verify(kind, received_bytes, key_resolver)` を使用します。文書種別は常に明示し、外部アダプターは
`SigningKey` と組織管理の `KeyResolver` だけです。検証結果は不変のバイト列、ハッシュ、署名、Principal 証拠を保持します。

任意の埋め込みプロトコル文書を検証します。

```cpp
#include <missionweaveprotocol/schema.hpp>

missionweaveprotocol::SchemaCatalog schemas;
auto result = schemas.validate("mission.schema.json", document);
if (!result.valid && result.issue) {
  // result.issue にはキーワード、インスタンス位置、Schema 位置、
  // メッセージが含まれます。
}
```

完全なプログラムは
`examples/validate_frame.cpp` と `examples/sign_document.cpp` を参照してください。

## 固定プロトコルバンドル

| 項目 | 値 |
| --- | --- |
| プロトコル commit | `6f10987627d62fb296e3490ceceb5539b1e94b70` |
| Schema 数 | `21` |
| Schema ツリー SHA-256 | `a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413` |
| 適合性 JSON 数 | `53` |
| 適合性ツリー SHA-256 | `21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da` |
| 結合バンドル SHA-256 | `b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7` |

`ProtocolBundle::verify()` は、ファイル数とパスおよびバイトに依存するダイジェストを
実行時に検証します。

## 適合性の範囲

```console
missionweaveprotocol-conformance
# 52/52 conformance vectors passed (25 valid, 27 invalid)
```

この結果は Schema とベクトルの適合性だけを示します。調整、スケジューリング、
Execution Lease、リプレイ、永続化、トランスポートライフサイクルの完全な動作適合性を
主張するものではありません。検証成功は認可でもなく、アプリケーションは
組織ポリシーと人間の承認を実施する必要があります。

## セキュリティ上の注意

- Ed25519 seed をソースコードに保存せず、適切なシークレットストアから
  読み込んでください。
- デコードした文書を認可済みの `Command` または `Event` として扱う前に、Schema の妥当性を
  検証してください。
- 拡張データはあくまでデータであり、プロトコルのコアフィールドを置き換えたり、
  それ自体で権限を付与したりすることはできません。
- 埋め込み Schema リゾルバーはネットワークへアクセスしません。

## ライセンス

Apache-2.0。第三者通知は `THIRD_PARTY_NOTICES.md` にあります。
