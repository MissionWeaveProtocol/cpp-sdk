[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | **日本語** | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

MissionWeaveProtocol の公式 C++20 プロトコル SDK です。厳格な JSON 処理、オフラインの
Draft 2020-12 Schema レジストリ、規範的な適合性ベクトル、RFC 8785 正規 JSON と
`sha256:` コンテンツ ID、Ed25519 署名、および Schema 検証付き frame codec を提供します。

現在のリリースが示すのは**Schema とベクトルの適合性**です。完全な Python 参照 runtime
の移植ではなく、Core、Worker 実行、Group 間 scheduling、storage、replay、WebSocket 接続
client は初期スコープに含まれません。

## 機能

- バイトを保持した正確な `PROTOCOL_PIN.json`、21 Schema、53 個の適合性 JSON ファイル。
- UTF-8 を厳格に解析し、デコード後の重複 member を拒否。
- format assertion を有効にした、完全オフラインの Draft 2020-12 `$id` 解決。
- `missionweaveprotocol-conformance` CLI。52/52 ベクトル（valid 25、invalid 27）に合格。
- UTF-16 property 順序と ECMAScript 数値表現を含む RFC 8785、および `sha256:<hex>` ID。
- RFC 8032 テストベクトル 1 で検証した Ed25519 署名と検証。
- 厳格な解析、WebSocket frame Schema 検証、正規エンコードを行う `FrameCodec`。
- `MissionWeaveProtocol::sdk` target を公開するインストール可能な CMake package。

## 要件とビルド

C++20 compiler、CMake 3.24 以降、OpenSSL 3.0 以降が必要です。Ninja を推奨します。
jsoncons 1.8.1 が見つからない場合、CMake は設定時に固定バージョンを取得します。runtime
検証はネットワークへアクセスしません。

registry package や release tag はまだ公開済みとして案内していません。保護された `main`
branch からビルドしてください。

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

利用側を設定するときは `CMAKE_PREFIX_PATH` にインストール prefix を指定します。

## 使用例

frame を厳格にデコードし、正規 JSON へエンコードします。

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
missionweaveprotocol::Ed25519Seed seed{}; // 本番では安全な secret store から読み込みます。
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

文書署名では、正規署名 payload から top-level の `signature` member だけを除外します。
同名の nested member は署名対象のままです。完全なプログラムは
`examples/validate_frame.cpp` と `examples/sign_document.cpp` を参照してください。

## 固定プロトコル bundle

| 項目 | 値 |
| --- | --- |
| プロトコル commit | `6f10987627d62fb296e3490ceceb5539b1e94b70` |
| Schema 数 | `21` |
| Schema tree SHA-256 | `a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413` |
| 適合性 JSON 数 | `53` |
| 適合性 tree SHA-256 | `21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da` |
| 結合 bundle SHA-256 | `b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7` |

`ProtocolBundle::verify()` は、ファイル数と path/byte に依存する digest を runtime で検証します。

## 適合性の範囲

```console
missionweaveprotocol-conformance
# 52/52 conformance vectors passed (25 valid, 27 invalid)
```

この結果は Schema とベクトルの適合性だけを示します。coordination、scheduling、lease、
replay、persistence、transport lifecycle の完全な動作適合性を主張するものではありません。
検証成功は authorization でもなく、アプリケーションは組織ポリシーと人間の承認を実施する
必要があります。

## ライセンス

Apache-2.0。第三者通知は `THIRD_PARTY_NOTICES.md` にあります。
