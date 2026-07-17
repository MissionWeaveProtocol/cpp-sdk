[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | **日本語** | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

MissionWeaveProtocol の公式 C++20 プロトコル SDK です。厳格な JSON 処理、オフラインの
Draft 2020-12 Schema レジストリ、規範的な適合性ベクトル、RFC 8785 正規 JSON と
`sha256:` コンテンツ ID、Ed25519 署名、および Schema 検証付き frame codec を提供します。

現在のリリースが示すのは**Schema とベクトルの適合性**です。完全な Python 参照 runtime
の移植ではなく、Core、Worker 実行、Group 間 scheduling、storage、replay、WebSocket 接続
client は初期スコープに含まれません。

## 機能

- バイトを保持した正確な `PROTOCOL_PIN.json`、21 Schema、44 個の適合性 JSON ファイル。
- UTF-8 を厳格に解析し、デコード後の重複 member を拒否。
- format assertion を有効にした、完全オフラインの Draft 2020-12 `$id` 解決。
- `missionweaveprotocol-conformance` CLI。43/43 ベクトル（valid 22、invalid 21）に合格。
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
| プロトコル commit | `00964ea9064cbf1f0eca8af21a0c57367ee14752` |
| Schema 数 | `21` |
| Schema tree SHA-256 | `cbb37b7d55ad1a21a01370d6c09677b05dcd1383d6d77fa60b9c58b0fd85c624` |
| 適合性 JSON 数 | `44` |
| 適合性 tree SHA-256 | `100d2d2104d07bd7dcfbde354555a85d244f4b7c20c1c5dda0136ce36b4b8675` |
| 結合 bundle SHA-256 | `281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda` |

`ProtocolBundle::verify()` は、ファイル数と path/byte に依存する digest を runtime で検証します。

## 適合性の範囲

```console
missionweaveprotocol-conformance
# 43/43 conformance vectors passed (22 valid, 21 invalid)
```

この結果は Schema とベクトルの適合性だけを示します。coordination、scheduling、lease、
replay、persistence、transport lifecycle の完全な動作適合性を主張するものではありません。
検証成功は authorization でもなく、アプリケーションは組織ポリシーと人間の承認を実施する
必要があります。

## ライセンス

Apache-2.0。第三者通知は `THIRD_PARTY_NOTICES.md` にあります。
