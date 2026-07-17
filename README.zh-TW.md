[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文** | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

MissionWeaveProtocol 官方 C++20 協定 SDK。它提供嚴格 JSON 處理、離線 Draft 2020-12
Schema 登錄、規範符合性向量、RFC 8785 規範 JSON 與 `sha256:` 內容識別碼、Ed25519
簽章，以及執行 Schema 驗證的 frame codec。

目前版本證明的是**Schema 與向量符合性**，並非完整 Python 參考 runtime 的移植版。
Core、Worker 執行、跨 Group 排程、儲存、重播與 WebSocket 連線 client 不在初始範圍內。

## 能力

- 精確且逐位元組保留的 `PROTOCOL_PIN.json`、21 個 Schema 與 44 個符合性 JSON 檔案。
- 嚴格 UTF-8 JSON 解析，並在解碼成員名稱後拒絕重複成員。
- 完全離線的 `$id` 解析，以及啟用 format assertion 的 Draft 2020-12 驗證。
- `missionweaveprotocol-conformance` CLI；43/43 個向量全部通過，其中 22 個有效、21 個無效。
- RFC 8785 規範 JSON、UTF-16 屬性排序、ECMAScript 數字格式與 `sha256:<hex>` 識別碼。
- 通過 RFC 8032 測試向量 1 的 Ed25519 簽章與驗證。
- `FrameCodec`：嚴格解析、WebSocket frame Schema 驗證與規範編碼。
- 可安裝的 CMake package，target 為 `MissionWeaveProtocol::sdk`。

## 環境需求與建置

需要 C++20 編譯器、CMake 3.24+ 與 OpenSSL 3.0+。建議使用 Ninja。若系統沒有
jsoncons 1.8.1，CMake 會在設定階段下載固定版本；runtime 驗證不會存取網路。

目前不宣稱已有 registry package 或 release tag，請從受保護的 `main` branch 建置：

```console
git clone https://github.com/MissionWeaveProtocol/cpp-sdk.git
cd cpp-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/missionweaveprotocol-conformance
cmake --install build --prefix /path/to/prefix
```

使用端的 CMake：

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

設定使用端時，請將 `CMAKE_PREFIX_PATH` 指向安裝 prefix。

## 使用範例

嚴格解碼並規範編碼 frame：

```cpp
#include <missionweaveprotocol/frame.hpp>

missionweaveprotocol::FrameCodec codec;
auto frame = codec.decode(input_bytes);
std::string canonical = codec.encode(frame);
```

建立內容識別碼並簽署文件：

```cpp
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>

auto content_id = missionweaveprotocol::canonical_sha256(document);
missionweaveprotocol::Ed25519Seed seed{}; // 正式環境必須從安全的金鑰儲存載入。
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

文件簽章只會從規範簽章 payload 移除頂層 `signature` 成員；同名巢狀成員仍受簽章保護。
完整程式請見 `examples/validate_frame.cpp` 與 `examples/sign_document.cpp`。

## 固定的協定 bundle

| 項目 | 值 |
| --- | --- |
| 協定 commit | `00964ea9064cbf1f0eca8af21a0c57367ee14752` |
| Schema 數量 | `21` |
| Schema tree SHA-256 | `cbb37b7d55ad1a21a01370d6c09677b05dcd1383d6d77fa60b9c58b0fd85c624` |
| 符合性 JSON 數量 | `44` |
| 符合性 tree SHA-256 | `100d2d2104d07bd7dcfbde354555a85d244f4b7c20c1c5dda0136ce36b4b8675` |
| 合併 bundle SHA-256 | `281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda` |

`ProtocolBundle::verify()` 會在 runtime 檢查檔案數量，以及對路徑與位元組敏感的摘要。

## 符合性範圍

```console
missionweaveprotocol-conformance
# 43/43 conformance vectors passed (22 valid, 21 invalid)
```

此結果僅表示 Schema 與向量符合性，不表示協調、排程、租約、重播、持久化或傳輸生命週期的
完整行為符合性。驗證通過也不等同於授權；應用程式仍須執行組織政策與人工核准要求。

## 授權條款

Apache-2.0。第三方聲明請見 `THIRD_PARTY_NOTICES.md`。
