[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文** | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

MissionWeaveProtocol 官方 C++20 協定 SDK。它提供嚴格 JSON 處理、離線 Draft 2020-12
Schema 登錄、規範符合性向量、RFC 8785 規範 JSON 與 `sha256:` 內容識別碼、Ed25519
簽章，以及執行 Schema 驗證的訊框編解碼器。

目前版本證明的是**Schema 與向量符合性**，並非完整 Python 參考執行階段的移植版。
Core、Worker 執行、跨 Group 排程、儲存、重播與 WebSocket 連線用戶端不在初始範圍內。

## 能力

- 精確且逐位元組保留的 `PROTOCOL_PIN.json`、21 個 Schema 與 53 個符合性 JSON 檔案。
- 嚴格 UTF-8 JSON 解析，並在解碼成員名稱後拒絕重複成員。
- 完全離線的 `$id` 解析，以及啟用格式斷言的 Draft 2020-12 驗證。
- `missionweaveprotocol-conformance` CLI；52/52 個向量全部通過，其中 25 個有效、27 個無效。
- RFC 8785 規範 JSON、UTF-16 屬性排序、ECMAScript 數字格式與 `sha256:<hex>` 識別碼。
- 通過 RFC 8032 測試向量 1 的 Ed25519 簽章與驗證。
- `FrameCodec`：嚴格解析、WebSocket 訊框 Schema 驗證與規範編碼。
- 可安裝的 CMake 套件，目標為 `MissionWeaveProtocol::sdk`。

## 環境需求與建置

需要 C++20 編譯器、CMake 3.24+ 與 OpenSSL 3.0+。建議使用 Ninja。若系統沒有
jsoncons 1.8.1，CMake 會在設定階段下載固定版本；執行階段驗證不會存取網路。

目前尚未發布至套件登錄庫，也沒有版本標籤，請從受保護的 `main` 分支建置：

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

設定使用端時，請將 `CMAKE_PREFIX_PATH` 指向安裝前綴。

## 使用範例

嚴格解碼並規範編碼訊框：

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

文件簽章只會從規範簽章承載內容移除頂層 `signature` 成員；同名巢狀成員仍受簽章保護。

完整六階段流程請使用 `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` 與
`verify(kind, received_bytes, key_resolver)`。文件種類必須明確指定；`SigningKey` 和組織控制的
`KeyResolver` 是僅有的外部轉接器，驗章結果會保留不可變的位元組、雜湊、簽章與已解析 Principal 證據。

驗證任何內嵌協定文件：

```cpp
#include <missionweaveprotocol/schema.hpp>

missionweaveprotocol::SchemaCatalog schemas;
auto result = schemas.validate("mission.schema.json", document);
if (!result.valid && result.issue) {
  // result.issue 包含關鍵字、實例位置、Schema 位置與訊息。
}
```

完整程式請見 `examples/validate_frame.cpp` 與 `examples/sign_document.cpp`。

## 固定的協定套件

| 項目 | 值 |
| --- | --- |
| 協定 commit | `6f10987627d62fb296e3490ceceb5539b1e94b70` |
| Schema 數量 | `21` |
| Schema 樹狀 SHA-256 | `a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413` |
| 符合性 JSON 數量 | `53` |
| 符合性樹狀 SHA-256 | `21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da` |
| 合併套件 SHA-256 | `b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7` |

`ProtocolBundle::verify()` 會在執行階段檢查檔案數量，以及對路徑與位元組敏感的摘要。

## 符合性範圍

```console
missionweaveprotocol-conformance
# 52/52 conformance vectors passed (25 valid, 27 invalid)
```

此結果僅表示 Schema 與向量符合性，不表示協調、排程、租約、重播、持久化或傳輸
生命週期的完整行為符合性。驗證通過也不等同於授權；應用程式仍須執行組織政策與
人工核准要求。

## 安全性說明

- 請勿在原始碼中存放 Ed25519 seed；應從適當的機密儲存載入。
- 將解碼後的文件視為已授權的 `Command` 或 `Event` 前，必須驗證其 Schema 有效性。
- 擴充資料仍然只是資料；它不能取代協定核心欄位，也不能自行授予權限。
- 內嵌 Schema 解析器不會存取網路。

## 授權條款

Apache-2.0。第三方聲明請見 `THIRD_PARTY_NOTICES.md`。
