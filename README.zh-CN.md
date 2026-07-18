[English](README.md) | **简体中文** | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

# MissionWeaveProtocol C++ SDK

MissionWeaveProtocol 官方 C++20 协议 SDK。它提供严格 JSON 处理、离线 Draft 2020-12
Schema 注册表、规范符合性向量、RFC 8785 规范 JSON 与 `sha256:` 内容标识、Ed25519
签名，以及执行 Schema 验证的帧编解码器。

当前版本证明的是**Schema 与向量符合性**，并不是完整 Python 参考运行时的移植版。
Core、Worker 执行、跨 Group 调度、存储、重放和 WebSocket 连接客户端暂不在初始范围内。

## 能力

- 精确、按字节保留的 `PROTOCOL_PIN.json`、21 个 Schema 和 53 个符合性 JSON 文件。
- 严格 UTF-8 JSON 解析，并在解码成员名后拒绝重复成员。
- 完全离线的 `$id` 解析和启用格式断言的 Draft 2020-12 验证。
- `missionweaveprotocol-conformance` CLI；52/52 个向量全部通过，其中 25 个有效、27 个无效。
- RFC 8785 规范 JSON、UTF-16 属性排序、ECMAScript 数字格式和 `sha256:<hex>` 标识。
- 通过 RFC 8032 测试向量 1 验证的 Ed25519 签名与验签。
- `FrameCodec`：严格解析、WebSocket 帧 Schema 验证和规范编码。
- 可安装的 CMake 包，目标名为 `MissionWeaveProtocol::sdk`。

## 环境要求与构建

需要 C++20 编译器、CMake 3.24+ 和 OpenSSL 3.0+。推荐使用 Ninja。若系统没有
jsoncons 1.8.1，CMake 会在配置阶段下载固定版本；运行时验证不访问网络。

目前不宣称已发布注册表包或版本标签，请从受保护的 `main` 分支构建：

```console
git clone https://github.com/MissionWeaveProtocol/cpp-sdk.git
cd cpp-sdk
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/missionweaveprotocol-conformance
cmake --install build --prefix /path/to/prefix
```

在使用方的 CMake 中：

```cmake
find_package(missionweaveprotocol CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE MissionWeaveProtocol::sdk)
```

配置使用方时，将 `CMAKE_PREFIX_PATH` 指向安装前缀。

## 使用示例

严格解码并规范编码帧：

```cpp
#include <missionweaveprotocol/frame.hpp>

missionweaveprotocol::FrameCodec codec;
auto frame = codec.decode(input_bytes);
std::string canonical = codec.encode(frame);
```

生成内容标识并签名文档：

```cpp
#include <missionweaveprotocol/canonical.hpp>
#include <missionweaveprotocol/crypto.hpp>

auto content_id = missionweaveprotocol::canonical_sha256(document);
missionweaveprotocol::Ed25519Seed seed{}; // 生产环境必须从安全密钥存储加载。
auto public_key = missionweaveprotocol::Ed25519::public_key_from_seed(seed);
auto signature = missionweaveprotocol::Ed25519::sign_document(seed, document);
bool valid = missionweaveprotocol::Ed25519::verify_document(public_key, document, signature);
```

文档签名只从规范签名载荷中移除顶层 `signature` 成员；同名嵌套成员仍受签名保护。

完整六阶段流程使用 `SignedDocumentCodec::sign(kind, unsigned_document, signing_key)` 与
`verify(kind, received_bytes, key_resolver)`。文档种类必须显式指定；`SigningKey` 和组织控制的
`KeyResolver` 是仅有的外部适配器，验签结果保留不可变的字节、哈希、签名及已解析 Principal 证据。

验证任意内嵌协议文档：

```cpp
#include <missionweaveprotocol/schema.hpp>

missionweaveprotocol::SchemaCatalog schemas;
auto result = schemas.validate("mission.schema.json", document);
if (!result.valid && result.issue) {
  // result.issue 包含关键字、实例位置、Schema 位置和消息。
}
```

完整程序见 `examples/validate_frame.cpp` 和 `examples/sign_document.cpp`。

## 固定的协议包

| 项目 | 值 |
| --- | --- |
| 协议提交 | `6f10987627d62fb296e3490ceceb5539b1e94b70` |
| Schema 数量 | `21` |
| Schema 树 SHA-256 | `a225900a2c2a6c0d03de38ffa7d67dd16fd1586ca63b8ce1d019159fba5f0413` |
| 符合性 JSON 数量 | `53` |
| 符合性树 SHA-256 | `21badf03fc8b05874a744a2d66d064265c635512dd49378b8d24ab1aa0e958da` |
| 合并包 SHA-256 | `b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7` |

`ProtocolBundle::verify()` 会在运行时校验文件数量以及对路径和字节敏感的摘要。

## 符合性边界

```console
missionweaveprotocol-conformance
# 52/52 conformance vectors passed (25 valid, 27 invalid)
```

该结果仅代表 Schema 与向量符合性，不代表协调、调度、租约、重放、持久化或传输
生命周期的完整行为符合性。验证通过也不等同于授权；应用仍须执行组织策略和
人类批准要求。

## 安全说明

- 不要在源代码中存放 Ed25519 种子；应从适当的密钥存储中加载。
- 将解码后的文档视为已授权的 `Command` 或 `Event` 前，必须验证其 Schema 有效性。
- 扩展数据仍然只是数据；它不能取代协议核心字段，也不能自行授予权限。
- 内嵌 Schema 解析器不会访问网络。

## 许可证

Apache-2.0。第三方声明见 `THIRD_PARTY_NOTICES.md`。
