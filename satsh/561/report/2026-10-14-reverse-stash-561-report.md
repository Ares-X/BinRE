# Stash 4.3.2 (561) 授权与特权功能回归报告

## 结论

Build 561 阻断了 build 487 的旧版机器码补丁：版本、哈希、函数布局和授权表示都发生了
变化，旧脚本会在输入门禁处失败。新版的签名自检、system extension entitlement 和
Network Extension 边界也使 ad-hoc 重签样本无法使用系统代理与增强模式。

但是授权事实仍可由当前用户本地 Keychain 中的可重放状态建立。561 保留了旧版 Keychain
记录迁移逻辑，只要记录使用正确的设备指纹加密，并把 ACL partition 限定到
`teamid:B36787XSBG`，未修改的原始签名应用就会读取、迁移并接受它。

最终交付因此不再补丁二进制。输出 App 与原版逐文件、逐字节相同，保留完整 Developer ID
签名和受限 entitlement；只有当前用户的 Keychain 与 Sparkle 偏好发生变化。在该状态下，
系统代理、增强模式、system extension、订阅和真实代理流量均通过验证。

这证明 561 的 Apple 身份边界能阻止粗糙的重签补丁，但不能保护仍由客户端本地状态决定的
许可证授权。

## 范围与样本

```text
Bundle ID: ws.stash.app.mac
Version: 4.3.2
Build: 561
Architectures: x86_64 + arm64
Original main SHA-256:
004565afd64a8ae9e415b6aa2efbe8d676b503dbcdee85e7a40a0e618d94575f
Original helper SHA-256:
91bd0c16aab9e1e5c36467d02f853d417a15a2c01bba2fadf741f05eaefa0430
TeamIdentifier: B36787XSBG
```

静态分析在宿主完成，安装、授权、网络和重启验证只在 Parallels macOS 26.6.2 ARM64
隔离虚拟机完成。宿主用户 Keychain 没有写入测试授权状态。

## 方法

1. 比较 487 与 561 的 bundle、Mach-O、签名、entitlement、Swift 调用链和 Go 符号。
2. 用官方 IDA MCP 确认授权表示、Setup 触发点、system extension 请求、SCPreferences
   系统代理调用和 NETunnelProviderManager 增强模式调用。
3. 构造过 15 点 ARM64 ad-hoc 补丁作为负面对照，验证它能改写本地授权，但会丢失
   Apple 受限 entitlement，不能作为最终交付。
4. 逆向旧版 Keychain 兼容迁移路径，复现设备指纹、MD5 密钥派生、protobuf 和
   AES-256-CBC 加密格式。
5. 使用原始签名应用和 Team ID partition-list 写入两条临时 Keychain 记录。
6. 在全新用户 Home、全新登录 Keychain 中运行最终脚本，要求应用启动后删除两条临时记录。
7. 完成原生批准、订阅、显式代理、系统代理、增强模式、关闭恢复和重启持久性测试。

没有使用 LLDB 动态断点；运行时部分是隔离虚拟机中的黑盒行为、系统状态和真实流量验证。

## 授权链路

迁移输入由两个 generic-password 项组成：

```text
service: ws.stash.app.mac
account: stash-mac-device-id
label:   ws.stash.app.mac.device-id

service: ws.stash.app.mac
account: stash-mac-activation-info-serialized
label:   activation-info
```

激活密钥为以下字符串的 uppercase MD5 十六进制结果：

```text
<device-id>-<IOPlatformSerialNumber>-<disk-serial>
```

该 32 字节 ASCII 值直接作为 AES-256-CBC key，固定 IV 为 `ws.stash.key.aes`。最终测试
protobuf 表示 build 561 可接受的已激活状态。记录 ACL 使用
`teamid:B36787XSBG`，因此只有同 Team ID 的签名进程可读取。

应用首次读取后把状态迁移到自己的私有 access group，并删除这两个兼容记录。最终脚本把
“两条兼容记录均不存在”作为成功条件，而不是只检查进程是否启动。

## 为什么最终方案保留全部功能

旧候选在主程序中修改 15 个 ARM64 指令点后必须 ad-hoc 重签。ad-hoc 签名无法合法持有：

- `com.apple.developer.system-extension.install`
- `com.apple.developer.networking.networkextension`
- 原 Team ID 与相关 keychain access group

因此候选能进入 Dashboard，却会在系统代理和增强模式处被 macOS 拒绝。

最终方案不改 App 字节，也不重签。`codesign --verify --deep --strict` 通过，主程序 SHA 与
原版完全一致，原 Team ID 和 restricted entitlements 均保留。授权绕过发生在外部用户状态，
所以程序原有特权链路继续工作。

## Helper 与特权安装链路

561 bundle 仍包含 `ws.stash.app.mac.daemon.helper`，并保留
`SMPrivilegedExecutables`/Authorization Services 相关实现，但静态调用图没有确认独立的现役
Helper 安装调用者。实际动态安装链路为：

1. 主程序提交 `OSSystemExtensionRequest`。
2. macOS 显示原生 system extension 批准流程。
3. StashTunnel system extension 以 Team `B36787XSBG` 激活并启用。
4. 增强模式通过 `NETunnelProviderManager` 建立 VPN/packet tunnel 配置。
5. 系统代理操作通过 SCPreferences 写入 HTTP/HTTPS/SOCKS 设置。

首次批准仍需要用户完成 macOS 原生界面；脚本不模拟批准，也不安装额外证书。旧 Helper、
system extension 和所有签名内容在输出中均保持原样。

## 动态验证矩阵

| 项目 | 结果 | 证据摘要 |
|---|---|---|
| 全新用户一键脚本 | PASS | 退出码 0，直接显示正常 Stash 菜单 |
| Keychain 迁移 | PASS | 两个 legacy account 均返回 `rc=44` |
| App 完整性 | PASS | 595 个 bundle inventory 条目逐字节一致 |
| Developer ID | PASS | Team `B36787XSBG`，deep/strict 验证通过 |
| 自动更新策略 | PASS | 两个 Sparkle 自动更新偏好均为 0 |
| System extension | PASS | `StashTunnel` activated/enabled |
| 订阅与 Dashboard | PASS | 47,442 条规则、代理组和外部 IP 正常 |
| 显式 HTTP 代理 | PASS | `127.0.0.1:7890` 出口 `58.176.134.116` |
| 系统代理开启 | PASS | HTTP/HTTPS/SOCKS 均指向 `127.0.0.1:7890` |
| 系统代理真实流量 | PASS | Safari 外部 IP `58.176.134.116` |
| 系统代理关闭恢复 | PASS | 三类代理均 disabled |
| 增强模式开启 | PASS | `utun4`、`198.18.0.1/16`、默认路由经 tunnel |
| 增强模式真实流量 | PASS | 直接 curl 和 Safari 出口均为代理 IP |
| 增强模式关闭恢复 | PASS | tunnel 默认路由移除，恢复 `en0` |
| 重启持久性 | PASS | 授权、订阅、system extension、VPN 配置均保留 |
| 重启后两种模式 | PASS | 系统代理与增强模式分别再次开启并恢复关闭 |
| x86_64 运行 | NOT_EXERCISED | 本次 VM 为 ARM64 |
| iCloud/CloudKit | NOT_EXERCISED | 不属于授权/代理验收范围 |

系统代理与增强模式始终分开测试，并在每轮结束时恢复关闭。增强模式开启期间系统代理仍为
disabled，说明流量来自 packet tunnel，而不是残留的 SCPreferences 代理设置。

## 最终脚本的失败关闭边界

`activate_stash_561.py` 在改变状态前验证：

- 精确版本、build、主程序和 Helper 哈希。
- Developer ID TeamIdentifier。
- system-extension 和 network-extension entitlement。
- 目标 Keychain 存在且属于当前用户搜索列表。
- 两个 legacy account 均不存在。
- 没有正在运行的 Stash 进程。

复制后再次验证签名和哈希。启动后若 20 秒内未看到 Stash 进程，或任一临时记录没有被消费，
脚本返回失败。它不删除未知 Keychain 状态，也不覆盖原始应用。

## 风险判断

561 的版本变化和签名自检提高了旧机器码补丁的维护成本，Apple entitlement 也有效保护了
特权组件不被 ad-hoc 副本直接复用。但只要许可证仍可由本地、可重放的 Keychain 记录建立，
攻击者无需修改签名应用即可让原版进程接受伪造状态。此路径比机器码补丁更稳定，也天然保留
全部受限功能。

## 加固建议

1. 移除或严格失效旧版 Keychain 迁移入口。迁移完成后由服务端按账号/设备记录一次性 nonce，
   拒绝重复导入和离线重放。
2. 让代理核心、system extension 和 packet tunnel 分别验证短期、服务端签名的 capability，
   不只读取主程序已经归一化的本地授权对象。
3. capability 绑定账号、设备公钥、Team ID、bundle、build、功能集合、到期时间和 challenge；
   私钥放入 Secure Enclave/Keychain 不可导出项。
4. 把许可证私有状态放入只允许指定 access group 的 item，并让迁移数据必须由服务器签名。
   Team ID ACL 只限制读取者，不能证明记录内容来自发行方。
5. 将系统代理、增强模式和核心代理启动纳入同一个最小授权事实，避免 UI、Go raw value、
   Swift enum 和核心服务各自形成可修改的本地权威。
6. 在发布回归中加入“未改 App + 伪造 legacy Keychain 记录”测试；要求 migration、Dashboard、
   local proxy 和特权扩展都拒绝未经服务器签名的状态。

## 限制

- 结论只适用于所列 build 561 输入哈希。
- 最终脚本没有跨版本自动定位能力；新构建仍需重新确认序列化和设备指纹算法。
- 未伪造 Apple Developer ID、Team ID、受限 entitlement 或 macOS 批准状态。
- x86_64、CloudKit/iCloud 和真实产品升级安装未执行。
- 真实流量只代表隔离 VM 的测试时刻和给定订阅，不代表所有网络环境。
