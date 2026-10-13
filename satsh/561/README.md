# Stash 4.3.2 (561) 本地授权回归

本目录用于软件所有者授权的二进制安全回归。最终方案不修改 Stash 的任何机器码，
而是复制原始 Developer ID 签名应用，并为当前用户写入两条一次性的旧版 Keychain
授权记录。原应用启动后会把记录迁移到自己的私有 access group，并删除临时记录。

因此输出 App 与输入 App 字节完全一致，Developer ID、Team ID、system extension、
network extension 和 restricted entitlements 都保留。系统代理与增强模式使用程序原有
实现，不由脚本模拟。

## 快速使用

要求：

- 原始包必须是下方精确列出的 `4.3.2 (561)` 构建。
- 本机需要 Xcode Command Line Tools，脚本会编译一个只读设备指纹辅助程序。
- 执行前退出所有 Stash 进程。
- 目标 Keychain 必须在当前用户的 Keychain 搜索列表中。

```bash
cd satsh/561

python3 activate_stash_561.py \
  --input "/path/to/Stash 561.app" \
  --output "/path/to/Stash 561 Patched.app"

python3 verify_signed_stash_561.py \
  --source "/path/to/Stash 561.app" \
  --app "/path/to/Stash 561 Patched.app"
```

脚本默认交互式读取当前登录 Keychain 密码、复制应用、写入授权记录、关闭 Sparkle
自动检查、启动 Stash，并确认两条临时记录已被应用消费。已有输出需要显式加 `--force`。

自动化环境可以传入：

```bash
python3 activate_stash_561.py \
  --input "/path/to/Stash 561.app" \
  --output "/path/to/Stash 561 Patched.app" \
  --keychain "$HOME/Library/Keychains/login.keychain-db" \
  --keychain-password 'KEYCHAIN_PASSWORD' \
  --force
```

`security(1)` 的 partition-list 接口只接受 `-k` 密码参数。脚本不会在日志或错误中
输出密码，但执行该系统命令的极短时间内，密码会出现在子进程 argv 中。共享机器应使用
交互模式，并确保没有不受信任的本地进程观察进程表。

保留现有 Sparkle 自动更新设置可加 `--keep-updates`。只生成副本和授权记录、不启动应用
可加 `--no-launch`；这时不会验证迁移结果。

## 严格输入约束

```text
Bundle ID: ws.stash.app.mac
Version: 4.3.2
Build: 561
Original main SHA-256:
004565afd64a8ae9e415b6aa2efbe8d676b503dbcdee85e7a40a0e618d94575f
Original helper SHA-256:
91bd0c16aab9e1e5c36467d02f853d417a15a2c01bba2fadf741f05eaefa0430
TeamIdentifier: B36787XSBG
```

版本、构建号、主程序、Helper、签名或关键 entitlement 任一不匹配，脚本都会失败关闭。
它不是跨版本通用补丁；新版本仍需重新确认授权序列化与设备指纹算法。

## 脚本做什么

1. 验证版本、哈希、Developer ID、Team ID 和受限 entitlement。
2. 用 `ditto` 创建签名保持不变的副本，并再次验证副本。
3. 读取 `IOPlatformSerialNumber` 和磁盘序列号，复现 Stash 的设备绑定密钥派生。
4. 生成测试用激活 protobuf，并用 AES-256-CBC 加密。
5. 写入两条限定 `teamid:B36787XSBG` 的临时 Keychain 记录。
6. 默认关闭当前用户的 Sparkle 自动检查和自动安装偏好。
7. 启动 Stash，并要求它在 20 秒内消费和删除两条临时记录。

脚本不会：

- 修改端口、订阅、配置文件、Setup 或窗口控制流。
- 修改、重签或注入主程序、Helper、system extension 或任何 framework。
- 启动本地授权服务器，伪造网络激活响应或绕过 macOS 系统批准。
- 在宿主机预装激活状态；授权状态属于运行脚本的当前用户 Keychain。

## 已验证结果

Parallels macOS 26.6.2 ARM64 隔离虚拟机中完成以下验证：

| 项目 | 结果 |
|---|---|
| 全新用户运行一键脚本 | PASS，无 Setup 或授权窗口 |
| 原 Developer ID 深度签名 | PASS |
| 临时 Keychain 记录迁移 | PASS，两条记录均返回 item-not-found |
| 原生 system extension 安装/启用 | PASS |
| 订阅、47,442 条规则与 Dashboard | PASS |
| 显式 HTTP 代理真实流量 | PASS |
| 设置为系统代理、Safari 真实流量 | PASS |
| 关闭系统代理并恢复网络设置 | PASS |
| 增强模式、UTUN、默认路由与真实流量 | PASS |
| 关闭增强模式并恢复路由 | PASS |
| 重启后授权、订阅、扩展与两种模式 | PASS |

首次安装 system extension/VPN 配置仍会显示 macOS 原生批准界面，这是程序设计的一部分，
不能也不应由激活脚本绕过。旧的 privileged Helper 文件保持原样；动态与静态结果显示 561
的必要特权路径以原生 system extension 和 Network Extension 配置为主。

完整方法、证据和加固建议见
[2026-10-14-reverse-stash-561-report.md](report/2026-10-14-reverse-stash-561-report.md)。

当前脚本哈希：

```text
activate_stash_561.py:
b36233dff0c98d3fef9b31d245d05b8282ad6bc580822ba057d1867a8a1260a3

verify_signed_stash_561.py:
83a187f1957ba5b547813229e93e04073138cbba818047c01d9991433b20ea8a

device_fingerprint.c:
850778410fc989f6c11e849ccb768d6c9e8382bc73d979e2012070037f484c36
```

仓库不包含原始应用或输出应用。
