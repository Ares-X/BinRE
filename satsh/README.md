# Stash 4.2.1 (487) ARM64 本地补丁

本目录用于用户自有软件的授权安全评估。脚本只支持经过验证的
`Stash 4.2.1 (487)` 原始包，并在独立副本上工作，不覆盖原始应用。

## 快速使用

```bash
cd satsh
python3 patch_stash_487.py --force
```

把原始应用放在脚本旁，默认输入为：

```text
Stash 487.app
```

默认输出：

```text
Stash_487_patched.app
Stash_487_patched.patch.json
Stash_487_patched.zip
```

首次生成且输出不存在时可以省略 `--force`。输出已存在时，
`--force` 只允许替换带匹配清单、且能证明由本脚本生成的 `.app`；
不会删除任意目录。构建在同盘临时目录完成，全部检查成功后才替换旧输出。

自定义输入或输出：

```bash
python3 patch_stash_487.py \
  --input "/path/to/Stash 487.app" \
  --output "/path/to/Stash_487_patched.app"
```

仓库不包含原始应用、修改后的应用或生成的 ZIP。它们分别属于输入和本地构建产物，
并由本目录的 `.gitignore` 排除。

保留原包的 Sparkle 自动检查默认值：

```bash
python3 patch_stash_487.py --force --keep-updates
```

## 输入约束

脚本会先验证以下条件，任一不匹配即停止：

- Bundle ID：`ws.stash.app.mac`
- 版本：`4.2.1`
- Build：`487`
- 主程序 SHA-256：
  `264e77c91a7e2075227d2a398b3bec77aa78093b6a7e5fcbd63b2207cc02ba69`
- Helper SHA-256：
  `2bc4a146cce06f7a3e0229d26cae997cc0cb892c8847b2dde9dec32cd50e66ce`

这不是“搜索一个字节然后盲改”的通用补丁。它是对 build 487 的严格、
失败关闭实现；版本或哈希改变后应重新做二进制差分与动态验证。

## 脚本会修改什么

1. 在 ARM64 主程序中修改 10 个激活状态归一化/读取点，使本地激活对象稳定返回已激活状态。
2. 在 ARM64 主程序中修改 2 个 CloudKit 容器创建点，避免临时签名无法使用生产 CloudKit 权限时启动崩溃。
3. 只修改 Helper 两个架构内嵌 plist 的 `SMAuthorizedClients`，并同步主程序的
   `SMPrivilegedExecutables`，让临时签名的测试副本可以安装原有 Helper；不修改 Helper 机器码。
4. 对副本做 ad-hoc 签名，保留可用权限，移除必须绑定原开发团队的生产权限。
5. 默认把 `SUEnableAutomaticChecks` 和 `SUAutomaticallyUpdate` 设为 `false`。
   Sparkle 框架仍在，脚本没有删除更新实现。
6. 生成 ZIP 和 JSON 清单；清单记录补丁前后字节、签名后真实 FAT 偏移、
   架构、权限变化、CDHash、脚本哈希和 ZIP 哈希。

## 脚本不会修改什么

- 不修改端口、用户配置文件或订阅内容。
- 不写死 `8089`、`18089`、`7890` 或其他端口。
- 不控制 Setup、激活或主窗口的显示/隐藏。
- 不注入 dylib，不启动本地 license server，不伪造 email/license key。
- 不修改原始 `Stash 487.app`。

## 架构与签名限制

- 应用包仍包含 `x86_64 + arm64`，但激活和 CloudKit 兼容补丁只覆盖 ARM64。
- x86_64 slice 未补丁、未运行；Intel Mac 不在本次通过范围。
- ad-hoc 签名无法复现生产 Team ID、CloudKit、Push、App Group 和原 Keychain Group 权限。
- 两个 CloudKit 兼容补丁允许核心代理功能启动，但 iCloud/CloudKit 同步不属于已验证功能。
- 该产物不是 Apple 公证发行包，适合隔离测试，不应替代正式签名发布流程。

## 已验证的虚拟机行为

在 ARM64 Parallels macOS 虚拟机中已验证：

- 首次启动不再出现激活窗口或重复 Setup 窗口。
- Helper 成功安装到系统目录并注册为 LaunchDaemon；重启后仍存在，按需空闲时退出码为 0。
- 私有测试订阅可在应用内下载、落盘并加载。
- 代理组、节点和延迟结果正常显示。
- 通过 `127.0.0.1:7890` 的 HTTP 代理请求返回 HTTP 204。
- 精确终止并重新启动 Stash 后，配置、规则和激活状态保持。
- 最终 canonical app 的主程序、Helper、Info.plist 和 CodeResources 哈希与虚拟机实测副本一致。

虚拟机中曾残留系统代理 `127.0.0.1:7897`，它导致最初的订阅下载失败；
清除该虚拟机环境状态后下载成功。脚本没有修改这一端口。

## 当前交付哈希

```text
script SHA-256:
615302778e591fe41c3d72fa7aae459f65edf3cbfa21ba97c2fa792c692412a0

patched main SHA-256:
9bd7b7c46ca6de8451e744ef3aee8148d3077005f7972b68a309fcf8a8dcb1b8

patched helper SHA-256:
a0b9859158b61664ad6b37e6e40967a209338dbc489c26daad23b83f6c736c23

ZIP SHA-256:
8119009b65eb2fc2d06eac375b7517942c6a65e3f0ef3cd9cf81d1ec21f3728e

app CDHash:
c864c7a1bb151624fd2a1242265949b261f64c7c
```

重新运行脚本会刷新构建时间，ZIP 哈希可能改变；主程序哈希和补丁前后字节应保持一致。

## 本地检查

```bash
python3 -m py_compile patch_stash_487.py
codesign --verify --deep --strict --verbose=4 Stash_487_patched.app
unzip -t Stash_487_patched.zip
shasum -a 256 Stash_487_patched.zip
```

## 仓库内容

| 路径 | 内容 |
|---|---|
| `patch_stash_487.py` | build 487 一键补丁、重签名、清单和 ZIP 生成器 |
| `2026-10-01_reverse-stash-487-report.md` | 完整逆向过程、动态验证矩阵、边界和加固建议 |
| `process/` | 评估范围、时间线、工作项和严格 case review |
| `evidence/E-*.md` | Evidence → Finding → Path 使用的证据记录 |
| `evidence/Stash-482-vs-487-targeted.diaphora` | 482→487 的 10 个目标函数匹配结果 |
| `evidence/Stash_487_patched.patch.json` | 已验证构建的脱敏参考清单 |
| `tools/export_diaphora_fast.py` | IDA/Diaphora 目标函数导出辅助脚本 |

VM 截图包含私有配置标识，因此没有随仓库分发；证据记录保留观察结论与原始哈希。

详细分析、动态测试矩阵和加固建议见
[2026-10-01_reverse-stash-487-report.md](2026-10-01_reverse-stash-487-report.md)。
