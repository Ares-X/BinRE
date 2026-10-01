# Mole (macOS) — License Crack

[Mole](https://github.com/tw93/Mole) 是 tw93 的 macOS 清理工具(付费授权,走
[Dodopayments](https://dodopayments.com)),Swift/SwiftUI 实现,内置三重防护:
代码签名完整性校验、license 服务器验证、keychain 试用计数。

本目录提供一键补丁脚本,破解后**离线、全功能、无试用限制**。

## 支持版本

| 项目 | 值 |
|---|---|
| 完整支持 | **v1.15.0 (294)**(按 fat SHA256 `304d66e1…c50136` 锁定,字节级校验) |
| 自动适配 | 未知版本自动特征定位 A/B/C 三补丁(见下);**D 补丁无法自动定位**,定位失败会安全中止并提示重新分析 |
| 平台 | arm64(fat 中的 x86_64 slice 不打补丁,Rosetta 下会回到未授权) |
| 环境 | macOS + python3;x86_64/arm64 均可运行脚本(补丁目标为 arm64 slice) |

## 破解方式(五个补丁)

| # | 地址(arm64 slice 内) | 改动 | 作用 |
|---|---|---|---|
| A | `0x10033ebd8` | `CSET W8,EQ` → `MOVZ W8,#1` | `LicenseGate.licensed` 恒为 true。该指令是 licensed 的**全二进制唯一写入点**(verify 异步续体的落盘处) |
| B | `0x100333f50` | 函数序言 → `MOV W0,#1; MOV W1,#0; MOV W2,#0; RET` | `OfficialBuildVerifier.Verdict` 恒 (success, nil)。**必需**——缺失则 app 启动零窗口(SecCodeCheckValidity 对 ad-hoc 签名必然失败,触发反篡改) |
| C | `0x100b3a6c0` | `https://live.dodopayments.com` → `http://127.0.0.1:23949/localx` | license 请求转向本地 fixture(仅为"输入 key 激活"体验,不影响已激活状态) |
| D | `0x10080e2d8` | 函数序言 → `MOV X0,#0; RET` | `TrialUsageStore` 试用计数读取恒 0,功能门禁的 "Free trial used up" 永不触发 |
| E | `0x10032dc58` | 函数序言 → `MOV X0,#0; MOV X1,#0; RET` | keychain 凭证读取恒 nil——app 不再调 `SecItemCopyMatching`,无钥匙串弹窗,表现为全新安装 |

### 关键原理

1. **双状态体系**:`LicenseGate.licensed` 与 `LicenseManager._status` 是独立的两套
   状态;功能门禁查的是 `_status`/试用计数,不是 gate.licensed。只打 A+B 会出现
   "主界面正常、功能却报试用用尽",所以需要 D。
2. **签名链处理**:修改可执行文件后必须重签。脚本用 `codesign -f -s -`(**不带**
   `--deep`——嵌套代码保持原签名,外层 ad-hoc 封印自洽,且不影响日后字节级还原);
   重签会导致 fat 内 arm64 slice 偏移漂移,故签名后**重新解析 fat header 复验**补丁。
3. **产品 ID 坑**(使用 activate.sh 时):本地 fixture 必须返回 Mac 产品 ID
   `pdt_0NeAQjL4YEqzkukadjRUT`(来自 checkout URL);若返回
   `pdt_0NoRCskSwjACLFPCWqpn4` 会命中 `PersistSuccessfulActivation` 里的单元素
   `Set<String>` 黑名单 → "This key is for Windows" → 自动注销。

## 使用

```bash
cd mole

python3 crack_mole.py              # 原地破解 /Applications/Mole.app(自动四件套备份)
python3 crack_mole.py --verify     # 检查五个补丁是否在盘
python3 crack_mole.py --restore    # 字节级还原官方版(原始开发者签名复活)
python3 crack_mole.py --out X.app  # 生成独立破解副本(不动原版,bundle id 改为 MoleCrk)
python3 crack_mole.py --open       # 附加:完成后启动

./activate.sh                      # 可选:起本地服务,菜单 License… 里输入任意 key 激活
```

注意:

- 原地模式需要终端持有 **App Management** 权限(系统设置 > 隐私与安全性 > App 管理),
  且必须是授权**之后启动**的终端,否则写可执行文件报 EPERM
- `Contents/MacOS/` 下出现任何非 Mach-O 杂物文件都会让 codesign 失败
  ("code object is not signed at all"),脚本会预检并给出清晰报错
- 备份(exe + Info.plist + `_CodeSignature` + 整个 app)存在脚本旁 `backups/`,
  `latest.json` 指向最新一轮,`--restore` 即完整回滚

## 新版本适配

已知 SHA 走锁定偏移;未知版本自动特征定位:

- **A**:20 字节指令签名(LDR/LDR/CMP/CSET/STRB),全 slice 唯一
- **B**:`"integrity: SecRequirementCreateWithString failed"` 日志字符串 →
  ADRL 引用回溯 → 左侧第二个函数序言(≥3 连 STP 且含 X29/X30)
- **C**:provider URL 字符串(仅 arm64 slice 范围内搜索)
- **D**:普通 Swift 方法无字节特征——需在 IDA 里从 `trial.remaining.one` 字符串
  引用的 UI 函数入手,找其 `2 - used` 减法前调用的计数读取函数,偏移加入
  `PATCHES[3]`(配合 [Diaphora](https://github.com/joxeankoret/diaphora) 把旧库
  符号迁移到新版本库会更快)

## 文件

| 文件 | 说明 |
|---|---|
| `crack_mole.py` | 主脚本(定位/补丁/备份/还原/校验) |
| `activate.sh` | 本地 license 服务启动器(任意 key 激活体验) |
| `license_lab_server.py` | 本地 fixture 服务,仅监听 127.0.0.1:23949 |

## 免责声明

仅限本地学习与安全研究用途。请尊重开发者的劳动,如需长期使用请[购买正版](https://checkout.dodopayments.com/buy/pdt_0NeAQjL4YEqzkukadjRUT)。
