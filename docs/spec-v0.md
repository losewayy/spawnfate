# spawnfate — Rule Spec v0

> **本文件的定位**：这是"一条命令线在 Windows 上的完整命运"的第一张全图。
> 来源标注约定：**[DOC]** 官方文档 · **[SRC]** 源码实证 · **[EMP]** 实测 · **[UNC]** 未确证（进语料库待测项）。
> 每条规则必须能指到一个可复算的语料库用例——spec 与语料库是同一资产的两面。

## 设计公理

1. **一条命令线有三个独立的解析器会碰它，各自规则不同**——这是全部复杂性的来源：
   - **生产者**（libuv/.NET/Python subprocess/Rust std…）把 argv 序列化成一条命令线
   - **解析器**（CreateProcess 内建搜索 / libuv `search_path` / cmd PATHEXT 走查）把名字变成可执行文件
   - **消费者**（MSVCRT/Go/Java/batch…）把命令线拆回 argv
2. **不存在普适编码**——能在 CLTAW 下 round-trip 的序列化在 MSVCRT `""` 规则、batch `%*`、PowerShell 下不保证 round-trip（R1.5）。工具的输出必须带"按哪个消费器判定"的语境。
3. **三个名字解析器，三种命运**（本工具的头牌洞见）：
   | 解析器 | 无扩展名裸名 | PATHEXT | 顺序 |
   |---|---|---|---|
   | CreateProcess 内建（仅 lpApplicationName=NULL 时） | 只补 `.exe` | 不用 | 父进程目录 → CWD → System32 → System → Windows → PATH [R0.3] |
   | libuv `search_path`（Node spawn） | 只试 `.com`/`.exe`，**永不试裸名** | **无视 PATHEXT** | CWD 优先 → PATH [R1.14] |
   | cmd.exe `/c` 重解析 | 试裸名 + PATHEXT 全表 | 用 | CWD（除非 NoCurrentDirectoryInExePath）→ PATH [R1.16] |

   → `spawn('npx')` 的死因不是"Windows 找不到 npx.cmd"，而是 **libuv 的解析表里根本没有 `.cmd` 这一项**。cmd 能救它恰恰因为 cmd 走的是另一套表。

---

## Layer 0 — CreateProcessW 语义

- **R0.1** [DOC] `lpApplicationName != NULL` 时它就是加载的模块，`lpCommandLine` 原样传给子进程——**Windows 从不替你拆 argv**，拆分是子进程自己运行时的事。
- **R0.2** [DOC] `lpApplicationName == NULL` 时取命令线第一个 token 作模块名；无扩展名补 `.exe`（名字以 `.` 结尾或含路径除外）。**无引号含空格路径会被逐空格试探**：`c:\program files\sub dir\prog` 依次试 `c:\program.exe` → `c:\program files\sub.exe` → …——这是经典的"程序文件劫持"面。
- **R0.3** [DOC] 裸名搜索顺序：父进程目录 → 父进程 CWD → System32 → 16位 System → Windows 目录 → PATH 逐条。每步先试裸名再试 `name.exe`。无 PATHEXT、无 App Paths。
- **R0.4** [DOC/MSRC] 解析到 `.bat`/`.cmd` 时 CreateProcess **隐式换成 system32\cmd.exe** 并把批文件（连同原命令线）交给 cmd——MS14-019 之后恒用系统目录 cmd。cmd 命令线的精确重组方式 **[UNC — 语料库必测项]**。
- **R0.5** [DOC] 错误面：找不到文件 → `ERROR_FILE_NOT_FOUND`（Node 侧 ENOENT）；找到但不是 PE 也不是批类型 → `ERROR_BAD_EXE_FORMAT`(193)。**存在但不可执行的文件不是 ENOENT，是 193**——`.txt`/`.sh` 显式启动会走这个分支。[EMP Node v24 实测：libuv 把 193 映射为 `EFTYPE`（inappropriate file type），spawn 报 `spawn EFTYPE`]
- **R0.6** [EMP] 路径词法规范化在每个组件上独立生效：`/`→`\`、`.`/`..` 词法消解（libuv 限定名照样吃扩展名试探——`spawn('./prog')` 实测命中 `prog.exe`）。
- **R0.7** [DOC/EMP] **尾点/尾空格剥离（CVE-2024-43402 面）**：Windows 对每组件剥尾部 `.`/` `——`evil.cmd.` 与 `evil.cmd` 是同一文件。早期 Node guard 用 `endsWith('.cmd')` 判定批文件，`evil.cmd.` 绕开；**v24 实测 `spawn('./tt.cmd.')` 仍 EINVAL**——修复后的 guard 先规范化再查后缀。规范化的 resolved 路径上判批类型是本工具的正确姿势。
- **R0.8** [DOC] DOS 保留设备名（`NUL`/`CON`/`AUX`/`PRN`/`COM1-9`/`LPT1-9`，含带扩展名形态 `con.txt`）通过 DOS 设备命名空间"存在"于每台机器——`CreateFile("nul")` 随处成功，但其中没有可 spawn 的 PE。预测：解析器可见、193 级失败。
- **R0.9** [DOC] **App Execution Alias**：`%LOCALAPPDATA%\Microsoft\WindowsApps\*.exe` 是 reparse point 占位符（FILE_ATTRIBUTE_REPARSE_POINT 0x400），OS loader 解析别名目标——装了应用则启动真身，没装则跳商店页。**单凭文件无法判定命运** [UNC]；建议处方：关 Settings→Apps→App execution aliases 或指向真安装路径。

- **R0.10** [EMP] **工作目录必须先存在**：libuv 在 exec 之前先 chdir，`cwd` 指向不存在的目录时 spawn 直接失败 `ENOENT`（errno -4058）——**名字解析根本没被调用**，所以它与"程序找不到"共用同一个错误面，靠错误码分不开。[EMP node v24.15.0：`spawnSync('cmd',['/c','echo'],{cwd:'<不存在>'})` → `code ENOENT / errno -4058`]。语料库用例一律 materialize 出 cwd（该假设一致成立），`cwd_missing` 开关把这个假设显式化，并让它可被单独测试。

## Layer 1 — 生产者序列化（argv → 命令线）

### 1a. 消费者契约（逆规则）

- **R1.1** [DOC] 分隔符只有空格和 TAB；`"` 切换引号态，引号本身被吃掉不发出。
- **R1.2** [DOC] `k` 个反斜杠后接 `"`：发出 `⌊k/2⌋` 个 `\`；k 为奇数则该 `"` 为字面（`\"`），为偶则切换引号态。不接 `"` 的反斜杠一律字面。
- **R1.3** [SRC/EMP] 生产者正规则（libuv `quote_cmd_arg` 实现）：参数为空或含 `空格/TAB/"` 需引用；引用时 `"` 逐个转 `\"`，`"` 前或行尾前的 `\` 串翻倍；空参 → `""`。
- **R1.4** [DOC/EMP] **MSVCRT(VS2008+) 特例**：引号区内 `""` 解析为单个字面 `"`。CommandLineToArgvW **没有**这条规则（`""` = 出引号再入引号 → 消失）。argv[0] 两边都特例：只看引号对、不处理反斜杠。
- **R1.5** [EMP] 无普适编码——按消费器标定输出语境。

### 1b. libuv/Node spawn 生产者

- **R1.6** [SRC] `quote_cmd_arg` 右向左扫描、`quote_hit` 后才翻倍 `\`；内嵌 `"` 一律 `\` 前缀。净效果 = R1.3 + 行尾 `\` 翻倍。
- **R1.7** [SRC] `make_program_args`：每 arg UTF-8→UTF-16 → 逐 arg 引号化（或 `windowsVerbatimArguments` 时原样）→ **单空格连接**；args[0] 是 as-typed `file`。
- **R1.8** [SRC] libuv 先用自家 `search_path` 解析出绝对路径作 `lpApplicationName`——**CreateProcess 的 PATH 搜索被绕过**；子进程 argv[0] 是输入的 file 串而非解析后路径。
- **R1.9** [SRC] Node `shell:true`/`shell:cmd`：`command = [file,...args].join(' ')` **完全无转义** → `file=ComSpec||cmd.exe`、`args=['/d','/s','/c', '"'+command+'"']`、强制 verbatim——子进程看到的是 `cmd.exe /d /s /c "<原样拼接>"` 一个逐字 token。这就是注入面 + DEP0190 的来源。
- **R1.10** [SRC] `shell:<非cmd>`：同样拼接，args=`['-c', command]`——按 POSIX `-c` 对待。

### 1c. CVE-2024-27980 家族（Node EINVAL 边界）

- **R1.11** [DOC/SRC] Node ≥18.20.2/20.12.2/21.7.3/22.0.0：`file` 字面串以 `.bat`/`.cmd`（不分大小写）结尾且无 `shell` → **同步抛 `EINVAL`**（errno −4071）。豁免：`{shell}`；`--security-revert=CVE-2024-27980` 可回退。
- **R1.12** [SRC] 检查打在**输入 file 串的扩展名**上、解析前——`spawn('npm.cmd')` EINVAL、`spawn('npm')` ENOENT（libuv 表里没有 .cmd）、`spawn('foo.bat',{shell:true})` → `cmd /d /s /c "foo.bat …"`。
- **R1.13** [DOC] CVE-2024-36138（2024-07 跟进修复）：初版检查可被绕过——其他扩展（`.com` 装批文本、注册 handler 扩展）也被当批处理执行；后续扩大了"批文件"判定面。

### 1d. 三解析器细则（见设计公理 3 表格 + R0.3 / R1.14 / R1.16）

- **R1.14** [SRC] libuv `search_path`：file 含 `\/:` → 不搜 PATH 只按 CWD 相对解；裸名 → **CWD 优先**再 PATH 逐条；有扩展名 → 先试原名再 `.com`/`.exe`；无扩展名 → **只试 `.com`/`.exe`**。不查可执行性——第一个存在的文件赢，CreateProcess 失败不回表继续找。`UV_PROCESS_WINDOWS_FILE_PATH_EXACT_NAME` 在有目录成分时先按原名试。
- **R1.15** [推导] 推论：`spawn('npx')` 撞上 PATH 里的 bash shim `npx` → **ENOENT**（裸名根本不在 libuv 的尝试表里）；`spawn('npx.sh')` → 找到 → CreateProcess → 193（[EMP] Node 报 `EFTYPE`，selftest 实测）；`spawn('npx.cmd')` → EINVAL（R1.11）。
- **R1.16** [DOC] cmd `/c` 重解析：CWD 优先（NoCurrentDirectoryInExePath 可关）→ PATH；试裸名 + PATHEXT 全表（默认 `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC`）。**cmd 会找到无扩展名 bash shim——然后把它当批文本喂给 cmd**（语料库必测项：实际命运是逐行执行还是报错）。
- **R1.17** [DOC] CreateProcess 内建顺序里**父进程应用目录先于 CWD**——与 libuv/cmd 都不同序。
- **[UNC]** libuv `UV_PROCESS_WINDOWS_RESOLVE_BATCH`（PR #5096）若落地，libuv 表将含 `.bat/.cmd`——规则引擎要留"libuv 版本特征"维度。

## Layer 2 — cmd.exe 重解析

### 2a. `/c` `/s` 引号规则（cmd /? 明载）

- **R2.1** [DOC] `/c`/`/k` 后全部为一个命令串 S。**保留全部引号**当且仅当：无 `/S`；S 中恰好两个 `"`；两引号间无 `&<>()@^|`；其间有空白；引号内是可执行文件名——**五条全满足**。
- **R2.2** [DOC] 否则若 `S[0]=='"'`：剥掉**第一个** `"` 和**最后一个** `"`（无视配对），保留其余。`cmd /c "prog" a b` → `prog a b`。
- **R2.3** [DOC/EMP] `/s` 直接禁用保留分支——`cmd /s /c "<anything>"` = "剥一层外壳引号，原样跑"。Node 整体裹一层 `"…"` 正是利用这条。
- **R2.4** [DOC+Wine 实证] `cmd /c "say five"` 且 `say five.bat` 存在 → 条件5满足 → 保留引号 → `"say five"` 作文件名执行。**存在性检查发生在解析时**——解析结果依赖文件系统状态，预言器要把这层标为"环境相关判定"。

### 2b. cmd 元字符与展开

- **R2.5** [EMP] 引号内只有 `"` 和换行特殊——`& | < > ( ) ^` 失活；`^` 引号内是字面、引号外是转义符（`^&`→`&`）；`""` 出再入=零贡献；**无反斜杠转义、引号内无法转义闭引号**。
- **R2.6** [EMP] `%var%` 在 `/c` 行解析期展开——**引号内照样展开**（引号保护不了 `%`）；命令线上 `%%` 保持 `%%`（减半是批文件内规则）；`^%X^%` 可破展开（cross-spawn 依赖此技）。
- **R2.7** [DOC/EMP] `!var!` 仅延迟展开开启时生效：`/V:ON`、注册表 DelayedExpansion、批内 `setlocal enabledelayedexpansion`。默认关 → `!x!` 字面穿过。
- **R2.8** [EMP] `/c` 行 `%` 一次性整体展开；批内 `( )` 块在块解析期整体展开（经典坑）；行内 `\r\n` 是命令分隔符——**换行注入是真实的**（cross-spawn #179）。
- **R2.9** [DOC] `&` 恒顺序、`&&`/`||` 条件、`<` `>` `>>` 重定向——仅引号外生效；行首 `@` 压回显。

### 2c. 批处理参数语义（消费者侧，见 L4）

- **R2.10** [DOC/EMP] 批的 `%1..%9` 由 cmd 自家 tokenizer 产出——分隔符 `, ; = <空格> <TAB>`（含 VT/FF）；引号保留在 `%N` 里（`%~1` 剥）；`%*` = %0 后原始尾巴含原分隔符。`foo.bat a,b` → `%1=a %2=b`。
- **R2.11** [DOC+推导] CreateProcess→隐式 cmd（R0.4）+ R2.10 意味着批目标是**重解析而非 argv 重切**；叠加 R2.5"引号内无法转义闭引号"⇒ **存在无法安全序列化的 argv 向量——这正是 BatBadBut/CVE-2024-24576**。预言器的正确输出在这种情况是"**不可安全序列化**"判定，不是乱猜转义。

## Layer 3 — PowerShell 调用者（可选模式）

- **三种参数传递模式** [DOC]：
  | 模式 | 行为 | 何时 |
  |---|---|---|
  | Legacy | 空格连接；仅含空格才加 `"`；内嵌 `"` **原样射出不可转义**；空串参数被丢 | PS 5.1 恒；PS 7.x `Windows` 模式下命中 legacy 名单目标 |
  | Standard | 正规 MSVCRT 序列化（空格/TAB/`"`/空 触发引用，`"`→`\"`，`\` 串规则） | PS 7.3+ 非 Windows 默认 |
  | Windows（7.3+ Windows 默认） | = Standard，但 `cmd/cscript/wscript/*.bat/*.cmd/*.js/*.vbs/*.wsf` 自动降级 Legacy | `$PSNativeCommandArgumentPassing` 可控 |
- `--%` 停止解析符：其后近乎逐字传（`%var%` 仍环境展开）——5.1/7.x 都支持。
- `powershell -Command <line>`：外部引号过 CLR 一拆后**整行当 PS 源码二次解析**——第二个绞肉面；`-File` 无此问题。
- `&` 调用符只决定哪个 token 是程序，不影响 arg 序列化。

## Layer 4 — 目标侧 argv 解析器族

| 目标 | 解析器 | 判定 |
|---|---|---|
| MSVC C/C++、Node、Python3、.NET | post-2008 MSVCRT（含 `""` 规则） | **MSVCRT-standard** [DOC/SRC] |
| Rust `std::env::args` | 自写 post-2008 规则，**但 argv[0] 走 CLTAVW 怪癖**（`"a"b x`→argv0=`a`,argv1=`b`） | MSVCRT-standard + argv0 标注 [SRC] |
| Go `os.Args` | **自写方言**：`""` 出引号态且发字面 `"`（两边都不像）；无 argv0 特例 | **runtime-specific** [SRC 本地实证] |
| Java | `JLI_CmdToArgs` 用 **CP_ACP** 重解析 + `*`/`?` **glob 展开应用参数** | runtime-specific + 编码有损 + glob [DOC/SRC] |
| .bat/.cmd | cmd tokenizer（分隔符不同、引号保留、%* 原始） | **完全不同的语法** |
| .ps1 | hop1=CLR MSVCRT → hop2=PS binder（`-Command` 有二次解析） | hop1 standard |
| CommandLineToArgvW（shell32） | **pre-2008**——无 `""`→`"` 规则 | 与 MSVCRT 明确分歧点 |
| 未识别 binary | — | 默认 MSVCRT（~80% 命中率）+ **置信度标签**，不打包票 |

**分歧示例**（同一串 `"a""b c"`）：MSVCRT→`a"b c` 一个参数；CLTAVW→`ab c`；**Go→两个参数 `a"b`+`c`**；批 `%1` 原样带引号。

---

## 语料库种子（实测校准项）

**可移植富矿**（许可全部兼容）：
- CPython `test_list2cmdline`（PSF）——高密度引号向量
- nodejs/node `test-child-process-spawn-windows-batch-file.js`（MIT）——CVE-2024-27980 回归用例
- cross-spawn 测试件（MIT）——`pre_()%!^&;,.bat`、`%CD%.bat`、shim 双转义
- Rust std `sys/args/windows.rs` 内嵌用例（MIT/Apache）——`%cd:~,%` 系
- Wine `programs/cmd/tests`（LGPL——**只读参考不抄**）

**没人写过、必须自测的**（[UNC] 清单）：隐式 bat 执行时 CreateProcess 重组的 cmd 线、`/c` 引号剥离的"可执行文件存在性"探测细节、扩展名非 PE 的 Node 错误码映射、cmd 对 bash shim 的实际处置、空 PATH 行为（libuv #4115）。

## 先验文献（docs 引用清单）

Colascione 2011《Everyone quotes command line arguments the wrong way》、Deley《How Command Line Parameters Are Parsed》（CRT 反汇编级实证）、MS CreateProcessW/CLTAVW/Parsing C++ 文档、SO #4094699 jeb/dbenham 批解析相位模型、RyotaK BatBadBut、CVE-2024-24576/27980/36138/43402、Wellons 2022、Graham Knop 2011、jdebp FGA、msys2-runtime #36。

## 实现选型（生态调研结论）

| 部件 | 选型 |
|---|---|
| PATHEXT 解析 | `pathsearch`（注入式 PATH/PATHEXT，迭代候选——天然适配"解释谁赢了"） |
| MSVCRT 序列化 | vendor Rust std `append_arg`/`append_bat_arg`（或 `privesc` 现成 vendored 版） |
| CLTAW 对照 | `windows-sys` CommandLineToArgvW（Windows 上做 ground truth 校验）+ `winsplit`（纯 Rust 跨平台模拟） |
| cmd 解析器 | **自研**（无现成 crate——按 jeb/dbenham 相位模型实现，本项目核心原创件） |
| PE magic | 手写 30 行（MZ + e_lfanew + PE\0\0） |
| 语料库 | `serde`+`serde_norway`/`serde_yml`（`serde_yaml` 已归档） |
| CLI | `clap` + `miette`/`annotate-snippets`（错误报告按"层"标注——天然贴合产品形态） |
| 分发 | `cargo-dist` 全家桶：crates.io + GitHub Releases + cargo-binstall + scoop/winget |

## 命名裁决

**`spawnfate`**——三平台全空（crates.io/npm/GitHub），语义直白。
备选 `argvfate`、`cmdfate`。`cmdxray` 已被 POSIX 命令解释器占用——避。
