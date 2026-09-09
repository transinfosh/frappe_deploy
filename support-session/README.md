# 临时远程支持会话

`support-session` 用于客户服务器无法被公司网络直接访问时，建立短时、可审计边界清晰的
SSH 反向隧道。客户只需执行一条由公司 CLI 生成的命令，无需另外输入会话码，后续操作由
公司运维人员通过堡垒机完成。

该模块独立于 `single-node` 和 `multi-node`，不会接管或修改现有 FRP 服务。FRP 与本模块可以
在同一堡垒机共存；两者不共用端口、Token、用户或配置文件。

## 安全边界

- 客户入口通过 Caddy HTTPS 提供 15 分钟随机地址，enrollment 仍由专用 SSH
  用户的每会话强制命令完成；
- 下载链接包含 256-bit 随机凭据，默认 15 分钟失效；拿到完整链接即可领取，必须通过安全渠道交付；
- 每个会话使用独立的 enrollment key、隧道 Unix 用户、隧道 key、operator key 和回环端口；
- 反向端口固定为堡垒机的 `127.0.0.1:<port>`，不会暴露到公网；
- 客户和堡垒机的 SSH Host Key 均严格固定，禁止首次连接自动信任；
- Linux 客户端创建临时免密 root 运维用户；Windows 客户端创建临时本地管理员；默认从接入起闲置两小时后自动删除，实际输入会自动续期；
- 关闭或过期时，堡垒机会终止隧道连接、删除隧道用户和私钥，客户机会删除临时用户、
  sudoers、密钥、systemd unit 与本地会话配置。

这是一条临时的完整 root 运维通道。创建会话前应获得客户授权，并在工单中记录客户、用途、
创建人和会话 ID。不要把接入链接公开传播，也不要把私钥或 enrollment 响应写入聊天记录或普通日志。

## 前置条件

堡垒机需要 Ubuntu、OpenSSH Server、Python 3 和 systemd。另需准备：

1. 一个解析到堡垒机的长期独立域名，例如 `bastion-support.example.com`；
2. 客户网络能够访问该域名的 HTTPS 和 SSH 端口；
3. 公司电脑到堡垒机的密钥 SSH 登录。安装器会为该用户配置仅能管理支持会话的限定 sudo。

堡垒机需已安装 Caddy。安装器会为独立域名增加受管的 `/tsuite-support/`
静态下载路由，不改动现有 FRP 配置。以后切换堡垒机 IP 时只需更新 DNS；若服务器
SSH Host Key 也改变，新会话脚本会固定新的 Host Key。

## 安装堡垒机模块

从固定版本检出仓库后执行：

```bash
cd support-session/bastion
sudo ./install.sh \
  --bastion-host bastion-support.example.com \
  --operator-user tunnel-user
```

安装器会先校验 sshd 的语法和 `tsuite-enroll` 用户的有效策略，再 reload SSH，并安装过期回收
timer。它不会开放 22000–22999 到公网，这些端口只能通过堡垒机本机回环地址访问；现有 FRP、
FRP 和 FRP Token 均不会被修改或复用。Caddy 只会增加一个独立的受管 import，并在校验或
reload 失败时自动恢复旧配置。

## GitHub 支持管理页面

支持页面是可选模块，使用 GitHub OAuth 登录并限制到指定 GitHub 组织（默认
`transinfosh`），可选择进一步限制到某个团队。页面只提供创建、查看和关闭会话；服务账户通过
固定参数的受限桥接程序调用会话管理器，不能执行任意 Shell 或 SSH 命令。

先在 GitHub 中创建一个 OAuth App：Homepage URL 为 `https://edge.trinfo.net/support/`，
Authorization callback URL 为 `https://edge.trinfo.net/support/auth/github/callback`。应用需要
请求 `read:org` scope。Client Secret 只在部署控制机安装时通过隐藏输入或 root-only 文件提供，绝不
提交到仓库、粘贴到聊天或放入命令行参数。

生产环境中页面安装在内网部署控制机，堡垒机只安装 forced-command 桥接程序。控制机通过固定
Host Key 和专用 bridge key 调用堡垒机，bridge key 不能获得普通 Shell。具体安装方式见
[control-node](../control-node/README.md)。堡垒机同机页面已经停用，避免 Web 进程与会话私钥处于
同一权限边界。浏览器中创建会话后，页面仅显示一次客户执行命令；完整命令包含接入凭据，应通过安全渠道发送给客户。该页面不替代客户发起的出站连接，也不提供
浏览器终端；客户仍只需执行页面给出的那一条命令。

页面的支持用途可选；填写后保留在会话详情中。已认证 GitHub 登录名仍作为创建人写入堡垒机会话。控制机专用 broker 会为
每个会话生成独立 operator key；Web 服务既不能读取私钥，也没有 ssh/run/force-close 权限。页面关闭
已接入会话时，broker 必须先通过客户通道确认本地清理已调度，之后才撤销堡垒机连接。

升级说明：会话管理器的 `create` 仍强制要求 `--created-by`，`--purpose` 可省略，缺省保存为空字符串。
页面、bridge、broker 和 CLI 的用途校验同步放宽，填写时仍限制为最多 200 个可见字符；关闭原因仍必填。
首页只展示尚未结束的会话及对应客户环境，统计也只计这些会话；已关闭/已过期记录保留供详情及后台审计查询。

## 安装公司端 CLI

```bash
cd support-session/operator
sudo ./install.sh
tsuite-support configure --bastion company-bastion
```

`company-bastion` 建议配置在公司电脑的 `~/.ssh/config` 中，并固定堡垒机 Host Key。公司端
生成的会话私钥只保存在 `~/.config/tsuite-support/sessions/`，关闭会话时删除。

## 日常流程

公司运维创建会话：

```bash
tsuite-support create customer-code --purpose "升级 SRM"
```

命令输出一条 `curl ... | sudo bash` 客户执行语句（Windows 为管理员 PowerShell 命令），无需另输会话码。
URL 使用 256-bit 随机标识，下载文件禁止缓存，并在登记、关闭或最迟 15 分钟到期时回收。
脚本内的 enrollment key 仅限本次会话的强制登记命令，并固定堡垒机 Host Key。登记后不能换绑
客户 Host Key；原 nonce 与 Host Key 可在领取期限内幂等重取响应，不能用下载脚本开启第二个会话。
新会话的 `token` 创建结果字段暂为旧调用方保留，但不再用于认证或向客户展示。

如果客户机仍保留上一次会话的本地配置，bootstrap 会使用本次新会话的专用登记密钥向堡垒机核对旧
会话状态。只有旧会话在堡垒机上已经是 `closed` 或 `expired` 时，才会自动运行旧客户端的本机
清理并继续建立新会话；`issued`、`enrolled` 或 `revoking` 会话一律拒绝覆盖。核对动作不会消费
新会话，因此本机清理失败后仍可在领取有效期内重试。旧会话状态不存在或本机配置不完整时，
系统也不会猜测性删除 root 运维凭据，需先人工核查。

客户完成 enrollment 后，公司端可执行：

```bash
tsuite-support status SESSION_ID
tsuite-support ssh SESSION_ID
tsuite-support run SESSION_ID -- sudo tsuite-deploy
```

完成工作后立即关闭，不必等待自动过期：

```bash
tsuite-support close SESSION_ID --closed-by alice
```

关闭命令只有在客户机确认清理任务已经调度后，才撤销堡垒机通道并删除公司本地 key；当前 SSH
连接随后中断属于预期行为。客户不可达时可用 `--force` 只撤销堡垒机端，但命令会明确警告客户
残留尚未确认，双方的原生 key 过期时间和 timer/GC 仍会兜底。强制关闭必须同时提供原因，例如：

```bash
tsuite-support close SESSION_ID --force --closed-by alice \
  --reason "客户服务器已离线；工单记录了待到期回收的本地残留"
```

堡垒机会持久记录关闭人、正常/强制/到期关闭方式和关闭原因。堡垒机可用
`sudo tsuite-support-session list` 核对是否仍有活动会话。

## 活动续期与兼容

新会话使用 `schema_version=2`，增加 `auth_mode=enrollment-key`、`idle_timeout_seconds`、
`last_activity_at` 和客户专用 `lease_private_key`。续期私钥不会出现在 show/list、页面或运维凭据中。
`expires_at` 表示当前确认的截止时间：未接入时是领取期限，登记后是闲置期限，默认为两小时。
`--session-ttl` 配置闲置窗口（300–28800 秒），不是会话总时长；`--token-ttl` 保留参数名，配置领取期限。

- 客户监控每 15 秒通过独立、绑定会话的 SSH key 请求租约。只有新的实际输入才把期限延长至当前时间加闲置窗口。
- CLI/broker 只上报终端/标准输入字节；发起一次 `run` 命令也算一次输入。输入会合并上报，正常网络下截止时间有约 30 秒内的采样延迟。
- 输出、错误输出、任务仍在运行、隧道保活、重连、页面刷新、show/list、停在提示符均不续期。
- 输入标记有效期最多 45 秒，同一标记只处理一次；运维端断开后不会依靠残留标记永久续期。
- 长任务若在最后一次输入之后持续超过闲置窗口，仍会到期，即使它一直输出日志。需要提前为此类任务配置更长的闲置窗口，或在期限内继续实际输入。
- 关闭、过期与续期共享互斥锁，关闭后不可复活。网络故障时不自行延长，按最后确认的截止时间清理。
- 堡垒机隧道与续期 key、Linux 运维 key、Windows 账号与 key 随租约同步。客户定时清理读取最新期限，后台任务不再有固定两小时/九小时运行限制。

升级需同步安装堡垒机管理器与受限 sudo 配置、Linux/Windows 客户脚本、控制机 broker/页面和公司 CLI，
新增的 `linux-client.py`、`tsuite_support_activity.py` 必须随安装器一起交付。已接入的旧会话仍按原固定期限关闭，
不会远程改写旧客户资源；需要动态续期时关闭后重新创建。旧 `schema_version=1` 的状态与 Linux 码验证路径保留。
不能只覆盖 manager 文件而遗漏 sudoers：登记/续期 forced-command 需要受限 root 入口更新原生密钥期限。

验收场景：免码接入及防换绑、领取期限长于闲置窗口、活动跨越旧截止时间、长任务/持续输出无输入不续期、
闲置提示符回收、仅保活不续期、网络断开后的截止清理、关闭与续期竞争、过期不复活、重启清理、旧会话兼容。

## 首次客户实测顺序

首次接入客户生产环境时，先只读检查时间、系统、Docker、Compose、站点 volume、部署状态与
PostgreSQL 版本。确认备份能够由与服务端同主版本的 `pg_dump` 完成后，再执行升级。删除旧
Compose 容器和旧 volume 必须放在新部署健康检查、站点登录与后台任务验证之后。

## Windows Server 接入

创建会话时选择 **Windows Server**，然后在客户机上以管理员身份打开 **64 位 Windows PowerShell
5.1**，执行页面的一次性命令，无需另输会话码。公司 CLI 同样支持：

```bash
tsuite-support create zj-mes --platform windows --purpose "Windows Server 维护"
```

前置条件：Windows Server 2019 或更新版本（成员服务器/独立服务器，域控制器不支持本地账号），
已安装 Win32 OpenSSH Client 和 Server，包含 `ssh.exe`、`sshd.exe`、`ssh-keygen.exe`，
可用的 LocalAccounts、ScheduledTasks 模块及出站 HTTPS/堡垒机 SSH 访问。应使用维护中的 Win32
OpenSSH 版本；当前目标客户环境为 10.0p2。安装脚本从 `sshd` 服务路径定位同一套二进制，不依赖 PATH。
接入前检查本机 SSH 登录与系统时钟。

Windows 会话的行为与边界：

- 临时账号名称沿用 `tsuite-ops-<会话ID前8位>`，使用不保存的随机密码，加入本地 Administrators。
  客户执行接入命令即授权该会话的临时管理员访问，权限范围与 Linux 临时 root 相当。
- 每会话目录为 `%ProgramData%\TSuiteSupport\<完整会话ID>`，仅 SYSTEM 和 Administrators 可访问。
  会话登记私钥只写入临时受限目录，结束引导时删除；登记私钥不进入命令参数，独立续期私钥仅保存在本机受限目录。
- SYSTEM 计划任务运行独立 `sshd -D`，只监听 `127.0.0.1` 上的临时端口，只允许本会话账号及公钥。
  反向隧道指向该端口。不会修改现有 `sshd_config`、管理员共享公钥文件、默认 Shell 或公网防火墙。
  会话使用独立 Host Key，并通过原有登记协议固定到运维端。
- Sshd/Tunnel 任务在启动后和机器重启后运行，连接失败每 5 秒重试，过期后不重连。
  Cleanup 任务从初始期限起每分钟复查最新到期时间，并在重启时补做过期清理。账号与公钥同时设置并更新原生过期时间。
- 普通关闭先请求 Windows SYSTEM 清理任务，收到确认后再撤销堡垒机。清理会禁用账号、停止任务、
  终止该账号的进程、删除临时用户及配置。强制关闭仍只代表堡垒机撤销；离线客户将在启动后清理。
- 不覆盖同名账号、会话目录或计划任务。安装失败会尝试回滚；已登记但安装失败的会话需关闭后重新创建。
  不同完整会话 ID 的资源独立；不要通过复制旧目录复用会话。

交互 SSH 沿用客户现有默认 Shell；CLI/broker 的 `run` 在 Windows 上通过 PowerShell 编码执行，
参数作为字面值传递（包含空格、引号、中文时同样有效）。需要管道等 Shell 语法时显式使用
`powershell.exe -Command '...'`，例如：

```bash
tsuite-support run SESSION_ID -- powershell.exe -NoProfile -Command 'Get-Service sshd'
```

本机手工关闭（管理员 PowerShell，替换 SESSION_ID）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramData\TSuiteSupport\SESSION_ID\client.ps1" -Mode Close -SessionId SESSION_ID
```

### 升级兼容与验证

会话协议增加 `platform`（`linux` / `windows`），缺省为 Linux，旧会话无需迁移。原有 JSON 字段、
回环端口和 Linux 命令保持兼容。需一起更新堡垒机管理器/bridge、控制机 broker/页面及使用中的公司 CLI；
堡垒机安装器会将 `bootstrap.ps1` 和 `windows-client.ps1` 安装到 Linux bootstrap 的同目录。
更新程序不等于已部署，正在运行的支持页面只有更新服务端后才会出现 Windows 选项。

验证命令：

```bash
python3 -m unittest discover -s support-session/tests -p 'test_*.py'
pwsh -NoProfile -File support-session/tests/test_windows_client.ps1
pwsh -NoProfile -File support-session/tests/test_windows_lease.ps1
```

PowerShell 测试使用隔离替身验证任务和清理行为，不创建真实账号或服务。正式使用前还需在可丢弃的
Windows Server 上验证真实会话：领取、SSH 公钥登录、带空格/中文参数执行、网络恢复、普通关闭、
离线跨过期后重启清理，以及已有 SAP1 登录仍正常。Linux 上的语法/单元测试不能代替 Windows 系统集成验证。

Windows API 依据：[计划任务](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset)、
[本地账号](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser)、
[Win32 OpenSSH SYSTEM 运行要求](https://github.com/PowerShell/Win32-OpenSSH/wiki/Troubleshooting-Steps)。

### Windows 启动错误诊断

临时监听未启动时，接入脚本会在回滚前输出计划任务状态及原始启动错误，并把诊断保存在
`%ProgramData%\TSuiteSupport\diagnostics\<会话ID>-startup.log`。诊断目录仅允许 SYSTEM 和
Administrators 访问；只收集任务状态及 SSH/任务启动错误，不复制会话配置、会话码或私钥。
临时账号、密钥和任务仍正常回滚，诊断文件保留供管理员排查，排查完成后可删除。

```powershell
Get-Content "$env:ProgramData\TSuiteSupport\diagnostics\*-startup.log"
```

主机私钥由管理员交互进程生成时可能保留个人 SID，SYSTEM 后台 `sshd` 会以
`bad permissions` / `UNPROTECTED PRIVATE KEY FILE` 拒绝它。客户端在启动任务前为主机私钥、
隧道私钥、公钥授权文件和独立 sshd 配置重建文件 ACL：所有者为 Administrators，关闭继承，
仅保留 SYSTEM 与 Administrators 的完全控制。不会修改 SAP1 或系统原有 SSH 服务的文件。
原生权限回归测试：`powershell.exe -NoProfile -File support-session/tests/test_windows_permissions.ps1`
（管理员 Windows 终端；Linux 会明确跳过此项）。
