# TSuite AI Agent 部署运行手册

本文是 AI Agent 执行 TSuite 发布、远程支持和客户部署时的统一入口。开始操作前必须完整阅读本文，
再按链接读取目标模块的专项说明。本文记录稳定拓扑、操作顺序、状态判断和安全边界，不保存任何密钥。

以后用户只需给出类似指令：

```text
按照 TSuite AI Agent 部署运行手册，把 srm 的 <提交或版本> 发布并部署到 dtaut-srm-prod-01。
```

Agent 应自行完成状态盘点、版本包含关系验证、构建跟踪、客户升级、migrate、健康检查、记录和会话关闭；
只有缺少客户授权、目标环境或发布版本等会实质改变结果的信息时，才向用户确认。

## 1. 任务完成标准

发布或部署任务必须形成完整闭环：

1. 确认目标环境、站点、当前镜像、数据库模式和期望版本；
2. 确认待发布代码已经提交并推送，目标 Tag 确实包含该提交；
3. 确认共享组件使用最新的已发布不可变 Tag，不能使用分支、裸 SHA 或 `latest`；
4. GitHub Actions 构建和推送镜像成功，并记录源码 commit、镜像 Tag 和 digest；
5. 客户端升级前备份成功，且备份可从服务器之外恢复；
6. 目标镜像已经在客户服务器实际运行，必要的 `bench migrate` 已成功执行；
7. HTTP、容器、队列、调度器和关键业务功能验证通过；
8. 记录部署结果并关闭临时支持会话。

只完成构建、只修改 inventory、只执行 `docker pull` 或只看到容器处于 running，都不能宣布部署完成。

## 2. 当前生产拓扑与事实来源

| 角色 | 当前地址或入口 | 主要职责 | 事实来源 |
| --- | --- | --- | --- |
| GitHub | `transinfosh/*` | 源码、不可变 Tag、Actions、GHCR | 远端仓库与 Actions 运行记录 |
| 部署控制机 | `adam@192.168.2.52` | 部署仓库、Ansible、发布文件、支持页面、FRPC | `/srv/tsuite-deploy`、`/etc/frp`、`/etc/tsuite-support-control` |
| 公网 edge | `edge.trinfo.net` | Caddy、FRPS、SSH enrollment 和反向隧道 | `/etc/caddy`、`/etc/frp`、`/etc/tsuite-support` |
| 支持管理页 | `https://edge.trinfo.net/support/` | GitHub SSO、创建/查看/关闭支持会话 | 控制机 `tsuite-support-console.service` |
| 客户单机部署 | 临时支持隧道内访问 | Frappe、Redis、队列、调度器及站点 | `/opt/tsuite-deploy/deployment.state` 和 Docker 实际状态 |

部署控制机是唯一日常部署工作台。开发机可修改和推送代码，但不应作为长期发布制品、Vault、客户文件
或运维私钥的唯一保存位置。公网 edge 只做入口和中转，不保存业务仓库、Ansible inventory 或客户部署制品。

控制机关键目录：

```text
/srv/tsuite-deploy/repositories/   部署仓库
/srv/tsuite-deploy/files/          客户下载文件
/srv/tsuite-deploy/logs/           部署日志
/srv/tsuite-deploy/backups/        控制面配置备份
/etc/frp/frpc.toml                 FRPC 配置和 Token（受限权限）
/etc/tsuite-support-console/       GitHub OAuth 配置
/etc/tsuite-support-control/       固定 Host Key 与 broker 通道配置
```

控制机支持通道由专用 `tsuite-support-operator` broker 管理：

```text
/etc/tsuite-support-control/bridge_ed25519         调用 edge forced-command 的固定 key
/etc/tsuite-support-control/edge_operator_ed25519  edge forced session proxy key（不能登录 Shell）
/var/lib/tsuite-support-operator/sessions/          每会话独立 customer operator key
```

Web 服务不能读取以上私钥。`adam` 也不直接读取私钥，只能通过最小 sudo 调用 broker 的受限动作。
固定私钥必须归 `tsuite-support-operator` 所有且权限为 `0600`；不能使用组可读的 `0640`，否则
OpenSSH 会因私钥权限过宽而拒绝加载。

客户单机关键目录：

```text
/opt/tsuite-deploy/.env
/opt/tsuite-deploy/deployment.inputs
/opt/tsuite-deploy/deployment.state
/opt/tsuite-deploy/compose.generated.yaml
/opt/tsuite-deploy/rollback/
```

## 3. 不可违反的边界

- 不在 Git、聊天、命令参数或普通日志中写入 OAuth Secret、FRP Token、GHCR Token、Vault 密码、
  数据库密码或 SSH 私钥；只记录受限文件路径。
- 不把开发机私钥复制到控制机。控制机必须使用独立 identity，公钥按最小权限授权。
- 不移动或覆盖已经发布的 Git Tag，不覆盖已经部署过的镜像 Tag；修复后递增版本重新发布。
- 构建使用的 `tsuite-base`、`tai-chat`、`transinfo-ui` 等共享组件必须是远端已存在、版本匹配的
  不可变 Tag。所谓“最新”是最新正式 Tag，不是 `main`、`latest` 或本地工作区内容。
- 不把“旧 Compose 接管”当成日常升级。已有 `/opt/tsuite-deploy/deployment.state` 且当前容器使用
  TSuite 目标 sites volume 时，应走升级流程。
- 不因 Docker network 地址冲突直接删除正在运行的网络、容器或 volume。先识别占用者，再选择未占用
  子网或停止已确认废弃的旧项目。
- 不自动恢复升级前数据库。Frappe schema 迁移未必向后兼容，回退镜像前必须评估数据库兼容性。
- 不删除旧容器、旧 volume 或备份，直到新部署登录、后台任务和关键业务验证全部通过。
- 临时支持会话提供完整 root 权限，必须获得客户授权；完成后立即关闭，不等待自动过期。

## 4. Agent 开始任务时的固定检查

先确认工作目录和仓库规则：

```bash
cd /srv/tsuite-deploy/repositories/tsuite_deploy
sed -n '1,220p' AGENTS.md
git status --short
git remote -v
git fetch --tags origin
```

存在无关未提交修改时必须保留，不得 reset、checkout 或覆盖。需要更新仓库时，先说明冲突文件并采用
不会破坏现场修改的方式处理。

检查控制面：

```bash
systemctl is-active nginx tsuite-frpc tsuite-support-console tsuite-github-egress
curl -fsS http://127.0.0.1:8081/_tsuite-control-health
curl -sS -o /dev/null -w '%{http_code}\n' https://edge.trinfo.net/_tsuite-control-health
curl -sS -o /dev/null -w '%{http_code}\n' https://edge.trinfo.net/support/
```

预期公网健康检查为 `200`，未登录支持页面通常为 `401` 或进入 GitHub 登录流程。若服务异常，先读取：

```bash
journalctl -u tsuite-frpc -u tsuite-support-console -u tsuite-github-egress -n 200 --no-pager
```

不得在未诊断原因前反复重装服务。

## 5. 判断任务类型

### 5.1 新安装

客户服务器没有目标站点、没有需保留的 sites volume，也没有有效的 TSuite 部署状态。使用
`single-node` 新安装流程。

### 5.2 已有 TSuite 部署升级

`/opt/tsuite-deploy/deployment.state` 存在，当前站点和目标 sites volume 已由生成的 Compose 使用。
重新运行 `sudo tsuite-deploy`，输入新镜像 Tag。脚本会备份、拉取镜像、重建容器、安装缺失应用、
执行 `bench migrate` 和健康检查。

### 5.3 旧 Compose 首次接管

站点仍由另一份 Compose 和旧 sites volume 运行，且尚未成功纳入 `/opt/tsuite-deploy`。只有此场景才使用
`--adopt-existing-site`。接管成功后，后续一律按“已有 TSuite 部署升级”处理。

### 5.4 多节点 Ansible 部署

目标属于 Control、Runtime、Customer、Database 或 Relay inventory 时，使用 `multi-node/ansible`，
不得混用单机交互脚本。先阅读 [多节点部署说明](../multi-node/README.md)。

## 6. 发布镜像

### 6.1 发布前证明目标提交已推送

在业务仓库执行：

```bash
git status --short
git fetch origin --tags
git rev-parse HEAD
git rev-parse origin/<目标分支>
git log -1 --oneline
```

工作区必须没有遗漏的目标改动，远端目标分支必须包含待发布提交。创建 Tag 后再次证明：

```bash
git merge-base --is-ancestor <必须包含的提交> <发布Tag>^{commit}
git ls-remote --exit-code --tags origin refs/tags/<发布Tag>
```

第一条命令返回 `0` 才表示 Tag 包含目标提交。

### 6.2 共享组件版本

检查业务镜像的发布工作流或构建参数，确认 `tsuite-base` 及其他共享组件：

1. 使用 `v<version>` 不可变 Tag；
2. Tag 与组件自身版本一致；
3. 远端 Tag 已存在；
4. 选择的是最新正式版本；若最新版本不兼容，必须记录固定旧版本的理由。

不要仅凭本地缓存或镜像列表判断“最新”。

### 6.3 触发并跟踪构建

业务 Frappe 聚合镜像由业务仓库的发布 Tag 触发；本仓库的 `build-images.yml` 只构建其声明支持的
独立 Python 服务。使用 GitHub CLI 时必须指定仓库并持续跟踪：

```bash
gh workflow list --repo transinfosh/<repo>
gh run list --repo transinfosh/<repo> --limit 10
gh run watch --repo transinfosh/<repo> <run-id> --exit-status
```

完成后记录 Actions 摘要中的源码 commit、版本和镜像 digest，并验证 GHCR manifest 可读取。构建失败时
修复根因并发布新 Tag，不复用失败或已发布的 Tag。

## 7. 创建客户临时支持会话

1. 运维人员打开 `https://edge.trinfo.net/support/`，使用获准的 GitHub 组织账号登录；
2. 使用固定、可复用的客户环境标识，例如 `dtaut-srm-prod-01`；同一机器不要每次换名字；
3. 点击“创建会话”；页面只显示一次客户执行命令；完整链接就是接入凭据；
4. 命令通过安全渠道交给客户；领取链接默认 15 分钟有效；
5. 客户执行一条 `curl ... | sudo bash` 命令，无需另输会话码；
6. 页面状态变为“已连接”后，记录完整 12 位会话 ID。

页面不持久保存原始客户命令，这是安全设计，不是数据丢失。需要重发时关闭旧会话并
创建新会话，不尝试从日志恢复 Token。

客户机可能因断网、强制关闭或旧版清理失败而残留 `/etc/tsuite-support-client`。新版 bootstrap 会
使用新会话的专用登记密钥向 edge 核对残留配置中的完整旧会话 ID：只有 edge 已将旧会话标记为
`closed` 或 `expired` 时才自动清理本机残留并继续；任何活动状态、缺失状态或无效本机配置都拒绝
覆盖。不要为绕过检查而直接删除临时用户、sudoers 或会话目录，应先查清 edge 与客户机两侧状态。

在控制机查看会话状态的受限命令为：

```bash
sudo -n -u tsuite-support-operator \
  /usr/local/bin/tsuite-support-console-action list
sudo -n -u tsuite-support-operator \
  /usr/local/bin/tsuite-support-console-action show <SESSION_ID>
```

开始部署前必须确认状态为 `enrolled`、`tunnel_reachable` 为 true，且未超过当前 `expires_at`。
新会话从接入起按闲置窗口自动续期，仅实际标准输入和发起 `run` 的那一次命令输入计为活动；
任务运行、输出、页面刷新与隧道保活均不续期。长任务无输入超过闲置窗口仍会到期。`expires_at` 会变化，不能按创建时缓存的期限删 key。新逻辑只作用于升级后重新创建的会话。

### 控制机到客户的 SSH 前置条件

控制机的 `tsuite-support-operator` broker 独占 bridge、edge forced proxy 和每会话客户私钥；Web
服务与日常账号均不能直接读取这些文件。broker 固定 edge 与客户 Host Key，并根据完整 12 位会话 ID
选择对应的独立客户 identity。禁止绕过 broker 读取密钥、手工拼接 SSH，或使用
`StrictHostKeyChecking=no`。

页面显示会话已连接后，先读取状态；只有 `status=enrolled` 且 `tunnel_reachable=true` 才能连接：

```bash
SESSION_ID=<SESSION_ID>
sudo -n -u tsuite-support-operator \
  /usr/local/bin/tsuite-support-console-action show "$SESSION_ID"
sudo -n -u tsuite-support-operator \
  /usr/local/bin/tsuite-support-console-action ssh "$SESSION_ID"
```

执行单条远端命令使用 broker 的 `run`，不要把密码或 Token 拼入命令行：

```bash
sudo -n -u tsuite-support-operator \
  /usr/local/bin/tsuite-support-console-action run "$SESSION_ID" -- sudo tsuite-deploy
```

## 8. 客户单机升级标准流程

### 8.1 只读盘点

进入客户服务器后先执行并保存非敏感结果：

```bash
hostnamectl
timedatectl status
docker version
docker compose version
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker network ls
sudo grep -E '^STATE_(SITE_NAME|IMAGE|APPS|DB_MODE|DOCKER_SUBNET|ADOPT_)' \
  /opt/tsuite-deploy/deployment.state
sudo docker compose --project-directory /opt/tsuite-deploy \
  -f /opt/tsuite-deploy/compose.generated.yaml ps
```

对数据库只记录模式、主机、端口和版本，不输出密码。若 PostgreSQL 安装在宿主机，明确记录服务端主版本；
镜像中的 `pg_dump` 版本较低时，当前单机脚本会使用匹配主版本的临时 PostgreSQL 客户端备份。

同时检查网络是否重叠：

```bash
docker network inspect $(docker network ls -q) \
  --format '{{.Name}}: {{range .IPAM.Config}}{{.Subnet}} {{end}}'
ip -4 route show
```

### 8.2 备份与部署工具

先确认站点文件、数据库备份目录和异地复制目标空间足够。自动备份留在 sites volume 内，不等于异地备份。
至少将本次升级备份复制到控制机 `/srv/tsuite-deploy/backups/<客户>/<UTC时间>/`，记录 SHA-256。

更新部署工具不会自动升级应用：

```bash
curl -fsSL https://raw.githubusercontent.com/transinfosh/tsuite_deploy/main/install.sh | sudo bash
sudo tsuite-deploy --dry-run
sudo tsuite-deploy
```

正式生产宜通过 `TSUITE_DEPLOY_REF=<不可变Tag或commit>` 固定部署工具版本。交互时沿用现有站点、数据库模式、
密码和网络，只有应用镜像输入新的已验证 Tag。不得因本次是“升级”而重新执行接管。

### 8.3 迁移和验证

`tsuite-deploy` 对已有站点会自动执行 `bench migrate`。仍需从日志确认 migrate 成功，而不是只看脚本退出码：

```bash
cd /opt/tsuite-deploy
sudo docker compose -f compose.generated.yaml ps
sudo docker compose -f compose.generated.yaml logs --tail=200 backend scheduler queue-short queue-long
sudo docker compose -f compose.generated.yaml exec -T backend \
  bench --site <SITE_NAME> list-apps
```

然后验证：

- 运行镜像 Tag/digest 与发布记录一致；
- 站点首页和登录正常；
- Redis、WebSocket、scheduler、short/long queue 正常；
- 目标 app 已安装，schema 和 patch 已迁移；
- 本次变更涉及的关键业务流程可用；
- 无持续增长的 traceback、重启循环或失败 job。

## 9. 失败处理与回退

升级失败时先保存现场日志，不要立即清理。`/opt/tsuite-deploy/rollback/<UTC时间>/` 保存配置快照，脚本
会输出恢复 `.env`、Compose、deployment state 和 `frappe_docker` commit 的命令。

处理顺序：

1. 判断失败发生在备份、拉取、网络创建、容器启动、migrate 还是健康检查；
2. 若数据库尚未迁移，可恢复旧配置和旧镜像后验证；
3. 若 migrate 已修改数据库，先评估 patch 可逆性；未经确认不要只回退镜像；
4. 需要恢复数据库时，使用已校验的站点备份，并记录恢复时间点和 SHA-256；
5. 恢复后重新验证站点、队列、调度器和业务功能。

网络重叠错误 `Pool overlaps with other one on this address space` 不是 PostgreSQL 升级问题。读取现有 Docker
网络、路由和 `STATE_DOCKER_SUBNET` 后，选择不冲突子网；只有确认旧项目已经完全接管且无需保留时，才停止
并删除旧 Compose 资源。

## 10. 结束会话与交付记录

部署验证完成后，在支持管理页点击红色“关闭会话”并确认。普通关闭会先通过客户通道确认清理任务已经
调度，之后才撤销堡垒机连接并删除控制机的会话私钥；若撤销失败，控制机会持久化清理确认并可在客户
隧道消失后继续重试。普通“关闭”按钮
只返回列表。只有运维人员记录客户侧残留风险后，才可在控制机执行带 `--closed-by` 与 `--reason` 的
`force-close`；强制关闭不代表客户清理完成，仍需依赖客户 expiry timer 并跟踪残留。edge 历史必须
保留关闭人、关闭方式与关闭原因。

每次交付至少记录：

```text
客户环境标识：
站点：
会话 ID：
部署前镜像：
部署后镜像：
业务源码 commit：
镜像 digest：
tsuite_deploy commit/ref：
数据库模式与版本：
备份位置与 SHA-256：
migrate 结果：
健康检查结果：
回退点：
执行人和完成时间：
```

记录中不得包含一次性会话码、密码、Token 或私钥。

## 11. 多节点最小命令链

多节点部署必须使用对应 inventory 和加密 Vault：

```bash
cd /srv/tsuite-deploy/repositories/tsuite_deploy/multi-node/ansible
ansible-playbook -i inventories/<inventory>/hosts.yml playbooks/preflight.yml \
  --vault-password-file <受限Vault密码文件>
ansible-playbook -i inventories/<inventory>/hosts.yml playbooks/deploy-all.yml \
  --vault-password-file <受限Vault密码文件>
ansible-playbook -i inventories/<inventory>/hosts.yml playbooks/verify.yml \
  --vault-password-file <受限Vault密码文件>
```

实际 inventory 和加密 Vault 保存在控制机，不从聊天重建。修改 inventory 前先备份加密文件，验证时避免
任何 `--diff` 或高 verbosity 输出 Secret。正式环境应使用 digest 锁定；内部演示允许 Tag 的配置不能复制到生产。

## 12. 控制面维护与恢复

控制机服务：

```text
nginx.service
tsuite-frpc.service
tsuite-support-console.service
tsuite-github-egress.service
tsuite-support-operator-gc.timer
```

控制机日常免密权限由 `/etc/sudoers.d/tsuite-deploy-operator` 限定，只允许：

- 页面以 `tsuite-support-operator` broker 身份执行会话 `create`、`list`、`show`、普通 `close`；
- `adam` 以 broker 身份执行 `list`、`show`、带关闭人参数的普通 `close`、带原因的 `force-close`、
  `ssh` 和 `run`；
- 精确重启 `nginx`、`tsuite-frpc`、`tsuite-support-console`、`tsuite-github-egress`。

2026-09-08 现场更新：用户已为 `adam` 增加 `(ALL : ALL) NOPASSWD: ALL`，
已通过 `sudo -n -l` 和 `sudo -n /usr/bin/id -u`（返回 `0`）核实；当前控制机部署无需再次输入 sudo 密码。
上面的精确会话与重启规则仍保留。旧配置备份
`/srv/tsuite-deploy/backups/control-sudoers/99-tsuite-bootstrap.before-hardening` 不应作为部署步骤恢复。

edge 服务：

```text
caddy.service
tai-frps.service
tsuite-support-gc.timer
```

控制面备份必须异机保存，至少包含：

- `/etc/frp/frpc.toml`；
- `/etc/tsuite-support-console/`（仅 OAuth 配置）；
- `/etc/tsuite-support-control/`（必须作为 Secret 加密备份）；
- 不备份 `/var/lib/tsuite-support-operator/sessions/`；其中是短期会话私钥，关闭或过期后必须删除；
- `/srv/tsuite-deploy/repositories/` 中的 inventory 与加密 Vault；
- Vault 密码文件和部署 identity（通过独立 Secret Manager 或离线加密备份）；
- edge 的 Caddy、FRPS、support-session 配置和 SSH Host Key。

恢复到新机器时，先恢复 SSH Host Key 或显式更新固定指纹，再恢复受限密钥和服务。禁止为“快速恢复”关闭
Host Key 校验。

## 13. 当前上线前仍需闭环的事项

以下项目没有完成前，系统可用于受控部署，但不能称为完全无人值守：

1. 配置控制机和 edge 的异机备份，并完成一次恢复演练；
2. 为 FRPC、支持管理页和会话 GC 配置告警；
3. 为会话历史和客户环境登记建立保留期、归档与分页策略。

Agent 每次开始部署时应先检查这些事项的当前状态。若缺项直接影响本次任务，应先补齐；若不影响本次受控
操作，应在交付记录中明确剩余风险，不能静默忽略。

## 14. 专项文档

- [仓库总览](../README.md)
- [部署控制机](../control-node/README.md)
- [临时远程支持会话](../support-session/README.md)
- [单机部署](../single-node/README.md)
- [多节点部署](../multi-node/README.md)
- [共享部署契约](../shared/contracts/README.md)
