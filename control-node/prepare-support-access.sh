#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="/etc/tsuite-support-control"
STATE_DIR="/var/lib/tsuite-support-operator"
BROKER_USER="tsuite-support-operator"
BROKER_GROUP="tsuite-support-operator"
CONSOLE_USER="tsuite-support-console"
BASTION_HOST="edge.trinfo.net"
BASTION_PORT="22"
BASTION_USER="tsuite-operator"
BASTION_HOST_KEY_FILE=""
OPERATOR_USER="adam"

die() {
	printf '错误: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
用法: sudo ./prepare-support-access.sh --bastion-host-key-file FILE [选项]

必填：
  --bastion-host-key-file FILE  已通过独立渠道核验的堡垒机 SSH Host Key 或 known_hosts

可选：
  --bastion-host HOST           默认 edge.trinfo.net
  --bastion-port PORT           默认 22
  --bastion-user USER           默认 tsuite-operator
  --operator-user USER          控制机日常运维账号，默认 adam
EOF
}

while (($#)); do
	case "$1" in
		--bastion-host-key-file) BASTION_HOST_KEY_FILE="${2:-}"; shift ;;
		--bastion-host) BASTION_HOST="${2:-}"; shift ;;
		--bastion-port) BASTION_PORT="${2:-}"; shift ;;
		--bastion-user) BASTION_USER="${2:-}"; shift ;;
		--operator-user) OPERATOR_USER="${2:-}"; shift ;;
		--help | -h) usage; exit 0 ;;
		*) die "未知参数: $1" ;;
	esac
	shift
done

[[ "$EUID" -eq 0 ]] || die "请使用 sudo 运行"
[[ -f "$BASTION_HOST_KEY_FILE" ]] || die "缺少已核验的堡垒机 Host Key 文件"
[[ "$BASTION_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || die "堡垒机域名无效"
if [[ ! "$BASTION_PORT" =~ ^[0-9]+$ ]] || ((BASTION_PORT < 1 || BASTION_PORT > 65535)); then
	die "堡垒机端口无效"
fi
[[ "$BASTION_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "堡垒机用户无效"
[[ "$OPERATOR_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "控制机运维用户无效"
id "$OPERATOR_USER" >/dev/null 2>&1 || die "控制机运维用户不存在: $OPERATOR_USER"
[[ -f "$REPO_ROOT/support-session/console/tsuite_support_remote_action.py" ]] || die "缺少控制机 broker 程序"
for command_name in getent gpasswd groupadd install python3 ssh-keygen systemctl useradd usermod visudo; do
	command -v "$command_name" >/dev/null 2>&1 || die "缺少命令: $command_name"
done

getent group "$BROKER_GROUP" >/dev/null || groupadd --system "$BROKER_GROUP"
if ! id "$BROKER_USER" >/dev/null 2>&1; then
	useradd --system --gid "$BROKER_GROUP" --home-dir "$STATE_DIR" \
		--shell /usr/sbin/nologin --password 'NP' "$BROKER_USER"
fi
usermod --gid "$BROKER_GROUP" --home "$STATE_DIR" --shell /usr/sbin/nologin --password 'NP' "$BROKER_USER"

remove_broker_membership() {
	local account="$1"
	id "$account" >/dev/null 2>&1 || return 0
	[[ "$(id -gn "$account")" != "$BROKER_GROUP" ]] || \
		die "$account 不能以 broker group 作为主组"
	if id -nG "$account" | tr ' ' '\n' | grep -Fxq "$BROKER_GROUP"; then
		gpasswd -d "$account" "$BROKER_GROUP" >/dev/null
	fi
}

remove_broker_membership "$OPERATOR_USER"
remove_broker_membership "$CONSOLE_USER"

install -d -m 0750 -o root -g "$BROKER_GROUP" "$CONFIG_DIR"
install -d -m 0700 -o "$BROKER_USER" -g "$BROKER_GROUP" "$STATE_DIR" "$STATE_DIR/sessions"
install -m 0755 -o root -g root \
	"$REPO_ROOT/support-session/console/tsuite_support_remote_action.py" \
	/usr/local/bin/tsuite-support-console-action
install -m 0644 -o root -g root "$REPO_ROOT/support-session/operator/tsuite_support_activity.py" /usr/local/bin/tsuite_support_activity.py

migrate_or_generate_key() {
	local name legacy target
	name="$1"
	legacy="$2"
	target="$CONFIG_DIR/$name"
	if [[ ! -f "$target" ]]; then
		if [[ -f "$legacy" ]]; then
			install -m 0600 -o "$BROKER_USER" -g "$BROKER_GROUP" "$legacy" "$target"
		else
			rm -f -- "$target.pub"
			ssh-keygen -q -t ed25519 -N '' -C "$name" -f "$target"
		fi
	fi
	# OpenSSH 会拒绝任何可被组或其他用户读取的私钥；仅 broker 用户可以持有它。
	chown "$BROKER_USER":"$BROKER_GROUP" "$target"
	chmod 0600 "$target"
	ssh-keygen -y -f "$target" | awk -v comment="$name" '{print $1, $2, comment}' >"$target.pub"
	chown root:root "$target.pub"
	chmod 0644 "$target.pub"
}

migrate_or_generate_key bridge_ed25519 /etc/tsuite-support-console/bridge_ed25519
migrate_or_generate_key edge_operator_ed25519 /etc/tsuite-support-console/edge_operator_ed25519

host_key="$(awk 'NF >= 2 && $1 !~ /^#/ {if ($1 ~ /^ssh-/) print $1, $2; else print $2, $3; exit}' "$BASTION_HOST_KEY_FILE")"
[[ "$host_key" == ssh-ed25519\ * || "$host_key" == ecdsa-sha2-nistp256\ * ]] || die "无法读取堡垒机 Host Key"
known_host="$BASTION_HOST"
[[ "$BASTION_PORT" == "22" ]] || known_host="[$BASTION_HOST]:$BASTION_PORT"
printf '%s %s\n' "$known_host" "$host_key" >"$CONFIG_DIR/known_hosts"
chown root:"$BROKER_GROUP" "$CONFIG_DIR/known_hosts"
chmod 0640 "$CONFIG_DIR/known_hosts"

python3 - "$CONFIG_DIR/action.json" "$BASTION_HOST" "$BASTION_PORT" "$BASTION_USER" \
	"$CONFIG_DIR/bridge_ed25519" "$CONFIG_DIR/edge_operator_ed25519" \
	"$CONFIG_DIR/known_hosts" "$STATE_DIR" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

path, host, port, user, bridge_key, edge_key, known_hosts, state_dir = sys.argv[1:]
value = {
    "host": host,
    "port": int(port),
    "user": user,
    "bridge_identity_file": bridge_key,
    "edge_identity_file": edge_key,
    "known_hosts_file": known_hosts,
    "state_dir": state_dir,
}
target = pathlib.Path(path)
fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(value, handle, ensure_ascii=False, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(temporary_name, 0o640)
os.replace(temporary_name, target)
PY
chown root:"$BROKER_GROUP" "$CONFIG_DIR/action.json"

sudoers_temporary="$(mktemp /etc/sudoers.d/.tsuite-deploy-operator.XXXXXX)"
trap 'unlink "$sudoers_temporary" 2>/dev/null || true' EXIT
cat >"$sudoers_temporary" <<EOF
Cmnd_Alias TSUITE_SUPPORT_WEB = /usr/local/bin/tsuite-support-console-action create *, /usr/local/bin/tsuite-support-console-action show *, /usr/local/bin/tsuite-support-console-action list, /usr/local/bin/tsuite-support-console-action close *
Cmnd_Alias TSUITE_SUPPORT_OPERATOR = /usr/local/bin/tsuite-support-console-action show *, /usr/local/bin/tsuite-support-console-action list, /usr/local/bin/tsuite-support-console-action close *, /usr/local/bin/tsuite-support-console-action force-close *, /usr/local/bin/tsuite-support-console-action ssh *, /usr/local/bin/tsuite-support-console-action run *
Cmnd_Alias TSUITE_CONTROL_SERVICES = /usr/bin/systemctl restart nginx.service, /usr/bin/systemctl restart tsuite-frpc.service, /usr/bin/systemctl restart tsuite-support-console.service, /usr/bin/systemctl restart tsuite-github-egress.service
$CONSOLE_USER ALL=($BROKER_USER) NOPASSWD: TSUITE_SUPPORT_WEB
$OPERATOR_USER ALL=($BROKER_USER) NOPASSWD: TSUITE_SUPPORT_OPERATOR
$OPERATOR_USER ALL=(root) NOPASSWD: TSUITE_CONTROL_SERVICES
EOF
chmod 0440 "$sudoers_temporary"
visudo -cf "$sudoers_temporary" >/dev/null || die "最小权限 sudoers 校验失败"
install -m 0440 -o root -g root "$sudoers_temporary" /etc/sudoers.d/tsuite-deploy-operator
unlink "$sudoers_temporary"
trap - EXIT
visudo -c >/dev/null || die "完整 sudoers 配置校验失败"

cat >/etc/systemd/system/tsuite-support-operator-gc.service <<EOF
[Unit]
Description=Garbage collect TSuite per-session operator keys
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$BROKER_USER
Group=$BROKER_GROUP
ExecStart=/usr/local/bin/tsuite-support-console-action gc
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=
SystemCallArchitectures=native
ReadOnlyPaths=$CONFIG_DIR
ReadWritePaths=$STATE_DIR
EOF

cat >/etc/systemd/system/tsuite-support-operator-gc.timer <<'EOF'
[Unit]
Description=Garbage collect TSuite per-session operator keys periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now tsuite-support-operator-gc.timer

printf '控制机支持 broker 已准备完成。\n'
printf '桥接公钥：%s\n' "$CONFIG_DIR/bridge_ed25519.pub"
printf 'edge forced proxy 公钥：%s\n' "$CONFIG_DIR/edge_operator_ed25519.pub"
