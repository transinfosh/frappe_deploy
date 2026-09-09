#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_ROOT="/usr/local/lib/tsuite-support"
CONFIG_DIR="/etc/tsuite-support"
STATE_DIR="/var/lib/tsuite-support"
DOWNLOADS_DIR="/var/lib/tsuite-support-downloads"
AUTHORIZED_KEYS_DIR="$CONFIG_DIR/authorized_keys"
ENROLL_USER="tsuite-enroll"
ENROLL_HOME="/var/empty/tsuite-enroll"
TUNNEL_GROUP="tsuite-tunnel"
BOOTSTRAP_SOURCE="$SCRIPT_DIR/../customer/bootstrap.sh"

BASTION_HOST=""
BASTION_PORT="22"
OPERATOR_USER=""
PORT_START="22000"
PORT_END="22999"
TOKEN_TTL_SECONDS="900"
SESSION_TTL_SECONDS="7200"

die() {
	printf '错误: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
用法: sudo ./install.sh [选项]

必填：
  --bastion-host HOST          堡垒机的稳定公网域名
  --operator-user USER         公司人员登录堡垒机使用的既有 SSH 用户

可选：
  --bastion-port PORT          堡垒机 SSH 端口，默认 22
  --port-range START-END       反向 SSH 回环端口范围，默认 22000-22999
  --token-ttl SECONDS          接入链接有效期，默认 900
  --session-ttl SECONDS        会话闲置超时，默认 7200
EOF
}

require_integer() {
	local name="$1" value="$2" minimum="$3" maximum="$4"
	[[ "$value" =~ ^[0-9]+$ ]] || die "$name 必须为整数"
	((value >= minimum && value <= maximum)) || die "$name 超出允许范围"
}

while (($#)); do
	case "$1" in
		--bastion-host) BASTION_HOST="${2:-}"; shift ;;
		--bastion-port) BASTION_PORT="${2:-}"; shift ;;
		--operator-user) OPERATOR_USER="${2:-}"; shift ;;
		--port-range)
			PORT_START="${2%%-*}"
			PORT_END="${2##*-}"
			shift
			;;
		--token-ttl) TOKEN_TTL_SECONDS="${2:-}"; shift ;;
		--session-ttl) SESSION_TTL_SECONDS="${2:-}"; shift ;;
		--help | -h) usage; exit 0 ;;
		*) die "未知参数: $1" ;;
	esac
	shift
done

[[ "$EUID" -eq 0 ]] || die "请使用 sudo 运行"
[[ "$BASTION_HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || die "堡垒机域名无效"
[[ "$OPERATOR_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "公司运维 SSH 用户名无效"
id "$OPERATOR_USER" >/dev/null 2>&1 || die "公司运维 SSH 用户不存在: $OPERATOR_USER"
require_integer "SSH 端口" "$BASTION_PORT" 1 65535
require_integer "端口范围起点" "$PORT_START" 1024 65535
require_integer "端口范围终点" "$PORT_END" "$PORT_START" 65535
require_integer "会话码有效期" "$TOKEN_TTL_SECONDS" 60 3600
require_integer "会话有效期" "$SESSION_TTL_SECONDS" 300 28800
[[ -f "$SCRIPT_DIR/tsuite_support_session.py" ]] || die "缺少 tsuite_support_session.py"
[[ -f "$BOOTSTRAP_SOURCE" ]] || die "缺少客户 bootstrap.sh"
for windows_script in bootstrap.ps1 windows-client.ps1; do
	[[ -f "$SCRIPT_DIR/../customer/$windows_script" ]] || die "缺少客户 $windows_script"
done
for command_name in caddy getent groupadd id install passwd python3 ssh sshd ssh-keygen systemctl useradd usermod visudo; do
	command -v "$command_name" >/dev/null 2>&1 || die "缺少命令: $command_name"
done
id caddy >/dev/null 2>&1 || die "Caddy 服务用户不存在"
[[ -f /etc/caddy/Caddyfile ]] || die "Caddyfile 不存在: /etc/caddy/Caddyfile"

getent group "$TUNNEL_GROUP" >/dev/null || groupadd --system "$TUNNEL_GROUP"
getent group "$ENROLL_USER" >/dev/null || groupadd --system "$ENROLL_USER"
install -d -m 0755 -o root -g root "$ENROLL_HOME"
if ! id "$ENROLL_USER" >/dev/null 2>&1; then
	useradd --system --gid "$ENROLL_USER" --home-dir "$ENROLL_HOME" --shell /bin/sh \
		--password 'NP' "$ENROLL_USER"
fi
usermod --home "$ENROLL_HOME" "$ENROLL_USER"
# OpenSSH refuses locked shadow markers before it evaluates authorized_keys.
# "NP" is the upstream-recommended non-hash marker for key-only accounts;
# public-key authentication remains the only enabled method below.
usermod --password 'NP' "$ENROLL_USER"
[[ "$(passwd -S "$ENROLL_USER" | awk '{print $2}')" == "P" ]] || \
	die "$ENROLL_USER 账户仍被系统标记为锁定"

install -d -m 0755 "$INSTALL_ROOT"
install -d -m 0755 -o root -g root "$CONFIG_DIR"
install -d -m 2770 -o "$ENROLL_USER" -g "$ENROLL_USER" "$STATE_DIR" "$STATE_DIR/sessions"
install -d -m 2750 -o root -g caddy "$DOWNLOADS_DIR"
install -d -m 0711 -o root -g root "$AUTHORIZED_KEYS_DIR"
install -m 0755 "$SCRIPT_DIR/tsuite_support_session.py" "$INSTALL_ROOT/tsuite-support-session"
install -m 0755 "$BOOTSTRAP_SOURCE" "$INSTALL_ROOT/bootstrap.sh"
install -m 0644 "$SCRIPT_DIR/../customer/linux-client.py" "$INSTALL_ROOT/linux-client.py"
install -m 0644 "$SCRIPT_DIR/../customer/bootstrap.ps1" "$SCRIPT_DIR/../customer/windows-client.ps1" "$INSTALL_ROOT/"
ln -sfn "$INSTALL_ROOT/tsuite-support-session" /usr/local/sbin/tsuite-support-session
install -m 0660 -o "$ENROLL_USER" -g "$ENROLL_USER" /dev/null "$STATE_DIR/.lock"
if [[ ! -f "$AUTHORIZED_KEYS_DIR/$ENROLL_USER" ]]; then
	install -m 0600 -o "$ENROLL_USER" -g "$ENROLL_USER" /dev/null "$AUTHORIZED_KEYS_DIR/$ENROLL_USER"
else
	chown "$ENROLL_USER:$ENROLL_USER" "$AUTHORIZED_KEYS_DIR/$ENROLL_USER"
	chmod 0600 "$AUTHORIZED_KEYS_DIR/$ENROLL_USER"
fi

host_key_file="/etc/ssh/ssh_host_ed25519_key.pub"
[[ -f "$host_key_file" ]] || die "堡垒机缺少 Ed25519 Host Key"
host_key="$(awk 'NF >= 2 {print $1, $2; exit}' "$host_key_file")"
[[ "$host_key" == ssh-ed25519\ * ]] || die "无法读取堡垒机 Ed25519 Host Key"

python3 - "$CONFIG_DIR/config.json" "$STATE_DIR" "$AUTHORIZED_KEYS_DIR" "$DOWNLOADS_DIR" \
	"$BASTION_HOST" "$BASTION_PORT" "$host_key" "$INSTALL_ROOT/bootstrap.sh" \
	"$PORT_START" "$PORT_END" "$TOKEN_TTL_SECONDS" "$SESSION_TTL_SECONDS" \
	"$TUNNEL_GROUP" <<'PY'
import json
import os
import sys

(
    path, state_dir, authorized_keys_dir, downloads_dir, bastion_host, bastion_port,
    host_key, bootstrap_path, port_start, port_end, token_ttl,
    session_ttl, tunnel_group,
) = sys.argv[1:]
value = {
    "state_dir": state_dir,
    "authorized_keys_dir": authorized_keys_dir,
    "downloads_dir": downloads_dir,
    "download_base_url": f"https://{bastion_host}/tsuite-support",
    "bastion_host": bastion_host,
    "bastion_port": int(bastion_port),
    "bastion_host_key": host_key,
    "bootstrap_path": bootstrap_path,
    "port_start": int(port_start),
    "port_end": int(port_end),
    "token_ttl_seconds": int(token_ttl),
    "session_ttl_seconds": int(session_ttl),
    "tunnel_group": tunnel_group,
}
temporary = path + ".tmp"
with open(temporary, "w", encoding="utf-8") as handle:
    json.dump(value, handle, ensure_ascii=False, sort_keys=True)
    handle.write("\n")
os.chmod(temporary, 0o640)
os.replace(temporary, path)
PY
chown root:"$ENROLL_USER" "$CONFIG_DIR/config.json"

caddy_snippet="/etc/caddy/tsuite-support.caddy"
caddy_console_routes="/etc/caddy/tsuite-support-console-routes.caddy"
caddy_import='import /etc/caddy/tsuite-support.caddy'
if [[ -f "$caddy_snippet" ]] && grep -Fqx '# Managed by tsuite_deploy/control-node.' "$caddy_snippet"; then
	grep -Fq 'handle_path /tsuite-support/*' "$caddy_snippet" || \
		die "control-node Caddy 配置缺少 /tsuite-support/* 路由"
	caddy validate --config /etc/caddy/Caddyfile >/dev/null || \
		die "现有 control-node Caddy 配置校验失败"
else
caddyfile_backup="$(mktemp /etc/caddy/.Caddyfile.tsuite-support.XXXXXX)"
cp -a /etc/caddy/Caddyfile "$caddyfile_backup"
caddy_snippet_backup=""
if [[ -f "$caddy_snippet" ]]; then
	caddy_snippet_backup="$(mktemp /etc/caddy/.tsuite-support.caddy.backup.XXXXXX)"
	cp -a "$caddy_snippet" "$caddy_snippet_backup"
fi
cat >"$caddy_snippet" <<EOF
# Managed by tsuite_deploy/support-session.
$BASTION_HOST {
    handle_path /tsuite-support/* {
        root * $DOWNLOADS_DIR
        header Cache-Control "no-store"
        header X-Content-Type-Options "nosniff"
        file_server
    }
    import $caddy_console_routes
    respond 404
}
EOF
chmod 0644 "$caddy_snippet"
if [[ ! -s "$caddy_console_routes" ]]; then
	cat >"$caddy_console_routes" <<'EOF'
@tsuite_support_console_disabled path /__tsuite-support-console-disabled__
respond @tsuite_support_console_disabled 404
EOF
	chmod 0644 "$caddy_console_routes"
fi
if ! grep -Fqx "$caddy_import" /etc/caddy/Caddyfile; then
	printf '\n# Managed by tsuite_deploy/support-session.\n%s\n' "$caddy_import" >>/etc/caddy/Caddyfile
fi
if ! caddy validate --config /etc/caddy/Caddyfile >/dev/null || ! systemctl reload caddy; then
	cp -a "$caddyfile_backup" /etc/caddy/Caddyfile
	if [[ -n "$caddy_snippet_backup" ]]; then
		cp -a "$caddy_snippet_backup" "$caddy_snippet"
	else
		rm -f "$caddy_snippet"
	fi
	systemctl reload caddy || true
	die "Caddy 支持会话配置应用失败，已恢复旧配置"
fi
rm -f "$caddyfile_backup"
[[ -z "$caddy_snippet_backup" ]] || rm -f "$caddy_snippet_backup"
fi

cat >/etc/sudoers.d/tsuite-support-session <<EOF
Defaults:$ENROLL_USER env_keep += "SSH_ORIGINAL_COMMAND"
$ENROLL_USER ALL=(root) NOPASSWD: /usr/local/sbin/tsuite-support-session --config $CONFIG_DIR/config.json enroll-ssh *, /usr/local/sbin/tsuite-support-session --config $CONFIG_DIR/config.json lease-ssh *
$OPERATOR_USER ALL=(root) NOPASSWD: /usr/local/sbin/tsuite-support-session --config $CONFIG_DIR/config.json create *
$OPERATOR_USER ALL=(root) NOPASSWD: /usr/local/sbin/tsuite-support-session --config $CONFIG_DIR/config.json show *
$OPERATOR_USER ALL=(root) NOPASSWD: /usr/local/sbin/tsuite-support-session --config $CONFIG_DIR/config.json list
$OPERATOR_USER ALL=(root) NOPASSWD: /usr/local/sbin/tsuite-support-session --config $CONFIG_DIR/config.json close *
EOF
chmod 0440 /etc/sudoers.d/tsuite-support-session
visudo -cf /etc/sudoers.d/tsuite-support-session >/dev/null || die "support-session sudoers 片段校验失败"
visudo -c >/dev/null || die "完整 sudoers 配置校验失败"

sshd_dropin="/etc/ssh/sshd_config.d/90-tsuite-support.conf"
temporary_dropin="$(mktemp /etc/ssh/sshd_config.d/.90-tsuite-support.XXXXXX)"
trap 'rm -f -- "$temporary_dropin"' EXIT
cat >"$temporary_dropin" <<EOF
# Managed by tsuite_deploy/support-session.
Match User $ENROLL_USER
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthorizedKeysFile $AUTHORIZED_KEYS_DIR/%u
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    GatewayPorts no
    PermitTTY no
    PermitTunnel no
    X11Forwarding no
    AllowAgentForwarding no
    PermitUserRC no
    MaxSessions 1
Match Group $TUNNEL_GROUP
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthorizedKeysFile $AUTHORIZED_KEYS_DIR/%u
    AllowTcpForwarding remote
    AllowStreamLocalForwarding no
    GatewayPorts no
    PermitOpen none
    PermitTTY no
    PermitTunnel no
    X11Forwarding no
    AllowAgentForwarding no
    PermitUserRC no
    MaxSessions 0
    ClientAliveInterval 30
    ClientAliveCountMax 3
Match all
EOF
chmod 0644 "$temporary_dropin"

backup_dropin=""
if [[ -f "$sshd_dropin" ]]; then
	backup_dropin="$(mktemp /etc/ssh/sshd_config.d/.90-tsuite-support.backup.XXXXXX)"
	cp -a "$sshd_dropin" "$backup_dropin"
fi
install -m 0644 "$temporary_dropin" "$sshd_dropin"
validation_error=""
if ! sshd -t; then
	validation_error="sshd 语法校验失败"
else
	effective_enroll_config="$(sshd -T -C "user=$ENROLL_USER,host=$BASTION_HOST,addr=127.0.0.1")"
	if ! grep -q '^allowtcpforwarding no$' <<<"$effective_enroll_config"; then
		validation_error="tsuite-enroll 的 AllowTcpForwarding 未生效"
	fi
fi
if [[ -n "$validation_error" ]]; then
	if [[ -n "$backup_dropin" ]]; then
		cp -a "$backup_dropin" "$sshd_dropin"
	else
		rm -f "$sshd_dropin"
	fi
	sshd -t || true
	die "$validation_error，已恢复旧配置"
fi
rm -f "$temporary_dropin"
[[ -z "$backup_dropin" ]] || rm -f "$backup_dropin"
trap - EXIT

cat >/etc/systemd/system/tsuite-support-gc.service <<EOF
[Unit]
Description=Expire TSuite support sessions

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/tsuite-support-session --config $CONFIG_DIR/config.json gc
EOF

cat >/etc/systemd/system/tsuite-support-gc.timer <<'EOF'
[Unit]
Description=Expire TSuite support sessions periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now tsuite-support-gc.timer
systemctl reload ssh

self_test_dir="$(mktemp -d /tmp/tsuite-support-ssh-self-test.XXXXXX)"
self_test_key="$self_test_dir/id_ed25519"
self_test_known_hosts="$self_test_dir/known_hosts"
self_test_authorized_backup="$self_test_dir/authorized_keys"
cp -a "$AUTHORIZED_KEYS_DIR/$ENROLL_USER" "$self_test_authorized_backup"
ssh-keygen -q -t ed25519 -N '' -C tsuite-support-install-self-test -f "$self_test_key"
printf 'command="/usr/bin/true",restrict %s\n' \
	"$(awk 'NF >= 2 {print $1, $2; exit}' "$self_test_key.pub")" >>"$AUTHORIZED_KEYS_DIR/$ENROLL_USER"
self_test_host="127.0.0.1"
if [[ "$BASTION_PORT" != "22" ]]; then
	self_test_host="[$self_test_host]:$BASTION_PORT"
fi
printf '%s %s\n' "$self_test_host" "$host_key" >"$self_test_known_hosts"
self_test_status=0
ssh -F none -T -i "$self_test_key" -o IdentitiesOnly=yes -o BatchMode=yes \
	-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$self_test_known_hosts" \
	-o ClearAllForwardings=yes -p "$BASTION_PORT" "$ENROLL_USER@127.0.0.1" self-test \
	</dev/null >/dev/null 2>&1 || self_test_status=$?
cp -a "$self_test_authorized_backup" "$AUTHORIZED_KEYS_DIR/$ENROLL_USER"
rm -f "$self_test_key" "$self_test_key.pub" "$self_test_known_hosts" "$self_test_authorized_backup"
rmdir "$self_test_dir"
((self_test_status == 0)) || die "tsuite-enroll 公钥登录自检失败"

printf 'support-session 堡垒机模块安装完成。\n'
printf 'SSH 域名：%s\n' "$BASTION_HOST"
printf 'Host Key 指纹：'
ssh-keygen -lf "$host_key_file" -E sha256 | awk '{print $2}'
