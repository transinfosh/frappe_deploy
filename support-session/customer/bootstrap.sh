#!/usr/bin/env bash
set -Eeuo pipefail

BASTION_HOST=""
BASTION_PORT=""
ENROLLMENT_KEY=""
KNOWN_HOSTS=""
ACCEPT_ROOT_ACCESS=false
KEY_AUTH=false
TOKEN="${TSUITE_SUPPORT_TOKEN:-}"
work_dir=""
ops_user=""
session_id=""
installation_complete=false
installation_started=false
existing_session_id=""

die() {
	printf '错误: %s\n' "$*" >&2
	exit 1
}

rollback_installation() {
	local exit_status="$?"
	if ((exit_status != 0)) && "$installation_started" && ! "$installation_complete"; then
		systemctl disable --now tsuite-support-client.service \
			tsuite-support-client-expiry.timer tsuite-support-client-monitor.service 2>/dev/null || true
		[[ -z "$ops_user" ]] || userdel -r "$ops_user" 2>/dev/null || true
		[[ -z "$session_id" ]] || rm -f "/etc/sudoers.d/tsuite-support-$session_id"
		rm -rf /etc/tsuite-support-client
		rm -f /etc/systemd/system/tsuite-support-client.service \
			/etc/systemd/system/tsuite-support-client-cleanup.service \
			/etc/systemd/system/tsuite-support-client-expiry.timer \
      /etc/systemd/system/tsuite-support-client-monitor.service \
			/usr/local/sbin/tsuite-support-client
		systemctl daemon-reload 2>/dev/null || true
	fi
	[[ -z "$work_dir" ]] || rm -rf -- "$work_dir"
	unset TOKEN
	exit "$exit_status"
}

trap rollback_installation EXIT

while (($#)); do
	case "$1" in
		--bastion-host) BASTION_HOST="${2:-}"; shift ;;
		--bastion-port) BASTION_PORT="${2:-}"; shift ;;
		--enrollment-key) ENROLLMENT_KEY="${2:-}"; shift ;;
		--known-hosts) KNOWN_HOSTS="${2:-}"; shift ;;
		--accept-temporary-root-access) ACCEPT_ROOT_ACCESS=true ;;
		--key-auth) KEY_AUTH=true ;;
		--help | -h)
			printf '用法: bootstrap.sh --bastion-host HOST --bastion-port PORT --enrollment-key FILE --known-hosts FILE --accept-temporary-root-access\n'
			exit 0
			;;
		*) die "未知参数: $1" ;;
	esac
	shift
done

[[ "$EUID" -eq 0 ]] || die "请使用 sudo 运行"
[[ "$BASTION_HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || die "堡垒机地址无效"
if [[ ! "$BASTION_PORT" =~ ^[0-9]+$ ]] || ((BASTION_PORT < 1 || BASTION_PORT > 65535)); then
	die "堡垒机 SSH 端口无效"
fi
[[ -f "$ENROLLMENT_KEY" && ! -L "$ENROLLMENT_KEY" ]] || die "本次会话的 enrollment key 无效"
[[ -f "$KNOWN_HOSTS" && ! -L "$KNOWN_HOSTS" ]] || die "堡垒机 known_hosts 无效"
"$ACCEPT_ROOT_ACCESS" || die "必须显式确认临时 root 运维访问"
command -v python3 >/dev/null 2>&1 || die "缺少 Python 3"
command -v ssh >/dev/null 2>&1 || die "缺少 OpenSSH Client"
command -v ssh-keygen >/dev/null 2>&1 || die "缺少 ssh-keygen"
command -v systemctl >/dev/null 2>&1 || die "缺少 systemd"
command -v useradd >/dev/null 2>&1 || die "缺少 useradd"
command -v visudo >/dev/null 2>&1 || die "缺少 visudo"
[[ -r /etc/ssh/ssh_host_ed25519_key.pub ]] || die "客户服务器缺少 Ed25519 SSH Host Key"
if [[ -e /etc/tsuite-support-client ]]; then
	[[ -d /etc/tsuite-support-client && ! -L /etc/tsuite-support-client ]] ||
		die "本机支持会话残留不是安全目录，请人工检查"
	[[ -f /etc/tsuite-support-client/session.conf && ! -L /etc/tsuite-support-client/session.conf ]] ||
		die "本机支持会话残留缺少有效配置，请人工清理"
	[[ -f /usr/local/sbin/tsuite-support-client && ! -L /usr/local/sbin/tsuite-support-client &&
		-x /usr/local/sbin/tsuite-support-client ]] ||
		die "本机支持会话清理程序缺失或无效，请人工清理"
	existing_session_id="$(python3 - /etc/tsuite-support-client/session.conf \
		"$BASTION_HOST" "$BASTION_PORT" <<'PY'
import re
import sys

expected = {"BASTION_HOST": sys.argv[2], "BASTION_PORT": sys.argv[3]}
values = {"SESSION_ID": [], "BASTION_HOST": [], "BASTION_PORT": []}
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        key, separator, value = line.rstrip("\n").partition("=")
        if separator and key in values:
            values[key].append(value)
if len(values["SESSION_ID"]) != 1 or not re.fullmatch(r"[a-f0-9]{12}", values["SESSION_ID"][0]):
    raise SystemExit("本机支持会话 SESSION_ID 无效")
for key, expected_value in expected.items():
    if values[key] != [expected_value]:
        raise SystemExit("本机支持会话所属堡垒机与本次会话不一致")
print(values["SESSION_ID"][0])
PY
)" || die "无法读取本机支持会话标识"
fi

if ! "$KEY_AUTH" && [[ -z "$TOKEN" ]]; then
	read -r -s -p "请输入一次性支持会话码: " TOKEN </dev/tty
	printf '\n' >/dev/tty
fi
"$KEY_AUTH" || [[ "$TOKEN" =~ ^[A-Za-z0-9_-]{40,128}$ ]] || die "会话码格式无效"

work_dir="$(mktemp -d /tmp/tsuite-support-bootstrap.XXXXXX)"
chmod 0700 "$work_dir"
nonce="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
customer_host_key="$(awk 'NF >= 2 {print $1, $2; exit}' /etc/ssh/ssh_host_ed25519_key.pub)"
printf '%s' "$TOKEN" >"$work_dir/token"
chmod 0600 "$work_dir/token"
python3 - "$work_dir/request.json" "$work_dir/reconcile.json" "$work_dir/token" \
	"$nonce" "$customer_host_key" "$existing_session_id" <<'PY'
import json
import os
import sys

path, reconcile_path, token_path, nonce, host_key, existing_session_id = sys.argv[1:]
with open(token_path, encoding="utf-8") as token_file:
    token = token_file.read()
with open(path, "w", encoding="utf-8") as handle:
    json.dump({"token": token, "nonce": nonce, "customer_host_key": host_key}, handle)
os.chmod(path, 0o600)
if existing_session_id:
    with open(reconcile_path, "w", encoding="utf-8") as handle:
        json.dump({"token": token, "existing_session_id": existing_session_id}, handle)
    os.chmod(reconcile_path, 0o600)
PY
enrollment_ssh=(
	ssh -F none -T -i "$ENROLLMENT_KEY" -o IdentitiesOnly=yes -o BatchMode=yes
	-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS"
	-o ClearAllForwardings=yes -p "$BASTION_PORT" tsuite-enroll@"$BASTION_HOST"
)
if [[ -n "$existing_session_id" ]]; then
	"${enrollment_ssh[@]}" reconcile \
		<"$work_dir/reconcile.json" >"$work_dir/reconcile-response.json"
	python3 - "$work_dir/reconcile-response.json" "$existing_session_id" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    response = json.load(handle)
if response != {"replace_existing_session": sys.argv[2]}:
    raise SystemExit("旧支持会话核对响应无效")
PY
	/usr/local/sbin/tsuite-support-client cleanup
	[[ ! -e /etc/tsuite-support-client && ! -e /usr/local/sbin/tsuite-support-client ]] ||
		die "旧支持会话本机清理未完成，请检查 systemd 和临时用户"
	printf '已确认远端旧会话 %s 终止，并完成本机残留清理。\n' "$existing_session_id"
fi
rm -f "$work_dir/token"
unset TOKEN
"${enrollment_ssh[@]}" linux-client </dev/null >"$work_dir/linux-client.py"
"${enrollment_ssh[@]}" enroll \
	<"$work_dir/request.json" >"$work_dir/response.json"
chmod 0600 "$work_dir/response.json"

python3 - "$work_dir/response.json" "$work_dir" <<'PY'
import json
import os
import pathlib
import re
import sys
import time

response_path, output_dir = sys.argv[1:]
with open(response_path, encoding="utf-8") as handle:
    value = json.load(handle)
required = {
    "schema_version", "session_id", "customer", "expires_at", "bastion_host",
    "bastion_port", "bastion_host_key", "remote_port", "tunnel_user",
    "tunnel_private_key", "operator_public_key",
}
if not required <= value.keys() or value["schema_version"] not in (1, 2):
    raise SystemExit("enrollment 响应格式无效")
if not re.fullmatch(r"[a-f0-9]{12}", value["session_id"]):
    raise SystemExit("session_id 无效")
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", value["customer"]):
    raise SystemExit("customer 无效")
if not re.fullmatch(r"[a-zA-Z0-9.-]+", value["bastion_host"]):
    raise SystemExit("bastion_host 无效")
if not isinstance(value["bastion_port"], int) or not 1 <= value["bastion_port"] <= 65535:
    raise SystemExit("端口无效")
if not isinstance(value["remote_port"], int) or not 1024 <= value["remote_port"] <= 65535:
    raise SystemExit("端口无效")
if value["tunnel_user"] != f"tsuite-tunnel-{value['session_id'][:8]}":
    raise SystemExit("tunnel_user 无效")
if not isinstance(value["expires_at"], int) or not time.time() < value["expires_at"] <= time.time() + 28800:
    raise SystemExit("expires_at 无效")
for key_name in ("bastion_host_key", "operator_public_key"):
    if not re.fullmatch(r"(ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+", value[key_name]):
        raise SystemExit(f"{key_name} 无效")
private_key = value["tunnel_private_key"]
if (
    not isinstance(private_key, str)
    or len(private_key) > 4096
    or not private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    or not private_key.endswith("-----END OPENSSH PRIVATE KEY-----\n")
):
    raise SystemExit("tunnel_private_key 无效")
if value["schema_version"] == 2:
    if type(value.get("idle_timeout_seconds")) is not int or not 300 <= value["idle_timeout_seconds"] <= 28800:
        raise SystemExit("idle_timeout_seconds 无效")
    lease_key = value.get("lease_private_key", "")
    if not isinstance(lease_key, str) or not lease_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n") or len(lease_key) > 4096:
        raise SystemExit("lease_private_key 无效")
output = pathlib.Path(output_dir)
(output / "payload.json").write_text(json.dumps(value), encoding="utf-8")
os.chmod(output / "payload.json", 0o600)
(output / "tunnel_ed25519").write_text(value["tunnel_private_key"], encoding="utf-8")
os.chmod(output / "tunnel_ed25519", 0o600)
PY

session_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session_id"])' "$work_dir/payload.json")"
bastion_host="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bastion_host"])' "$work_dir/payload.json")"
bastion_port="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bastion_port"])' "$work_dir/payload.json")"
bastion_host_key="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bastion_host_key"])' "$work_dir/payload.json")"
remote_port="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["remote_port"])' "$work_dir/payload.json")"
tunnel_user="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tunnel_user"])' "$work_dir/payload.json")"
operator_public_key="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["operator_public_key"])' "$work_dir/payload.json")"
expires_at="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expires_at"])' "$work_dir/payload.json")"

[[ "$bastion_host" == "$BASTION_HOST" && "$bastion_port" == "$BASTION_PORT" ]] ||
	die "enrollment 返回的堡垒机地址不一致"
known_host_prefix="$bastion_host"
[[ "$bastion_port" == "22" ]] || known_host_prefix="[$bastion_host]:$bastion_port"
grep -Fqx "$known_host_prefix $bastion_host_key" "$KNOWN_HOSTS" ||
	die "enrollment 返回的堡垒机 Host Key 不一致"

ops_user="tsuite-ops-${session_id:0:8}"
id "$ops_user" >/dev/null 2>&1 && die "临时运维用户已存在，拒绝覆盖: $ops_user"
[[ ! -e "/etc/sudoers.d/tsuite-support-$session_id" ]] || die "临时 sudoers 已存在，拒绝覆盖"
installation_started=true
renewable="$(python3 -c 'import json,sys; print("true" if json.load(open(sys.argv[1]))["schema_version"] == 2 else "false")' "$work_dir/payload.json")"
useradd --create-home --shell /bin/bash --password 'NP' "$ops_user"
ops_home="$(getent passwd "$ops_user" | cut -d: -f6)"
ops_group="$(id -gn "$ops_user")"
install -d -m 0700 -o "$ops_user" -g "$ops_group" "$ops_home/.ssh"
key_expiry="$(date -u -d "@$expires_at" +%Y%m%d%H%M%SZ)"
[[ "$key_expiry" =~ ^[0-9]{14}Z$ ]] || die "无法生成临时 SSH Key 过期时间"
printf 'expiry-time="%s",from="127.0.0.1",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc %s tsuite-support:%s\n' \
	"$key_expiry" "$operator_public_key" "$session_id" >"$ops_home/.ssh/authorized_keys"
chown "$ops_user:$ops_group" "$ops_home/.ssh/authorized_keys"
chmod 0600 "$ops_home/.ssh/authorized_keys"
printf '%s ALL=(root) NOPASSWD: ALL\n' "$ops_user" >"/etc/sudoers.d/tsuite-support-$session_id"
chmod 0440 "/etc/sudoers.d/tsuite-support-$session_id"
visudo -cf "/etc/sudoers.d/tsuite-support-$session_id" >/dev/null || die "临时 sudoers 校验失败"

install -d -m 0700 /etc/tsuite-support-client
install -m 0600 "$work_dir/tunnel_ed25519" /etc/tsuite-support-client/tunnel_ed25519
if "$renewable"; then
    install -m 0700 "$work_dir/linux-client.py" /etc/tsuite-support-client/monitor.py
    python3 - "$work_dir/payload.json" "$ops_user" <<'PY_STATE'
import json
import pathlib
import sys
root = pathlib.Path('/etc/tsuite-support-client')
value = json.load(open(sys.argv[1]))
(root / 'lease_ed25519').write_text(value.pop('lease_private_key'))
(root / 'lease_ed25519').chmod(0o600)
value.pop('tunnel_private_key')
value['ops_user'] = sys.argv[2]
(root / 'session.json').write_text(json.dumps(value))
(root / 'session.json').chmod(0o600)
PY_STATE
fi
printf '%s %s\n' "$known_host_prefix" "$bastion_host_key" >/etc/tsuite-support-client/known_hosts
chmod 0600 /etc/tsuite-support-client/known_hosts
cat >/etc/tsuite-support-client/session.conf <<EOF
SESSION_ID=$session_id
BASTION_HOST=$bastion_host
BASTION_PORT=$bastion_port
REMOTE_PORT=$remote_port
TUNNEL_USER=$tunnel_user
OPS_USER=$ops_user
EXPIRES_AT=$expires_at
EOF
chmod 0600 /etc/tsuite-support-client/session.conf

cat >/usr/local/sbin/tsuite-support-client <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
CONFIG=/etc/tsuite-support-client/session.conf
[[ "$EUID" -eq 0 ]] || { printf '请使用 sudo 运行\n' >&2; exit 1; }
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { printf '支持会话配置不存在\n' >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONFIG"
action="${1:-status}"
if [[ "$action" == cleanup* || "$action" == close || "$action" == activity ]]; then
    exec 9>/etc/tsuite-support-client/.lock
    flock -x 9
    . "$CONFIG"
fi
case "$action" in
  activity)
    [[ ! -e /etc/tsuite-support-client/closing ]] && (( $(date +%s) < EXPIRES_AT )) || exit 1
    touch /etc/tsuite-support-client/activity
    ;;

  open) systemctl enable --now tsuite-support-client.service ;;
  close)
    touch /etc/tsuite-support-client/closing
    systemctl start --no-block tsuite-support-client-cleanup.service
    printf 'cleanup-scheduled:%s\n' "$SESSION_ID"
    ;;
  status) systemctl status --no-pager tsuite-support-client.service ;;
  run-tunnel)
    if (( $(date +%s) >= EXPIRES_AT )); then
      printf '支持会话已过期，拒绝重建隧道\n' >&2
      exit 0
    fi
    exec /usr/bin/ssh -NT -F none \
      -i /etc/tsuite-support-client/tunnel_ed25519 \
      -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile=/etc/tsuite-support-client/known_hosts \
      -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
      -p "$BASTION_PORT" -R "127.0.0.1:$REMOTE_PORT:127.0.0.1:22" \
      "$TUNNEL_USER@$BASTION_HOST"
    ;;
  cleanup|cleanup-if-expired)
    if [[ "$action" == cleanup-if-expired && ! -e /etc/tsuite-support-client/closing ]] && (( $(date +%s) < EXPIRES_AT )); then exit 0; fi
    touch /etc/tsuite-support-client/closing
    systemctl disable --now tsuite-support-client-monitor.service 2>/dev/null || true
    systemctl disable tsuite-support-client.service tsuite-support-client-expiry.timer tsuite-support-client-monitor.service 2>/dev/null || true
    systemctl stop tsuite-support-client.service 2>/dev/null || true
    pkill -KILL -u "$OPS_USER" 2>/dev/null || true
    userdel -r "$OPS_USER" 2>/dev/null || true
    rm -f "/etc/sudoers.d/tsuite-support-$SESSION_ID"
    rm -rf /etc/tsuite-support-client
    rm -f /etc/systemd/system/tsuite-support-client.service \
      /etc/systemd/system/tsuite-support-client-cleanup.service \
      /etc/systemd/system/tsuite-support-client-expiry.timer \
      /etc/systemd/system/tsuite-support-client-monitor.service \
      /usr/local/sbin/tsuite-support-client
    systemctl daemon-reload
    ;;
  *) printf '用法: sudo tsuite-support-client {open|close|status}\n' >&2; exit 1 ;;
esac
EOF
chmod 0755 /usr/local/sbin/tsuite-support-client

runtime_seconds="$((expires_at - $(date +%s)))"
((runtime_seconds > 0)) || die "支持会话在安装完成前已过期"
runtime_limit="RuntimeMaxSec=$runtime_seconds"
"$renewable" && runtime_limit=""
cat >/etc/systemd/system/tsuite-support-client.service <<EOF
[Unit]
Description=TSuite temporary reverse SSH support session
After=network-online.target ssh.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/tsuite-support-client run-tunnel
Restart=on-failure
RestartSec=5
$runtime_limit
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/tsuite-support-client-cleanup.service <<'EOF'
[Unit]
Description=Cleanup TSuite support session

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 2
ExecStart=/usr/local/sbin/tsuite-support-client cleanup-if-expired
EOF
cat >/etc/systemd/system/tsuite-support-client-expiry.timer <<EOF
[Unit]
Description=Expire TSuite support session

[Timer]
OnBootSec=15s
OnUnitActiveSec=15s
Persistent=true
AccuracySec=5s
Unit=tsuite-support-client-cleanup.service

[Install]
WantedBy=timers.target
EOF
if "$renewable"; then
cat >/etc/systemd/system/tsuite-support-client-monitor.service <<'EOF'
[Unit]
Description=Renew active TSuite support lease
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 /etc/tsuite-support-client/monitor.py
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
if "$renewable"; then systemctl enable --now tsuite-support-client-monitor.service; fi
systemctl enable --now tsuite-support-client.service tsuite-support-client-expiry.timer
installation_complete=true
printf '支持会话已建立，会话 ID: %s，有效期至 epoch %s。\n' "$session_id" "$expires_at"
