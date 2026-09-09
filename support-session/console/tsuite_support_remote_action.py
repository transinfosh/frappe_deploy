#!/usr/bin/env python3
"""Broker per-session operator keys and constrained support actions."""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any


CUSTOMER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
SESSION_RE = re.compile(r"^[a-f0-9]{12}$")
CREATED_BY_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
PUBLIC_KEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+$")
CONTROL_PATH = "/var/lib/tsuite-support-operator/ssh-control-%C"
CONFIG_PATH = pathlib.Path("/etc/tsuite-support-control/action.json")


class RemoteActionError(RuntimeError):
	pass


def atomic_write(path: pathlib.Path, content: str, mode: int = 0o600) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as handle:
			handle.write(content)
			handle.flush()
			os.fsync(handle.fileno())
		os.chmod(temporary_name, mode)
		os.replace(temporary_name, path)
	finally:
		with contextlib.suppress(FileNotFoundError):
			os.unlink(temporary_name)


def read_json(path: pathlib.Path) -> dict[str, Any]:
	try:
		with path.open(encoding="utf-8") as handle:
			value = json.load(handle)
	except (FileNotFoundError, json.JSONDecodeError) as error:
		raise RemoteActionError(f"配置或状态无效: {path}") from error
	if not isinstance(value, dict):
		raise RemoteActionError(f"配置或状态必须是 JSON 对象: {path}")
	return value


@dataclass(frozen=True)
class Settings:
	host: str
	port: int
	user: str
	bridge_identity_file: pathlib.Path
	edge_identity_file: pathlib.Path
	known_hosts_file: pathlib.Path
	state_dir: pathlib.Path

	@classmethod
	def load(cls, path: pathlib.Path = CONFIG_PATH) -> "Settings":
		value = read_json(path)
		settings = cls(
			host=str(value["host"]),
			port=int(value.get("port", 22)),
			user=str(value["user"]),
			bridge_identity_file=pathlib.Path(value["bridge_identity_file"]),
			edge_identity_file=pathlib.Path(value["edge_identity_file"]),
			known_hosts_file=pathlib.Path(value["known_hosts_file"]),
			state_dir=pathlib.Path(value["state_dir"]),
		)
		settings.validate()
		return settings

	def validate(self) -> None:
		if not re.fullmatch(r"[A-Za-z0-9.-]+", self.host):
			raise RemoteActionError("堡垒机域名无效")
		if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.user):
			raise RemoteActionError("堡垒机用户名无效")
		if not 1 <= self.port <= 65535:
			raise RemoteActionError("堡垒机 SSH 端口无效")
		for path in (self.bridge_identity_file, self.edge_identity_file, self.known_hosts_file):
			if not path.is_file():
				raise RemoteActionError(f"SSH 文件不存在: {path}")
		if not self.state_dir.is_dir():
			raise RemoteActionError(f"会话状态目录不存在: {self.state_dir}")


def validate_customer(value: str) -> str:
	if not CUSTOMER_RE.fullmatch(value):
		raise argparse.ArgumentTypeError("客户标识无效")
	return value


def validate_session_id(value: str) -> str:
	if not SESSION_RE.fullmatch(value):
		raise argparse.ArgumentTypeError("会话 ID 无效")
	return value


def validate_created_by(value: str) -> str:
	if not CREATED_BY_RE.fullmatch(value):
		raise argparse.ArgumentTypeError("会话创建人格式无效")
	return value


def validate_purpose(value: str, *, allow_empty: bool = False) -> str:
	value = value.strip()
	if (not value and not allow_empty) or len(value) > 200 or any(ord(character) < 32 for character in value):
		raise argparse.ArgumentTypeError("支持用途必须为 1-200 个可见字符")
	return value


def run(
	args: list[str],
	*,
	input_text: str | None = None,
	env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
	return subprocess.run(
		args, input=input_text, text=True, check=False, capture_output=True, env=env
	)


def customer_proxy_environment() -> dict[str, str]:
	# ProxyCommand is executed through $SHELL. Keep the broker account nologin,
	# and override the shell only for the strictly generated customer SSH child.
	environment = os.environ.copy()
	environment["SHELL"] = "/bin/sh"
	return environment


def ensure_success(result: subprocess.CompletedProcess[str], message: str) -> str:
	if result.returncode != 0:
		detail = result.stderr.strip() or message
		raise RemoteActionError(detail)
	return result.stdout


def bridge_ssh_args(settings: Settings, *, multiplex: bool = True) -> list[str]:
	arguments = [
		"ssh", "-F", "none", "-T", "-i", str(settings.bridge_identity_file),
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", f"UserKnownHostsFile={settings.known_hosts_file}",
		"-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10",
		"-o", "ConnectionAttempts=1", "-p", str(settings.port),
	]
	if multiplex:
		arguments.extend([
			"-o", "ControlMaster=auto", "-o", "ControlPersist=3600",
			"-o", f"ControlPath={CONTROL_PATH}",
		])
	else:
		arguments.extend(["-o", "ControlMaster=no", "-o", "ControlPath=none"])
	arguments.append(f"{settings.user}@{settings.host}")
	return arguments


def test_edge_operator(settings: Settings) -> None:
	result = run([
		"ssh", "-F", "none", "-T", "-i", str(settings.edge_identity_file),
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", f"UserKnownHostsFile={settings.known_hosts_file}",
		"-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10",
		"-o", "ConnectionAttempts=1", "-p", str(settings.port),
		f"{settings.user}@{settings.host}", "self-test",
	])
	ensure_success(result, "edge forced proxy 自检失败")


def remote_action(
	settings: Settings,
	*arguments: str,
	input_text: str | None = None,
	multiplex: bool = True,
) -> subprocess.CompletedProcess[str]:
	return run([*bridge_ssh_args(settings, multiplex=multiplex), *arguments], input_text=input_text)


def session_state_path(settings: Settings, session_id: str) -> pathlib.Path:
	if not SESSION_RE.fullmatch(session_id):
		raise RemoteActionError("会话 ID 无效")
	return settings.state_dir / "sessions" / f"{session_id}.json"


def identity_path(settings: Settings, session_id: str) -> pathlib.Path:
	return settings.state_dir / "sessions" / f"{session_id}.ed25519"


def load_local_session(settings: Settings, session_id: str) -> dict[str, Any]:
	value = read_json(session_state_path(settings, session_id))
	if value.get("id") != session_id or value.get("identity_file") != str(identity_path(settings, session_id)):
		raise RemoteActionError("本地会话状态与会话 ID 不一致")
	if not identity_path(settings, session_id).is_file():
		raise RemoteActionError("会话 operator identity 不存在")
	return value


def remove_local_session(settings: Settings, session_id: str) -> None:
	for path in (identity_path(settings, session_id), session_state_path(settings, session_id)):
		with contextlib.suppress(FileNotFoundError):
			path.unlink()


def remote_session(settings: Settings, session_id: str) -> dict[str, Any]:
	result = remote_action(settings, "show", session_id)
	try:
		value = json.loads(ensure_success(result, "无法读取堡垒机会话"))
	except json.JSONDecodeError as error:
		raise RemoteActionError("堡垒机返回了无效会话状态") from error
	if not isinstance(value, dict) or value.get("id") != session_id:
		raise RemoteActionError("堡垒机会话与请求不一致")
	return value


def close_remote(
	settings: Settings,
	session_id: str,
	closed_by: str,
	mode: str,
	reason: str,
) -> subprocess.CompletedProcess[str]:
	request = json.dumps({
		"closed_by": closed_by,
		"mode": mode,
		"reason": reason,
	}, ensure_ascii=False, separators=(",", ":")) + "\n"
	return remote_action(settings, "close", session_id, input_text=request)


def create_session(
	settings: Settings, customer: str, created_by: str, purpose: str = "", platform: str = "linux",
) -> dict[str, Any]:
	if platform not in ("linux", "windows"):
		raise RemoteActionError("客户操作系统无效")
	sessions_dir = settings.state_dir / "sessions"
	sessions_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
	with tempfile.TemporaryDirectory(prefix="tsuite-support-operator.") as temporary_dir:
		key_path = pathlib.Path(temporary_dir) / "operator_ed25519"
		key_result = run([
			"ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
			f"tsuite-support:{customer}:{created_by}", "-f", str(key_path),
		])
		ensure_success(key_result, "无法生成会话 operator identity")
		public_key = key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()
		request = json.dumps({
			"customer": customer,
			"platform": platform,
			"operator_public_key": public_key,
			"created_by": created_by,
			"purpose": purpose,
		}, ensure_ascii=False, separators=(",", ":")) + "\n"
		created_result = remote_action(settings, "create", input_text=request)
		try:
			created = json.loads(ensure_success(created_result, "堡垒机会话创建失败"))
		except json.JSONDecodeError as error:
			raise RemoteActionError("堡垒机返回了无效创建结果") from error
		session_id = created.get("id") if isinstance(created, dict) else None
		if not isinstance(session_id, str) or not SESSION_RE.fullmatch(session_id):
			raise RemoteActionError("堡垒机返回了无效会话 ID")
		if created.get("platform", "linux") != platform:
			close_remote(settings, session_id, "system:broker", "force", "堡垒机未返回请求的操作系统")
			raise RemoteActionError("堡垒机不支持请求的操作系统，请同步升级")
		if not isinstance(created.get("token"), str) or not isinstance(created.get("customer_command"), str):
			close_remote(settings, session_id, "system:broker", "force", "堡垒机返回的会话凭据无效")
			raise RemoteActionError("堡垒机返回的会话凭据无效")
		if not isinstance(created.get("expires_at"), int) or created["expires_at"] <= int(time.time()):
			close_remote(settings, session_id, "system:broker", "force", "堡垒机返回的会话到期时间无效")
			raise RemoteActionError("堡垒机返回的会话到期时间无效")
		try:
			atomic_write(identity_path(settings, session_id), key_path.read_text(encoding="utf-8"))
			atomic_write(
				session_state_path(settings, session_id),
				json.dumps({
					"id": session_id,
					"customer": customer,
					"platform": platform,
					"created_by": created_by,
					"purpose": purpose,
					"expires_at": created["expires_at"],
					"idle_timeout_seconds": created.get("idle_timeout_seconds"),
					"identity_file": str(identity_path(settings, session_id)),
				}, ensure_ascii=False, sort_keys=True) + "\n",
			)
		except Exception:
			close_remote(settings, session_id, "system:broker", "force", "控制机无法保存会话独立私钥")
			remove_local_session(settings, session_id)
			raise
	return created


def windows_command(command: list[str]) -> str:
	"""Pass native Windows argv without cmd.exe or PowerShell string interpolation."""
	quote = lambda value: "'" + value.replace("'", "''") + "'"
	script = (
		"$ErrorActionPreference = 'Stop'; $start = New-Object Diagnostics.ProcessStartInfo; "
		f"$start.FileName = {quote(command[0])}; "
		f"$start.Arguments = {quote(subprocess.list2cmdline(command[1:]))}; "
		"$start.UseShellExecute = $false; $process = [Diagnostics.Process]::Start($start); "
		"$process.WaitForExit(); exit $process.ExitCode"
	)
	return encoded_powershell(script)


def encoded_powershell(script: str) -> str:
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + base64.b64encode(
		script.encode("utf-16-le")
	).decode()


def windows_cleanup(session_id: str) -> str:
	if not re.fullmatch(r"[a-f0-9]{12}", session_id):
		raise ValueError("会话 ID 无效")
	return encoded_powershell(
		f"& (Join-Path $env:ProgramData 'TSuiteSupport/{session_id}/client.ps1') "
		f"-Mode Close -SessionId '{session_id}'"
	)


def customer_ssh_args(
	settings: Settings,
	session_id: str,
	remote: dict[str, Any],
	known_hosts: pathlib.Path,
) -> list[str]:
	load_local_session(settings, session_id)
	host_key = remote.get("customer_host_key")
	if not isinstance(host_key, str) or not PUBLIC_KEY_RE.fullmatch(host_key):
		raise RemoteActionError("客户尚未接入或客户 Host Key 无效")
	port = int(remote.get("remote_port", 0))
	if not 1024 <= port <= 65535:
		raise RemoteActionError("客户反向端口无效")
	if remote.get("status") != "enrolled" or not remote.get("tunnel_reachable"):
		raise RemoteActionError("客户隧道当前不可达")
	atomic_write(known_hosts, f"[127.0.0.1]:{port} {host_key}\n")
	proxy_command = shlex.join([
		"ssh", "-F", "none", "-T", "-i", str(settings.edge_identity_file),
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", f"UserKnownHostsFile={settings.known_hosts_file}",
		"-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
		"-o", "ClearAllForwardings=yes", "-p", str(settings.port),
		f"{settings.user}@{settings.host}", "proxy", session_id,
	])
	return [
		"ssh", "-F", "none", "-i", str(identity_path(settings, session_id)),
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
		"-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
		"-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
		"-o", f"ProxyCommand={proxy_command}", "-p", str(port),
		f"tsuite-ops-{session_id[:8]}@127.0.0.1",
	]


def connect_with_activity(arguments, base_arguments, remote, session_id, running_command, env=None):
	import importlib.util
	module_path = pathlib.Path(__file__).resolve().with_name("tsuite_support_activity.py")
	if not module_path.is_file():
		module_path = pathlib.Path(__file__).resolve().parents[1] / "operator" / "tsuite_support_activity.py"
	spec = importlib.util.spec_from_file_location("tsuite_support_activity", module_path)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module.connect(arguments, base_arguments, remote.get("platform", "linux"), session_id,
		running_command=running_command, env=env)


def connect_customer(settings: Settings, session_id: str, command: list[str] | None = None) -> int:
	remote = remote_session(settings, session_id)
	with tempfile.TemporaryDirectory(prefix="tsuite-support-known-hosts.") as temporary_dir:
		known_hosts = pathlib.Path(temporary_dir) / "known_hosts"
		arguments = customer_ssh_args(settings, session_id, remote, known_hosts)
		base_arguments = list(arguments)
		if command:
			arguments.append(windows_command(command) if remote.get("platform") == "windows" else shlex.join(command))
		if remote.get("idle_timeout_seconds"):
			return connect_with_activity(arguments, base_arguments, remote, session_id, bool(command), customer_proxy_environment())
		return subprocess.call(arguments, env=customer_proxy_environment())


def close_session(
	settings: Settings,
	session_id: str,
	closed_by: str,
	*,
	force: bool = False,
	reason: str | None = None,
) -> None:
	remote = remote_session(settings, session_id)
	status = str(remote.get("status", ""))
	if status in {"closed", "expired"}:
		remove_local_session(settings, session_id)
		return
	if status in {"enrolled", "revoking"} and not force:
		local = load_local_session(settings, session_id)
		if not local.get("cleanup_confirmed_at"):
			with tempfile.TemporaryDirectory(prefix="tsuite-support-known-hosts.") as temporary_dir:
				known_hosts = pathlib.Path(temporary_dir) / "known_hosts"
				arguments = customer_ssh_args(settings, session_id, remote, known_hosts)
				cleanup = run(
					[*arguments, windows_cleanup(session_id) if remote.get("platform") == "windows"
					 else "sudo -n /usr/local/sbin/tsuite-support-client close"],
					env=customer_proxy_environment(),
				)
				if cleanup.returncode != 0 or f"cleanup-scheduled:{session_id}" not in cleanup.stdout:
					raise RemoteActionError("客户侧清理未确认；会话未撤销，请重试或由运维显式 force-close")
			local["cleanup_confirmed_at"] = int(time.time())
			atomic_write(
				session_state_path(settings, session_id),
				json.dumps(local, ensure_ascii=False, sort_keys=True) + "\n",
			)
	close_reason = reason if force else (
		"客户侧清理已确认" if status in {"enrolled", "revoking"} else "客户尚未接入"
	)
	result = close_remote(
		settings,
		session_id,
		closed_by,
		"force" if force else "normal",
		close_reason or "运维人员强制撤销会话",
	)
	ensure_success(result, "堡垒机会话关闭失败")
	remove_local_session(settings, session_id)


def garbage_collect(settings: Settings) -> None:
	sessions_dir = settings.state_dir / "sessions"
	now = int(time.time())
	for state_path in sessions_dir.glob("*.json"):
		session_id = state_path.stem
		if not SESSION_RE.fullmatch(session_id):
			continue
		try:
			remote = remote_session(settings, session_id)
		except RemoteActionError:
			with contextlib.suppress(RemoteActionError, KeyError, TypeError, ValueError):
				local = load_local_session(settings, session_id)
				if not local.get("idle_timeout_seconds") and int(local["expires_at"]) <= int(time.time()):
					remove_local_session(settings, session_id)
			continue
		if remote.get("status") in {"closed", "expired"}:
			remove_local_session(settings, session_id)
	for key_path in sessions_dir.glob("*.ed25519"):
		session_id = key_path.name.removesuffix(".ed25519")
		if (
			SESSION_RE.fullmatch(session_id)
			and not session_state_path(settings, session_id).exists()
			and int(key_path.stat().st_mtime) <= now - 300
		):
			with contextlib.suppress(FileNotFoundError):
				key_path.unlink()


def parser() -> argparse.ArgumentParser:
	root = argparse.ArgumentParser(description=__doc__)
	subparsers = root.add_subparsers(dest="action", required=True)
	create = subparsers.add_parser("create")
	create.add_argument("customer", type=validate_customer)
	create.add_argument("--created-by", required=True, type=validate_created_by)
	create.add_argument("--purpose", default="", type=lambda value: validate_purpose(value, allow_empty=True))
	create.add_argument("--platform", choices=("linux", "windows"), default="linux")
	show = subparsers.add_parser("show")
	show.add_argument("session_id", type=validate_session_id)
	close = subparsers.add_parser("close")
	close.add_argument("session_id", type=validate_session_id)
	close.add_argument("--closed-by", required=True, type=validate_created_by)
	force_close = subparsers.add_parser("force-close")
	force_close.add_argument("session_id", type=validate_session_id)
	force_close.add_argument("--closed-by", required=True, type=validate_created_by)
	force_close.add_argument("--reason", required=True, type=validate_purpose)
	ssh_parser = subparsers.add_parser("ssh")
	ssh_parser.add_argument("session_id", type=validate_session_id)
	run_parser = subparsers.add_parser("run")
	run_parser.add_argument("session_id", type=validate_session_id)
	run_parser.add_argument("remote_command", nargs=argparse.REMAINDER)
	subparsers.add_parser("list")
	subparsers.add_parser("gc")
	subparsers.add_parser("self-test")
	return root


def main() -> int:
	args = parser().parse_args()
	settings = Settings.load()
	if args.action == "create":
		created = create_session(settings, args.customer, args.created_by, args.purpose, args.platform)
		print(json.dumps(created, ensure_ascii=False, separators=(",", ":")))
		return 0
	if args.action == "list":
		result = remote_action(settings, "list")
		sys.stdout.write(ensure_success(result, "无法读取会话列表"))
		return 0
	if args.action == "gc":
		garbage_collect(settings)
		return 0
	if args.action == "self-test":
		result = remote_action(settings, "list", multiplex=False)
		ensure_success(result, "控制台 forced-command bridge 自检失败")
		test_edge_operator(settings)
		return 0
	if args.action == "show":
		print(json.dumps(remote_session(settings, args.session_id), ensure_ascii=False, separators=(",", ":")))
		return 0
	if args.action == "close":
		close_session(settings, args.session_id, args.closed_by)
		return 0
	if args.action == "force-close":
		close_session(settings, args.session_id, args.closed_by, force=True, reason=args.reason)
		return 0
	if args.action == "ssh":
		return connect_customer(settings, args.session_id)
	if not args.remote_command:
		raise RemoteActionError("缺少远端命令")
	command = args.remote_command[1:] if args.remote_command[0] == "--" else args.remote_command
	if not command:
		raise RemoteActionError("缺少远端命令")
	return connect_customer(settings, args.session_id, command)


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except (RemoteActionError, KeyError, TypeError, ValueError) as error:
		print(f"错误: {error}", file=sys.stderr)
		raise SystemExit(1)
