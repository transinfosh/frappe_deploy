#!/usr/bin/env python3
"""Issue and serve short-lived TSuite reverse-SSH support sessions."""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any


CUSTOMER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
CREATED_BY_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
PUBLIC_KEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/=]+(?: .*)?$")
SESSION_TRANSITIONS = {
	"issued": {"enrolled", "revoking"},
	"enrolled": {"revoking"},
	"revoking": {"closed", "expired"},
	"closed": set(),
	"expired": set(),
}


class SupportError(RuntimeError):
	pass


def atomic_json_write(path: pathlib.Path, value: dict[str, Any], mode: int = 0o660) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as handle:
			json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
			handle.write("\n")
			handle.flush()
			os.fsync(handle.fileno())
		os.chmod(temporary_name, mode)
		os.replace(temporary_name, path)
	finally:
		with contextlib.suppress(FileNotFoundError):
			os.unlink(temporary_name)


def read_json(path: pathlib.Path) -> dict[str, Any]:
	with path.open(encoding="utf-8") as handle:
		value = json.load(handle)
	if not isinstance(value, dict):
		raise SupportError(f"JSON 对象格式无效: {path}")
	return value


def validate_public_key(value: str) -> str:
	value = value.strip()
	if not PUBLIC_KEY_RE.fullmatch(value):
		raise SupportError("仅支持受信任的 Ed25519/ECDSA SSH 公钥")
	return value


def key_without_comment(value: str) -> str:
	parts = validate_public_key(value).split()
	return " ".join(parts[:2])


def token_hash(token: str) -> str:
	return hashlib.sha256(token.encode()).hexdigest()


def validate_created_by(value: str) -> str:
	value = value.strip()
	if not CREATED_BY_RE.fullmatch(value):
		raise SupportError("会话创建人格式无效")
	return value


def validate_purpose(value: str, *, allow_empty: bool = False) -> str:
	value = value.strip()
	if (not value and not allow_empty) or len(value) > 200 or any(ord(character) < 32 for character in value):
		raise SupportError("支持用途必须为 1-200 个可见字符")
	return value


def chown_to_user(path: pathlib.Path, username: str) -> None:
	account = pwd.getpwnam(username)
	os.chown(path, account.pw_uid, account.pw_gid)


@dataclass(frozen=True)
class Settings:
	state_dir: pathlib.Path
	authorized_keys_dir: pathlib.Path
	downloads_dir: pathlib.Path
	download_base_url: str
	bastion_host: str
	bastion_port: int
	bastion_host_key: str
	bootstrap_path: pathlib.Path
	port_start: int
	port_end: int
	token_ttl_seconds: int
	session_ttl_seconds: int
	tunnel_group: str = "tsuite-tunnel"

	@classmethod
	def load(cls, path: pathlib.Path) -> "Settings":
		value = read_json(path)
		return cls(
			state_dir=pathlib.Path(value["state_dir"]),
			authorized_keys_dir=pathlib.Path(value["authorized_keys_dir"]),
			downloads_dir=pathlib.Path(value["downloads_dir"]),
			download_base_url=value["download_base_url"].rstrip("/"),
			bastion_host=value["bastion_host"],
			bastion_port=int(value.get("bastion_port", 22)),
			bastion_host_key=key_without_comment(value["bastion_host_key"]),
			bootstrap_path=pathlib.Path(value["bootstrap_path"]),
			port_start=int(value.get("port_start", 22000)),
			port_end=int(value.get("port_end", 22999)),
			token_ttl_seconds=int(value.get("token_ttl_seconds", 900)),
			session_ttl_seconds=int(value.get("session_ttl_seconds", 7200)),
			tunnel_group=value.get("tunnel_group", "tsuite-tunnel"),
		)

	def validate(self) -> None:
		if not re.fullmatch(r"[A-Za-z0-9.-]+", self.bastion_host):
			raise SupportError("堡垒机域名无效")
		if self.download_base_url != f"https://{self.bastion_host}/tsuite-support":
			raise SupportError("下载地址必须使用堡垒机 HTTPS 域名和 /tsuite-support 路径")
		if not 1 <= self.bastion_port <= 65535:
			raise SupportError("堡垒机 SSH 端口无效")
		if not (1024 <= self.port_start <= self.port_end <= 65535):
			raise SupportError("反向端口范围无效")
		if not 60 <= self.token_ttl_seconds <= 3600:
			raise SupportError("会话码有效期无效")
		if not 300 <= self.session_ttl_seconds <= 28800:
			raise SupportError("支持会话有效期无效")
		if not self.bootstrap_path.is_file():
			raise SupportError("bootstrap 脚本不存在")


class SessionStore:
	def __init__(self, settings: Settings):
		self.settings = settings
		self.sessions_dir = settings.state_dir / "sessions"
		self.lock_path = settings.state_dir / ".lock"
		self.sessions_dir.mkdir(parents=True, exist_ok=True)
		self.lock_path.touch(mode=0o660, exist_ok=True)

	@contextlib.contextmanager
	def locked(self):
		with self.lock_path.open("r+") as handle:
			fcntl.flock(handle, fcntl.LOCK_EX)
			yield

	def path(self, session_id: str) -> pathlib.Path:
		if not re.fullmatch(r"[a-f0-9]{12}", session_id):
			raise SupportError("会话 ID 无效")
		return self.sessions_dir / f"{session_id}.json"

	def load(self, session_id: str) -> dict[str, Any]:
		path = self.path(session_id)
		if not path.exists():
			raise SupportError("会话不存在")
		return read_json(path)

	def save(self, session: dict[str, Any]) -> None:
		atomic_json_write(self.path(session["id"]), session)

	def all(self) -> list[dict[str, Any]]:
		return [read_json(path) for path in sorted(self.sessions_dir.glob("*.json"))]

	def transition(self, session: dict[str, Any], status: str) -> None:
		current = session["status"]
		if status == current:
			return
		if status not in SESSION_TRANSITIONS[current]:
			raise SupportError(f"非法会话状态迁移: {current} -> {status}")
		session["status"] = status
		session[f"{status}_at"] = int(time.time())

	def find_by_token(self, supplied_hash: str) -> dict[str, Any] | None:
		for session in self.all():
			if token_digest := session.get("token_hash"):
				if secrets.compare_digest(token_digest, supplied_hash):
					return session
		return None


def port_available(host: str, port: int) -> bool:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
		probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			probe.bind((host, port))
		except OSError:
			return False
	return True


def port_listening(host: str, port: int) -> bool:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
		probe.settimeout(0.3)
		return probe.connect_ex((host, port)) == 0


def allocate_port(store: SessionStore) -> int:
	reserved = {
		int(session["remote_port"])
		for session in store.all()
		if session["status"] not in {"closed", "expired"}
	}
	for port in range(store.settings.port_start, store.settings.port_end + 1):
		if port not in reserved and port_available("127.0.0.1", port):
			return port
	raise SupportError("没有可用的反向 SSH 端口")


def run(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
	return subprocess.run(args, input=input_text, text=True, check=True, capture_output=True)


def create_tunnel_identity(session_id: str, customer: str, settings: Settings) -> tuple[str, str, str]:
	username = f"tsuite-tunnel-{session_id[:8]}"
	if os.geteuid() != 0:
		raise SupportError("创建会话必须使用 root")
	if shutil.which("useradd") is None or shutil.which("ssh-keygen") is None:
		raise SupportError("缺少 useradd 或 ssh-keygen")
	try:
		run("getent", "passwd", username)
		raise SupportError(f"隧道用户已存在: {username}")
	except subprocess.CalledProcessError:
		pass
	run(
		"useradd", "--system", "--gid", settings.tunnel_group,
		"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
		"--password", "NP", username,
	)
	try:
		with tempfile.TemporaryDirectory(prefix="tsuite-support-key.") as temporary_dir:
			key_path = pathlib.Path(temporary_dir) / "tunnel_ed25519"
			run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{customer}:{session_id}", "-f", str(key_path))
			private_key = key_path.read_text(encoding="utf-8")
			public_key = key_without_comment(key_path.with_suffix(".pub").read_text(encoding="utf-8"))
	except Exception:
		with contextlib.suppress(subprocess.CalledProcessError):
			run("userdel", username)
		raise
	authorized_key = (
		f'command="/usr/sbin/nologin",restrict,port-forwarding,'
		f'permitlisten="127.0.0.1:{{remote_port}}",expiry-time="{{expiry}}" '
		f'{public_key} {customer}:{session_id}\n'
	)
	return username, private_key, authorized_key


def create_key_pair(comment: str) -> tuple[str, str]:
	with tempfile.TemporaryDirectory(prefix="tsuite-support-key.") as temporary_dir:
		key_path = pathlib.Path(temporary_dir) / "key_ed25519"
		run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key_path))
		return (
			key_path.read_text(encoding="utf-8"),
			key_without_comment(key_path.with_suffix(".pub").read_text(encoding="utf-8")),
		)


def ssh_expiry(epoch: int) -> str:
	return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(epoch))


def rewrite_enrollment_authorized_keys(store: SessionStore) -> None:
	lines = []
	for session in store.all():
		public_key = session.get("enrollment_public_key")
		if session["status"] not in {"issued", "enrolled"} or not public_key:
			continue
		lines.append(
			f'command="sudo -n /usr/local/sbin/tsuite-support-session --config '
			f'/etc/tsuite-support/config.json enroll-ssh {session["id"]}",'
			f'restrict,expiry-time="{ssh_expiry(session["token_expires_at"])}" '
			f'{public_key} enrollment:{session["id"]}\n'
		)
	for session in store.all():
		if session["status"] != "enrolled" or not session.get("lease_public_key"):
			continue
		lines.append(
			f'command="sudo -n /usr/local/sbin/tsuite-support-session --config '
			f'/etc/tsuite-support/config.json lease-ssh {session["id"]}",'
			f'restrict,expiry-time="{ssh_expiry(session["expires_at"])}" '
			f'{session["lease_public_key"]} lease:{session["id"]}\n'
		)
	path = store.settings.authorized_keys_dir / "tsuite-enroll"
	path.parent.mkdir(parents=True, exist_ok=True)
	temporary = path.with_name(f".{path.name}.{os.getpid()}")
	try:
		temporary.write_text("".join(lines), encoding="utf-8")
		os.chmod(temporary, 0o600)
		chown_to_user(temporary, "tsuite-enroll")
		os.replace(temporary, path)
	finally:
		with contextlib.suppress(FileNotFoundError):
			temporary.unlink()


def read_public_key(path: str) -> str:
	if path == "-":
		return key_without_comment(sys.stdin.read())
	return key_without_comment(pathlib.Path(path).read_text(encoding="utf-8"))


def create_session(
	store: SessionStore,
	customer: str,
	operator_public_key: str,
	created_by: str,
	purpose: str = "",
	platform: str = "linux",
) -> tuple[dict[str, Any], str]:
	if not CUSTOMER_RE.fullmatch(customer):
		raise SupportError("客户标识仅允许小写字母、数字和连字符")
	created_by = validate_created_by(created_by)
	purpose = validate_purpose(purpose, allow_empty=True)
	if platform not in {"linux", "windows"}:
		raise SupportError("客户操作系统无效")
	settings = store.settings
	settings.validate()
	if platform == "windows":
		for name in ("bootstrap.ps1", "windows-client.ps1"):
			if not settings.bootstrap_path.with_name(name).is_file():
				raise SupportError("请先安装 Windows 客户脚本")
	with store.locked():
		session_id = secrets.token_hex(6)
		while store.path(session_id).exists():
			session_id = secrets.token_hex(6)
		remote_port = allocate_port(store)
		token = secrets.token_urlsafe(32)
		download_id = secrets.token_urlsafe(32)
		now = int(time.time())
		username, private_key, authorized_key_template = create_tunnel_identity(session_id, customer, settings)
		enrollment_private_key, enrollment_public_key = create_key_pair(f"enrollment:{session_id}")
		authorized_keys_path = settings.authorized_keys_dir / username
		try:
			authorized_key = authorized_key_template.format(
				remote_port=remote_port,
				expiry=ssh_expiry(now + settings.session_ttl_seconds),
			)
			settings.authorized_keys_dir.mkdir(parents=True, exist_ok=True)
			authorized_keys_path.write_text(authorized_key, encoding="utf-8")
			os.chmod(authorized_keys_path, 0o600)
			chown_to_user(authorized_keys_path, username)
			session = {
				"id": session_id,
				"customer": customer,
				"platform": platform,
				"auth_mode": "enrollment-key",
				"idle_timeout_seconds": settings.session_ttl_seconds,
				"created_by": created_by,
				"purpose": purpose,
				"status": "issued",
				"created_at": now,
				"token_expires_at": now + settings.token_ttl_seconds,
				"expires_at": now + settings.token_ttl_seconds,
				"token_hash": token_hash(token),
				"download_id": download_id,
				"remote_port": remote_port,
				"tunnel_user": username,
				"tunnel_private_key": private_key,
				"operator_public_key": key_without_comment(operator_public_key),
				"enrollment_private_key": enrollment_private_key,
				"enrollment_public_key": enrollment_public_key,
			}
			store.save(session)
			rewrite_enrollment_authorized_keys(store)
			write_customer_script(settings, session)
		except Exception:
			with contextlib.suppress(FileNotFoundError):
				authorized_keys_path.unlink()
			with contextlib.suppress(subprocess.CalledProcessError):
				run("userdel", username)
			with contextlib.suppress(FileNotFoundError):
				store.path(session_id).unlink()
			with contextlib.suppress(FileNotFoundError):
				(settings.downloads_dir / download_id).unlink()
			with contextlib.suppress(Exception):
				rewrite_enrollment_authorized_keys(store)
			raise
	return session, token


def public_session(session: dict[str, Any]) -> dict[str, Any]:
	secret_fields = {
		"token_hash", "tunnel_private_key", "operator_public_key", "enroll_nonce",
		"enrollment_private_key", "enrollment_public_key", "download_id",
		"lease_private_key", "lease_public_key",
	}
	return {key: value for key, value in session.items() if key not in secret_fields}


def enrollment_payload(session: dict[str, Any], settings: Settings) -> dict[str, Any]:
	return {
		"schema_version": 2 if session.get("idle_timeout_seconds") else 1,
		**({"idle_timeout_seconds": session["idle_timeout_seconds"],
			"lease_private_key": session["lease_private_key"]} if session.get("idle_timeout_seconds") else {}),
		"platform": session.get("platform", "linux"),
		"session_id": session["id"],
		"customer": session["customer"],
		"expires_at": session["expires_at"],
		"bastion_host": settings.bastion_host,
		"bastion_port": settings.bastion_port,
		"bastion_host_key": settings.bastion_host_key,
		"remote_port": session["remote_port"],
		"tunnel_user": session["tunnel_user"],
		"tunnel_private_key": session["tunnel_private_key"],
		"operator_public_key": session["operator_public_key"],
	}


def enrollment_authenticated(session: dict[str, Any], token: str, key_authenticated: bool) -> bool:
	if session.get("auth_mode") == "enrollment-key":
		return key_authenticated
	return secrets.compare_digest(session.get("token_hash", ""), token_hash(token))


def rewrite_tunnel_expiry(store: SessionStore, session: dict[str, Any]) -> None:
	path = store.settings.authorized_keys_dir / session["tunnel_user"]
	text = path.read_text(encoding="utf-8")
	text, count = re.subn(r'expiry-time="[0-9]{14}Z"', f'expiry-time="{ssh_expiry(session["expires_at"])}"', text)
	if count != 1:
		raise SupportError("隧道公钥到期配置无效")
	temporary = path.with_name(f".{path.name}.{os.getpid()}")
	try:
		temporary.write_text(text, encoding="utf-8")
		os.chmod(temporary, 0o600)
		chown_to_user(temporary, session["tunnel_user"])
		os.replace(temporary, path)
	finally:
		with contextlib.suppress(FileNotFoundError):
			temporary.unlink()


def renew_lease(store: SessionStore, session_id: str, active: bool) -> dict[str, Any]:
	if type(active) is not bool:
		raise SupportError("活动标志无效")
	with store.locked():
		session = store.load(session_id)
		now = int(time.time())
		if session["status"] != "enrolled" or now >= session["expires_at"]:
			raise SupportError("支持会话已经结束或过期")
		if not session.get("idle_timeout_seconds"):
			raise SupportError("旧会话不支持续期")
		if active:
			session["last_activity_at"] = now
			session["expires_at"] = max(session["expires_at"], now + session["idle_timeout_seconds"])
			rewrite_tunnel_expiry(store, session)
			store.save(session)
			rewrite_enrollment_authorized_keys(store)
		return {"session_id": session_id, "expires_at": session["expires_at"],
			"idle_timeout_seconds": session["idle_timeout_seconds"]}


def lease_ssh(store: SessionStore, session_id: str) -> None:
	if os.environ.get("SSH_ORIGINAL_COMMAND") != "lease":
		raise SupportError("续期密钥仅允许 lease")
	request = sys.stdin.buffer.readline(1025)
	if not request or len(request) > 1024 or sys.stdin.buffer.read(1):
		raise SupportError("续期请求大小无效")
	try:
		body = json.loads(request)
		if not isinstance(body, dict) or set(body) != {"active"}:
			raise SupportError("续期请求格式无效")
		payload = renew_lease(store, session_id, body["active"])
	except (ValueError, TypeError) as error:
		raise SupportError("续期请求格式无效") from error
	print(json.dumps(payload, separators=(",", ":")))


def confirm_session_replacement(
	store: SessionStore,
	token: str,
	new_session_id: str,
	existing_session_id: str,
	*, key_authenticated: bool = False,
) -> str:
	"""Confirm that a local session residue belongs to a terminal edge session.

	This deliberately does not consume the new enrollment token. The customer can
	retry safely if local cleanup fails after the confirmation.
	"""
	now = int(time.time())
	with store.locked():
		new_session = store.load(new_session_id)
		if not enrollment_authenticated(new_session, token, key_authenticated):
			raise SupportError("会话码无效")
		if new_session["status"] != "issued":
			raise SupportError("会话码已经被使用")
		if now >= new_session["token_expires_at"]:
			raise SupportError("会话码已过期")
		if now >= new_session["expires_at"]:
			raise SupportError("支持会话已过期")
		if existing_session_id == new_session_id:
			raise SupportError("本机登记的会话与新会话相同")
		existing_session = store.load(existing_session_id)
		if existing_session["status"] not in {"closed", "expired"}:
			raise SupportError("本机登记的旧支持会话仍处于活动状态，请先关闭")
	return existing_session_id


def enroll(store: SessionStore, token: str, nonce: str, customer_host_key: str, session_id: str | None = None, *, key_authenticated: bool = False) -> dict[str, Any]:
	if not NONCE_RE.fullmatch(nonce):
		raise SupportError("enrollment nonce 无效")
	customer_host_key = key_without_comment(customer_host_key)
	now = int(time.time())
	with store.locked():
		session = store.load(session_id) if session_id else store.find_by_token(token_hash(token))
		if session is None or not enrollment_authenticated(session, token, key_authenticated):
			raise SupportError("会话码无效")
		if now >= session["token_expires_at"] and session["status"] in {"issued", "enrolled"}:
			raise SupportError("会话码已过期")
		if now >= session["expires_at"]:
			raise SupportError("支持会话已过期")
		if session["status"] == "issued":
			if session.get("idle_timeout_seconds"):
				session["expires_at"] = now + session["idle_timeout_seconds"]
				session["last_activity_at"] = now
				session["lease_private_key"], session["lease_public_key"] = create_key_pair(f'lease:{session["id"]}')
				rewrite_tunnel_expiry(store, session)
			session["enroll_nonce"] = nonce
			session["customer_host_key"] = customer_host_key
			session.pop("enrollment_private_key", None)
			if not session.get("idle_timeout_seconds"):
				session.pop("enrollment_public_key", None)
			store.transition(session, "enrolled")
			store.save(session)
		elif session["status"] == "enrolled" and secrets.compare_digest(session.get("enroll_nonce", ""), nonce):
			if not secrets.compare_digest(session["customer_host_key"], customer_host_key):
				raise SupportError("同一 enrollment nonce 的客户 Host Key 不一致")
		else:
			raise SupportError("会话码已经被使用")
		if session.get("idle_timeout_seconds"):
			rewrite_enrollment_authorized_keys(store)
			remove_customer_script(store.settings, session)
	return enrollment_payload(session, store.settings)


def terminate_session(
	store: SessionStore,
	session: dict[str, Any],
	status: str,
	*,
	closed_by: str,
	close_mode: str,
	close_reason: str,
) -> None:
	if session["status"] != "revoking":
		if close_mode not in {"normal", "force", "expiry"}:
			raise SupportError("会话关闭方式无效")
		session["closed_by"] = validate_created_by(closed_by)
		session["close_mode"] = close_mode
		session["close_reason"] = validate_purpose(close_reason)
		store.transition(session, "revoking")
		session.pop("enrollment_private_key", None)
		session.pop("enrollment_public_key", None)
		remove_customer_script(store.settings, session)
		store.save(session)
		rewrite_enrollment_authorized_keys(store)
	with contextlib.suppress(subprocess.CalledProcessError):
		run("pkill", "-KILL", "-u", session["tunnel_user"])
	authorized_key_path = store.settings.authorized_keys_dir / session["tunnel_user"]
	with contextlib.suppress(FileNotFoundError):
		authorized_key_path.unlink()
	if os.geteuid() == 0:
		with contextlib.suppress(subprocess.CalledProcessError):
			run("userdel", session["tunnel_user"])
	for _ in range(10):
		if not port_listening("127.0.0.1", int(session["remote_port"])):
			break
		time.sleep(0.05)
	user_still_exists = subprocess.run(
		["getent", "passwd", session["tunnel_user"]],
		check=False, capture_output=True,
	).returncode == 0
	if authorized_key_path.exists() or user_still_exists or port_listening("127.0.0.1", int(session["remote_port"])):
		raise SupportError(f"会话 {session['id']} 撤销未完成，将由 GC 重试")
	session.pop("tunnel_private_key", None)
	session.pop("operator_public_key", None)
	session.pop("token_hash", None)
	session.pop("lease_private_key", None)
	session.pop("lease_public_key", None)
	session.pop("enroll_nonce", None)
	store.transition(session, status)
	store.save(session)
	rewrite_enrollment_authorized_keys(store)


def gc_terminal_status(session: dict[str, Any]) -> str:
	if session.get("status") == "revoking" and session.get("close_mode") in {"normal", "force"}:
		return "closed"
	return "expired"


def enroll_ssh(store: SessionStore, session_id: str) -> None:
	original_command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
	if original_command == "bootstrap":
		sys.stdout.write(store.settings.bootstrap_path.read_text(encoding="utf-8"))
		return
	if original_command == "linux-client":
		sys.stdout.write(store.settings.bootstrap_path.with_name("linux-client.py").read_text(encoding="utf-8"))
		return
	if original_command not in {"reconcile", "enroll"}:
		raise SupportError("仅允许 bootstrap、reconcile 或 enroll")
	request = sys.stdin.buffer.readline(8193)
	if not request or len(request) > 8192 or sys.stdin.buffer.read(1):
		raise SupportError("enrollment 请求大小无效")
	try:
		body = json.loads(request)
		if original_command == "reconcile":
			existing_session_id = confirm_session_replacement(
				store, body.get("token", ""), session_id, body["existing_session_id"], key_authenticated=True
			)
			payload = {"replace_existing_session": existing_session_id}
		else:
			payload = enroll(
				store, body.get("token", ""), body["nonce"], body["customer_host_key"], session_id, key_authenticated=True
			)
	except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
		raise SupportError("enrollment 请求格式无效") from error
	print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def customer_script(settings: Settings, session: dict[str, Any]) -> str:
	if session.get("platform", "linux") == "windows":
		configuration = {
			"session_id": session["id"],
			"bastion_host": settings.bastion_host,
			"bastion_port": settings.bastion_port,
			"bastion_host_key": settings.bastion_host_key,
			"enrollment_private_key": session["enrollment_private_key"],
		}
		bootstrap = settings.bootstrap_path.with_name("bootstrap.ps1").read_text(encoding="utf-8")
		client = settings.bootstrap_path.with_name("windows-client.ps1").read_bytes()
		return bootstrap.replace(
			"__TSUITE_CONFIG_BASE64__", base64.b64encode(json.dumps(configuration).encode()).decode()
		).replace("__TSUITE_CLIENT_BASE64__", base64.b64encode(client).decode())
	enrollment_key = base64.b64encode(session["enrollment_private_key"].encode()).decode()
	known_host = settings.bastion_host
	if settings.bastion_port != 22:
		known_host = f"[{known_host}]:{settings.bastion_port}"
	inner = "\n".join((
		"set -Eeuo pipefail",
		'temporary="$(mktemp -d /tmp/tsuite-support-enroll.XXXXXX)"',
		'trap \'rm -rf -- "$temporary"\' EXIT',
		"umask 077",
		f"printf %s {shlex.quote(enrollment_key)} | base64 --decode >\"$temporary/enrollment_key\"",
		f"printf '%s\\n' {shlex.quote(f'{known_host} {settings.bastion_host_key}')} >\"$temporary/known_hosts\"",
		"ssh -F none -T -i \"$temporary/enrollment_key\" -o IdentitiesOnly=yes -o BatchMode=yes "
		"-o StrictHostKeyChecking=yes -o UserKnownHostsFile=\"$temporary/known_hosts\" "
		"-o ClearAllForwardings=yes "
		f"-p {settings.bastion_port} tsuite-enroll@{shlex.quote(settings.bastion_host)} bootstrap | "
		"sudo bash -s -- --enrollment-key \"$temporary/enrollment_key\" "
		"--known-hosts \"$temporary/known_hosts\" "
		f"--bastion-host {shlex.quote(settings.bastion_host)} --bastion-port {settings.bastion_port} "
		"--accept-temporary-root-access --key-auth",
	))
	return f"bash -c {shlex.quote(inner)}"


def customer_command(settings: Settings, session: dict[str, Any]) -> str:
	download_id = session.get("download_id", "")
	if not re.fullmatch(r"[A-Za-z0-9_-]{43}", download_id):
		raise SupportError("下载标识无效")
	url = f"{settings.download_base_url}/{download_id}"
	if session.get("platform", "linux") == "windows":
		return (
			"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
			f'"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; '
			f"& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('{url}')))\""
		)
	return f"curl -fsS --proto '=https' --tlsv1.2 {shlex.quote(url)} | sudo bash"


def write_customer_script(settings: Settings, session: dict[str, Any]) -> None:
	settings.downloads_dir.mkdir(parents=True, exist_ok=True)
	path = settings.downloads_dir / session["download_id"]
	fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as handle:
			handle.write(customer_script(settings, session))
			handle.write("\n")
			handle.flush()
			os.fsync(handle.fileno())
		os.chmod(temporary_name, 0o640)
		os.replace(temporary_name, path)
	finally:
		with contextlib.suppress(FileNotFoundError):
			os.unlink(temporary_name)


def remove_customer_script(settings: Settings, session: dict[str, Any]) -> None:
	download_id = session.get("download_id", "")
	if re.fullmatch(r"[A-Za-z0-9_-]{43}", download_id):
		with contextlib.suppress(FileNotFoundError):
			(settings.downloads_dir / download_id).unlink()


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--config", default="/etc/tsuite-support/config.json")
	subparsers = parser.add_subparsers(dest="command", required=True)
	create = subparsers.add_parser("create")
	create.add_argument("--customer", required=True)
	create.add_argument("--operator-public-key", required=True)
	create.add_argument("--created-by", required=True)
	create.add_argument("--purpose", default="")
	create.add_argument("--platform", choices=("linux", "windows"), default="linux")
	create.add_argument("--json", action="store_true")
	show = subparsers.add_parser("show")
	show.add_argument("session_id")
	show.add_argument("--json", action="store_true")
	subparsers.add_parser("list")
	close = subparsers.add_parser("close")
	close.add_argument("session_id")
	close.add_argument("--closed-by", required=True)
	close.add_argument("--mode", required=True, choices=("normal", "force"))
	close.add_argument("--reason", required=True)
	subparsers.add_parser("gc")
	enroll_parser = subparsers.add_parser("enroll-ssh")
	enroll_parser.add_argument("session_id")
	lease_parser = subparsers.add_parser("lease-ssh")
	lease_parser.add_argument("session_id")
	return parser


def main() -> int:
	args = build_parser().parse_args()
	settings = Settings.load(pathlib.Path(args.config))
	settings.validate()
	store = SessionStore(settings)
	try:
		if args.command == "create":
			session, token = create_session(
				store,
				args.customer,
				read_public_key(args.operator_public_key),
				args.created_by,
				args.purpose,
				args.platform,
			)
			result = public_session(session) | {"token": token}
			result["customer_command"] = customer_command(settings, session)
			print(json.dumps(result, ensure_ascii=False) if args.json else result["customer_command"])

		elif args.command == "show":
			result = public_session(store.load(args.session_id))
			result["tunnel_reachable"] = port_listening("127.0.0.1", int(result["remote_port"]))
			print(json.dumps(result, ensure_ascii=False) if args.json else json.dumps(result, ensure_ascii=False, indent=2))
		elif args.command == "list":
			for session in store.all():
				print(f"{session['id']}\t{session['customer']}\t{session['status']}\t{session['remote_port']}")
		elif args.command == "close":
			with store.locked():
				session = store.load(args.session_id)
				if session["status"] not in {"closed", "expired"}:
					terminate_session(
						store,
						session,
						"closed",
						closed_by=args.closed_by,
						close_mode=args.mode,
						close_reason=args.reason,
					)
		elif args.command == "gc":
			now = int(time.time())
			gc_errors = []
			with store.locked():
				for session in store.all():
					if session["status"] == "enrolled" or now >= session["token_expires_at"]:
						remove_customer_script(settings, session)
					token_expired = session["status"] == "issued" and now >= session["token_expires_at"]
					session_expired = now >= session["expires_at"]
					should_retry = session["status"] == "revoking"
					if session["status"] not in {"closed", "expired"} and (token_expired or session_expired or should_retry):
						try:
							terminal_status = gc_terminal_status(session)
							terminate_session(
								store,
								session,
								terminal_status,
								closed_by="system:expiry",
								close_mode="expiry",
								close_reason="支持会话或一次性会话码已到期",
							)
						except SupportError as error:
							gc_errors.append(str(error))
			if gc_errors:
				raise SupportError("；".join(gc_errors))
		elif args.command == "lease-ssh":
			lease_ssh(store, args.session_id)
		elif args.command == "enroll-ssh":
			enroll_ssh(store, args.session_id)
		return 0
	except SupportError as error:
		print(f"错误: {error}", file=sys.stderr)
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
