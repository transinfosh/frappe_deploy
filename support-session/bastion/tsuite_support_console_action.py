#!/usr/bin/env python3
"""Narrow root-only bridge between the support console and session manager."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import threading


CONFIG = "/etc/tsuite-support/config.json"
MANAGER = "/usr/local/sbin/tsuite-support-session"
CUSTOMER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
SESSION_RE = re.compile(r"^[a-f0-9]{12}$")
CREATED_BY_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
MAX_CREATE_BYTES = 8192


class ActionError(RuntimeError):
	pass


def run_manager(*arguments: str, input_text: str | None = None) -> int:
	command = [MANAGER, "--config", CONFIG, *arguments]
	if os.geteuid() != 0:
		command = ["sudo", "-n", *command]
	result = subprocess.run(
		command,
		check=False,
		input=input_text,
		text=True,
		stdout=sys.stdout,
		stderr=sys.stderr,
	)
	return result.returncode


def manager_output(*arguments: str) -> str:
	command = [MANAGER, "--config", CONFIG, *arguments]
	if os.geteuid() != 0:
		command = ["sudo", "-n", *command]
	result = subprocess.run(command, check=False, capture_output=True, text=True)
	if result.returncode:
		raise ActionError(result.stderr.strip() or "无法读取会话状态")
	return result.stdout


def relay_session() -> int:
	try:
		arguments = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
	except ValueError as error:
		raise ActionError("代理命令格式无效") from error
	if arguments == ["self-test"]:
		manager_output("list")
		return 0
	if len(arguments) != 2 or arguments[0] != "proxy" or not SESSION_RE.fullmatch(arguments[1]):
		raise ActionError("仅允许代理已登记的支持会话")
	session_id = arguments[1]
	try:
		session = json.loads(manager_output("show", session_id, "--json"))
	except json.JSONDecodeError as error:
		raise ActionError("会话状态格式无效") from error
	if not isinstance(session, dict) or session.get("id") != session_id:
		raise ActionError("会话状态与代理请求不一致")
	if session.get("status") != "enrolled" or not session.get("tunnel_reachable"):
		raise ActionError("支持会话当前不可达")
	port = int(session.get("remote_port", 0))
	if not 1024 <= port <= 65535:
		raise ActionError("支持会话端口无效")
	with socket.create_connection(("127.0.0.1", port), timeout=10) as upstream:
		upstream.settimeout(None)

		def copy_input() -> None:
			try:
				while chunk := os.read(sys.stdin.fileno(), 65536):
					upstream.sendall(chunk)
			except (BrokenPipeError, ConnectionError, OSError):
				pass
			finally:
				with contextlib.suppress(OSError):
					upstream.shutdown(socket.SHUT_WR)

		threading.Thread(target=copy_input, daemon=True).start()
		while chunk := upstream.recv(65536):
			view = memoryview(chunk)
			while view:
				written = os.write(sys.stdout.fileno(), view)
				view = view[written:]
	return 0


def session_id(value: str) -> str:
	if not SESSION_RE.fullmatch(value):
		raise argparse.ArgumentTypeError("会话 ID 无效")
	return value


def read_request() -> dict[str, object]:
	request = sys.stdin.buffer.readline(MAX_CREATE_BYTES + 1)
	if not request or len(request) > MAX_CREATE_BYTES or sys.stdin.buffer.read(1):
		raise ActionError("会话请求大小无效")
	try:
		value = json.loads(request)
	except json.JSONDecodeError as error:
		raise ActionError("会话请求格式无效") from error
	if not isinstance(value, dict):
		raise ActionError("会话请求必须是 JSON 对象")
	return value


def read_create_request() -> dict[str, str]:
	value = read_request()
	fields = {key: value.get(key) for key in ("customer", "operator_public_key", "created_by")}
	fields["purpose"] = value.get("purpose", "")
	if not all(isinstance(item, str) for item in fields.values()):
		raise ActionError("创建会话请求字段无效")
	if not CUSTOMER_RE.fullmatch(fields["customer"]):
		raise ActionError("客户标识仅允许小写字母、数字和连字符")
	if not CREATED_BY_RE.fullmatch(fields["created_by"]):
		raise ActionError("会话创建人格式无效")
	purpose = fields["purpose"].strip()
	if len(purpose) > 200 or any(ord(character) < 32 for character in purpose):
		raise ActionError("支持用途最多为 200 个可见字符")
	fields["purpose"] = purpose
	platform = value.get("platform", "linux")
	if platform not in ("linux", "windows"):
		raise ActionError("客户操作系统无效")
	fields["platform"] = platform
	return fields


def read_close_request() -> dict[str, str]:
	value = read_request()
	fields = {key: value.get(key) for key in ("closed_by", "mode", "reason")}
	if not all(isinstance(item, str) for item in fields.values()):
		raise ActionError("关闭会话请求字段无效")
	if not CREATED_BY_RE.fullmatch(fields["closed_by"]):
		raise ActionError("会话关闭人格式无效")
	if fields["mode"] not in {"normal", "force"}:
		raise ActionError("会话关闭方式无效")
	reason = fields["reason"].strip()
	if not reason or len(reason) > 200 or any(ord(character) < 32 for character in reason):
		raise ActionError("关闭原因必须为 1-200 个可见字符")
	fields["reason"] = reason
	return fields


def parser() -> argparse.ArgumentParser:
	root = argparse.ArgumentParser(description=__doc__)
	subparsers = root.add_subparsers(dest="action", required=True)
	subparsers.add_parser("create")
	show = subparsers.add_parser("show")
	show.add_argument("session_id", type=session_id)
	close = subparsers.add_parser("close")
	close.add_argument("session_id", type=session_id)
	subparsers.add_parser("list")
	return root


def main(arguments: list[str] | None = None) -> int:
	arguments = list(sys.argv[1:] if arguments is None else arguments)
	if arguments == ["--proxy"]:
		return relay_session()
	if arguments == ["--forced"]:
		try:
			arguments = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
		except ValueError as error:
			raise ActionError("远程操作格式无效") from error
	args = parser().parse_args(arguments)
	if args.action == "create":
		request = read_create_request()
		return run_manager(
			"create",
			"--customer", request["customer"],
			"--operator-public-key", "-",
			"--created-by", request["created_by"],
			"--purpose", request["purpose"],
			"--platform", request["platform"],
			"--json",
			input_text=request["operator_public_key"],
		)
	if args.action == "show":
		return run_manager("show", args.session_id, "--json")
	if args.action == "close":
		request = read_close_request()
		return run_manager(
			"close", args.session_id,
			"--closed-by", request["closed_by"],
			"--mode", request["mode"],
			"--reason", request["reason"],
		)
	return run_manager("list")


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except (ActionError, OSError, TypeError, ValueError) as error:
		print(f"错误: {error}", file=sys.stderr)
		raise SystemExit(1)
