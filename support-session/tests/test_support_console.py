import importlib.util
from importlib.machinery import SourceFileLoader
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import types
import unittest
import urllib.parse
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
	"tsuite_support_console", ROOT / "console" / "tsuite_support_console.py"
)
CONSOLE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = CONSOLE
SPEC.loader.exec_module(CONSOLE)

REMOTE_SPEC = importlib.util.spec_from_file_location(
	"tsuite_support_remote_action", ROOT / "console" / "tsuite_support_remote_action.py"
)
REMOTE = importlib.util.module_from_spec(REMOTE_SPEC)
assert REMOTE_SPEC.loader is not None
sys.modules[REMOTE_SPEC.name] = REMOTE
REMOTE_SPEC.loader.exec_module(REMOTE)

BASTION_ACTION_SPEC = importlib.util.spec_from_file_location(
	"tsuite_support_console_action", ROOT / "bastion" / "tsuite_support_console_action.py"
)
BASTION_ACTION = importlib.util.module_from_spec(BASTION_ACTION_SPEC)
assert BASTION_ACTION_SPEC.loader is not None
sys.modules[BASTION_ACTION_SPEC.name] = BASTION_ACTION
BASTION_ACTION_SPEC.loader.exec_module(BASTION_ACTION)

CLI_PATH = ROOT / "operator" / "tsuite-support"
CLI_SPEC = importlib.util.spec_from_loader(
	"tsuite_support_cli", SourceFileLoader("tsuite_support_cli", str(CLI_PATH))
)
CLI = importlib.util.module_from_spec(CLI_SPEC)
assert CLI_SPEC.loader is not None
sys.modules[CLI_SPEC.name] = CLI
CLI_SPEC.loader.exec_module(CLI)


class SupportConsoleTest(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.settings = CONSOLE.Settings(
			client_id="Iv1.example_client_id",
			client_secret="a" * 32,
			allowed_org="transinfosh",
			allowed_team="support",
			public_url="https://edge.example.com/support",
			state_dir=pathlib.Path(self.temporary.name) / "state",
		)

	def tearDown(self):
		self.temporary.cleanup()

	def call(self, app, path, method="GET", body="", cookie=None, query=""):
		captured = {}
		environ = {
			"PATH_INFO": path,
			"REQUEST_METHOD": method,
			"QUERY_STRING": query,
			"CONTENT_LENGTH": str(len(body.encode())),
			"wsgi.input": __import__("io").BytesIO(body.encode()),
		}
		if cookie:
			environ["HTTP_COOKIE"] = cookie
		result = b"".join(app(environ, lambda status, headers: captured.update(status=status, headers=headers)))
		return captured, result.decode()

	def test_callback_url_and_pkce_challenge_are_deterministic(self):
		self.assertEqual(self.settings.callback_url, "https://edge.example.com/support/auth/github/callback")
		self.assertEqual(CONSOLE.code_challenge("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0")

	def test_oauth_state_can_only_be_consumed_once(self):
		store = CONSOLE.Store(self.settings.state_dir)
		state, verifier = store.new_oauth_state()
		self.assertEqual(store.consume_oauth_state(state), verifier)
		self.assertIsNone(store.consume_oauth_state(state))

	def test_oauth_callback_is_bound_to_the_starting_browser(self):
		app = CONSOLE.Application(self.settings)
		captured, _ = self.call(app, "/login")
		location = dict(captured["headers"])["Location"]
		state = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["state"][0]
		oauth_cookie = next(value for key, value in captured["headers"] if key == "Set-Cookie")
		cookie_value = oauth_cookie.split(";", 1)[0]
		with mock.patch.object(CONSOLE, "github_identity", return_value=("alice", "Alice")) as identity:
			captured, _ = self.call(app, "/auth/github/callback", query=f"state={state}&code=code")
			self.assertTrue(captured["status"].startswith("400"))
			identity.assert_not_called()
			captured, _ = self.call(
				app,
				"/auth/github/callback",
				cookie=cookie_value,
				query=f"state={state}&code=code",
			)
			self.assertTrue(captured["status"].startswith("303"))
			identity.assert_called_once()

	def test_dashboard_requires_authenticated_cookie(self):
		app = CONSOLE.Application(self.settings)
		captured, content = self.call(app, "/")
		self.assertTrue(captured["status"].startswith("401"))
		self.assertIn("使用 GitHub 登录", content)
		self.assertIn('href="/support/login"', content)
		self.assertIn(("Cache-Control", "no-store"), captured["headers"])

	def test_dashboard_uses_the_public_support_prefix(self):
		app = CONSOLE.Application(self.settings)
		session_id, _ = app.store.new_session("alice", "Alice")
		with mock.patch.object(CONSOLE, "manager") as manager:
			captured, content = self.call(app, "/", cookie=f"tsuite_support_session={session_id}")
		self.assertTrue(captured["status"].startswith("200"))
		self.assertIn('action="/support/session"', content)
		self.assertIn('action="/support/logout"', content)
		self.assertIn('fetch("/support/sessions"', content)
		self.assertIn("正在加载会话列表", content)
		manager.assert_not_called()

	def test_dashboard_groups_customers_and_shows_full_session_ids(self):
		app = CONSOLE.Application(self.settings)
		session_id, _ = app.store.new_session("alice", "Alice")
		listing = (
			"012345abcdef\tcustomer-one\tclosed\t22000\n"
			"fedcba543210\tcustomer-one\tenrolled\t22001\n"
			"111111111111\tcustomer-two\texpired\t22002\n"
		)
		with mock.patch.object(CONSOLE, "manager", return_value=listing):
			captured, content = self.call(app, "/sessions", cookie=f"tsuite_support_session={session_id}")
		self.assertTrue(captured["status"].startswith("200"))
		self.assertIn(("Content-Type", "application/json; charset=utf-8"), captured["headers"])
		value = json.loads(content)
		content = value["summary"] + value["groups"]
		self.assertEqual(content.count('class="customer-name">customer-one'), 1)
		self.assertIn("1 次会话 · 1 个活动", content)
		self.assertNotIn(">012345abcdef</a>", content)
		self.assertIn(">fedcba543210</a>", content)
		self.assertIn("已连接", content)
		self.assertNotIn("已关闭", content)
		self.assertNotIn("已过期", content)
		self.assertNotIn("customer-two", content)
		self.assertNotIn("历史会话", content)
		self.assertIn("<strong>1</strong> 个客户环境", content)
		self.assertIn('action="/support/session/fedcba543210/close"', content)
		self.assertNotIn('action="/support/session/012345abcdef/close"', content)
		self.assertIn(".inline-actions form{margin:0 0 0 auto}", CONSOLE.page("test", "").decode())

	def test_dashboard_empty_after_all_sessions_end(self):
		app = CONSOLE.Application(self.settings)
		session_id, _ = app.store.new_session("alice", "Alice")
		with mock.patch.object(CONSOLE, "manager", return_value="012345abcdef\told-customer\tclosed\t22000\n"):
			_, content = self.call(app, "/sessions", cookie=f"tsuite_support_session={session_id}")
		value = json.loads(content)
		self.assertIn("当前没有活动支持会话", value["groups"])
		self.assertNotIn("old-customer", value["groups"])
		self.assertIn("<strong>0</strong> 个客户环境", value["summary"])

	def test_create_accepts_omitted_purpose(self):
		app = CONSOLE.Application(self.settings)
		session_id, csrf = app.store.new_session("alice", "Alice")
		_, dashboard = self.call(app, "/", cookie=f"tsuite_support_session={session_id}")
		self.assertIn("支持用途（可选）", dashboard)
		self.assertNotIn('name="purpose" required', dashboard)
		with mock.patch.object(CONSOLE, "manager", return_value=json.dumps({
			"id": "012345abcdef", "token": "", "auth_mode": "enrollment-key", "customer_command": "command",
		})) as manager:
			captured, _ = self.call(app, "/session", "POST", f"csrf={csrf}&customer=customer-one", f"tsuite_support_session={session_id}")
		self.assertTrue(captured["status"].startswith("200"))
		manager.assert_called_once_with("create", "customer-one", "--created-by", "alice", "--purpose", "")


	def test_detail_localizes_fields_values_and_destructive_action(self):
		app = CONSOLE.Application(self.settings)
		session_id, csrf = app.store.new_session("alice", "Alice")
		info = {
			"id": "012345abcdef",
			"customer": "customer-one",
			"created_by": "alice",
			"purpose": "升级 SRM",
			"status": "issued",
			"created_at": 1787882034,
			"remote_port": 22000,
			"tunnel_reachable": False,
		}
		with mock.patch.object(CONSOLE, "manager", return_value=json.dumps(info)):
			captured, content = self.call(
				app, "/session/012345abcdef", cookie=f"tsuite_support_session={session_id}"
			)
		self.assertTrue(captured["status"].startswith("200"))
		self.assertIn("<th>客户环境标识</th>", content)
		self.assertIn("<th>创建人</th><td>alice</td>", content)
		self.assertIn("<th>支持用途</th><td>升级 SRM</td>", content)
		self.assertIn("<th>创建时间</th>", content)
		self.assertIn("2026-08-28 09:53:54（UTC+8）", content)
		self.assertIn("<th>隧道可达</th><td>否</td>", content)
		self.assertIn("等待客户", content)
		self.assertIn('class="button" href="/support/">关闭</a>', content)
		self.assertIn('class="danger">关闭会话</button>', content)
		self.assertIn('<div class="detail-actions"><a class="button"', content)
		self.assertLess(content.index(">关闭</a>"), content.index(">关闭会话</button>"))
		self.assertIn(f'name="csrf" value="{csrf}"', content)

	def test_close_route_checks_csrf_and_calls_manager(self):
		app = CONSOLE.Application(self.settings)
		session_id, csrf = app.store.new_session("alice", "Alice")
		with mock.patch.object(CONSOLE, "manager", return_value="") as manager:
			captured, _ = self.call(
				app,
				"/session/012345abcdef/close",
				"POST",
				f"csrf={csrf}",
				f"tsuite_support_session={session_id}",
			)
		self.assertTrue(captured["status"].startswith("303"))
		self.assertIn(("Location", "/support/"), captured["headers"])
		manager.assert_called_once_with("close", "012345abcdef", "--closed-by", "alice")

	def test_key_enrollment_page_has_only_customer_command(self):
		app = CONSOLE.Application(self.settings)
		session_id, csrf = app.store.new_session("alice", "Alice")
		with mock.patch.object(CONSOLE, "manager", return_value=json.dumps({
			"id": "012345abcdef", "token": "unused-compatibility-field", "auth_mode": "enrollment-key",
			"customer_command": "curl https://example.invalid | sudo bash",
		})):
			captured, content = self.call(app, "/session", "POST", f"csrf={csrf}&customer=customer-one&purpose=upgrade", f"tsuite_support_session={session_id}")
		self.assertTrue(captured["status"].startswith("200"))
		self.assertNotIn('id="support-token"', content)
		self.assertNotIn("unused-compatibility-field", content)
		self.assertIn("无需另输会话码", content)


	def test_create_requires_csrf_and_never_persists_one_time_token(self):
		app = CONSOLE.Application(self.settings)
		session_id, csrf = app.store.new_session("alice", "Alice")
		with mock.patch.object(CONSOLE, "manager", return_value=json.dumps({
			"id": "012345abcdef", "token": "do-not-persist", "customer_command": "curl https://example.invalid | sudo bash",
		})) as manager:
			captured, content = self.call(app, "/session", "POST", f"csrf={csrf}&customer=customer-one&purpose=upgrade-srm", f"tsuite_support_session={session_id}")
		self.assertTrue(captured["status"].startswith("200"))
		manager.assert_called_once_with("create", "customer-one", "--created-by", "alice", "--purpose", "upgrade-srm")
		self.assertIn("do-not-persist", content)
		self.assertIn('data-copy-target="customer-command"', content)
		self.assertIn('data-copy-target="support-token"', content)
		self.assertIn('id="support-token" class="secret token"', content)
		self.assertIn('navigator.clipboard.writeText(target.textContent)', content)
		self.assertNotIn("#fff7ed", content)
		self.assertNotIn("#eff6ff", content)
		with app.store.connection() as connection:
			self.assertEqual(connection.execute("SELECT COUNT(*) FROM web_session").fetchone()[0], 1)
			self.assertEqual(connection.execute("SELECT COUNT(*) FROM oauth_state").fetchone()[0], 0)
		captured, content = self.call(app, "/session", "POST", "csrf=wrong&customer=customer-one&purpose=upgrade-srm", f"tsuite_support_session={session_id}")
		self.assertTrue(captured["status"].startswith("400"))
		self.assertNotIn("do-not-persist", content)

	def test_manager_bridge_is_fixed_and_not_shell_based(self):
		action = (ROOT / "bastion" / "tsuite_support_console_action.py").read_text(encoding="utf-8")
		bridge = (ROOT / "bastion" / "install-console-bridge.sh").read_text(encoding="utf-8")
		remote = (ROOT / "console" / "tsuite_support_remote_action.py").read_text(encoding="utf-8")
		self.assertIn('"--operator-public-key", "-"', action)
		self.assertNotIn("OPERATOR_PUBLIC_KEY", action)
		self.assertIn("CUSTOMER_RE", action)
		self.assertIn("SESSION_RE", action)
		self.assertNotIn("shell=True", action)
		self.assertIn('"StrictHostKeyChecking=yes"', remote)
		self.assertIn('"ClearAllForwardings=yes"', remote)
		self.assertIn('"ControlMaster=auto"', remote)
		self.assertIn('"ControlPersist=3600"', remote)
		self.assertIn('CONTROL_PATH = "/var/lib/tsuite-support-operator/ssh-control-%C"', remote)
		self.assertIn('remote_action(settings, "list", multiplex=False)', remote)
		self.assertIn('"-o", "ControlMaster=no", "-o", "ControlPath=none"', remote)
		self.assertIn('"sudo -n /usr/local/sbin/tsuite-support-client close"', remote)
		self.assertIn('subparsers.add_parser("force-close")', remote)
		self.assertIn('sudoers_file="/etc/sudoers.d/tsuite-support-session"', bridge)
		self.assertNotIn('sudoers_file="/etc/sudoers.d/tsuite-support-console-bridge"', bridge)
		self.assertIn('command="/usr/local/sbin/tsuite-support-console-action --proxy",restrict', bridge)
		self.assertNotIn("port-forwarding", bridge)
		self.assertNotIn("permitopen=", bridge)
		self.assertIn('f"{settings.user}@{settings.host}", "proxy", session_id', remote)
		self.assertNotIn('"-W", "%h:%p"', remote)
		self.assertNotIn("shell=True", remote)

	def test_remote_action_rejects_untrusted_identifiers_before_ssh(self):
		with self.assertRaises(SystemExit):
			REMOTE.parser().parse_args(["create", "customer;uname", "--created-by", "alice", "--purpose", "upgrade"])
		with self.assertRaises(SystemExit):
			REMOTE.parser().parse_args(["show", "../../etc/passwd"])

	def test_bastion_bridge_accepts_a_validated_per_session_public_key(self):
		request = json.dumps({
			"customer": "customer-one",
			"operator_public_key": "ssh-ed25519 " + "A" * 44,
			"created_by": "alice",
			"purpose": "upgrade SRM",
		}).encode() + b"\n"
		stdin = io.TextIOWrapper(io.BytesIO(request), encoding="utf-8")
		with mock.patch.object(BASTION_ACTION.sys, "stdin", stdin), \
			mock.patch.object(BASTION_ACTION, "run_manager", return_value=0) as manager:
			self.assertEqual(BASTION_ACTION.main(["create"]), 0)
		arguments = manager.call_args.args
		self.assertIn("--operator-public-key", arguments)
		self.assertIn("--created-by", arguments)
		self.assertIn("--purpose", arguments)
		self.assertEqual(manager.call_args.kwargs["input_text"], "ssh-ed25519 " + "A" * 44)

	def test_optional_purpose_passes_bridge_and_cli_but_reason_remains_required(self):
		with mock.patch.object(BASTION_ACTION, "read_request", return_value={
			"customer": "customer-one", "operator_public_key": "ssh-ed25519 " + "A" * 44, "created_by": "alice",
		}):
			self.assertEqual(BASTION_ACTION.read_create_request()["purpose"], "")
		self.assertEqual(REMOTE.parser().parse_args(["create", "customer-one", "--created-by", "alice"]).purpose, "")
		self.assertEqual(CLI.parser().parse_args(["create", "customer-one"]).purpose, "")
		with self.assertRaises(Exception):
			REMOTE.validate_purpose("")
		with self.assertRaises(Exception):
			REMOTE.validate_purpose("a" * 201, allow_empty=True)


	def test_bastion_bridge_records_close_audit(self):
		request = json.dumps({
			"closed_by": "alice",
			"mode": "force",
			"reason": "客户服务器已离线，记录残留风险",
		}).encode() + b"\n"
		stdin = io.TextIOWrapper(io.BytesIO(request), encoding="utf-8")
		with mock.patch.object(BASTION_ACTION.sys, "stdin", stdin), \
			mock.patch.object(BASTION_ACTION, "run_manager", return_value=0) as manager:
			self.assertEqual(BASTION_ACTION.main(["close", "012345abcdef"]), 0)
		self.assertEqual(manager.call_args.args, (
			"close", "012345abcdef",
			"--closed-by", "alice",
			"--mode", "force",
			"--reason", "客户服务器已离线，记录残留风险",
		))

	def test_edge_proxy_relays_only_the_requested_active_session(self):
		class Upstream:
			def __init__(self):
				self.received = []
				self.responses = iter((b"server-data", b""))

			def __enter__(self):
				return self

			def __exit__(self, *unused):
				return False

			def settimeout(self, value):
				return None

			def sendall(self, value):
				self.received.append(value)

			def shutdown(self, how):
				return None

			def recv(self, size):
				return next(self.responses)

		class ImmediateThread:
			def __init__(self, target, daemon):
				self.target = target

			def start(self):
				self.target()

		upstream = Upstream()
		session = json.dumps({
			"id": "012345abcdef",
			"status": "enrolled",
			"tunnel_reachable": True,
			"remote_port": 22000,
		})
		with mock.patch.dict(BASTION_ACTION.os.environ, {"SSH_ORIGINAL_COMMAND": "proxy 012345abcdef"}), \
			mock.patch.object(BASTION_ACTION, "manager_output", return_value=session), \
			mock.patch.object(BASTION_ACTION.socket, "create_connection", return_value=upstream) as connect, \
			mock.patch.object(BASTION_ACTION.threading, "Thread", ImmediateThread), \
			mock.patch.object(BASTION_ACTION.os, "read", side_effect=(b"client-data", b"")), \
			mock.patch.object(BASTION_ACTION.os, "write", return_value=len(b"server-data")) as write:
			self.assertEqual(BASTION_ACTION.relay_session(), 0)
		connect.assert_called_once_with(("127.0.0.1", 22000), timeout=10)
		self.assertEqual(upstream.received, [b"client-data"])
		write.assert_called_once()

	def test_edge_proxy_rejects_a_revoking_session(self):
		session = json.dumps({
			"id": "012345abcdef",
			"status": "revoking",
			"tunnel_reachable": True,
			"remote_port": 22000,
		})
		with mock.patch.dict(BASTION_ACTION.os.environ, {"SSH_ORIGINAL_COMMAND": "proxy 012345abcdef"}), \
			mock.patch.object(BASTION_ACTION, "manager_output", return_value=session), \
			mock.patch.object(BASTION_ACTION.socket, "create_connection") as connect:
			with self.assertRaisesRegex(BASTION_ACTION.ActionError, "当前不可达"):
				BASTION_ACTION.relay_session()
		connect.assert_not_called()


class SupportOperatorBrokerTest(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		root = pathlib.Path(self.temporary.name)
		for name in ("bridge", "edge", "known_hosts"):
			(root / name).write_text("test", encoding="utf-8")
		(root / "state").mkdir()
		self.settings = REMOTE.Settings(
			host="edge.example.com",
			port=22,
			user="tsuite-operator",
			bridge_identity_file=root / "bridge",
			edge_identity_file=root / "edge",
			known_hosts_file=root / "known_hosts",
			state_dir=root / "state",
		)

	def tearDown(self):
		self.temporary.cleanup()

	def test_create_generates_a_distinct_operator_key_per_session(self):
		requests = []
		ids = iter(("012345abcdef", "fedcba543210"))

		def create_remote(settings, *arguments, input_text=None):
			self.assertEqual(arguments, ("create",))
			request = json.loads(input_text)
			requests.append(request)
			session_id = next(ids)
			return subprocess.CompletedProcess(
				[], 0, json.dumps({
					"id": session_id,
					"token": "token",
					"customer_command": "curl https://example.invalid | sudo bash",
					"expires_at": int(time.time()) + 7200,
				}), "",
			)

		with mock.patch.object(REMOTE, "remote_action", side_effect=create_remote):
			REMOTE.create_session(self.settings, "customer-one", "alice", "upgrade one")
			REMOTE.create_session(self.settings, "customer-one", "alice", "upgrade two")
		first = REMOTE.identity_path(self.settings, "012345abcdef").read_text(encoding="utf-8")
		second = REMOTE.identity_path(self.settings, "fedcba543210").read_text(encoding="utf-8")
		self.assertNotEqual(first, second)
		self.assertNotEqual(requests[0]["operator_public_key"], requests[1]["operator_public_key"])
		self.assertEqual(requests[0]["created_by"], "alice")
		self.assertEqual(requests[0]["purpose"], "upgrade one")

	def test_new_customer_connection_is_rejected_after_revocation_starts(self):
		session_id = "012345abcdef"
		REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
		REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({
			"id": session_id,
			"identity_file": str(REMOTE.identity_path(self.settings, session_id)),
		}))
		remote = {
			"id": session_id,
			"status": "revoking",
			"tunnel_reachable": True,
			"remote_port": 22000,
			"customer_host_key": "ssh-ed25519 " + "A" * 44,
		}
		with self.assertRaisesRegex(REMOTE.RemoteActionError, "当前不可达"):
			REMOTE.customer_ssh_args(
				self.settings,
				session_id,
				remote,
				pathlib.Path(self.temporary.name) / "customer-known-hosts",
			)

	def test_close_confirms_customer_cleanup_before_revoking_bastion(self):
		session_id = "012345abcdef"
		REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
		REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({
			"id": session_id,
			"identity_file": str(REMOTE.identity_path(self.settings, session_id)),
		}))
		events = []
		cleanup_environment = {}
		remote = {
			"id": session_id,
			"status": "enrolled",
			"tunnel_reachable": True,
			"remote_port": 22000,
			"customer_host_key": "ssh-ed25519 " + "A" * 44,
		}

		def cleanup_run(arguments, input_text=None, env=None):
			events.append("customer-cleanup")
			cleanup_environment.update(env or {})
			return subprocess.CompletedProcess(arguments, 0, f"cleanup-scheduled:{session_id}\n", "")

		def close_remote(settings, *arguments, input_text=None):
			events.append("bastion-close")
			return subprocess.CompletedProcess([], 0, "", "")

		with mock.patch.object(REMOTE, "remote_session", return_value=remote), \
			mock.patch.object(REMOTE, "customer_ssh_args", return_value=["ssh"]), \
			mock.patch.object(REMOTE, "run", side_effect=cleanup_run), \
			mock.patch.object(REMOTE, "remote_action", side_effect=close_remote):
			REMOTE.close_session(self.settings, session_id, "alice")
		self.assertEqual(events, ["customer-cleanup", "bastion-close"])
		self.assertEqual(cleanup_environment.get("SHELL"), "/bin/sh")
		self.assertFalse(REMOTE.identity_path(self.settings, session_id).exists())
		self.assertFalse(REMOTE.session_state_path(self.settings, session_id).exists())

	def test_close_failure_preserves_bastion_session_and_local_key(self):
		session_id = "012345abcdef"
		REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
		REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({
			"id": session_id,
			"identity_file": str(REMOTE.identity_path(self.settings, session_id)),
		}))
		remote = {
			"id": session_id,
			"status": "enrolled",
			"tunnel_reachable": True,
			"remote_port": 22000,
			"customer_host_key": "ssh-ed25519 " + "A" * 44,
		}
		cleanup = subprocess.CompletedProcess([], 1, "", "cleanup failed")
		with mock.patch.object(REMOTE, "remote_session", return_value=remote), \
			mock.patch.object(REMOTE, "customer_ssh_args", return_value=["ssh"]), \
			mock.patch.object(REMOTE, "run", return_value=cleanup), \
			mock.patch.object(REMOTE, "remote_action") as remote_action:
			with self.assertRaisesRegex(REMOTE.RemoteActionError, "客户侧清理未确认"):
				REMOTE.close_session(self.settings, session_id, "alice")
		remote_action.assert_not_called()
		self.assertTrue(REMOTE.identity_path(self.settings, session_id).exists())
		self.assertTrue(REMOTE.session_state_path(self.settings, session_id).exists())

	def test_customer_proxy_uses_shell_without_enabling_broker_login(self):
		session_id = "012345abcdef"
		with mock.patch.object(REMOTE, "remote_session", return_value={"id": session_id}), \
			mock.patch.object(REMOTE, "customer_ssh_args", return_value=["ssh"]), \
			mock.patch.object(REMOTE.subprocess, "call", return_value=0) as call:
			self.assertEqual(REMOTE.connect_customer(self.settings, session_id, ["true"]), 0)
		arguments, = call.call_args.args
		self.assertEqual(arguments, ["ssh", "true"])
		self.assertEqual(call.call_args.kwargs["env"]["SHELL"], "/bin/sh")

	def test_force_close_skips_customer_cleanup_and_removes_local_key(self):
		session_id = "012345abcdef"
		REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
		REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({
			"id": session_id,
			"identity_file": str(REMOTE.identity_path(self.settings, session_id)),
		}))
		remote = {"id": session_id, "status": "enrolled", "tunnel_reachable": False}
		closed = subprocess.CompletedProcess([], 0, "", "")
		with mock.patch.object(REMOTE, "remote_session", return_value=remote), \
			mock.patch.object(REMOTE, "run") as cleanup, \
			mock.patch.object(REMOTE, "remote_action", return_value=closed) as remote_action:
			REMOTE.close_session(
				self.settings,
				session_id,
				"alice",
				force=True,
				reason="客户服务器已离线",
			)
		cleanup.assert_not_called()
		request = json.loads(remote_action.call_args.kwargs["input_text"])
		self.assertEqual(request, {
			"closed_by": "alice",
			"mode": "force",
			"reason": "客户服务器已离线",
		})
		self.assertFalse(REMOTE.identity_path(self.settings, session_id).exists())
		self.assertFalse(REMOTE.session_state_path(self.settings, session_id).exists())

	def test_close_retry_uses_persisted_cleanup_confirmation(self):
		session_id = "012345abcdef"
		REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
		REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({
			"id": session_id,
			"identity_file": str(REMOTE.identity_path(self.settings, session_id)),
		}))
		first_remote = {
			"id": session_id,
			"status": "enrolled",
			"tunnel_reachable": True,
			"remote_port": 22000,
			"customer_host_key": "ssh-ed25519 " + "A" * 44,
		}
		second_remote = first_remote | {"status": "revoking", "tunnel_reachable": False}
		cleanup = subprocess.CompletedProcess([], 0, f"cleanup-scheduled:{session_id}\n", "")
		close_failed = subprocess.CompletedProcess([], 1, "", "edge temporarily unavailable")
		close_succeeded = subprocess.CompletedProcess([], 0, "", "")
		with mock.patch.object(REMOTE, "remote_session", side_effect=[first_remote, second_remote]), \
			mock.patch.object(REMOTE, "customer_ssh_args", return_value=["ssh"]) as ssh_args, \
			mock.patch.object(REMOTE, "run", return_value=cleanup) as cleanup_run, \
			mock.patch.object(REMOTE, "remote_action", side_effect=[close_failed, close_succeeded]):
			with self.assertRaisesRegex(REMOTE.RemoteActionError, "edge temporarily unavailable"):
				REMOTE.close_session(self.settings, session_id, "alice")
			state = REMOTE.read_json(REMOTE.session_state_path(self.settings, session_id))
			self.assertIsInstance(state.get("cleanup_confirmed_at"), int)
			REMOTE.close_session(self.settings, session_id, "alice")
		self.assertEqual(cleanup_run.call_count, 1)
		self.assertEqual(ssh_args.call_count, 1)
		self.assertFalse(REMOTE.identity_path(self.settings, session_id).exists())
		self.assertFalse(REMOTE.session_state_path(self.settings, session_id).exists())

	def test_gc_removes_keys_only_after_remote_session_ends(self):
		for session_id in ("012345abcdef", "fedcba543210"):
			REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
			REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({
				"id": session_id,
				"identity_file": str(REMOTE.identity_path(self.settings, session_id)),
			}))

		def status(settings, session_id):
			return {"id": session_id, "status": "expired" if session_id.startswith("0") else "enrolled"}

		with mock.patch.object(REMOTE, "remote_session", side_effect=status):
			REMOTE.garbage_collect(self.settings)
		self.assertFalse(REMOTE.identity_path(self.settings, "012345abcdef").exists())
		self.assertTrue(REMOTE.identity_path(self.settings, "fedcba543210").exists())

	def test_gc_keeps_renewable_identity_when_edge_is_unreachable(self):
		session_id = "012345abcdef"
		REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
		REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({
			"id": session_id, "identity_file": str(REMOTE.identity_path(self.settings, session_id)),
			"expires_at": int(time.time()) - 100, "idle_timeout_seconds": 7200,
		}))
		with mock.patch.object(REMOTE, "remote_session", side_effect=REMOTE.RemoteActionError("offline")):
			REMOTE.garbage_collect(self.settings)
		self.assertTrue(REMOTE.identity_path(self.settings, session_id).exists())


	def test_gc_removes_only_stale_orphan_keys(self):
		stale_id = "012345abcdef"
		fresh_id = "fedcba543210"
		for session_id in (stale_id, fresh_id):
			REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), "private")
		old = int(time.time()) - 600
		os.utime(REMOTE.identity_path(self.settings, stale_id), (old, old))
		REMOTE.garbage_collect(self.settings)
		self.assertFalse(REMOTE.identity_path(self.settings, stale_id).exists())
		self.assertTrue(REMOTE.identity_path(self.settings, fresh_id).exists())


class CompanyCliCloseTest(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		self.sessions_dir = pathlib.Path(self.temporary.name)
		self.config_path = self.sessions_dir / "config.json"
		self.config_path.write_text('{"bastion":"edge"}\n', encoding="utf-8")
		self.session_id = "012345abcdef"
		self.identity = self.sessions_dir / f"{self.session_id}.ed25519"
		self.identity.write_text("private", encoding="utf-8")
		self.local = {
			"id": self.session_id,
			"identity_file": str(self.identity),
		}
		CLI.atomic_write(
			self.sessions_dir / f"{self.session_id}.json",
			json.dumps(self.local) + "\n",
		)

	def tearDown(self):
		self.temporary.cleanup()

	def args(self, **values):
		return types.SimpleNamespace(
			session_id=self.session_id,
			closed_by="alice",
			force=False,
			reason=None,
			**values,
		)

	def test_issued_session_closes_without_customer_ssh(self):
		remote = {"id": self.session_id, "status": "issued"}
		with mock.patch.object(CLI, "CONFIG_PATH", self.config_path), \
			mock.patch.object(CLI, "SESSIONS_DIR", self.sessions_dir), \
			mock.patch.object(CLI, "show_remote", return_value=remote), \
			mock.patch.object(CLI, "customer_ssh_args") as customer_ssh, \
			mock.patch.object(CLI, "remote_cli") as remote_cli, \
			mock.patch("builtins.print") as printed:
			CLI.close(self.args())
		customer_ssh.assert_not_called()
		self.assertEqual(remote_cli.call_args.args[-6:], (
			"--closed-by", "alice", "--mode", "normal", "--reason", "客户尚未接入",
		))
		printed.assert_called_once_with(f"会话已关闭（客户尚未接入）: {self.session_id}")

	def test_legacy_cli_rejects_new_connections_after_revocation_starts(self):
		remote = {
			"id": self.session_id,
			"status": "revoking",
			"tunnel_reachable": True,
			"remote_port": 22000,
			"customer_host_key": "ssh-ed25519 " + "A" * 44,
		}
		with mock.patch.object(CLI, "SESSIONS_DIR", self.sessions_dir):
			with self.assertRaisesRegex(CLI.CliError, "开始撤销"):
				CLI.customer_ssh_args({"bastion": "edge"}, self.local, remote)

	def test_cleanup_confirmation_survives_revoke_failure(self):
		remote_first = {
			"id": self.session_id,
			"status": "enrolled",
			"remote_port": 22000,
			"customer_host_key": "ssh-ed25519 " + "A" * 44,
		}
		remote_second = remote_first | {"status": "revoking", "tunnel_reachable": False}
		cleanup = subprocess.CompletedProcess([], 0, f"cleanup-scheduled:{self.session_id}\n", "")
		with mock.patch.object(CLI, "CONFIG_PATH", self.config_path), \
			mock.patch.object(CLI, "SESSIONS_DIR", self.sessions_dir), \
			mock.patch.object(CLI, "show_remote", side_effect=[remote_first, remote_second]), \
			mock.patch.object(CLI, "customer_ssh_args", return_value=(["ssh"], self.sessions_dir / "known")) as customer_ssh, \
			mock.patch.object(CLI.subprocess, "run", return_value=cleanup) as cleanup_run, \
			mock.patch.object(CLI, "remote_cli", side_effect=[CLI.CliError("edge unavailable"), mock.DEFAULT]), \
			mock.patch("builtins.print"):
			with self.assertRaisesRegex(CLI.CliError, "edge unavailable"):
				CLI.close(self.args())
			state = json.loads((self.sessions_dir / f"{self.session_id}.json").read_text(encoding="utf-8"))
			self.assertIsInstance(state.get("cleanup_confirmed_at"), int)
			CLI.close(self.args())
		self.assertEqual(cleanup_run.call_count, 1)
		self.assertEqual(customer_ssh.call_count, 1)


if __name__ == "__main__":
	unittest.main()
