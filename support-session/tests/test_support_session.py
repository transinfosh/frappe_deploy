import importlib.util
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
	"tsuite_support_session", ROOT / "bastion" / "tsuite_support_session.py"
)
SUPPORT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = SUPPORT
SPEC.loader.exec_module(SUPPORT)


PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"


class SupportSessionTest(unittest.TestCase):
	def setUp(self):
		self.temporary = tempfile.TemporaryDirectory()
		root = pathlib.Path(self.temporary.name)
		self.settings = SUPPORT.Settings(
			state_dir=root / "state",
			authorized_keys_dir=root / "authorized_keys",
			downloads_dir=root / "downloads",
			download_base_url="https://bastion.example.com/tsuite-support",
			bastion_host="bastion.example.com",
			bastion_port=22,
			bastion_host_key=PUBLIC_KEY,
			bootstrap_path=root / "bootstrap.sh",
			port_start=22000,
			port_end=22010,
			token_ttl_seconds=900,
			session_ttl_seconds=7200,
		)
		self.settings.bootstrap_path.write_text("#!/bin/sh\n", encoding="utf-8")
		self.store = SUPPORT.SessionStore(self.settings)

	def tearDown(self):
		self.temporary.cleanup()

	def save_issued_session(self, token="one-time-token"):
		now = int(time.time())
		session = {
			"id": "012345abcdef",
			"customer": "customer-one",
			"status": "issued",
			"created_at": now,
			"token_expires_at": now + 900,
			"expires_at": now + 7200,
			"token_hash": SUPPORT.token_hash(token),
			"remote_port": 22000,
			"tunnel_user": "tsuite-tunnel-012345ab",
			"tunnel_private_key": "PRIVATE",
			"operator_public_key": PUBLIC_KEY,
		}
		self.store.save(session)
		return token

	def save_terminal_session(self, session_id, status):
		now = int(time.time())
		self.store.save({
			"id": session_id,
			"customer": "customer-one",
			"status": status,
			"created_at": now - 3600,
			"token_expires_at": now - 2700,
			"expires_at": now - 1 if status == "expired" else now + 3600,
			"remote_port": 22001,
			"tunnel_user": f"tsuite-tunnel-{session_id[:8]}",
		})

	def test_enrollment_is_idempotent_only_for_same_nonce_and_host_key(self):
		token = self.save_issued_session()
		nonce = "abcdefghijklmnopqrstuvwxyz012345"
		first = SUPPORT.enroll(self.store, token, nonce, PUBLIC_KEY)
		second = SUPPORT.enroll(self.store, token, nonce, PUBLIC_KEY)
		self.assertEqual(first, second)
		self.assertEqual(first["tunnel_private_key"], "PRIVATE")
		with self.assertRaisesRegex(SUPPORT.SupportError, "已经被使用"):
			SUPPORT.enroll(self.store, token, "different-nonce-abcdefghijklmnopqrstuvwxyz", PUBLIC_KEY)

	def test_public_session_omits_all_credentials(self):
		self.save_issued_session()
		public = SUPPORT.public_session(self.store.load("012345abcdef"))
		self.assertNotIn("token_hash", public)
		self.assertNotIn("tunnel_private_key", public)
		self.assertNotIn("operator_public_key", public)

	def test_audit_fields_are_validated(self):
		self.assertEqual(SUPPORT.validate_created_by("alice-ops"), "alice-ops")
		self.assertEqual(SUPPORT.validate_purpose(" 升级 SRM "), "升级 SRM")
		self.assertEqual(SUPPORT.validate_purpose("  ", allow_empty=True), "")
		self.assertEqual(SUPPORT.build_parser().parse_args(["create", "--customer", "one", "--operator-public-key", "-", "--created-by", "alice"]).purpose, "")
		with self.assertRaises(SUPPORT.SupportError):
			SUPPORT.validate_created_by("alice;root")
		with self.assertRaises(SUPPORT.SupportError):
			SUPPORT.validate_purpose("\n")

	def test_gc_preserves_the_original_manual_close_outcome(self):
		self.assertEqual(
			SUPPORT.gc_terminal_status({"status": "revoking", "close_mode": "normal"}),
			"closed",
		)
		self.assertEqual(
			SUPPORT.gc_terminal_status({"status": "revoking", "close_mode": "force"}),
			"closed",
		)
		self.assertEqual(SUPPORT.gc_terminal_status({"status": "revoking"}), "expired")

	def test_enrollment_key_is_forced_to_one_session_and_native_expiry(self):
		self.save_issued_session()
		session = self.store.load("012345abcdef")
		session["enrollment_private_key"] = "PRIVATE"
		session["enrollment_public_key"] = PUBLIC_KEY
		self.store.save(session)
		with mock.patch.object(SUPPORT, "chown_to_user"):
			SUPPORT.rewrite_enrollment_authorized_keys(self.store)
		authorized = (self.settings.authorized_keys_dir / "tsuite-enroll").read_text(encoding="utf-8")
		self.assertIn("enroll-ssh 012345abcdef", authorized)
		self.assertIn("restrict,expiry-time=", authorized)

	def test_customer_download_is_short_and_script_pins_host(self):
		session = {
			"download_id": "A" * 43,
			"enrollment_private_key": "SESSION ENROLLMENT KEY\n",
		}
		command = SUPPORT.customer_command(self.settings, session)
		script = SUPPORT.customer_script(
			self.settings,
			session,
		)
		self.assertEqual(
			command,
			"curl -fsS --proto '=https' --tlsv1.2 "
			"https://bastion.example.com/tsuite-support/" + "A" * 43 + " | sudo bash",
		)
		self.assertIn("StrictHostKeyChecking=yes", script)
		self.assertIn("bastion.example.com", script)
		self.assertNotIn("one-time-token", command)
		self.assertNotIn("one-time-token", script)

	def test_customer_script_file_is_not_publicly_listable_by_mode(self):
		self.settings.downloads_dir.mkdir(mode=0o750)
		session = {
			"download_id": "B" * 43,
			"enrollment_private_key": "SESSION ENROLLMENT KEY\n",
		}
		SUPPORT.write_customer_script(self.settings, session)
		path = self.settings.downloads_dir / session["download_id"]
		self.assertEqual(path.stat().st_mode & 0o777, 0o640)
		self.assertIn("StrictHostKeyChecking=yes", path.read_text(encoding="utf-8"))
		SUPPORT.remove_customer_script(self.settings, session)
		self.assertFalse(path.exists())

	def test_expired_token_is_left_for_root_gc(self):
		token = self.save_issued_session()
		session = self.store.load("012345abcdef")
		session["token_expires_at"] = int(time.time()) - 1
		self.store.save(session)
		with self.assertRaisesRegex(SUPPORT.SupportError, "会话码已过期"):
			SUPPORT.enroll(self.store, token, "abcdefghijklmnopqrstuvwxyz012345", PUBLIC_KEY)
		self.assertEqual(self.store.load("012345abcdef")["status"], "issued")

	def test_terminal_remote_session_can_be_reconciled_without_consuming_new_token(self):
		token = self.save_issued_session()
		for old_session_id, status in (("111111111111", "closed"), ("222222222222", "expired")):
			with self.subTest(status=status):
				self.save_terminal_session(old_session_id, status)
				confirmed = SUPPORT.confirm_session_replacement(
					self.store, token, "012345abcdef", old_session_id
				)
				self.assertEqual(confirmed, old_session_id)
				self.assertEqual(self.store.load("012345abcdef")["status"], "issued")

	def test_active_remote_session_cannot_be_reconciled(self):
		token = self.save_issued_session()
		old_session_id = "333333333333"
		self.save_terminal_session(old_session_id, "closed")
		old = self.store.load(old_session_id)
		old["status"] = "enrolled"
		old["expires_at"] = int(time.time()) + 3600
		self.store.save(old)
		with self.assertRaisesRegex(SUPPORT.SupportError, "仍处于活动状态"):
			SUPPORT.confirm_session_replacement(
				self.store, token, "012345abcdef", old_session_id
			)
		self.assertEqual(self.store.load("012345abcdef")["status"], "issued")

	def test_settings_reject_missing_bootstrap(self):
		value = self.settings.__dict__ | {"bootstrap_path": pathlib.Path(self.temporary.name) / "missing"}
		with self.assertRaises(SUPPORT.SupportError):
			SUPPORT.Settings(**value).validate()


class StaticSecurityTest(unittest.TestCase):
	def test_customer_token_is_not_put_in_history_or_systemd(self):
		bootstrap = (ROOT / "customer" / "bootstrap.sh").read_text(encoding="utf-8")
		self.assertIn('read -r -s -p "请输入一次性支持会话码', bootstrap)
		self.assertIn('printf \'%s\' "$TOKEN" >"$work_dir/token"', bootstrap)
		self.assertNotIn("Environment=TSUITE_SUPPORT_TOKEN", bootstrap)
		self.assertIn("OnUnitActiveSec=15s", bootstrap)
		self.assertIn("cleanup-if-expired", bootstrap)
		self.assertIn('"${enrollment_ssh[@]}" reconcile', bootstrap)
		self.assertIn('/usr/local/sbin/tsuite-support-client cleanup', bootstrap)
		self.assertNotIn('本机已有支持会话，请先关闭后再创建新会话', bootstrap)

	def test_tunnel_key_and_sshd_are_loopback_only(self):
		server = (ROOT / "bastion" / "tsuite_support_session.py").read_text(encoding="utf-8")
		installer = (ROOT / "bastion" / "install.sh").read_text(encoding="utf-8")
		self.assertIn('permitlisten="127.0.0.1:', server)
		self.assertIn("GatewayPorts no", installer)
		self.assertIn("AllowTcpForwarding remote", installer)
		self.assertIn("Match User $ENROLL_USER", installer)
		self.assertIn("usermod --password 'NP'", installer)
		self.assertIn('"--password", "NP", username', server)
		self.assertIn("chown_to_user(authorized_keys_path, username)", server)
		self.assertIn('chown_to_user(temporary, "tsuite-enroll")', server)
		self.assertIn('install -d -m 0711 -o root -g root "$AUTHORIZED_KEYS_DIR"', installer)
		self.assertIn("tsuite-enroll 公钥登录自检失败", installer)
		self.assertIn('ENROLL_HOME="/var/empty/tsuite-enroll"', installer)
		self.assertIn("/tsuite-support/*", installer)
		self.assertIn("# Managed by tsuite_deploy/control-node.", installer)
		self.assertIn("control-node Caddy 配置缺少", installer)
		self.assertIn('Cache-Control "no-store"', installer)
		self.assertNotIn("NOPASSWD: ALL", installer)

	def test_operator_run_preserves_remote_argument_boundaries(self):
		operator = (ROOT / "operator" / "tsuite-support").read_text(encoding="utf-8")
		self.assertIn("ssh_args.append(shlex.join(command))", operator)
		self.assertIn('if command[0] == "--":', operator)

	def test_customer_operator_account_uses_impossible_password(self):
		bootstrap = (ROOT / "customer" / "bootstrap.sh").read_text(encoding="utf-8")
		self.assertIn("useradd --create-home --shell /bin/bash --password 'NP'", bootstrap)

	def test_console_is_restricted_to_local_caddy_proxy_and_fixed_actions(self):
		installer = (ROOT / "bastion" / "install-console.sh").read_text(encoding="utf-8")
		control_installer = (ROOT.parent / "control-node" / "install-support-console.sh").read_text(encoding="utf-8")
		prepare = (ROOT.parent / "control-node" / "prepare-support-access.sh").read_text(encoding="utf-8")
		self.assertIn("堡垒机同机支持页面已停用", installer)
		self.assertIn("ProtectSystem=strict", control_installer)
		self.assertNotIn("SupplementaryGroups=tsuite-deploy", control_installer)
		self.assertNotIn("CapabilityBoundingSet=", control_installer)
		self.assertIn('ReadWritePaths=$STATE_DIR $BROKER_STATE_DIR', control_installer)
		self.assertIn('ExecStartPre=/usr/bin/sudo -n -u $BROKER_USER /usr/local/bin/tsuite-support-console-action list', control_installer)
		self.assertIn('首次安装必须提供 --github-client-secret-file', control_installer)
		self.assertIn('existing.get("github_client_secret", "")', control_installer)
		self.assertIn("TSUITE_SUPPORT_WEB", prepare)
		self.assertIn("TSUITE_SUPPORT_OPERATOR", prepare)
		self.assertNotIn("NOPASSWD: ALL", prepare)
		self.assertIn('local name legacy target', prepare)
		self.assertIn('target="$CONFIG_DIR/$name"', prepare)
		self.assertIn('chown "$BROKER_USER":"$BROKER_GROUP" "$target"', prepare)
		self.assertIn('chmod 0600 "$target"', prepare)
		self.assertNotIn('chmod 0640 "$target"', prepare)
		self.assertIn('remove_broker_membership "$OPERATOR_USER"', prepare)
		self.assertIn('remove_broker_membership "$CONSOLE_USER"', prepare)
		web_alias = next(line for line in prepare.splitlines() if line.startswith("Cmnd_Alias TSUITE_SUPPORT_WEB"))
		self.assertNotIn("force-close", web_alias)
		self.assertNotIn(" ssh *", web_alias)
		self.assertNotIn(" run *", web_alias)
		self.assertIn('"$CONFIG_DIR/operator_ed25519"', control_installer)

	def test_edge_operator_shell_only_allows_forced_entry_points(self):
		installer = (ROOT / "bastion" / "install-console-bridge.sh").read_text(encoding="utf-8")
		shell = (ROOT / "bastion" / "tsuite-support-operator-shell").read_text(encoding="utf-8")
		self.assertIn("tsuite-support-operator-shell", installer)
		self.assertIn("usermod --shell", installer)
		self.assertIn("tsuite-support-console-action --forced", shell)
		self.assertIn("tsuite-support-console-action --proxy", shell)
		self.assertNotIn("/bin/bash", shell)
		self.assertNotIn("/bin/sh -c", shell)


if __name__ == "__main__":
	unittest.main()
