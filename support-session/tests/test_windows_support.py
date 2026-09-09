import base64
import io
import json
import subprocess
import time
import unittest
from unittest import mock

import test_support_session as sessions
import test_support_console as console

SUPPORT = sessions.SUPPORT
REMOTE = console.REMOTE
CLI = console.CLI


class WindowsSessionTest(unittest.TestCase):
	setUp = sessions.SupportSessionTest.setUp
	tearDown = sessions.SupportSessionTest.tearDown

	def test_windows_bundle_contains_pinned_configuration_and_no_linux_commands(self):
		for name in ('bootstrap.ps1', 'windows-client.ps1'):
			self.settings.bootstrap_path.with_name(name).write_bytes((sessions.ROOT / 'customer' / name).read_bytes())
		session = {'id': '012345abcdef', 'platform': 'windows', 'download_id': 'A' * 43,
			'enrollment_private_key': 'TEST PRIVATE KEY'}
		command = SUPPORT.customer_command(self.settings, session)
		script = SUPPORT.customer_script(self.settings, session)
		self.assertIn('powershell.exe', command)
		self.assertNotIn('sudo bash', command)
		self.assertNotIn('PRIVATE KEY', command)
		self.assertNotIn('__TSUITE_', script)
		self.assertIn('StrictHostKeyChecking=yes', script)
		encoded = script.split("FromBase64String('", 1)[1].split("'", 1)[0]
		configuration = json.loads(base64.b64decode(encoded))
		self.assertEqual(configuration['session_id'], session['id'])
		self.assertEqual(configuration['bastion_host_key'], self.settings.bastion_host_key)
		SUPPORT.write_customer_script(self.settings, session)
		SUPPORT.remove_customer_script(self.settings, session)
		self.assertFalse((self.settings.downloads_dir / session['download_id']).exists())

	def test_windows_platform_is_recorded_and_returned_during_enrollment(self):
		for name in ('bootstrap.ps1', 'windows-client.ps1'):
			self.settings.bootstrap_path.with_name(name).write_bytes((sessions.ROOT / 'customer' / name).read_bytes())
		with mock.patch.object(SUPPORT, 'create_tunnel_identity', return_value=('test-user', 'private', 'key')), \
			mock.patch.object(SUPPORT, 'create_key_pair', return_value=('private', sessions.PUBLIC_KEY)), \
			mock.patch.object(SUPPORT, 'chown_to_user'), mock.patch.object(SUPPORT, 'allocate_port', return_value=22000):
			session, token = SUPPORT.create_session(self.store, 'windows-one', sessions.PUBLIC_KEY, 'alice', '维护', 'windows')
		with mock.patch.object(SUPPORT, 'rewrite_tunnel_expiry'), mock.patch.object(SUPPORT, 'chown_to_user'):
			payload = SUPPORT.enroll(self.store, '', 'a' * 32, sessions.PUBLIC_KEY, session['id'], key_authenticated=True)
		self.assertEqual(payload['platform'], 'windows')
		self.assertEqual(SUPPORT.public_session(session)['platform'], 'windows')

	def test_missing_windows_assets_fails_before_creating_accounts(self):
		with mock.patch.object(SUPPORT, 'create_tunnel_identity') as create:
			with self.assertRaisesRegex(SUPPORT.SupportError, 'Windows'):
				SUPPORT.create_session(self.store, 'windows-one', sessions.PUBLIC_KEY, 'alice', 'upgrade', 'windows')
		create.assert_not_called()

	def test_legacy_enrollment_defaults_to_linux(self):
		token = sessions.SupportSessionTest.save_issued_session(self)
		self.assertEqual(SUPPORT.enroll(self.store, token, 'a' * 32, sessions.PUBLIC_KEY)['platform'], 'linux')


class WindowsBrokerTest(unittest.TestCase):
	setUp = console.SupportOperatorBrokerTest.setUp
	tearDown = console.SupportOperatorBrokerTest.tearDown

	def test_windows_creation_passes_platform_without_persisting_secrets(self):
		created = {'id': '012345abcdef', 'platform': 'windows', 'token': 'DO-NOT-STORE',
			'customer_command': 'powershell.exe download', 'expires_at': int(time.time()) + 7200}
		with mock.patch.object(REMOTE, 'remote_action', return_value=subprocess.CompletedProcess([], 0, json.dumps(created))) as action:
			REMOTE.create_session(self.settings, 'windows-one', 'alice', 'maintenance', 'windows')
		self.assertEqual(json.loads(action.call_args.kwargs['input_text'])['platform'], 'windows')
		state = REMOTE.session_state_path(self.settings, created['id']).read_text()
		self.assertNotIn('DO-NOT-STORE', state)

	def test_windows_close_confirms_cleanup_before_revoking_and_preserves_failed_session(self):
		for returncode in (0, 1):
			with self.subTest(returncode=returncode):
				session_id = '012345abcdef'
				REMOTE.atomic_write(REMOTE.session_state_path(self.settings, session_id), json.dumps({'id': session_id, 'identity_file': str(REMOTE.identity_path(self.settings, session_id))}))
				REMOTE.atomic_write(REMOTE.identity_path(self.settings, session_id), 'test private')
				remote = {'id': session_id, 'platform': 'windows', 'status': 'enrolled'}
				cleanup = subprocess.CompletedProcess([], returncode, f'cleanup-scheduled:{session_id}\n')
				with mock.patch.object(REMOTE, 'remote_session', return_value=remote), \
					mock.patch.object(REMOTE, 'customer_ssh_args', return_value=['ssh']), \
					mock.patch.object(REMOTE, 'run', return_value=cleanup) as run, \
					mock.patch.object(REMOTE, 'close_remote', return_value=subprocess.CompletedProcess([], 0, '')) as close:
					if returncode:
						with self.assertRaises(REMOTE.RemoteActionError):
							REMOTE.close_session(self.settings, session_id, 'alice')
						close.assert_not_called()
						self.assertTrue(REMOTE.session_state_path(self.settings, session_id).exists())
					else:
						REMOTE.close_session(self.settings, session_id, 'alice')
						close.assert_called_once()
					command = run.call_args.args[0][-1]
					decoded = base64.b64decode(command.split()[-1]).decode('utf-16-le')
					self.assertIn('-Mode Close', decoded)
					self.assertIn(session_id, decoded)
					self.assertNotIn('sudo', decoded)

	def test_both_clients_encode_windows_native_arguments_and_exit_code(self):
		for client in (REMOTE, CLI):
			args = ['powershell.exe', '-Command', 'Write-Output "a b"', "O'Brien", '中文', '']
			encoded = client.windows_command(args)
			decoded = base64.b64decode(encoded.split()[-1]).decode('utf-16-le')
			self.assertIn('exit $process.ExitCode', decoded)
			self.assertIn(subprocess.list2cmdline(args[1:]).replace("'", "''"), decoded)
			with self.assertRaises(ValueError):
				client.windows_cleanup("id'; whoami")


class WindowsConsoleTest(unittest.TestCase):
	setUp = console.SupportConsoleTest.setUp
	tearDown = console.SupportConsoleTest.tearDown
	call = console.SupportConsoleTest.call

	def test_windows_selection_reaches_broker_and_invalid_platform_is_rejected(self):
		app = console.CONSOLE.Application(self.settings)
		session_id, csrf = app.store.new_session('alice', 'Alice')
		cookie = f'tsuite_support_session={session_id}'
		body = f'csrf={csrf}&customer=windows-one&purpose=maintenance&platform=windows'
		with mock.patch.object(console.CONSOLE, 'manager', return_value=json.dumps({
			'id': '012345abcdef', 'token': 'secret', 'customer_command': 'powershell.exe test',
		})) as manager:
			captured, content = self.call(app, '/session', 'POST', body, cookie)
			self.assertTrue(captured['status'].startswith('200'))
			self.assertIn('管理员 PowerShell', content)
			self.assertEqual(manager.call_args.args[-2:], ('--platform', 'windows'))
			manager.reset_mock()
			captured, _ = self.call(app, '/session', 'POST', body.replace('platform=windows', 'platform=invalid'), cookie)
			self.assertTrue(captured['status'].startswith('400'))
			manager.assert_not_called()

	def test_bridge_validates_and_passes_windows_platform(self):
		for platform in ('windows', 'invalid'):
			request = {'customer': 'windows-one', 'created_by': 'alice', 'purpose': 'maintenance',
				'operator_public_key': sessions.PUBLIC_KEY, 'platform': platform}
			stdin = io.TextIOWrapper(io.BytesIO(json.dumps(request).encode() + b'\n'))
			with mock.patch.object(console.BASTION_ACTION.sys, 'stdin', stdin), \
				mock.patch.object(console.BASTION_ACTION, 'run_manager', return_value=0) as manager:
				if platform == 'invalid':
					with self.assertRaises(console.BASTION_ACTION.ActionError):
						console.BASTION_ACTION.main(['create'])
					manager.assert_not_called()
				else:
					console.BASTION_ACTION.main(['create'])
					args = manager.call_args.args
					self.assertEqual(args[args.index('--platform') + 1], 'windows')
