import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_support_session as sessions

SUPPORT = sessions.SUPPORT
ROOT = sessions.ROOT
spec = importlib.util.spec_from_file_location('linux_client', ROOT / 'customer/linux-client.py')
CLIENT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CLIENT)


class RenewableSessionTest(unittest.TestCase):
    tearDown = sessions.SupportSessionTest.tearDown
    def setUp(self):
        sessions.SupportSessionTest.setUp(self)
        sessions.SupportSessionTest.save_issued_session(self)
        self.session_id = '012345abcdef'
        session = self.store.load(self.session_id)
        session.update(auth_mode='enrollment-key', idle_timeout_seconds=300,
                       enrollment_public_key=sessions.PUBLIC_KEY, download_id='a' * 43)
        self.store.save(session)
        self.settings.authorized_keys_dir.mkdir()
        (self.settings.authorized_keys_dir / session['tunnel_user']).write_text(
            'restrict,expiry-time="20990101000000Z" ' + sessions.PUBLIC_KEY + '\n')
        self.settings.downloads_dir.mkdir()
        (self.settings.downloads_dir / session['download_id']).write_text('secret bootstrap')
        self.chown = mock.patch.object(SUPPORT, 'chown_to_user')
        self.chown.start()
        self.addCleanup(self.chown.stop)
        self.keys = mock.patch.object(SUPPORT, 'create_key_pair', return_value=('PRIVATE', sessions.PUBLIC_KEY))
        self.keys.start()
        self.addCleanup(self.keys.stop)

    def enroll_new(self):
        return SUPPORT.enroll(self.store, '', 'a' * 32, sessions.PUBLIC_KEY, self.session_id, key_authenticated=True)

    def test_new_session_requires_bound_ssh_key_not_old_code(self):
        with self.assertRaises(SUPPORT.SupportError):
            SUPPORT.enroll(self.store, 'one-time-token', 'a' * 32, sessions.PUBLIC_KEY, self.session_id)
        result = self.enroll_new()
        self.assertEqual(result['schema_version'], 2)
        self.assertEqual(result['idle_timeout_seconds'], 300)
        self.assertEqual(result['lease_private_key'], 'PRIVATE')
        self.assertEqual(result, self.enroll_new())
        self.assertFalse((self.settings.downloads_dir / ('a' * 43)).exists())
        authorized = (self.settings.authorized_keys_dir / 'tsuite-enroll').read_text()
        self.assertIn('lease-ssh ' + self.session_id, authorized)
        self.assertIn('enroll-ssh ' + self.session_id, authorized)
        with self.assertRaises(SUPPORT.SupportError):
            SUPPORT.enroll(self.store, '', 'b' * 32, sessions.PUBLIC_KEY, self.session_id, key_authenticated=True)

    def test_issued_session_can_enroll_after_idle_duration_but_before_link_expiry(self):
        now = int(time.time())
        session = self.store.load(self.session_id)
        session['expires_at'] = now + 900
        self.store.save(session)
        with mock.patch.object(SUPPORT.time, 'time', return_value=now + 600):
            self.assertEqual(self.enroll_new()['expires_at'], now + 900)

    def test_idle_window_starts_at_enrollment_and_only_activity_extends_it(self):
        now = int(time.time())
        with mock.patch.object(SUPPORT.time, 'time', return_value=now + 100):
            initial = self.enroll_new()['expires_at']
        self.assertEqual(initial, now + 400)
        with mock.patch.object(SUPPORT.time, 'time', return_value=now + 350):
            self.assertEqual(SUPPORT.renew_lease(self.store, self.session_id, False)['expires_at'], initial)
            renewed = SUPPORT.renew_lease(self.store, self.session_id, True)['expires_at']
        self.assertEqual(renewed, now + 650)
        with mock.patch.object(SUPPORT.time, 'time', return_value=now + 450):
            self.assertGreater(SUPPORT.renew_lease(self.store, self.session_id, True)['expires_at'], renewed)
        self.assertIn(SUPPORT.ssh_expiry(now + 750),
                      (self.settings.authorized_keys_dir / 'tsuite-tunnel-012345ab').read_text())

    def test_ended_and_expired_sessions_cannot_be_renewed(self):
        self.enroll_new()
        for status in ('issued', 'revoking', 'closed', 'expired'):
            session = self.store.load(self.session_id)
            session['status'] = status
            self.store.save(session)
            with self.assertRaises(SUPPORT.SupportError):
                SUPPORT.renew_lease(self.store, self.session_id, True)
        session['status'] = 'enrolled'
        session['expires_at'] = int(time.time())
        self.store.save(session)
        with self.assertRaises(SUPPORT.SupportError):
            SUPPORT.renew_lease(self.store, self.session_id, True)

    def test_activity_must_be_boolean_and_private_lease_fields_never_public(self):
        self.enroll_new()
        for value in ('true', 1, None, {}):
            with self.assertRaises(SUPPORT.SupportError):
                SUPPORT.renew_lease(self.store, self.session_id, value)
        result = SUPPORT.public_session(self.store.load(self.session_id))
        self.assertNotIn('lease_private_key', result)
        self.assertNotIn('lease_public_key', result)


class LinuxActivityTest(unittest.TestCase):
    def test_client_download_does_not_consume_piped_bootstrap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = root / 'ssh'
            helper.write_text('#!/bin/sh\ncat >/dev/null\nprintf client-source\n')
            helper.chmod(0o700)
            line = next(line for line in (ROOT / 'customer/bootstrap.sh').read_text().splitlines()
                        if '"${enrollment_ssh[@]}" linux-client' in line)
            script = f'work_dir={directory}\nenrollment_ssh=({helper})\n{line}\nprintf reached-enrollment\n'
            result = subprocess.run(['bash', '-s'], input=script, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'reached-enrollment')
            self.assertEqual((root / 'linux-client.py').read_text(), 'client-source')

    def test_only_new_recent_input_markers_are_activity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            marker = root / 'activity'
            now = time.time()
            with mock.patch.object(CLIENT, 'ROOT', root):
                self.assertEqual(CLIENT.active(None, now), (False, None))
                marker.touch()
                found, stamp = CLIENT.active(None, now + 1)
                self.assertTrue(found)
                self.assertFalse(CLIENT.active(stamp, now + 2)[0])
                self.assertFalse(CLIENT.active(None, now + 46)[0])
                os.utime(marker, (now + 5, now + 5))
                self.assertTrue(CLIENT.active(stamp, now + 6)[0])

    def test_acknowledged_input_is_not_replayed_after_monitor_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            state = {'expires_at': int(time.time()) + 300}
            (root / 'session.json').write_text(json.dumps(state))
            (root / 'activity').touch()
            with mock.patch.object(CLIENT, 'ROOT', root), mock.patch.object(CLIENT, 'request_lease', return_value=state['expires_at']) as request, mock.patch.object(CLIENT, 'apply_expiry'), mock.patch.object(CLIENT.time, 'sleep', side_effect=RuntimeError('end iteration')):
                for _ in range(2):
                    with self.assertRaisesRegex(RuntimeError, 'end iteration'):
                        CLIENT.watch()
            self.assertEqual([call.args[1] for call in request.call_args_list], [True, False])
            self.assertFalse((root / 'activity').exists())

    def test_invalid_lease_response_does_not_change_local_state(self):
        state = dict(session_id='012345abcdef', bastion_host='example.com', bastion_port=22,
                     idle_timeout_seconds=300, expires_at=int(time.time()) + 200)
        for response in ({'session_id': 'ffffffffffff', 'expires_at': state['expires_at'], 'idle_timeout_seconds': 300},
                         {'session_id': state['session_id'], 'expires_at': state['expires_at'] + 10000, 'idle_timeout_seconds': 300}):
            with mock.patch.object(CLIENT.subprocess, 'run', return_value=mock.Mock(stdout=json.dumps(response))):
                with self.assertRaises(ValueError):
                    CLIENT.request_lease(state, True)


class RelayTest(unittest.TestCase):
    def test_output_and_running_process_do_not_trigger_further_renewals(self):
        for running_command, input_bytes, expected in [(False, b'', 0), (True, b'', 1), (False, b'input', 1)]:
            with self.subTest(running_command=running_command, input=input_bytes), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                events = root / 'events'
                runner = root / 'runner.py'
                helper = root / 'helper.py'
                helper.write_text(f"with open({str(events)!r}, 'a') as output: output.write('input\\n')\n")
                module = ROOT / 'operator/tsuite_support_activity.py'
                runner.write_text(f"""import importlib.util, sys
spec = importlib.util.spec_from_file_location('relay', {str(module)!r})
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
relay.REPORT_INTERVAL_SECONDS = 0.05
command = [sys.executable, '-u', '-c', 'import time; [(print("output"), time.sleep(0.05)) for _ in range(12)]']
sys.exit(relay.connect(command, [sys.executable, {str(helper)!r}], 'linux', '012345abcdef', running_command={running_command!r}))
""")
                result = subprocess.run([sys.executable, str(runner)], input=input_bytes, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(events.read_text().splitlines()) if events.exists() else 0, expected)

    def test_fast_run_waits_for_its_input_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            events = root / 'events'
            helper = root / 'helper.py'
            helper.write_text(f"import time; time.sleep(0.2)\nwith open({str(events)!r}, 'a') as output: output.write('input\\n')\n")
            runner = root / 'runner.py'
            module = ROOT / 'operator/tsuite_support_activity.py'
            runner.write_text(f"""import importlib.util, sys
spec = importlib.util.spec_from_file_location('relay', {str(module)!r})
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
sys.exit(relay.connect(['/bin/true'], [sys.executable, {str(helper)!r}], 'linux', '012345abcdef', running_command=True))
""")
            result = subprocess.run([sys.executable, str(runner)], input=b'', capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(events.read_text(), 'input\n')

    def test_large_bidirectional_stream_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runner = root / 'runner.py'
            module = ROOT / 'operator/tsuite_support_activity.py'
            runner.write_text(f'''import importlib.util, sys
spec = importlib.util.spec_from_file_location('relay', {str(module)!r})
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
command = [sys.executable, '-c', "import sys; sys.stdout.buffer.write(b'x'*262144); sys.stdout.flush(); data=sys.stdin.buffer.read(); sys.stderr.write(str(len(data))); sys.exit(7)"]
sys.exit(relay.connect(command, ['/bin/true'], 'linux', '012345abcdef', running_command=True))
''')
            result = subprocess.run([sys.executable, str(runner)], input=b'y' * 262144, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertEqual(result.stdout, b'x' * 262144)
            self.assertEqual(result.stderr, b'262144')
