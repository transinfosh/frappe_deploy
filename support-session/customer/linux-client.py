#!/usr/bin/env python3
"""Root-owned activity monitor for a single renewable support lease."""
import contextlib
import fcntl
import json
import os
import pathlib
import pwd
import re
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path('/etc/tsuite-support-client')


def atomic_write(path, text, mode=0o600, owner=None):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        if owner:
            os.chown(temporary, *owner)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def active(previous, now):
    try:
        stat = (ROOT / 'activity').stat()
        stamp = stat.st_mtime_ns
        return stamp != previous and 0 <= now - stat.st_mtime <= 45, stamp
    except FileNotFoundError:
        return False, previous


def request_lease(state, activity):
    result = subprocess.run([
        '/usr/bin/ssh', '-F', 'none', '-T', '-i', str(ROOT / 'lease_ed25519'),
        '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', f'UserKnownHostsFile={ROOT / "known_hosts"}', '-o', 'ClearAllForwardings=yes',
        '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
        '-p', str(state['bastion_port']), f'tsuite-enroll@{state["bastion_host"]}', 'lease',
    ], input=json.dumps({'active': activity}) + '\n', capture_output=True, text=True, timeout=20, check=True)
    reply = json.loads(result.stdout)
    now = int(time.time())
    expiry = reply.get('expires_at')
    if (reply.get('session_id') != state['session_id'] or type(expiry) is not int
            or reply.get('idle_timeout_seconds') != state['idle_timeout_seconds']
            or not now < expiry <= now + state['idle_timeout_seconds'] + 30
            or expiry < state['expires_at']):
        raise ValueError('Invalid support lease response')
    return expiry


def apply_expiry(state, expiry):
    account = pwd.getpwnam(state['ops_user'])
    keys = pathlib.Path(account.pw_dir) / '.ssh/authorized_keys'
    stamp = time.strftime('%Y%m%d%H%M%SZ', time.gmtime(expiry))
    updated, count = re.subn(r'expiry-time="[0-9]{14}Z"', f'expiry-time="{stamp}"', keys.read_text())
    if count != 1:
        raise ValueError('Invalid support authorized_keys')
    atomic_write(keys, updated, owner=(account.pw_uid, account.pw_gid))
    configuration = ROOT / 'session.conf'
    updated, count = re.subn(r'^EXPIRES_AT=\d+$', f'EXPIRES_AT={expiry}', configuration.read_text(), flags=re.M)
    if count != 1:
        raise ValueError('Invalid support expiry configuration')
    # The cleanup timer reads session.conf under the same lock.
    state['expires_at'] = expiry
    atomic_write(ROOT / 'session.json', json.dumps(state))
    atomic_write(configuration, updated)


def watch():
    previous = None
    while ROOT.is_dir():
        try:
            with (ROOT / '.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                state = json.loads((ROOT / 'session.json').read_text())
                now = time.time()
                if (ROOT / 'closing').exists() or now >= state['expires_at']:
                    return
                activity, stamp = active(previous, now)
                expiry = request_lease(state, activity)
                apply_expiry(state, expiry)
                previous = stamp
                with contextlib.suppress(FileNotFoundError):
                    (ROOT / "activity").unlink()
        except (subprocess.SubprocessError, OSError, ValueError):
            # Never manufacture a local extension when the server is unreachable.
            print('Support lease check failed; retaining the confirmed expiry.', file=sys.stderr, flush=True)
        time.sleep(15)


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('Root required')
    watch()
