"""Relay SSH unchanged while reporting real operator activity to the customer."""
import base64
import contextlib
import os
import selectors
import signal
import subprocess
import sys
import threading
import time


REPORT_INTERVAL_SECONDS = 15


def activity_command(platform, session_id):
    if platform == 'windows':
        script = (f"& (Join-Path $env:ProgramData 'TSuiteSupport/{session_id}/client.ps1') "
                  f"-Mode Activity -SessionId '{session_id}'")
        return 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + base64.b64encode(script.encode('utf-16-le')).decode()
    return 'sudo -n /usr/local/sbin/tsuite-support-client activity'


def connect(arguments, base_arguments, platform, session_id, *, running_command, env=None):
    # A separate short SSH request never exposes the customer lease key to the operator.
    stop = threading.Event()
    activity = [time.monotonic() if running_command else float("-inf")]
    helper = [None]

    reported = [float("-inf")]

    def report_once():
        event = activity[0]
        if event <= reported[0] or time.monotonic() - event > 30:
            return
        try:
            helper[0] = subprocess.Popen(
                [*base_arguments, activity_command(platform, session_id)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
            )
            if helper[0].wait(timeout=20) == 0:
                reported[0] = event
        except subprocess.TimeoutExpired:
            helper[0].kill()
            helper[0].wait()
        except OSError:
            pass
        finally:
            helper[0] = None

    def report():
        while not stop.is_set():
            report_once()
            stop.wait(REPORT_INTERVAL_SECONDS)

    # A local PTY preserves terminal echo, job control, SSH escapes and window resizing.
    terminal = sys.stdin.isatty() and not running_command
    old_terminal = None
    previous_resize = None
    master = slave = None
    process = None
    thread = None
    input_thread = None
    completed = False
    try:
        if terminal:
            import fcntl
            import pty
            import termios
            import tty
            master, slave = pty.openpty()

            def resize(*_):
                size = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b'\0' * 8)
                fcntl.ioctl(master, termios.TIOCSWINSZ, size)

            resize()
            previous_resize = signal.signal(signal.SIGWINCH, resize)
            old_terminal = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
            process = subprocess.Popen(arguments, stdin=slave, stdout=slave, stderr=slave, env=env)
            os.close(slave)
            slave = None
            read_fds = {master: sys.stdout.fileno()}
            input_fd = master
        else:
            process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            read_fds = {process.stdout.fileno(): sys.stdout.fileno(), process.stderr.fileno(): sys.stderr.fileno()}
            input_fd = process.stdin.fileno()
        thread = threading.Thread(target=report, daemon=True)
        thread.start()
        def forward_input():
            # Drain output independently: a child may write before reading a large stdin.
            with selectors.SelectSelector() as inputs:
                inputs.register(sys.stdin.fileno(), selectors.EVENT_READ)
                while not stop.is_set():
                    if not inputs.select(timeout=0.2):
                        continue
                    try:
                        data = os.read(sys.stdin.fileno(), 65536)
                        if not data:
                            if not terminal:
                                process.stdin.close()
                            return
                        activity[0] = time.monotonic()
                        while data and not stop.is_set():
                            data = data[os.write(input_fd, data):]
                    except OSError:
                        return

        input_thread = threading.Thread(target=forward_input, daemon=True)
        input_thread.start()
        with selectors.SelectSelector() as selector:
            for fd in read_fds:
                selector.register(fd, selectors.EVENT_READ)
            while read_fds:
                for key, _ in selector.select(timeout=1):
                    fd = key.fd
                    try:
                        data = os.read(fd, 65536)
                    except OSError:
                        data = b''
                    if not data:
                        selector.unregister(fd)
                        del read_fds[fd]
                        continue
                    while data:
                        data = data[os.write(read_fds[fd], data):]
            result = process.wait()
            completed = True
            return result
    finally:
        stop.set()
        if not completed:
            running_helper = helper[0]
            if running_helper is not None:
                with contextlib.suppress(OSError):
                    running_helper.terminate()
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if input_thread:
            input_thread.join(timeout=1)
        if old_terminal is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_terminal)
        if previous_resize is not None:
            signal.signal(signal.SIGWINCH, previous_resize)
        if thread:
            thread.join(timeout=21)
        # Let a fast successful command's report finish, then flush any final input.
        # Each request is bounded; a failed report never extends the lease locally.
        if completed and thread and not thread.is_alive():
            report_once()
        for fd in (master, slave):
            if fd is not None:
                os.close(fd)
