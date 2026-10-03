"""Bounded subprocess lifetime, including its process group on Linux."""
import os
import signal
import subprocess


def run_bounded(argv, *, timeout=120, **kwargs):
    with subprocess.Popen(argv, start_new_session=True, **kwargs) as child:
        try:
            child.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            try:
                if os.name == 'posix':
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
            except ProcessLookupError:
                pass
            child.wait()
            raise
        return subprocess.CompletedProcess(argv, child.returncode)
