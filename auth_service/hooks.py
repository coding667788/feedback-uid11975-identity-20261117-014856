"""Test-only synchronization and crash hooks.

Hooks let tests create *real* rendezvous points between processes (file
barriers), sequence events across requests (touch / wait_file) and kill
a server at an exact point in the transaction lifecycle (kill).  They are
only active when ``enable_test_hooks`` is set in the config and are
triggered per-request through the ``X-Test-Hooks`` header, so a
production deployment (hooks disabled) is unaffected.

No fixed sleeps are used anywhere: barriers and wait_file poll for an
actual condition.
"""

import os
import pathlib
import re
import threading
import time


class HookError(Exception):
    pass


_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class Hooks:
    def __init__(self, enabled=False, directory=None):
        self.enabled = bool(enabled) and bool(directory)
        self.dir = pathlib.Path(directory) if directory else None
        if self.enabled:
            self.dir.mkdir(parents=True, exist_ok=True)

    def run(self, point, req_hooks):
        if not self.enabled or not req_hooks:
            return
        specs = req_hooks.get(point)
        if not specs:
            return
        if not isinstance(specs, list):
            raise HookError(f"hook spec for {point} must be a list")
        for spec in specs:
            self._run_one(point, spec)

    def _run_one(self, point, spec):
        if not isinstance(spec, dict):
            raise HookError("hook spec must be an object")
        action = spec.get("action")
        if action == "kill":
            # Real, immediate process termination (no cleanup, no response).
            os._exit(1)
        name = spec.get("name", "")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise HookError("invalid hook name")
        if action == "touch":
            (self.dir / name).write_text("x", encoding="ascii")
        elif action == "wait_file":
            target = self.dir / name
            self._wait(lambda: target.exists(), spec, point)
        elif action == "barrier":
            count = spec.get("count")
            if not isinstance(count, int) or count < 1:
                raise HookError("barrier requires a positive integer count")
            bdir = self.dir / ("barrier_" + name)
            bdir.mkdir(exist_ok=True)
            marker = bdir / f"{os.getpid()}_{threading.get_ident()}"
            marker.write_text("x", encoding="ascii")
            self._wait(lambda: len(list(bdir.iterdir())) >= count, spec, point)
        else:
            raise HookError(f"unknown hook action {action!r}")

    @staticmethod
    def _wait(cond, spec, point):
        timeout = spec.get("timeout", 60)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise HookError("invalid hook timeout")
        deadline = time.monotonic() + timeout
        while not cond():
            if time.monotonic() > deadline:
                raise HookError(f"hook wait timed out at {point}")
            time.sleep(0.01)
