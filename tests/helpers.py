"""Shared test helpers: config factory, server processes, HTTP client,
independent reference hashing, read-only DB inspection."""

import hashlib
import hmac
import http.client
import json
import os
import subprocess
import sys
import time

from auth_service import db as dbmod
from auth_service.config import default_config_dict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Fast but structurally identical parameters for tests.
TEST_PARAM_OVERRIDES = {
    "pbkdf2_iterations": 8000,
    "pbkdf2_min_iterations": 1000,
    "pbkdf2_max_iterations": 100000,
    "scrypt_n": 4096,
    "scrypt_min_n": 1024,
    "scrypt_max_n": 32768,
    "admin_token": "test-admin-token",
}


def make_config(dirpath, hooks=True, **overrides):
    d = default_config_dict()
    d.update(TEST_PARAM_OVERRIDES)
    if hooks:
        d["enable_test_hooks"] = True
        d["hook_dir"] = os.path.join(dirpath, "hooks")
    d.update(overrides)
    path = os.path.join(dirpath, "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(d, f)
    return path


def hook_file(config_path, name):
    with open(config_path, "r", encoding="utf-8") as f:
        d = json.load(f)
    return os.path.join(d["hook_dir"], name)


def start_server(config, db):
    proc = subprocess.Popen(
        [sys.executable, "-m", "auth_service.server",
         "--config", config, "--db", db, "--port", "0"],
        cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    line = proc.stdout.readline().strip()
    if not line.startswith("READY "):
        raise RuntimeError(f"server did not start: {line!r}")
    return proc, int(line.split()[1])


def stop_server(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def post(port, path, payload=None, headers=None, timeout=60):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("POST", path, json.dumps(payload or {}),
                     {"Content-Type": "application/json", **(headers or {})})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, json.loads(data.decode("utf-8")) if data else {}
    finally:
        conn.close()


def post_expect_death(port, path, payload=None, headers=None, timeout=60):
    """Send a request whose handler kills the server; return the exception."""
    try:
        post(port, path, payload, headers, timeout)
    except Exception as e:  # RemoteDisconnected / ConnectionResetError / ...
        return e
    return None


def wait_file(path, timeout=30):
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise TimeoutError(f"timed out waiting for {path}")
        time.sleep(0.01)


def ref_verify(algo, password, salt, params_json, expected):
    """Independent reference hash check (does not import service crypto)."""
    params = json.loads(params_json)
    if algo == "pbkdf2-sha256":
        h = hashlib.pbkdf2_hmac("sha256", password, salt,
                                params["iterations"], dklen=params["dklen"])
    elif algo == "scrypt":
        h = hashlib.scrypt(password, salt=salt, n=params["n"], r=params["r"],
                           p=params["p"], dklen=params["dklen"],
                           maxmem=1 << 30)
    else:
        raise AssertionError(f"unknown algo {algo!r}")
    return hmac.compare_digest(h, expected)


def read_account_ro(db, username):
    """Read one account row via a read-only connection."""
    conn = dbmod.connect(db, readonly=True)
    try:
        return conn.execute(
            "SELECT username, cred_version, session_gen, algo, salt, hash, params"
            " FROM accounts WHERE username = ?", (username,)).fetchone()
    finally:
        conn.close()


def count_sessions_ro(db, username):
    conn = dbmod.connect(db, readonly=True)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE username = ?",
            (username,)).fetchone()[0]
    finally:
        conn.close()
