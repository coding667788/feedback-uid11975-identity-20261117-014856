"""Core authentication logic.

Concurrency rules implemented here:

* Expensive password hashing (verify / re-hash) always runs *outside* any
  database write transaction and outside any global lock.  Connections are
  per-operation and idle while hashing.
* After the expensive computation finishes, the write transaction
  re-checks that the credential it computed against is still the current
  one (``cred_version`` unchanged).  If a password change or admin reset
  committed in between, the stale result is discarded with a 409 conflict
  -- it never overwrites a newer password, never downgrades a newer hash,
  and never issues a session for a stale generation.
* Password change and admin reset advance ``cred_version`` and
  ``session_gen`` atomically in one transaction and delete all sessions.
* A pure hash upgrade (PBKDF2 -> scrypt after a successful legacy login)
  only rewrites the stored algorithm fields; it does not touch
  ``cred_version`` or ``session_gen``, so existing sessions survive.
"""

import hashlib
import secrets
import sqlite3
import time

from . import crypto
from . import db as dbmod


class AuthError(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.code = code
        self.status = status


def _rollback_quietly(conn):
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass


def check_username(cfg, username):
    if not isinstance(username, str) or not username:
        raise AuthError("bad_request", 400)
    if len(username.encode("utf-8")) > cfg.username_max_bytes:
        raise AuthError("bad_request", 400)


def check_password_input(cfg, password):
    """Passwords are raw UTF-8 bytes; only a hard length cap is enforced."""
    if not isinstance(password, (bytes, bytearray)):
        raise AuthError("bad_request", 400)
    if len(password) == 0:
        raise AuthError("password_empty", 400)
    if len(password) > cfg.password_max_bytes:
        raise AuthError("password_too_long", 400)


def _load_record(cfg, conn, username):
    row = conn.execute(
        "SELECT cred_version, session_gen, algo, salt, hash, params"
        " FROM accounts WHERE username = ?", (username,)).fetchone()
    if row is None:
        return None, None
    cred_version, session_gen, algo, salt, hash_, params = row
    try:
        rec = crypto.validate_record(cfg, algo, salt, hash_, params)
    except crypto.RecordInvalid:
        raise AuthError("credential_record_invalid", 500)
    return (cred_version, session_gen), rec


def create_account(db_path, cfg, username, password, algo):
    """Create a user with an explicitly chosen algorithm (seeding/tests)."""
    check_username(cfg, username)
    check_password_input(cfg, password)
    if algo == crypto.ALGO_SCRYPT:
        nh = crypto.hash_scrypt(cfg, password)
    elif algo == crypto.ALGO_PBKDF2:
        nh = crypto.hash_pbkdf2(cfg, password)
    else:
        raise AuthError("bad_request", 400)
    conn = dbmod.connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO accounts"
                " (username, cred_version, session_gen, algo, salt, hash, params)"
                " VALUES (?, 1, 1, ?, ?, ?, ?)",
                (username, nh.algo, nh.salt, nh.hash, nh.params_json))
            conn.execute("COMMIT")
        except sqlite3.IntegrityError:
            _rollback_quietly(conn)
            raise AuthError("user_exists", 409)
        except BaseException:
            _rollback_quietly(conn)
            raise
    finally:
        conn.close()


def login(db_path, cfg, hooks, username, password, req_hooks=None):
    """Verify password; upgrade legacy hash on success; issue a session."""
    check_username(cfg, username)
    check_password_input(cfg, password)
    conn = dbmod.connect(db_path)
    try:
        state, rec = _load_record(cfg, conn, username)
        if state is None:
            crypto.dummy_verify(cfg, password)
            raise AuthError("invalid_credentials", 401)
        cred_version, _ = state

        # Expensive verification happens outside any transaction/lock.
        if not crypto.verify(cfg, rec, password):
            raise AuthError("invalid_credentials", 401)
        hooks.run("login.after_verify", req_hooks)

        # Expensive upgrade hash also happens outside the write transaction.
        upgrade = None
        if rec.algo == crypto.ALGO_PBKDF2:
            upgrade = crypto.hash_scrypt(cfg, password)

        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT cred_version, session_gen FROM accounts WHERE username = ?",
                (username,)).fetchone()
            if row is None or row[0] != cred_version:
                # The credential we verified was replaced meanwhile (change
                # or reset committed).  Discard our stale verification and
                # any upgrade we computed; do not issue a session.
                raise AuthError("credential_changed", 409)
            session_gen = row[1]
            if upgrade is not None:
                # Pure algorithm upgrade: versions and sessions untouched.
                conn.execute(
                    "UPDATE accounts SET algo = ?, salt = ?, hash = ?, params = ?"
                    " WHERE username = ? AND cred_version = ?",
                    (upgrade.algo, upgrade.salt, upgrade.hash,
                     upgrade.params_json, username, cred_version))
            token = secrets.token_bytes(32)
            now = time.time()
            conn.execute(
                "INSERT INTO sessions"
                " (token_hash, username, session_gen, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (hashlib.sha256(token).digest(), username, session_gen,
                 now, now + cfg.session_ttl_seconds))
            hooks.run("login.before_commit", req_hooks)
            conn.execute("COMMIT")
        except BaseException:
            _rollback_quietly(conn)
            raise
        hooks.run("login.after_commit", req_hooks)
        return token.hex()
    finally:
        conn.close()


def change_password(db_path, cfg, hooks, username, old_password, new_password,
                    req_hooks=None):
    check_username(cfg, username)
    check_password_input(cfg, old_password)
    check_password_input(cfg, new_password)
    conn = dbmod.connect(db_path)
    try:
        state, rec = _load_record(cfg, conn, username)
        if state is None:
            crypto.dummy_verify(cfg, old_password)
            raise AuthError("invalid_credentials", 401)
        cred_version, _ = state

        # Expensive: verify old password and hash the new one, both outside
        # the write transaction.
        if not crypto.verify(cfg, rec, old_password):
            raise AuthError("invalid_credentials", 401)
        nh = crypto.hash_scrypt(cfg, new_password)
        hooks.run("change.after_verify", req_hooks)

        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT cred_version FROM accounts WHERE username = ?",
                (username,)).fetchone()
            if row is None or row[0] != cred_version:
                # Another change/reset committed first; our verification of
                # the old password is stale.  Refuse rather than overwrite.
                raise AuthError("credential_changed", 409)
            conn.execute(
                "UPDATE accounts SET cred_version = cred_version + 1,"
                " session_gen = session_gen + 1,"
                " algo = ?, salt = ?, hash = ?, params = ?"
                " WHERE username = ? AND cred_version = ?",
                (nh.algo, nh.salt, nh.hash, nh.params_json,
                 username, cred_version))
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
            hooks.run("change.before_commit", req_hooks)
            conn.execute("COMMIT")
        except BaseException:
            _rollback_quietly(conn)
            raise
        hooks.run("change.after_commit", req_hooks)
    finally:
        conn.close()


def admin_reset(db_path, cfg, hooks, username, new_password, req_hooks=None):
    check_username(cfg, username)
    check_password_input(cfg, new_password)
    # Expensive hash computed before the write transaction begins.
    nh = crypto.hash_scrypt(cfg, new_password)
    conn = dbmod.connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE accounts SET cred_version = cred_version + 1,"
                " session_gen = session_gen + 1,"
                " algo = ?, salt = ?, hash = ?, params = ?"
                " WHERE username = ?",
                (nh.algo, nh.salt, nh.hash, nh.params_json, username))
            if cur.rowcount == 0:
                raise AuthError("user_not_found", 404)
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
            hooks.run("reset.before_commit", req_hooks)
            conn.execute("COMMIT")
        except BaseException:
            _rollback_quietly(conn)
            raise
        hooks.run("reset.after_commit", req_hooks)
    finally:
        conn.close()


def validate_session(db_path, cfg, token_hex):
    """Return (valid, username).  A session is only valid for the account's
    current session generation, so resets/changes revoke it immediately."""
    if not isinstance(token_hex, str):
        return False, None
    try:
        token = bytes.fromhex(token_hex)
    except ValueError:
        return False, None
    if len(token) != 32:
        return False, None
    th = hashlib.sha256(token).digest()
    conn = dbmod.connect(db_path)
    try:
        row = conn.execute(
            "SELECT s.username, s.expires_at, s.session_gen, a.session_gen"
            " FROM sessions s JOIN accounts a ON a.username = s.username"
            " WHERE s.token_hash = ?", (th,)).fetchone()
        if row is None:
            return False, None
        username, expires_at, sess_gen, acct_gen = row
        if sess_gen != acct_gen or expires_at <= time.time():
            return False, None
        return True, username
    finally:
        conn.close()
