"""SQLite storage layer.

One row per account carries both the credential version and the session
generation so that password changes / resets can advance both atomically
in a single transaction.  Sessions are stored as SHA-256 token hashes.
"""

import pathlib
import sqlite3
import urllib.parse

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    username      TEXT PRIMARY KEY,
    cred_version  INTEGER NOT NULL CHECK (cred_version >= 1),
    session_gen   INTEGER NOT NULL CHECK (session_gen >= 1),
    algo          TEXT NOT NULL,
    salt          BLOB NOT NULL,
    hash          BLOB NOT NULL,
    params        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash    BLOB PRIMARY KEY,
    username      TEXT NOT NULL REFERENCES accounts(username) ON DELETE CASCADE,
    session_gen   INTEGER NOT NULL,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
"""


def connect(path, readonly=False):
    if readonly:
        posix = pathlib.Path(str(path)).absolute().as_posix()
        uri = "file:" + urllib.parse.quote(posix) + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=30)
    else:
        conn = sqlite3.connect(str(path), isolation_level=None, timeout=30)
    conn.execute("PRAGMA busy_timeout = 30000")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(path):
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
