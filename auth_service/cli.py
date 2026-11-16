"""Command line interface: init / reset / check.

  python -m auth_service.cli init  --config cfg.json --db auth.db
  python -m auth_service.cli reset --config cfg.json --db auth.db --user alice
  python -m auth_service.cli check --config cfg.json --db auth.db [--user U]

``check`` opens the database read-only and verifies stored hashes with an
independent reference implementation (auth_service.reference), never with
the service's own hashing path.  It prints versions and validity only --
never passwords, hashes or tokens.
"""

import argparse
import getpass
import json
import os
import secrets
import sys

from . import core, crypto, db as dbmod, reference
from .config import default_config_dict, load_config
from .hooks import Hooks

# Pre-provisioned test users (documented in README; no registration flow).
SEED_USERS = [
    ("alice", "Alice#pass1", crypto.ALGO_PBKDF2),   # legacy credential
    ("bob", "Bob#pass2", crypto.ALGO_SCRYPT),       # current credential
    ("carol", " 密码🔑 spaces ", crypto.ALGO_PBKDF2),  # non-ASCII + edge spaces
    ("dave", "Dave#pass4", crypto.ALGO_PBKDF2),     # legacy credential
]

_NO_HOOKS = Hooks(False, None)


def cmd_init(args):
    if not os.path.exists(args.config):
        d = default_config_dict()
        d["admin_token"] = secrets.token_hex(24)
        with open(args.config, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        print(f"created config {args.config} with a generated admin token")
    cfg = load_config(args.config)
    dbmod.init_schema(args.db)
    if not args.no_seed:
        for username, password, algo in SEED_USERS:
            try:
                core.create_account(args.db, cfg, username,
                                    password.encode("utf-8"), algo)
                print(f"seeded user {username} ({algo})")
            except core.AuthError as e:
                if e.code == "user_exists":
                    print(f"user {username} already exists, skipped")
                else:
                    raise
    print("init ok")
    return 0


def cmd_reset(args):
    cfg = load_config(args.config)
    password = args.new_password
    if password is None:
        password = getpass.getpass("new password: ")
    core.admin_reset(args.db, cfg, _NO_HOOKS, args.user, password.encode("utf-8"))
    print(f"reset ok: {args.user}")
    return 0


def cmd_check(args):
    cfg = load_config(args.config)
    conn = dbmod.connect(args.db, readonly=True)
    ok = True
    try:
        rows = conn.execute(
            "SELECT username, cred_version, session_gen, algo, salt, hash, params"
            " FROM accounts ORDER BY username").fetchall()
        if not rows:
            print("no accounts")
        for username, cv, sg, algo, salt, hash_, params in rows:
            try:
                crypto.validate_record(cfg, algo, salt, hash_, params)
                status = "record-ok"
            except crypto.RecordInvalid as e:
                status = f"RECORD-INVALID ({e})"
                ok = False
            nsess = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE username = ?",
                (username,)).fetchone()[0]
            print(f"{username}: algo={algo} cred_version={cv} "
                  f"session_gen={sg} sessions={nsess} {status}")

        if args.user:
            row = conn.execute(
                "SELECT algo, salt, hash, params FROM accounts WHERE username = ?",
                (args.user,)).fetchone()
            if row is None:
                print(f"user {args.user} not found")
                return 2
            password = args.password
            if password is None:
                password = getpass.getpass("password to verify: ")
            algo, salt, hash_, params = row
            try:
                match = reference.reference_verify(
                    algo, password.encode("utf-8"), salt, params, hash_)
            except (ValueError, KeyError) as e:
                print(f"reference check failed: {e}")
                return 1
            print("password: MATCH" if match else "password: NO-MATCH")
            ok = ok and match
    finally:
        conn.close()
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog="auth_service.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create schema and seed test users")
    p.add_argument("--config", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--no-seed", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("reset", help="admin reset of a user's password")
    p.add_argument("--config", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--new-password", default=None)
    p.set_defaults(func=cmd_reset)

    p = sub.add_parser("check", help="read-only structural + reference check")
    p.add_argument("--config", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--user", default=None)
    p.add_argument("--password", default=None)
    p.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except core.AuthError as e:
        print(f"error: {e.code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
