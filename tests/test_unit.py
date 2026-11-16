"""Unit tests: input handling, record validation, upgrade semantics,
session revocation, CLI check command."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from auth_service import core, crypto, db as dbmod
from auth_service.config import load_config
from auth_service.hooks import Hooks

from tests import helpers

NO_HOOKS = Hooks(False, None)


class UnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="authunit_")
        self.cfg_path = helpers.make_config(self.tmp, hooks=False)
        self.cfg = load_config(self.cfg_path)
        self.db = os.path.join(self.tmp, "unit.db")
        dbmod.init_schema(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add_user(self, name, password, algo):
        core.create_account(self.db, self.cfg, name, password.encode("utf-8"), algo)

    def login(self, name, password):
        return core.login(self.db, self.cfg, NO_HOOKS, name,
                          password.encode("utf-8"))

    def tamper(self, sql, params=()):
        conn = dbmod.connect(self.db)
        try:
            conn.execute(sql, params)
        finally:
            conn.close()

    # -- password byte handling ------------------------------------------
    def test_password_used_as_exact_utf8_bytes(self):
        self.add_user("u_exact", " 密码🔑 tail ", "scrypt")
        self.login("u_exact", " 密码🔑 tail ")            # exact match works
        for variant in ("密码🔑 tail", " 密码🔑 tail", " 密码🔑 tail  ",
                        "密码🔑 tail ", " 密码🔑  tail "):
            with self.assertRaises(core.AuthError) as cm:
                self.login("u_exact", variant)
            self.assertEqual(cm.exception.code, "invalid_credentials")

    def test_password_length_cap(self):
        with self.assertRaises(core.AuthError) as cm:
            core.check_password_input(self.cfg, b"x" * 257)
        self.assertEqual(cm.exception.code, "password_too_long")
        core.check_password_input(self.cfg, b"x" * 256)  # boundary ok
        with self.assertRaises(core.AuthError):
            core.check_password_input(self.cfg, b"")

    # -- legacy upgrade ----------------------------------------------------
    def test_legacy_login_upgrades_without_touching_versions(self):
        self.add_user("u_leg", "Leg#pw1", "pbkdf2-sha256")
        before = helpers.read_account_ro(self.db, "u_leg")
        self.assertEqual(before[3], "pbkdf2-sha256")
        token = self.login("u_leg", "Leg#pw1")
        after = helpers.read_account_ro(self.db, "u_leg")
        self.assertEqual(after[3], "scrypt")
        self.assertEqual(after[1], before[1])  # cred_version unchanged
        self.assertEqual(after[2], before[2])  # session_gen unchanged
        # stored hash verified with the independent reference implementation
        self.assertTrue(helpers.ref_verify("scrypt", "Leg#pw1".encode(),
                                           after[4], after[6], after[5]))
        # session issued in the same transaction is valid
        valid, who = core.validate_session(self.db, self.cfg, token)
        self.assertTrue(valid)
        self.assertEqual(who, "u_leg")

    def test_failed_login_does_not_upgrade(self):
        self.add_user("u_fail", "Right#pw", "pbkdf2-sha256")
        with self.assertRaises(core.AuthError) as cm:
            self.login("u_fail", "Wrong#pw")
        self.assertEqual(cm.exception.code, "invalid_credentials")
        row = helpers.read_account_ro(self.db, "u_fail")
        self.assertEqual(row[3], "pbkdf2-sha256")

    # -- change / reset ----------------------------------------------------
    def test_change_password_bumps_versions_and_revokes(self):
        self.add_user("u_chg", "Old#pw1", "scrypt")
        token = self.login("u_chg", "Old#pw1")
        before = helpers.read_account_ro(self.db, "u_chg")
        core.change_password(self.db, self.cfg, NO_HOOKS,
                             "u_chg", b"Old#pw1", b"New#pw2")
        after = helpers.read_account_ro(self.db, "u_chg")
        self.assertEqual(after[1], before[1] + 1)  # cred_version +1
        self.assertEqual(after[2], before[2] + 1)  # session_gen +1
        valid, _ = core.validate_session(self.db, self.cfg, token)
        self.assertFalse(valid)                    # old session revoked
        with self.assertRaises(core.AuthError):
            self.login("u_chg", "Old#pw1")
        self.login("u_chg", "New#pw2")

    def test_change_password_wrong_old_rejected(self):
        self.add_user("u_chg2", "Real#pw", "scrypt")
        with self.assertRaises(core.AuthError) as cm:
            core.change_password(self.db, self.cfg, NO_HOOKS,
                                 "u_chg2", b"Fake#pw", b"New#pw")
        self.assertEqual(cm.exception.code, "invalid_credentials")

    def test_admin_reset_bumps_versions_and_revokes(self):
        self.add_user("u_rst", "Old#pw9", "pbkdf2-sha256")
        token = self.login("u_rst", "Old#pw9")
        before = helpers.read_account_ro(self.db, "u_rst")
        core.admin_reset(self.db, self.cfg, NO_HOOKS, "u_rst", b"Reset#pw1")
        after = helpers.read_account_ro(self.db, "u_rst")
        self.assertEqual(after[1], before[1] + 1)
        self.assertEqual(after[2], before[2] + 1)
        self.assertEqual(after[3], "scrypt")
        valid, _ = core.validate_session(self.db, self.cfg, token)
        self.assertFalse(valid)
        with self.assertRaises(core.AuthError):
            self.login("u_rst", "Old#pw9")
        self.login("u_rst", "Reset#pw1")

    def test_reset_unknown_user_404(self):
        with self.assertRaises(core.AuthError) as cm:
            core.admin_reset(self.db, self.cfg, NO_HOOKS, "nobody", b"x")
        self.assertEqual(cm.exception.code, "user_not_found")

    # -- hostile / corrupt records -----------------------------------------
    def test_unknown_algorithm_rejected(self):
        self.add_user("u_alg", "Pw#1", "scrypt")
        self.tamper("UPDATE accounts SET algo = 'argon2' WHERE username = 'u_alg'")
        with self.assertRaises(core.AuthError) as cm:
            self.login("u_alg", "Pw#1")
        self.assertEqual(cm.exception.code, "credential_record_invalid")

    def test_huge_scrypt_params_rejected_without_allocation(self):
        self.add_user("u_big", "Pw#2", "scrypt")
        evil = json.dumps({"n": 1 << 40, "r": 8, "p": 1, "dklen": 32})
        self.tamper("UPDATE accounts SET params = ? WHERE username = 'u_big'",
                    (evil,))
        with self.assertRaises(core.AuthError) as cm:
            self.login("u_big", "Pw#2")  # must fail fast, no 512 GiB alloc
        self.assertEqual(cm.exception.code, "credential_record_invalid")

    def test_huge_pbkdf2_iterations_rejected(self):
        self.add_user("u_it", "Pw#3", "pbkdf2-sha256")
        evil = json.dumps({"iterations": 10 ** 12, "dklen": 32})
        self.tamper("UPDATE accounts SET params = ? WHERE username = 'u_it'",
                    (evil,))
        with self.assertRaises(core.AuthError) as cm:
            self.login("u_it", "Pw#3")
        self.assertEqual(cm.exception.code, "credential_record_invalid")

    def test_truncated_record_rejected(self):
        self.add_user("u_trunc", "Pw#4", "scrypt")
        self.tamper("UPDATE accounts SET hash = x'0011' WHERE username = 'u_trunc'")
        with self.assertRaises(core.AuthError) as cm:
            self.login("u_trunc", "Pw#4")
        self.assertEqual(cm.exception.code, "credential_record_invalid")

    # -- CLI check -----------------------------------------------------------
    def test_cli_check_reference_verify(self):
        self.add_user("u_cli", "Cli#pw1", "scrypt")
        base = [sys.executable, "-m", "auth_service.cli", "check",
                "--config", self.cfg_path, "--db", self.db,
                "--user", "u_cli"]
        ok = subprocess.run(base + ["--password", "Cli#pw1"],
                            cwd=helpers.REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("MATCH", ok.stdout)
        bad = subprocess.run(base + ["--password", "Nope#pw"],
                             cwd=helpers.REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("NO-MATCH", bad.stdout)


if __name__ == "__main__":
    unittest.main()
