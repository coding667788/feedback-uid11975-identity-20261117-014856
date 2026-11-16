"""Independent reference hash implementation.

Used by the ``check`` CLI command (and mirrored by the test suite) to
recompute stored hashes *without* going through auth_service.crypto, so a
bug in the service's own hashing path cannot silently validate itself.
"""

import hashlib
import hmac
import json


def reference_hash(algo, password, salt, params_json):
    params = json.loads(params_json)
    if algo == "pbkdf2-sha256":
        return hashlib.pbkdf2_hmac(
            "sha256", password, salt,
            int(params["iterations"]), dklen=int(params["dklen"]))
    if algo == "scrypt":
        return hashlib.scrypt(
            password, salt=salt,
            n=int(params["n"]), r=int(params["r"]), p=int(params["p"]),
            dklen=int(params["dklen"]), maxmem=1 << 30)
    raise ValueError(f"unknown algorithm {algo!r}")


def reference_verify(algo, password, salt, params_json, expected):
    return hmac.compare_digest(
        reference_hash(algo, password, salt, params_json), expected)
