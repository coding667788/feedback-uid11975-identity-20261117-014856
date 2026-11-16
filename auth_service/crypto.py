"""Password hashing, record validation and verification.

Passwords are handled as raw UTF-8 bytes: no trimming, no case folding,
no Unicode normalization.  Only salted, one-way hashes are ever stored.

Every record read from the database is validated against the trusted
server configuration *before* any parameter is used, so a forged record
cannot trigger huge memory allocation or unbounded CPU time.
"""

import hashlib
import hmac
import json
import os
from dataclasses import dataclass

ALGO_PBKDF2 = "pbkdf2-sha256"
ALGO_SCRYPT = "scrypt"
ALGOS = (ALGO_PBKDF2, ALGO_SCRYPT)


class RecordInvalid(Exception):
    """A stored credential record is unknown, corrupt or out of range."""


@dataclass
class Record:
    algo: str
    salt: bytes
    hash: bytes
    params: dict


@dataclass
class NewHash:
    algo: str
    salt: bytes
    hash: bytes
    params_json: str


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def validate_record(cfg, algo, salt, hash_, params_json):
    """Validate a stored record against trusted config ranges.

    Raises RecordInvalid for unknown algorithms, corrupt fields, or any
    parameter outside the trusted range.  Nothing is allocated or computed
    from the stored parameters before they are fully validated.
    """
    if algo not in ALGOS:
        raise RecordInvalid(f"unknown algorithm {algo!r}")
    if not isinstance(salt, bytes) or len(salt) != cfg.salt_len:
        raise RecordInvalid("salt missing or wrong length")
    if not isinstance(hash_, bytes) or len(hash_) != cfg.dklen:
        raise RecordInvalid("hash missing or wrong length")
    try:
        params = json.loads(params_json)
    except (TypeError, ValueError):
        raise RecordInvalid("params is not valid JSON")
    if not isinstance(params, dict):
        raise RecordInvalid("params is not a JSON object")

    if algo == ALGO_PBKDF2:
        if set(params) != {"iterations", "dklen"}:
            raise RecordInvalid("unexpected pbkdf2 parameter set")
        it, dk = params["iterations"], params["dklen"]
        if not _is_int(it) or not (cfg.pbkdf2_min_iterations <= it <= cfg.pbkdf2_max_iterations):
            raise RecordInvalid("pbkdf2 iterations outside trusted range")
        if dk != cfg.dklen:
            raise RecordInvalid("pbkdf2 dklen mismatch")
    else:  # scrypt
        if set(params) != {"n", "r", "p", "dklen"}:
            raise RecordInvalid("unexpected scrypt parameter set")
        n, r, p, dk = params["n"], params["r"], params["p"], params["dklen"]
        if not (_is_int(n) and _is_int(r) and _is_int(p)):
            raise RecordInvalid("scrypt parameters must be integers")
        if n & (n - 1) or not (cfg.scrypt_min_n <= n <= cfg.scrypt_max_n):
            raise RecordInvalid("scrypt n outside trusted range")
        if not (1 <= r <= cfg.scrypt_max_r) or not (1 <= p <= cfg.scrypt_max_p):
            raise RecordInvalid("scrypt r/p outside trusted range")
        if 128 * n * r * p > cfg.scrypt_maxmem:
            raise RecordInvalid("scrypt parameters exceed memory cap")
        if dk != cfg.dklen:
            raise RecordInvalid("scrypt dklen mismatch")
    return Record(algo, salt, hash_, params)


def verify(cfg, rec, password):
    """Verify a password against a validated record (constant-time compare)."""
    if rec.algo == ALGO_PBKDF2:
        h = hashlib.pbkdf2_hmac(
            "sha256", password, rec.salt, rec.params["iterations"], dklen=cfg.dklen)
    else:
        h = hashlib.scrypt(
            password, salt=rec.salt, n=rec.params["n"], r=rec.params["r"],
            p=rec.params["p"], dklen=cfg.dklen, maxmem=cfg.scrypt_maxmem)
    return hmac.compare_digest(h, rec.hash)


def _params_json(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def hash_scrypt(cfg, password):
    """Hash with the current (target) algorithm and a fresh random salt."""
    salt = os.urandom(cfg.salt_len)
    h = hashlib.scrypt(
        password, salt=salt, n=cfg.scrypt_n, r=cfg.scrypt_r, p=cfg.scrypt_p,
        dklen=cfg.dklen, maxmem=cfg.scrypt_maxmem)
    params = _params_json({"n": cfg.scrypt_n, "r": cfg.scrypt_r,
                           "p": cfg.scrypt_p, "dklen": cfg.dklen})
    return NewHash(ALGO_SCRYPT, salt, h, params)


def hash_pbkdf2(cfg, password):
    """Hash with the legacy algorithm (only used to seed legacy test users)."""
    salt = os.urandom(cfg.salt_len)
    h = hashlib.pbkdf2_hmac(
        "sha256", password, salt, cfg.pbkdf2_iterations, dklen=cfg.dklen)
    params = _params_json({"iterations": cfg.pbkdf2_iterations, "dklen": cfg.dklen})
    return NewHash(ALGO_PBKDF2, salt, h, params)


def dummy_verify(cfg, password):
    """Burn roughly one verification's worth of CPU for unknown usernames."""
    hashlib.pbkdf2_hmac("sha256", password, b"\x00" * cfg.salt_len,
                        cfg.pbkdf2_min_iterations, dklen=cfg.dklen)
