"""
Password hashing  (the most important part of a login system)
=============================================================
* Default: Argon2id (argon2-cffi) - OWASP's first-choice algorithm. It is
  deliberately slow AND memory-hungry, so GPUs/ASICs gain little advantage.
* Every hash contains its own random salt, so identical passwords produce
  different hashes and rainbow tables are useless.
* The stored string also records the parameters, so cost can be raised later
  and old hashes upgraded at next login (needs_rehash).

Fallback for machines where argon2-cffi cannot be installed:
  set PASSWORD_HASHER=scrypt  (Werkzeug's scrypt - also memory-hard).
  This is for development/testing ONLY and prints a warning. We never fall back
  silently: a missing library must not quietly weaken security.
"""
import os
import sys

ALGORITHM = os.environ.get("PASSWORD_HASHER", "argon2").lower()

if ALGORITHM == "argon2":
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
    except ImportError:
        raise SystemExit("argon2-cffi is not installed. Run:  pip install argon2-cffi\n"
                         "(or set PASSWORD_HASHER=scrypt for a testing-only fallback)")
    _ph = PasswordHasher()          # library defaults follow RFC 9106 guidance

    def hash_password(password: str) -> str:
        return _ph.hash(password)

    def verify_password(stored_hash: str, password: str) -> bool:
        try:
            return _ph.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(stored_hash: str) -> bool:
        return _ph.check_needs_rehash(stored_hash)

elif ALGORITHM == "scrypt":
    from werkzeug.security import check_password_hash, generate_password_hash
    print("WARNING: using the scrypt fallback (testing only). "
          "Install argon2-cffi and unset PASSWORD_HASHER for real use.", file=sys.stderr)

    def hash_password(password: str) -> str:
        return generate_password_hash(password, method="scrypt")

    def verify_password(stored_hash: str, password: str) -> bool:
        try:
            return check_password_hash(stored_hash, password)
        except ValueError:
            return False

    def needs_rehash(stored_hash: str) -> bool:
        return False
else:
    raise SystemExit(f"Unknown PASSWORD_HASHER '{ALGORITHM}' (use argon2 or scrypt)")
