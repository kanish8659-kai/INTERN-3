"""
Time-based One-Time Passwords (RFC 6238) - written with the standard library so
you can explain every line. Compatible with Google Authenticator, Authy,
Microsoft Authenticator, etc.

  HOTP(key, counter) = truncate( HMAC-SHA1(key, counter) )        RFC 4226
  TOTP               = HOTP(key, floor(unix_time / 30))           RFC 6238
"""
import base64
import hashlib
import hmac
import os
import re
import struct
import time
from urllib.parse import quote

STEP = 30
CODE_RE = re.compile(r"\d{6}")


def new_secret() -> str:
    """160-bit random secret, Base32 encoded (what authenticator apps expect)."""
    return base64.b32encode(os.urandom(20)).decode()


def hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F                                   # dynamic truncation
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** digits).zfill(digits)


def totp(secret_b32: str, at: float = None, digits: int = 6) -> str:
    at = time.time() if at is None else at
    return hotp(secret_b32, int(at // STEP), digits)


def verify(secret_b32: str, code: str, at: float = None, window: int = 1,
           last_step: int = 0):
    """
    Returns the matching time-step (int) or None.
    * window=1 tolerates +-30 s of clock drift.
    * last_step blocks REPLAY: a code that was already accepted (or older)
      can never be used again.
    """
    if not CODE_RE.fullmatch(code or ""):
        return None
    at = time.time() if at is None else at
    current = int(at // STEP)
    for step in range(current - window, current + window + 1):
        if step <= last_step:
            continue
        if hmac.compare_digest(hotp(secret_b32, step), code):
            return step
    return None


def provisioning_uri(secret_b32: str, username: str, issuer: str = "Thiranex Secure Login") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}&digits=6&period=30"
