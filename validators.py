"""Server-side input validation (never trust the browser; allow-list approach)."""
import re

USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,30}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")
MIN_PW, MAX_PW = 10, 128          # MAX stops "hash a 10 MB password" denial of service

# Tiny demo list. In production use a big list (e.g. SecLists top 10k) or the
# HaveIBeenPwned k-anonymity API.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789", "1234567890", "qwertyuiop",
    "iloveyou123", "admin12345", "welcome123", "letmein123", "changeme123",
    "passw0rd123", "abc1234567", "1q2w3e4r5t", "qwerty12345", "p@ssw0rd123",
}


def validate_username(username: str) -> list:
    if not USERNAME_RE.fullmatch(username):
        return ["Username must be 3-30 characters: letters, digits or underscore only."]
    return []


def validate_email(email: str) -> list:
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return ["Please enter a valid email address."]
    return []


def validate_password(password: str, username: str = "") -> list:
    errors = []
    if not MIN_PW <= len(password) <= MAX_PW:
        return [f"Password must be {MIN_PW}-{MAX_PW} characters long."]
    classes = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                   any(c.isdigit() for c in password),
                   any(not c.isalnum() for c in password)])
    if classes < 3 and len(password) < 16:
        errors.append("Use at least 3 of: lowercase, uppercase, digits, symbols "
                      "(or make it 16+ characters long).")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("That password is too common.")
    if len(username) >= 3 and username.lower() in password.lower():
        errors.append("Password must not contain your username.")
    return errors
