"""
Automated tests for the Secure Login System.
Run:  python -m unittest -v test_secure_login
(If argon2-cffi is not installed the tests run with the scrypt TEST fallback and the
Argon2-specific tests are skipped - install argon2-cffi to run them.)
"""
import importlib.util
import os
import re
import sqlite3
import tempfile
import unittest

HAVE_ARGON2 = importlib.util.find_spec("argon2") is not None
if not HAVE_ARGON2:
    os.environ.setdefault("PASSWORD_HASHER", "scrypt")

import app as app_module
import passwords
import totp
import validators

GOOD_PW = "Correct-Horse-42!"


class Clock:
    def __init__(self): self.t = 1_800_000_000.0
    def __call__(self): return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "t.db")
        self.clock = Clock()
        self.app = app_module.create_app({"DATABASE": self.db_path, "SECRET_KEY": "test-key",
                                          "CLOCK": self.clock, "TESTING": True})
        self.c = self.app.test_client()

    # -- helpers --------------------------------------------------------------
    def token(self, client, path="/login"):
        html = client.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, client, path, data, page=None):
        data = dict(data); data["csrf_token"] = self.token(client, page or path)
        return client.post(path, data=data)

    def register(self, client=None, user="alice", email="alice@example.com", pw=GOOD_PW):
        client = client or self.c
        return self.post(client, "/register", {"username": user, "email": email,
                                               "password": pw, "confirm": pw})

    def login(self, client=None, user="alice", pw=GOOD_PW):
        return self.post(client or self.c, "/login", {"username": user, "password": pw})

    def sql(self, query, params=()):
        con = sqlite3.connect(self.db_path); con.row_factory = sqlite3.Row
        try: return con.execute(query, params).fetchall()
        finally: con.close()

    def logged_in(self):
        self.register(); r = self.login()
        self.assertEqual(r.status_code, 302)


class TestPasswordsAndValidation(unittest.TestCase):
    def test_hash_verify_and_salting(self):
        h1, h2 = passwords.hash_password("Abc-123-xyz!"), passwords.hash_password("Abc-123-xyz!")
        self.assertNotEqual(h1, h2)                       # random salt
        self.assertTrue(passwords.verify_password(h1, "Abc-123-xyz!"))
        self.assertFalse(passwords.verify_password(h1, "wrong"))
        self.assertFalse(passwords.verify_password("not-a-hash", "x"))
    @unittest.skipUnless(HAVE_ARGON2, "argon2-cffi not installed")
    def test_argon2_format(self):
        self.assertTrue(passwords.hash_password("x" * 12).startswith("$argon2id$"))
    def test_validators(self):
        self.assertTrue(validators.validate_username("a b"))
        self.assertTrue(validators.validate_username("x' OR '1'='1"))
        self.assertTrue(validators.validate_username("<script>"))
        self.assertEqual(validators.validate_username("alice_01"), [])
        self.assertTrue(validators.validate_email("bad@@x"))
        self.assertEqual(validators.validate_email("a.b+c@example.co.in"), [])
        self.assertTrue(validators.validate_password("short1!"))
        self.assertTrue(validators.validate_password("password123"))
        self.assertTrue(validators.validate_password("alicealice1!A", "alice"))
        self.assertTrue(validators.validate_password("alllowercaseletters"[:12]))
        self.assertTrue(validators.validate_password("x" * 129))
        self.assertEqual(validators.validate_password("correct horse battery staple"), [])


class TestTOTP(unittest.TestCase):
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # base32("12345678901234567890")
    def test_rfc4226_hotp_vectors(self):
        expected = ["755224", "287082", "359152", "969429", "338314", "254676"]
        self.assertEqual([totp.hotp(self.SECRET, i) for i in range(6)], expected)
    def test_rfc6238_totp_vector(self):
        self.assertEqual(totp.totp(self.SECRET, at=59, digits=8), "94287082")
        self.assertEqual(totp.totp(self.SECRET, at=1111111109, digits=8), "07081804")
    def test_verify_window_and_replay(self):
        t = 1_700_000_000
        code = totp.totp(self.SECRET, t)
        step = totp.verify(self.SECRET, code, t)
        self.assertEqual(step, t // 30)
        self.assertIsNotNone(totp.verify(self.SECRET, code, t + 30))          # drift tolerated
        self.assertIsNone(totp.verify(self.SECRET, code, t + 120))            # too old
        self.assertIsNone(totp.verify(self.SECRET, code, t, last_step=step))  # replay blocked
        self.assertIsNone(totp.verify(self.SECRET, "abcdef", t))
        self.assertIsNone(totp.verify(self.SECRET, "12345", t))
    def test_new_secret_valid(self):
        s = totp.new_secret(); self.assertEqual(len(s), 32); totp.totp(s)


class TestRegistration(Base):
    def test_register_stores_only_a_hash(self):
        self.assertEqual(self.register().status_code, 302)
        row = self.sql("SELECT * FROM users")[0]
        self.assertNotIn(GOOD_PW, row["password_hash"])
        self.assertTrue(row["password_hash"].startswith("$argon2id$" if HAVE_ARGON2 else "scrypt:"))
    def test_duplicate_and_weak_and_mismatch(self):
        self.register()
        self.assertEqual(self.register(user="ALICE", email="o@example.com").status_code, 400)  # case-insens.
        self.assertEqual(self.register(user="bob", email="alice@example.com").status_code, 400)
        self.assertEqual(self.register(user="bob", email="b@example.com", pw="password123").status_code, 400)
        r = self.post(self.c, "/register", {"username": "bob", "email": "b@example.com",
                                            "password": GOOD_PW, "confirm": GOOD_PW + "x"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(self.sql("SELECT * FROM users")), 1)
    def test_injection_and_xss_usernames_rejected(self):
        for bad in ["admin'--", "x'); DROP TABLE users;--", "<script>alert(1)</script>"]:
            r = self.register(user=bad, email="z@example.com")
            self.assertEqual(r.status_code, 400)
            self.assertNotIn("<script>alert(1)</script>", r.get_data(as_text=True))
        self.assertEqual(self.sql("SELECT count(*) AS n FROM users")[0]["n"], 0)
    def test_xss_in_email_field_is_escaped_when_redisplayed(self):
        r = self.register(email='"><script>alert(1)</script>@x.com')
        body = r.get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)


class TestLogin(Base):
    def test_success_and_dashboard(self):
        self.logged_in()
        r = self.c.get("/dashboard")
        self.assertEqual(r.status_code, 200); self.assertIn("alice", r.get_data(as_text=True))
    def test_dashboard_requires_login(self):
        r = self.c.get("/dashboard"); self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
    def test_failures_are_indistinguishable(self):
        self.register()
        a = self.login(user="alice", pw="WrongPass-1!")
        b = self.login(user="nobody", pw="WrongPass-1!")
        self.assertEqual((a.status_code, b.status_code), (401, 401))
        flash = lambda r: re.search(r'class="flash error">([^<]+)<', r.get_data(as_text=True)).group(1)
        self.assertEqual(flash(a), flash(b))
    def test_sql_injection_attempts_fail(self):
        self.register()
        for u, p in [("admin' --", "x"), ("' OR '1'='1", "' OR '1'='1"), ("alice' OR 1=1 --", "x"),
                     ("alice", "' OR '1'='1"), ("x'; DROP TABLE users; --", "x")]:
            self.assertEqual(self.login(user=u, pw=p).status_code, 401, (u, p))
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
        self.assertEqual(self.sql("SELECT count(*) AS n FROM users")[0]["n"], 1)   # table intact
    def test_lockout_after_five_failures(self):
        self.register()
        for _ in range(5): self.login(pw="WrongPass-1!")
        self.assertEqual(self.login().status_code, 401)             # correct pw, but locked
        self.clock.t += app_module.LOCK_SECONDS + 1
        self.assertEqual(self.login().status_code, 302)             # lock expired
    def test_failed_counter_resets_on_success(self):
        self.register()
        for _ in range(4): self.login(pw="WrongPass-1!")
        self.login(); self.post(self.c, "/logout", {}, page="/dashboard")
        for _ in range(4): self.login(pw="WrongPass-1!")
        self.assertEqual(self.login().status_code, 302)             # never reached 5 in a row
    def test_audit_log_written(self):
        self.register(); self.login(pw="WrongPass-1!"); self.login()
        events = [r["event"] for r in self.sql("SELECT event FROM audit_log")]
        for e in ("register", "login_failed", "login_success"): self.assertIn(e, events)


class TestSessions(Base):
    def test_logout_invalidates_session_on_server(self):
        self.logged_in()
        stolen = self.c.get_cookie("session").value                   # attacker copies the cookie
        r = self.post(self.c, "/logout", {}, page="/dashboard")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
        self.assertEqual(self.sql("SELECT count(*) AS n FROM sessions")[0]["n"], 0)
        other = self.app.test_client(); other.set_cookie("session", stolen)
        self.assertEqual(other.get("/dashboard").status_code, 302)   # replayed cookie is dead
    def test_logout_get_not_allowed(self):
        self.logged_in(); self.assertEqual(self.c.get("/logout").status_code, 405)
    def test_idle_timeout(self):
        self.logged_in()
        self.clock.t += app_module.IDLE_TIMEOUT + 1
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
    def test_activity_extends_idle_but_absolute_timeout_wins(self):
        self.logged_in()
        for _ in range(40):                                           # 40 x 14 min = 9.3 h of activity
            self.clock.t += 14 * 60
            code = self.c.get("/dashboard").status_code
            if code == 302: break
        self.assertEqual(code, 302)
        self.assertGreater(self.clock.t, 1_800_000_000 + app_module.ABSOLUTE_TIMEOUT - 1)
    def test_new_session_token_on_each_login(self):
        self.register(); self.login(); t1 = self.sql("SELECT token_hash FROM sessions")[0]["token_hash"]
        self.post(self.c, "/logout", {}, page="/dashboard"); self.login()
        t2 = self.sql("SELECT token_hash FROM sessions")[0]["token_hash"]
        self.assertNotEqual(t1, t2)


class TestCSRFAndHeaders(Base):
    def test_post_without_csrf_rejected(self):
        r = self.c.post("/register", data={"username": "bob", "email": "b@example.com",
                                           "password": GOOD_PW, "confirm": GOOD_PW})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(self.sql("SELECT * FROM users")), 0)
    def test_post_with_wrong_csrf_rejected(self):
        self.c.get("/login")
        r = self.c.post("/login", data={"username": "a", "password": "b", "csrf_token": "forged"})
        self.assertEqual(r.status_code, 400)
    def test_logout_needs_csrf(self):
        self.logged_in()
        self.assertEqual(self.c.post("/logout").status_code, 400)
        self.assertEqual(self.c.get("/dashboard").status_code, 200)   # still logged in
    def test_security_headers(self):
        h = self.c.get("/").headers
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY"); self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["Cache-Control"], "no-store")
    def test_cookie_flags(self):
        cookie = self.c.get("/").headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie); self.assertIn("SameSite=Lax", cookie)
        secure_app = app_module.create_app({"DATABASE": os.path.join(self.tmp, "s.db"),
                                            "SECRET_KEY": "k", "SESSION_COOKIE_SECURE": True})
        r = secure_app.test_client().get("/")
        self.assertIn("Secure", r.headers["Set-Cookie"]); self.assertIn("Strict-Transport-Security", r.headers)
    def test_error_pages_do_not_leak(self):
        r = self.c.get("/nope"); self.assertEqual(r.status_code, 404)
        self.assertNotIn("Traceback", r.get_data(as_text=True))


class Test2FA(Base):
    def enable_2fa(self):
        self.logged_in()
        self.c.get("/2fa/setup")
        secret = self.sql("SELECT totp_secret FROM users")[0]["totp_secret"]
        r = self.post(self.c, "/2fa/setup", {"code": totp.totp(secret, self.clock())})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.sql("SELECT totp_enabled FROM users")[0]["totp_enabled"], 1)
        self.post(self.c, "/logout", {}, page="/dashboard")
        return secret
    def test_setup_rejects_wrong_code(self):
        self.logged_in(); self.c.get("/2fa/setup")
        self.post(self.c, "/2fa/setup", {"code": "000000"})
        self.assertEqual(self.sql("SELECT totp_enabled FROM users")[0]["totp_enabled"], 0)
    def test_login_requires_second_factor(self):
        secret = self.enable_2fa()
        r = self.login(); self.assertEqual(r.status_code, 302); self.assertIn("/2fa/verify", r.headers["Location"])
        self.assertEqual(self.c.get("/dashboard").status_code, 302)          # password alone is not enough
        self.clock.t += 30
        r = self.post(self.c, "/2fa/verify", {"code": totp.totp(secret, self.clock())})
        self.assertEqual(r.status_code, 302); self.assertIn("/dashboard", r.headers["Location"])
        self.assertEqual(self.c.get("/dashboard").status_code, 200)
    def test_wrong_code_rejected(self):
        self.enable_2fa(); self.login()
        self.assertEqual(self.post(self.c, "/2fa/verify", {"code": "123456"}).status_code, 401)
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
    def test_code_replay_blocked(self):
        secret = self.enable_2fa(); self.clock.t += 30
        code = totp.totp(secret, self.clock())
        self.login(); self.assertEqual(self.post(self.c, "/2fa/verify", {"code": code}).status_code, 302)
        self.post(self.c, "/logout", {}, page="/dashboard")
        self.login(); self.assertEqual(self.post(self.c, "/2fa/verify", {"code": code}).status_code, 401)
    def test_2fa_brute_force_locks_account(self):
        secret = self.enable_2fa(); self.clock.t += 30
        self.login()                                                  # password OK -> pending 2FA
        for _ in range(app_module.MAX_FAILED):
            self.assertEqual(self.post(self.c, "/2fa/verify", {"code": "000000"},
                                       page="/2fa/verify").status_code in (401, 302), True)
        locked = self.sql("SELECT locked_until FROM users")[0]["locked_until"]
        self.assertGreater(locked, self.clock())                      # lock-out was triggered
        good = totp.totp(secret, self.clock())                        # even a VALID code is now refused
        r = self.post(self.c, "/2fa/verify", {"code": good}, page="/2fa/verify")
        self.assertEqual(r.status_code, 302); self.assertIn("/login", r.headers["Location"])
        self.assertEqual(self.c.get("/dashboard").status_code, 302)
    def test_pending_state_expires(self):
        secret = self.enable_2fa(); self.login()
        self.clock.t += app_module.PENDING_2FA_SECONDS + 1
        self.assertEqual(self.c.get("/2fa/verify").status_code, 302)
    def test_disable_requires_password(self):
        self.logged_in(); self.c.get("/2fa/setup")
        secret = self.sql("SELECT totp_secret FROM users")[0]["totp_secret"]
        self.post(self.c, "/2fa/setup", {"code": totp.totp(secret, self.clock())})
        self.post(self.c, "/2fa/disable", {"password": "wrong"}, page="/dashboard")
        self.assertEqual(self.sql("SELECT totp_enabled FROM users")[0]["totp_enabled"], 1)
        self.post(self.c, "/2fa/disable", {"password": GOOD_PW}, page="/dashboard")
        self.assertEqual(self.sql("SELECT totp_enabled FROM users")[0]["totp_enabled"], 0)


if __name__ == "__main__":
    unittest.main()
