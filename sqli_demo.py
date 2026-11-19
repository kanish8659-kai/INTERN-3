#!/usr/bin/env python3
"""
SQL injection demo: VULNERABLE vs SAFE login query (throw-away in-memory DB).
Run:  python sqli_demo.py      -> take a screenshot as evidence for your report.
Passwords here are plain text ONLY because this is a toy to show the query bug;
the real app (app.py) never stores plain passwords.
"""
import sqlite3

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
conn.execute("INSERT INTO users VALUES ('admin', 'S3cret-demo-pw')")


def vulnerable_login(username, password):
    # BAD: user input is glued into the SQL text
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print("   SQL sent to database:", sql)
    try:
        return conn.execute(sql).fetchone() is not None
    except sqlite3.Error as e:
        print("   Database error:", e)
        return False


def safe_login(username, password):
    # GOOD: '?' placeholders - input is sent as DATA, never as SQL code
    sql = "SELECT * FROM users WHERE username = ? AND password = ?"
    print("   SQL sent to database:", sql, "| data:", (username, password))
    return conn.execute(sql, (username, password)).fetchone() is not None


attacks = [("admin' --", "anything"), ("' OR '1'='1", "' OR '1'='1"), ("admin", "wrong")]
for name, func in [("VULNERABLE", vulnerable_login), ("SAFE (parameterised)", safe_login)]:
    print(f"\n=== {name} ===")
    for u, p in attacks:
        print(f" Attempt username={u!r} password={p!r}")
        print("   -> LOGIN", "SUCCEEDED (attack worked!)" if func(u, p) else "rejected")
print("\n=== Legitimate user on the safe version ===")
print("   -> LOGIN", "succeeded" if safe_login("admin", "S3cret-demo-pw") else "rejected")
