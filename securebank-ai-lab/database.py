"""
database.py
-----------
Sets up the SQLite database and seeds it with demo users and transactions.

This is an INTENTIONALLY VULNERABLE lab application built for an educational
Web App Pentesting course project. Run it ONLY on localhost / an isolated
environment. Do not expose it to the internet.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "bank.db")


def get_db():
    """Open a connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and seed demo data (drops any existing data)."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,          -- plaintext on purpose (lab)
            role      TEXT NOT NULL DEFAULT 'user',
            balance   INTEGER NOT NULL DEFAULT 0,
            full_name TEXT NOT NULL,
            bio       TEXT DEFAULT ''         -- stored XSS / indirect injection sink
        )
    """)

    c.execute("""
        CREATE TABLE transactions (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount  INTEGER NOT NULL,
            note    TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    users = [
        # username, password, role, balance, full_name, bio
        ("admin",  "admin123",  "admin", 500000, "Bank Administrator", "System administrator account."),
        ("ali",    "ali123",    "user",     200, "Ali Al-Otaibi",     "Regular customer."),
        ("sara",   "sara123",   "user",   15000, "Sara Al-Qahtani",   "Saving for a house."),
        ("victim", "victim123", "user",   90000, "Victim User",       "High-value target account."),
    ]
    c.executemany(
        "INSERT INTO users (username, password, role, balance, full_name, bio) VALUES (?,?,?,?,?,?)",
        users,
    )

    transactions = [
        (2, -50,   "Coffee shop"),
        (2, 300,   "Salary"),
        (3, -1200, "Rent"),
        (3, 5000,  "Freelance payment"),
        (4, 90000, "Inheritance"),
    ]
    c.executemany(
        "INSERT INTO transactions (user_id, amount, note) VALUES (?,?,?)",
        transactions,
    )

    conn.commit()
    conn.close()
    print(f"[+] Database initialized at {DB_PATH}")
    print("[+] Demo accounts:")
    for u in users:
        print(f"      {u[0]:8} / {u[1]:10} (role={u[2]})")


if __name__ == "__main__":
    init_db()
