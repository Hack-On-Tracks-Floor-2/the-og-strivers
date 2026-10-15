"""Tiny user store used as a ProofPatch test fixture (intentionally vulnerable)."""
import hashlib
import sqlite3


def connect(path=":memory:"):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    db.executemany("INSERT INTO users (name, email) VALUES (?, ?)",
                   [("alice", "alice@example.test"), ("bob", "bob@example.test")])
    return db


def find_user(db, name):
    # Vulnerable: user input is formatted straight into SQL.
    rows = db.execute("SELECT id, name, email FROM users WHERE name = '%s'" % name).fetchall()
    return rows


def checksum(data):
    return hashlib.sha256(data).hexdigest()
