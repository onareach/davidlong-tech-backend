#!/usr/bin/env python3
"""Seed a test user in the local database. Run from backend root."""
import os
import sys

# Add parent for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bcrypt
import psycopg2

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://dev_user:dev123@localhost:5432/davidlong_tech?sslmode=disable",
)

def main():
    email = "verify@example.com"
    password = "password123"
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM tbl_user WHERE email = %s;", (email,))
    if cur.fetchone():
        print(f"User {email} already exists.")
        cur.close()
        conn.close()
        return

    cur.execute(
        "INSERT INTO tbl_user (email, password_hash, display_name) VALUES (%s, %s, %s);",
        (email, password_hash, "Verify"),
    )
    conn.commit()
    cur.close()
    conn.close()
    print(f"Created user {email} / {password}")

if __name__ == "__main__":
    main()
