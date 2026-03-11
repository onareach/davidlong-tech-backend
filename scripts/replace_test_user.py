#!/usr/bin/env python3
"""Replace verify@example.com with onareach@yahoo.com / Research@123."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bcrypt
import psycopg2

OLD_EMAIL = "verify@example.com"
NEW_EMAIL = "onareach@yahoo.com"
NEW_PASSWORD = "Research@123"

def main():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        database_url = "postgresql://dev_user:dev123@localhost:5432/davidlong_tech?sslmode=disable"

    password_hash = bcrypt.hashpw(NEW_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = psycopg2.connect(
        database_url,
        sslmode="require" if database_url.startswith("postgres://") else "disable",
    )
    cur = conn.cursor()

    cur.execute(
        "UPDATE tbl_user SET email = %s, password_hash = %s, display_name = %s WHERE email = %s;",
        (NEW_EMAIL, password_hash, "David Long", OLD_EMAIL),
    )
    updated = cur.rowcount

    if updated == 0:
        cur.execute(
            "INSERT INTO tbl_user (email, password_hash, display_name) VALUES (%s, %s, %s);",
            (NEW_EMAIL, password_hash, "David Long"),
        )
        conn.commit()
        print(f"Inserted {NEW_EMAIL}")
    else:
        conn.commit()
        print(f"Updated {OLD_EMAIL} -> {NEW_EMAIL}")

    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
