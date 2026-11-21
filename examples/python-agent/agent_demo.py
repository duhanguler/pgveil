"""
Example: Connecting any Python AI SQL Agent (LangChain, CrewAI, OpenAI Agents, raw psycopg)
through pgveil with a 1-line port swap (5432 -> 6432).

Zero driver changes. Zero PostgreSQL extensions. Full wire-speed PII masking + AST firewall.
"""

import os
import sys

try:
    import psycopg
except ImportError:
    print("Install psycopg first: pip install 'psycopg[binary]'")
    sys.exit(1)

DSN = os.getenv(
    "PGVEIL_DSN",
    "postgres://pgveil:pgveil_dev_password@127.0.0.1:6432/pgveil_demo?sslmode=disable&application_name=langchain-support-agent",
)


def main() -> None:
    with psycopg.connect(DSN, autocommit=True) as conn:
        print("1) Safe AI agent read (TCKN, IBAN, Email, Phone masked dynamically on the wire):")
        with conn.cursor() as cur:
            cur.execute("SELECT id, full_name, email, tckn, iban FROM customers ORDER BY id LIMIT 3")
            for row in cur.fetchall():
                print("  ", row)

        print("\n2) Unstructured support ticket scan (embedded credit card & AWS key auto-redacted):")
        with conn.cursor() as cur:
            cur.execute("SELECT id, subject, body FROM support_tickets ORDER BY id LIMIT 2")
            for row in cur.fetchall():
                print("  ", row)

        print("\n3) Simulated prompt-injected destructive query (blocked by PostgreSQL 17 AST Firewall):")
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM orders WHERE 1 = 1")
        except psycopg.Error as exc:
            print(f"   BLOCKED cleanly (SQLSTATE {exc.sqlstate}): {exc.diag.message_primary}")


if __name__ == "__main__":
    main()
