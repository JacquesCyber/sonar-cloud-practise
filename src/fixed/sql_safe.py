"""
SQL Injection - Secure Implementations
========================================
These are the corrected versions of the vulnerable examples in sql_injection.py.
Each fix uses parameterized queries (also called prepared statements).

Core Fix: Parameterized Queries
--------------------------------
The fundamental fix is to NEVER construct SQL queries by concatenating user input.
Instead, use parameterization:
- The SQL structure is sent to the database separately from the data
- The database treats the parameters as DATA, not as part of the SQL structure
- Shell metacharacters and SQL control characters in user input become harmless literals

Database driver syntax for parameters:
  SQLite (sqlite3):  ?          e.g., "WHERE id = ?"
  PostgreSQL (psycopg2): %s     e.g., "WHERE id = %s"
  MySQL (mysql-connector): %s   e.g., "WHERE id = %s"
  SQLAlchemy:        :name      e.g., "WHERE id = :user_id"

What SonarCloud Checks:
------------------------
After fixing, SonarCloud's taint analysis no longer finds a path from user input
to an unparameterized execute() call. The rule python:S2077 will no longer fire.
"""

import sqlite3
import psycopg2
import re
from typing import Optional


# =============================================================================
# FIX 1: Parameterized query — SQLite
# =============================================================================
# The ? placeholder separates SQL structure from data.
# sqlite3's execute() sends the structure and data separately to the DB engine.
# The DB engine ALWAYS treats ? values as literals, never as SQL syntax.
def get_user_by_id_safe(user_id: int) -> Optional[tuple]:
    """
    Safe: Uses parameterized query with ? placeholder.
    The user_id is passed as a separate argument, never concatenated into SQL.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: Parameterized query — user_id is bound as a literal value
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))  # Tuple with the parameter value

    return cursor.fetchone()


# =============================================================================
# FIX 2: Parameterized query with multiple parameters
# =============================================================================
# Multiple ? placeholders, matched positionally to the tuple of values.
# Even if username contains ' OR '1'='1, it's treated as a literal string.
def authenticate_user_safe(username: str, password_hash: str) -> bool:
    """
    Safe: Both parameters bound separately from SQL structure.

    Additional security note: In a real system, compare password hashes using
    a constant-time comparison (hmac.compare_digest) and hash passwords with
    bcrypt/argon2, not plain SHA-256. This example focuses on the SQL fix only.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: Two ? placeholders, two values in the tuple
    query = "SELECT id FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, password_hash))

    return cursor.fetchone() is not None


# =============================================================================
# FIX 3: Parameterized LIKE query
# =============================================================================
# LIKE queries need special handling: the % wildcard in LIKE is a DB feature,
# not a format string wildcard. Place it inside the parameter value, not in SQL.
def search_products_safe(search_term: str, category: str) -> list:
    """
    Safe: LIKE wildcards are part of the parameter value, not the SQL string.
    The entire search_term (with our added %) is treated as a literal LIKE pattern.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: Wildcards are placed IN the parameter value, not in the SQL template
    # The SQL string itself never includes user data
    like_pattern = f"%{search_term}%"  # This is safe — we control this format
    query = "SELECT * FROM products WHERE name LIKE ? AND category = ?"
    cursor.execute(query, (like_pattern, category))

    return cursor.fetchall()


# =============================================================================
# FIX 4: Dynamic ORDER BY — safe approach using allowlists
# =============================================================================
# ORDER BY column names CANNOT be parameterized (SQL doesn't allow it).
# The solution is an ALLOWLIST: only permit known-safe column names.
# This is the correct pattern for any case where identifiers (not values)
# come from user input.
ALLOWED_ORDER_COLUMNS = frozenset({
    'created_at', 'total_price', 'status', 'order_id'
})
ALLOWED_ORDER_DIRECTIONS = frozenset({'ASC', 'DESC'})

def get_orders_safe(user_id: int, order_by: str = 'created_at',
                    direction: str = 'DESC') -> list:
    """
    Safe: Dynamic ORDER BY uses allowlist validation.
    If order_by is not in ALLOWED_ORDER_COLUMNS, a ValueError is raised.
    The SQL string is constructed using only allowlisted, developer-controlled values.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: Strict allowlist check — rejects anything not explicitly allowed
    if order_by not in ALLOWED_ORDER_COLUMNS:
        raise ValueError(f"Invalid sort column: {order_by}")
    if direction.upper() not in ALLOWED_ORDER_DIRECTIONS:
        raise ValueError(f"Invalid sort direction: {direction}")

    # The column name comes from our allowlist (developer-controlled), not raw user input
    query = f"SELECT * FROM orders WHERE user_id = ? ORDER BY {order_by} {direction}"
    cursor.execute(query, (user_id,))  # user_id is still parameterized

    return cursor.fetchall()


# =============================================================================
# FIX 5: Dynamic table names — allowlist approach
# =============================================================================
# Table and column names cannot be parameterized in SQL.
# The allowlist pattern is mandatory for any dynamic identifiers.
ALLOWED_TABLES = frozenset({
    'orders', 'products', 'categories', 'user_profiles'
})
ALLOWED_COLUMNS = {
    'orders': frozenset({'order_id', 'created_at', 'total_price', 'status'}),
    'products': frozenset({'product_id', 'name', 'price', 'stock_count'}),
}

def get_table_data_safe(table_name: str, column_name: str) -> list:
    """
    Safe: Both table and column names validated against allowlists.
    Only pre-approved table/column combinations are permitted.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAFE: Allowlist validation for table name
    if table_name not in ALLOWED_TABLES:
        raise ValueError(f"Table not permitted: {table_name}")

    # SAFE: Allowlist validation for column name (per-table allowlist)
    if table_name not in ALLOWED_COLUMNS:
        raise ValueError(f"No columns configured for table: {table_name}")
    if column_name not in ALLOWED_COLUMNS[table_name]:
        raise ValueError(f"Column not permitted: {column_name}")

    # Both identifiers come from developer-controlled allowlists
    query = f"SELECT {column_name} FROM {table_name} LIMIT 100"
    cursor.execute(query)

    return cursor.fetchall()


# =============================================================================
# FIX 6: PostgreSQL with psycopg2 parameterized queries
# =============================================================================
# psycopg2 uses %s as the placeholder (not ? like sqlite3).
# IMPORTANT: psycopg2's %s is NOT Python's % string formatting.
# Do NOT use string formatting — pass parameters as the second argument to execute().
def get_report_safe(start_date: str, end_date: str, department: str) -> list:
    """
    Safe: psycopg2 parameterized query with %s placeholders.
    All user-supplied values passed as parameters, never concatenated.
    """
    conn = psycopg2.connect("dbname=appdb user=app")
    cursor = conn.cursor()

    # SAFE: psycopg2 parameters — %s in the query, values as separate tuple
    query = """
        SELECT employee_id, department
        FROM hr_data
        WHERE hire_date BETWEEN %s AND %s
        AND department = %s
    """
    # IMPORTANT: salary is excluded here intentionally — principle of least privilege
    # Only return the columns this function's callers need.
    cursor.execute(query, (start_date, end_date, department))

    return cursor.fetchall()


# =============================================================================
# FIX 7: SQLAlchemy ORM — the idiomatic approach
# =============================================================================
# SQLAlchemy's ORM handles parameterization automatically.
# When you use filter() with column comparisons, parameters are always bound safely.
# This is the preferred approach for larger Python applications.
def get_user_sqlalchemy_safe(user_id: int):
    """
    Safe: SQLAlchemy ORM constructs parameterized queries automatically.
    You never write SQL strings manually — the ORM handles parameterization.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite:///app.db")

    with Session(engine) as session:
        # Method 1: ORM query (always parameterized)
        # user = session.query(User).filter(User.id == user_id).first()

        # Method 2: text() with named parameters (when raw SQL is needed)
        result = session.execute(
            text("SELECT * FROM users WHERE id = :user_id"),
            {"user_id": user_id}  # Named parameter binding
        )
        return result.fetchone()
