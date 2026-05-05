"""
SQL Injection Vulnerability Examples
=====================================
OWASP Category: A03:2021 - Injection
CWE: CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
SonarCloud Rule: python:S2077 - Formatting SQL queries is security-sensitive
Severity in SonarCloud: CRITICAL (Vulnerability)

What is SQL Injection?
----------------------
SQL injection occurs when user-controlled input is concatenated directly into
an SQL query string. An attacker can manipulate the query structure to:
- Bypass authentication
- Extract data from other tables (UNION attacks)
- Modify or delete data
- Execute administrative operations (DROP TABLE, xp_cmdshell, etc.)

Why SonarCloud Catches This:
----------------------------
SonarCloud tracks "taint flow" — it follows user input from SOURCE (e.g., a
function parameter, HTTP request) through your code to a SINK (e.g., a database
execute() call). If tainted data reaches a dangerous sink without sanitization,
it raises python:S2077.

How to Find This in SonarCloud:
--------------------------------
1. Dashboard > Issues tab
2. Filter by: Type=Vulnerability, Rule=python:S2077
3. Click the issue to see the data flow highlighted in the code viewer
4. The "Why is this an issue?" tab explains the vulnerability
"""

import sqlite3
import psycopg2


# =============================================================================
# VULNERABLE EXAMPLE 1: Direct string concatenation
# =============================================================================
# SonarCloud flags this immediately: user_id is passed directly into an
# f-string that becomes part of the SQL query.
#
# Attack vector:
#   user_id = "1 OR 1=1 --"
#   Results in: SELECT * FROM users WHERE id = 1 OR 1=1 --
#   This returns ALL users regardless of the id value.
#
# Worse attack:
#   user_id = "1 UNION SELECT username, password, null FROM admin_users --"
#   This exfiltrates admin credentials.
def get_user_by_id_vulnerable(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: f-string interpolation with user input directly in SQL
    # SonarCloud Rule: python:S2077
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # <-- SonarCloud marks this line as the sink

    return cursor.fetchone()


# =============================================================================
# VULNERABLE EXAMPLE 2: String concatenation with +
# =============================================================================
# Classic concatenation vulnerability. SonarCloud tracks the username variable
# from the function parameter to the execute() call.
#
# Attack vector:
#   username = "admin' --"
#   Query becomes: SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
#   The -- comments out the password check, bypassing authentication.
def authenticate_user_vulnerable(username, password):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: string concatenation in SQL query
    # SonarCloud Rule: python:S2077
    query = ("SELECT * FROM users WHERE username = '" + username +
             "' AND password = '" + password + "'")
    cursor.execute(query)  # <-- SonarCloud marks this as a vulnerability

    return cursor.fetchone() is not None


# =============================================================================
# VULNERABLE EXAMPLE 3: % formatting
# =============================================================================
# The % string formatting operator is just as dangerous as f-strings or +.
# SonarCloud recognizes all string formatting patterns as potential taint sinks.
#
# Attack vector:
#   search_term = "' OR '1'='1"
#   Query: SELECT * FROM products WHERE name LIKE '%' OR '1'='1%'
#   Returns all products regardless of the search term.
def search_products_vulnerable(search_term, category):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: % string formatting in SQL
    # SonarCloud Rule: python:S2077
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%' AND category = '%s'" % (
        search_term, category
    )
    cursor.execute(query)

    return cursor.fetchall()


# =============================================================================
# VULNERABLE EXAMPLE 4: .format() method
# =============================================================================
# Python's .format() is equally vulnerable. The taint flow still applies:
# user input → .format() → SQL string → execute() = vulnerability.
#
# Attack vector:
#   order_by = "name; DROP TABLE orders; --"
#   The ORDER BY injection drops the entire table.
#   (Note: SQLite doesn't support multiple statements, but PostgreSQL does)
def get_orders_vulnerable(user_id, order_by):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: .format() string interpolation in SQL
    # SonarCloud Rule: python:S2077
    query = "SELECT * FROM orders WHERE user_id = {} ORDER BY {}".format(
        user_id, order_by
    )
    cursor.execute(query)

    return cursor.fetchall()


# =============================================================================
# VULNERABLE EXAMPLE 5: Dynamic table/column names (harder to fix)
# =============================================================================
# Even if you parameterize values, dynamic table/column names are a problem.
# SQL parameterization only works for VALUES, not identifiers.
#
# This is a common pattern in multi-tenant applications and reporting tools.
#
# Attack vector:
#   table_name = "users; DROP TABLE audit_log; SELECT * FROM users WHERE 1=1 --"
def get_table_data_vulnerable(table_name, column_name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # VULNERABLE: Table and column names cannot be parameterized
    # SonarCloud Rule: python:S2077
    query = f"SELECT {column_name} FROM {table_name} LIMIT 100"
    cursor.execute(query)

    return cursor.fetchall()


# =============================================================================
# VULNERABLE EXAMPLE 6: PostgreSQL with psycopg2
# =============================================================================
# The same vulnerability exists with other database drivers.
# SonarCloud analyzes psycopg2 execute() calls with the same rules.
def get_report_vulnerable(start_date, end_date, department):
    conn = psycopg2.connect("dbname=appdb user=app")
    cursor = conn.cursor()

    # VULNERABLE: Direct interpolation in PostgreSQL query
    # SonarCloud Rule: python:S2077
    # PostgreSQL supports stacked queries and COPY TO STDOUT, making
    # injection here potentially worse than with SQLite.
    query = f"""
        SELECT employee_id, salary, department
        FROM hr_data
        WHERE hire_date BETWEEN '{start_date}' AND '{end_date}'
        AND department = '{department}'
    """
    cursor.execute(query)

    return cursor.fetchall()
