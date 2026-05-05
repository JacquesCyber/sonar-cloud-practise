"""
Hardcoded Secrets / Credentials Vulnerability Examples
=======================================================
OWASP Category: A02:2021 - Cryptographic Failures
                A07:2021 - Identification and Authentication Failures
CWE: CWE-798 - Use of Hard-coded Credentials
     CWE-259 - Use of Hard-coded Password
SonarCloud Rules:
  - python:S6437 - Credentials should not be hard-coded
  - python:S2068 - Passwords should not be hard-coded
  - python:S105  - Hard-coded passwords should not be used
Severity in SonarCloud: BLOCKER (Vulnerability) — highest severity

What are Hardcoded Secrets?
---------------------------
Hardcoded secrets are credentials, API keys, tokens, or cryptographic keys
embedded directly in source code. This is dangerous because:

1. Source code is often stored in version control (Git)
2. Git history is permanent — even if you delete the secret in a later commit,
   it remains accessible in the commit history
3. Developers frequently share/copy code, spreading the secret
4. Build artifacts (compiled code, Docker images) may contain the secret
5. Logs, error messages, and stack traces may expose it

Real-World Impact:
------------------
- 2022: Samsung source code leaked to GitHub included AWS credentials
- 2021: Twitch breach — hardcoded credentials in leaked source
- Constant: GitHub's secret scanning finds thousands of hardcoded secrets daily
  (AWS keys, Stripe keys, etc.) that attackers exploit within minutes

Why SonarCloud Catches This:
----------------------------
SonarCloud uses pattern matching and entropy analysis to detect:
- Variable names suggesting credentials (password, secret, key, token, api_key)
- Values that match known secret formats (AWS ARNs, JWT tokens, UUID patterns)
- High-entropy strings assigned to credential-suggesting variable names
"""

import requests
import boto3
import psycopg2
import smtplib
import jwt


# =============================================================================
# VULNERABLE EXAMPLE 1: Database credentials
# =============================================================================
# The most common hardcoded secret. A developer hardcoded the DB password
# "for convenience" and committed it. Now it's in git history forever.
#
# SonarCloud Rule: python:S6437
#
# Real impact: Full database access for anyone who clones the repo.
DB_HOST = "db.example.com"
DB_PORT = 5432
DB_NAME = "production_db"
DB_USER = "app_user"
DB_PASSWORD = "P@ssw0rd!SuperSecret123"  # SonarCloud flags this immediately


def connect_to_database():
    # VULNERABLE: Using hardcoded credentials defined above
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD  # Taint flow: hardcoded constant → connection
    )
    return conn


# =============================================================================
# VULNERABLE EXAMPLE 2: AWS credentials
# =============================================================================
# AWS access keys have a distinctive format (AKIA...) that SonarCloud and
# GitHub's secret scanning both recognize. AWS also auto-scans public repos
# and revokes exposed keys, but the damage may already be done.
#
# SonarCloud Rule: python:S6437
#
# Real impact: Full AWS account compromise, potential for massive cloud bills,
# data exfiltration, and supply chain attacks.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"       # SonarCloud: python:S6437
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Flagged


def upload_to_s3(file_path, bucket_name):
    # VULNERABLE: Hardcoded AWS credentials
    client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,           # Hardcoded
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,   # Hardcoded
        region_name='us-east-1'
    )
    client.upload_file(file_path, bucket_name, file_path)


# =============================================================================
# VULNERABLE EXAMPLE 3: API keys inline in function calls
# =============================================================================
# Developers sometimes hardcode secrets directly in function arguments,
# thinking "it's just one place." Still flagged by SonarCloud.
#
# SonarCloud Rule: python:S6437
def send_payment(amount, card_token):
    # VULNERABLE: Stripe secret key hardcoded in function body
    import stripe
    stripe.api_key = "sk_live_EXAMPLE_FAKE_KEY_FOR_SONAR_DEMO"  # python:S6437

    charge = stripe.Charge.create(
        amount=amount,
        currency="usd",
        source=card_token,
        description="Purchase"
    )
    return charge


# =============================================================================
# VULNERABLE EXAMPLE 4: JWT secret key
# =============================================================================
# If your JWT signing secret is hardcoded and exposed, attackers can:
# - Forge arbitrary JWT tokens
# - Impersonate any user including admins
# - Bypass all authentication
#
# SonarCloud Rule: python:S6437
JWT_SECRET = "my-super-secret-jwt-key-do-not-share"  # SonarCloud flags this


def create_auth_token(user_id, is_admin=False):
    # VULNERABLE: Signing JWTs with a hardcoded secret
    payload = {
        'user_id': user_id,
        'is_admin': is_admin,
        'exp': 3600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')  # Uses hardcoded key
    return token


def verify_auth_token(token):
    # An attacker who knows JWT_SECRET can create admin tokens:
    # jwt.encode({'user_id': 1, 'is_admin': True, 'exp': 99999999}, 'my-super-secret-jwt-key-do-not-share')
    return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])


# =============================================================================
# VULNERABLE EXAMPLE 5: SMTP credentials for email sending
# =============================================================================
# Email service credentials hardcoded. Attacker can:
# - Send phishing emails from your domain
# - Access your email service account
# - Exhaust your email sending quota
#
# SonarCloud Rule: python:S2068
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "noreply@example.com"
SMTP_PASSWORD = "gmail_app_password_abc123XYZ"  # SonarCloud: python:S2068


def send_email(to_address, subject, body):
    # VULNERABLE: SMTP auth with hardcoded credentials
    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USER, SMTP_PASSWORD)  # Hardcoded credentials
    message = f"Subject: {subject}\n\n{body}"
    server.sendmail(SMTP_USER, to_address, message)
    server.quit()


# =============================================================================
# VULNERABLE EXAMPLE 6: "Encrypted" or "obfuscated" secrets (still vulnerable)
# =============================================================================
# Developers sometimes think encoding or splitting the secret helps.
# It does NOT. SonarCloud and determined attackers can still find these.
# Base64 is encoding, not encryption. Anyone can decode it.
import base64

# STILL VULNERABLE: Base64 encoding is trivial to reverse
# echo "c3VwZXJzZWNyZXRwYXNzd29yZA==" | base64 -d
ENCODED_PASSWORD = base64.b64decode("c3VwZXJzZWNyZXRwYXNzd29yZA==").decode()

# STILL VULNERABLE: Splitting across variables fools nobody
SECRET_PART_1 = "super"
SECRET_PART_2 = "secret"
SECRET_PART_3 = "password123"
REAL_SECRET = SECRET_PART_1 + SECRET_PART_2 + SECRET_PART_3


# =============================================================================
# VULNERABLE EXAMPLE 7: Default credentials that should be changed
# =============================================================================
# "Default" credentials left in place. Common in IoT firmware, internal tools.
# CWE-1392: Use of Default Credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"  # SonarCloud: python:S2068

DEFAULT_API_KEY = "changeme"  # Also flagged — still a hardcoded secret

WEBHOOK_SECRET = "webhook_secret_replace_in_production"  # Flagged
