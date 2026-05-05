"""
Secrets Management - Secure Implementations
=============================================
These are the corrected versions of the vulnerable examples in hardcoded_secrets.py.

Core Fix: Never Store Secrets in Source Code
--------------------------------------------
The golden rule: source code should contain NO credentials, keys, or tokens.
Secrets must come from the environment at runtime, from a secrets manager,
or from a configuration system that is NOT committed to version control.

Solution Hierarchy (best to acceptable):
1. Secrets Manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager)
   - Centralized, auditable, rotatable
   - Best for production systems

2. Environment Variables
   - Simple, well-understood, supported everywhere
   - Used in Kubernetes (from Secret objects), Docker, Heroku, GitHub Actions
   - Acceptable for many scenarios if environment is secured

3. .env files (local development ONLY)
   - MUST be in .gitignore — never committed
   - Use python-dotenv to load them
   - Never use in production — use env vars or secrets manager instead

4. CI/CD Platform Secrets
   - GitHub Actions: Settings > Secrets and variables > Actions
   - Encrypted at rest, not visible in logs, not accessible by fork PRs
   - Good for CI/CD contexts

What Never to Do:
- Hardcode secrets in source code
- Commit .env files
- Print/log secrets
- Store secrets in comments
- Use environment variable names that expose secret values
"""

import os
import logging
from functools import lru_cache
from typing import Optional

# python-dotenv loads .env file in development (not committed to git)
# Install: pip install python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()  # Loads .env file if present (development convenience)
except ImportError:
    pass  # In production, secrets come from environment directly

logger = logging.getLogger(__name__)


# =============================================================================
# FIX 1: Database credentials from environment variables
# =============================================================================
# Environment variables are set:
# - In development: via .env file (git-ignored) or shell export
# - In production: via your platform (Kubernetes Secrets, AWS ECS task def, etc.)
# - In CI/CD: via GitHub Actions secrets → env vars

def get_db_connection():
    """
    Safe: All credentials read from environment variables.
    If a required variable is missing, fail loudly at startup — not silently at runtime.
    """
    # Read credentials from environment — NEVER hardcode these values
    db_host = os.environ.get('DB_HOST', 'localhost')
    db_port = int(os.environ.get('DB_PORT', '5432'))
    db_name = os.environ.get('DB_NAME')
    db_user = os.environ.get('DB_USER')
    db_password = os.environ.get('DB_PASSWORD')

    # Fail fast if required credentials are missing
    # This catches misconfigured deployments immediately at startup
    missing = [k for k, v in {
        'DB_NAME': db_name,
        'DB_USER': db_user,
        'DB_PASSWORD': db_password
    }.items() if not v]

    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Check your .env file (development) or deployment configuration (production)."
        )

    import psycopg2
    return psycopg2.connect(
        host=db_host,
        port=db_port,
        dbname=db_name,
        user=db_user,
        password=db_password
    )


# =============================================================================
# FIX 2: AWS credentials via IAM roles (preferred) or environment variables
# =============================================================================
# Best practice: In AWS environments, use IAM roles attached to EC2/ECS/Lambda.
# boto3 automatically picks up credentials from the instance metadata service.
# You don't need to pass credentials at all — boto3 handles it via the
# credentials chain: env vars → ~/.aws/credentials → IAM role → metadata service

def upload_to_s3(file_path: str, bucket_name: str) -> None:
    """
    Safe: boto3 uses the AWS credential chain automatically.
    In production on AWS: attach an IAM role with minimal S3 permissions.
    In development: use `aws configure` or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env vars.
    Never hardcode AWS credentials.
    """
    import boto3

    # SAFE: No credentials passed — boto3 uses the credential chain:
    # 1. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars
    # 2. ~/.aws/credentials file (local dev)
    # 3. IAM role attached to the instance/container (production)
    # 4. AWS SSO, etc.
    client = boto3.client('s3')  # No credentials argument
    client.upload_file(file_path, bucket_name, file_path)


# =============================================================================
# FIX 3: API keys from environment variables with validation
# =============================================================================
@lru_cache(maxsize=1)
def get_stripe_key() -> str:
    """
    Safe: Stripe key from environment variable.
    Cached to avoid repeated env lookups. Validated at call time.
    """
    key = os.environ.get('STRIPE_SECRET_KEY')
    if not key:
        raise EnvironmentError("STRIPE_SECRET_KEY environment variable is not set")

    # Sanity check the key format (not security, just catches configuration errors)
    if not (key.startswith('sk_live_') or key.startswith('sk_test_')):
        raise ValueError("STRIPE_SECRET_KEY does not appear to be a valid Stripe key")

    return key


def send_payment(amount: int, card_token: str) -> dict:
    """
    Safe: Retrieves Stripe key from environment at runtime.
    """
    import stripe
    # SAFE: Key from environment, not hardcoded
    stripe.api_key = get_stripe_key()

    charge = stripe.Charge.create(
        amount=amount,
        currency="usd",
        source=card_token,
        description="Purchase"
    )
    return charge


# =============================================================================
# FIX 4: JWT with a strong, rotatable secret from environment
# =============================================================================
def get_jwt_secret() -> str:
    """
    Safe: JWT secret from environment variable.
    For production: generate a cryptographically strong secret with:
      python -c "import secrets; print(secrets.token_hex(64))"
    Store the result in your secrets manager or as an environment variable.
    """
    secret = os.environ.get('JWT_SECRET_KEY')
    if not secret:
        raise EnvironmentError("JWT_SECRET_KEY environment variable is not set")
    if len(secret) < 32:
        raise ValueError("JWT_SECRET_KEY must be at least 32 characters")
    return secret


def create_auth_token(user_id: int, is_admin: bool = False) -> str:
    """
    Safe: JWT signed with environment-sourced secret.
    Also adds iat (issued at) and a reasonable expiration.
    """
    import jwt
    import time

    payload = {
        'user_id': user_id,
        'is_admin': is_admin,
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600  # 1 hour
    }

    # SAFE: Secret from environment variable, not hardcoded
    return jwt.encode(payload, get_jwt_secret(), algorithm='HS256')


def verify_auth_token(token: str) -> dict:
    """Safe: Verifies JWT using secret from environment."""
    import jwt
    return jwt.decode(token, get_jwt_secret(), algorithms=['HS256'])


# =============================================================================
# FIX 5: SMTP credentials from environment
# =============================================================================
def send_email(to_address: str, subject: str, body: str) -> None:
    """
    Safe: SMTP credentials from environment variables.
    In production, prefer transactional email services (SendGrid, SES, Mailgun)
    that use API keys rather than SMTP passwords.
    """
    import smtplib

    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')

    if not smtp_user or not smtp_password:
        raise EnvironmentError("SMTP_USER and SMTP_PASSWORD must be set")

    # SAFE: Credentials from environment, not hardcoded
    server = smtplib.SMTP(smtp_host, smtp_port)
    server.starttls()
    server.login(smtp_user, smtp_password)
    message = f"Subject: {subject}\n\n{body}"
    server.sendmail(smtp_user, to_address, message)
    server.quit()


# =============================================================================
# FIX 6: Using a Secrets Manager (production best practice)
# =============================================================================
# For production systems, use a dedicated secrets manager.
# This provides: rotation, auditing, fine-grained access control, versioning.

@lru_cache(maxsize=None)
def get_secret_from_aws(secret_name: str, region: str = 'us-east-1') -> dict:
    """
    Safe: Retrieves secrets from AWS Secrets Manager at runtime.
    The secret is cached in memory for the lifetime of the process
    (cache invalidates on restart, which forces fresh rotation pickup).

    To use: store your DB credentials as a JSON object in AWS Secrets Manager.
    IAM role on your compute resource needs secretsmanager:GetSecretValue permission.
    """
    import boto3
    import json

    client = boto3.client('secretsmanager', region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])


def get_db_connection_from_secrets_manager():
    """
    Production-grade: Credentials from AWS Secrets Manager.
    """
    import psycopg2

    # SAFE: All credentials fetched from Secrets Manager — nothing hardcoded
    secret = get_secret_from_aws(os.environ['DB_SECRET_NAME'])

    return psycopg2.connect(
        host=secret['host'],
        port=secret['port'],
        dbname=secret['dbname'],
        user=secret['username'],
        password=secret['password']
    )


# =============================================================================
# FIX 7: Generate strong secrets programmatically when needed
# =============================================================================
import secrets as secrets_module

def generate_secure_token(length: int = 32) -> str:
    """
    Safe: Use the secrets module (CSPRNG) for all security-sensitive tokens.
    Do NOT use random.random(), random.randint(), or uuid.uuid4() for secrets.
    The secrets module uses os.urandom() which reads from /dev/urandom (a CSPRNG).
    """
    # SAFE: secrets.token_urlsafe generates a URL-safe base64-encoded random string
    return secrets_module.token_urlsafe(length)


def generate_api_key() -> str:
    """Generate a cryptographically strong API key."""
    # SAFE: 32 bytes = 256 bits of entropy, displayed as 64 hex characters
    return secrets_module.token_hex(32)


def generate_password_reset_token() -> str:
    """Generate a single-use password reset token."""
    # SAFE: URL-safe token suitable for use in URL parameters
    return secrets_module.token_urlsafe(32)  # 32 bytes = 43 URL-safe characters


# =============================================================================
# .env file example (this belongs in .env, which is git-ignored)
# =============================================================================
# Create a .env file at your project root with:
#
#   DB_HOST=localhost
#   DB_PORT=5432
#   DB_NAME=myapp_dev
#   DB_USER=myapp_user
#   DB_PASSWORD=your-local-dev-password-here
#   JWT_SECRET_KEY=generate-with-python-c-import-secrets-print-secrets-token-hex-64
#   STRIPE_SECRET_KEY=sk_test_your_test_key
#   SMTP_USER=dev@example.com
#   SMTP_PASSWORD=your-app-password
#
# Then add to .gitignore:
#   .env
#   .env.local
#   .env.*.local
#   *.env
