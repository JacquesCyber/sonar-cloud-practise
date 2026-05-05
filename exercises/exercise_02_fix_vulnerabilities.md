# Exercise 02: Fix Vulnerabilities and Verify with SonarCloud

## Objective

Apply security fixes to the vulnerable code examples and use SonarCloud to verify that the fixes resolve the issues. By the end of this exercise, you'll understand:
- How to fix each vulnerability type (SQL injection, XSS, hardcoded secrets, weak crypto, command injection)
- The SonarCloud re-analysis workflow
- How to track vulnerability remediation progress

**Estimated time**: 90-120 minutes

---

## Prerequisites

- [ ] Completed Exercise 01 — your first SonarCloud scan is complete
- [ ] SonarCloud showing vulnerabilities in `src/vulnerable/`
- [ ] Git and your preferred editor set up

---

## Understanding the Fix Strategy

Before diving in, understand the approach:

1. The files in `src/vulnerable/` contain intentional vulnerabilities
2. The files in `src/fixed/` contain the correct implementations
3. In this exercise, you will modify the vulnerable files to use secure patterns
4. After pushing, SonarCloud re-analyzes and should no longer flag those patterns
5. You'll compare "before" and "after" metric snapshots

**Do NOT simply delete the vulnerable files.** SonarCloud would no longer see them, but you wouldn't learn the fix patterns. Instead, modify each vulnerable file to use secure code, keeping the function signatures the same.

---

## Part 1: Fix SQL Injection (25 minutes)

### Step 1.1: Understand the Vulnerability

Open `src/vulnerable/sql_injection.py` and review the first vulnerable function:
```python
def get_user_by_id_vulnerable(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
```

What makes this vulnerable:
- `user_id` is a function parameter (user-controlled in a web app context)
- It's interpolated directly into the SQL string via f-string
- SonarCloud traces this: parameter → f-string → cursor.execute() = SQL injection sink

### Step 1.2: Apply the Fix

For each vulnerable function in `sql_injection.py`, apply the parameterized query fix.

**The fix pattern:**

BEFORE (vulnerable):
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

AFTER (safe):
```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # User input as a parameter, not in the SQL string
```

**For PostgreSQL (psycopg2)**, the placeholder is `%s` not `?`:
```python
query = "SELECT * FROM users WHERE user_id = %s"
cursor.execute(query, (user_id,))  # Note: NOT Python % formatting — it's psycopg2 parameterization
```

**Reference implementation**: See `src/fixed/sql_safe.py` for complete fixed versions.

### Step 1.3: Handle the ORDER BY Case

The `get_orders_vulnerable()` function has a tricky case — ORDER BY column names cannot be parameterized in SQL. The fix requires an allowlist:

```python
ALLOWED_ORDER_COLUMNS = frozenset({'created_at', 'total_price', 'status', 'order_id'})

def get_orders_safe(user_id, order_by='created_at'):
    if order_by not in ALLOWED_ORDER_COLUMNS:
        raise ValueError(f"Invalid sort column: {order_by}")
    # Now safe to use order_by in SQL — it's been validated against a developer-controlled list
    query = f"SELECT * FROM orders WHERE user_id = ? ORDER BY {order_by}"
    cursor.execute(query, (user_id,))
```

### Step 1.4: Commit the SQL Fixes

```bash
git add src/vulnerable/sql_injection.py
git commit -m "Fix SQL injection vulnerabilities - use parameterized queries

Replaced all string-concatenated SQL queries with parameterized queries.
- f-strings → ? or %s placeholders
- Dynamic ORDER BY now uses allowlist validation
- SonarCloud rule python:S2077 should be resolved"

git push origin main
```

### Step 1.5: Verify in SonarCloud

1. Wait for the GitHub Actions pipeline to complete
2. In SonarCloud, go to Issues > filter by Rule: `python:S2077`
3. The previously flagged lines in `sql_injection.py` should no longer appear
4. If they still appear, check that you pushed correctly and the analysis completed

---

## Part 2: Fix Hardcoded Secrets (20 minutes)

### Step 2.1: Understand Why This Is BLOCKER Severity

Hardcoded secrets are rated BLOCKER because:
- The secret is immediately visible to anyone with repository access
- Git history preserves the secret even after removal
- Unlike most other vulnerabilities, this requires NO exploitation complexity — the attacker literally reads the code

### Step 2.2: Apply the Fix

The fix is to load secrets from environment variables instead of hardcoding them.

**The fix pattern:**

BEFORE (vulnerable):
```python
DB_PASSWORD = "P@ssw0rd!SuperSecret123"  # BLOCKER

def connect_to_database():
    conn = psycopg2.connect(password=DB_PASSWORD)
```

AFTER (safe):
```python
import os

def connect_to_database():
    db_password = os.environ.get('DB_PASSWORD')
    if not db_password:
        raise EnvironmentError("DB_PASSWORD environment variable is not set")
    conn = psycopg2.connect(password=db_password)
```

**Apply this pattern to ALL secrets in `hardcoded_secrets.py`:**
- Database credentials → `os.environ.get('DB_PASSWORD')`
- AWS keys → Use boto3's credential chain (no explicit keys)
- API keys → `os.environ.get('STRIPE_SECRET_KEY')`
- JWT secret → `os.environ.get('JWT_SECRET_KEY')`
- SMTP password → `os.environ.get('SMTP_PASSWORD')`

**Reference implementation**: See `src/fixed/secrets_safe.py`

### Step 2.3: Create a .env.example File

Create a template showing what environment variables are needed (without real values):

```bash
cat > .env.example << 'EOF'
# Copy this to .env and fill in your values
# NEVER commit .env to version control

DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp_dev
DB_USER=myapp_user
DB_PASSWORD=your-dev-password-here

JWT_SECRET_KEY=generate-with: python -c "import secrets; print(secrets.token_hex(64))"

STRIPE_SECRET_KEY=sk_test_your_test_key_here

SMTP_USER=dev@example.com
SMTP_PASSWORD=your-smtp-password
EOF
```

Make sure `.env` is in `.gitignore`:
```bash
echo ".env" >> .gitignore
echo "*.env" >> .gitignore
echo ".env.local" >> .gitignore
```

### Step 2.4: Commit the Secret Fixes

```bash
git add src/vulnerable/hardcoded_secrets.py .env.example .gitignore
git commit -m "Fix hardcoded credentials - use environment variables

Moved all credentials to environment variables:
- Database password: DB_PASSWORD env var
- AWS keys: removed (use boto3 credential chain)
- Stripe key: STRIPE_SECRET_KEY env var
- JWT secret: JWT_SECRET_KEY env var
- SMTP password: SMTP_PASSWORD env var

Added .env.example template for local development setup.
IMPORTANT: The actual secrets from the original file should be considered
compromised and rotated if they were real credentials.

Resolves SonarCloud rule python:S6437 (hardcoded credentials)"

git push origin main
```

---

## Part 3: Fix Weak Cryptography (25 minutes)

### Step 3.1: Password Hashing Fix

The most critical fix is changing MD5/SHA-1 password hashing to bcrypt.

**Install bcrypt first:**
```bash
pip install bcrypt
# Add to requirements.txt:
echo "bcrypt>=4.0.0" >> requirements.txt
```

BEFORE:
```python
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # python:S4790
```

AFTER:
```python
import bcrypt
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())
```

### Step 3.2: Symmetric Encryption Fix

Replace DES and AES-ECB with AES-256-GCM:

BEFORE:
```python
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)  # python:S5547
```

AFTER:
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_safe(plaintext: bytes, key: bytes) -> bytes:
    assert len(key) == 32, "Key must be 32 bytes"
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext  # Pack nonce+tag+ciphertext together
```

### Step 3.3: Fix Weak Random for Security Tokens

BEFORE:
```python
import random
token = ''.join([str(random.randint(0, 9)) for _ in range(32)])  # python:S2245
```

AFTER:
```python
import secrets
token = secrets.token_urlsafe(32)  # CSPRNG-backed, 256 bits of entropy
```

### Step 3.4: Fix Disabled TLS Verification

BEFORE:
```python
ctx.verify_mode = ssl.CERT_NONE  # python:S4830
```

AFTER: Remove the custom context entirely, or:
```python
# Just use the default — verification is on by default
response = requests.get(url)  # No verify=False
```

### Step 3.5: Commit Crypto Fixes

```bash
git add src/vulnerable/insecure_crypto.py requirements.txt
git commit -m "Fix weak cryptography vulnerabilities

- Replace MD5/SHA-1 password hashing with bcrypt (work factor 12)
- Replace DES/AES-ECB with AES-256-GCM authenticated encryption
- Replace random.random() with secrets.token_urlsafe() for security tokens
- Replace RC4 with ChaCha20-Poly1305
- Re-enable TLS certificate verification
- Generate random IVs per encryption (not hardcoded)

Resolves: python:S5547, python:S4790, python:S2245, python:S4830, python:S3329"

git push origin main
```

---

## Part 4: Fix Command Injection (20 minutes)

### Step 4.1: The Core Fix

For every `os.system()` or `subprocess.run(..., shell=True)` with user input:

**Option A (preferred): Replace with a Python library**
```python
# Instead of: os.popen(f"sha256sum {filename}").read()
import hashlib
with open(filename, 'rb') as f:
    return hashlib.sha256(f.read()).hexdigest()
```

**Option B: Use subprocess list form (no shell)**
```python
# Instead of: subprocess.run(f"ping -c 4 {hostname}", shell=True)
# First validate:
if not re.match(r'^[a-zA-Z0-9._-]{1,253}$', hostname):
    raise ValueError("Invalid hostname")
# Then run without shell:
subprocess.run(["ping", "-c", "4", hostname], shell=False)
#              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#              List form: each element is a separate OS argument
#              The hostname becomes a LITERAL argument to ping
#              ; | && have no special meaning
```

**Option C: Strict input validation (last resort)**
```python
import re
if not re.match(r'^[a-zA-Z0-9._-]+$', user_input):
    raise ValueError("Input contains invalid characters")
# Only use if you've verified the allowlist is correct and sufficient
```

### Step 4.2: Fix the eval() Issue

```python
# Instead of: result = eval(formula)
# Use the AST-based safe evaluator from src/fixed/command_safe.py
import ast, operator
SAFE_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}

def safe_eval(expr):
    tree = ast.parse(expr, mode='eval')
    def _eval(node):
        if isinstance(node, ast.Constant): return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPS:
            return SAFE_OPS[type(node.op)](_eval(node.left), _eval(node.right))
        raise ValueError(f"Disallowed: {type(node).__name__}")
    return _eval(tree.body)
```

### Step 4.3: Commit Command Injection Fixes

```bash
git add src/vulnerable/command_injection.py
git commit -m "Fix OS command injection vulnerabilities

- Replace os.system() + shell=True with subprocess list form
- Replace eval() with AST-based safe expression evaluator
- Add strict allowlist validation for all user-provided identifiers
- Replace shell-based file operations with Python standard library equivalents

All user input validated before any OS-level operation.
Resolves: python:S2076, python:S4721, python:S1523"

git push origin main
```

---

## Part 5: Verify All Fixes in SonarCloud (15 minutes)

### Step 5.1: Wait for Analysis Completion

After your last push, wait for:
1. The GitHub Actions pipeline to complete (check the Actions tab)
2. SonarCloud processing (1-2 minutes after the pipeline)

### Step 5.2: Compare Before and After

Go to SonarCloud and check the Activity tab:

1. Click **Activity** in the project navigation
2. You should see multiple analysis events (one per push)
3. Compare the Vulnerability count over the analysis history
4. It should be trending down with each fix

### Step 5.3: Verify Each Rule Is Resolved

Check that these rules no longer appear in the Issues tab:

| Rule | Expected Status |
|---|---|
| python:S2077 | No issues (or resolved) |
| python:S6437 | No issues |
| python:S2076 | No issues |
| python:S5547 | No issues |
| python:S4790 | No issues |
| python:S2245 | No issues (hotspot resolved) |

For each rule: Issues > filter by Rule > confirm no open issues in the fixed files.

### Step 5.4: Check the Quality Gate Status

Is the Quality Gate now passing?

If still failing, check which conditions are failing:
- **Coverage**: You may need to write tests to hit the coverage threshold
- **Hotspots Reviewed**: You need to review Security Hotspots in the SonarCloud UI (see docs/04_security_hotspots.md)
- **Remaining vulnerabilities**: Some issues may still exist — check the Issues tab

### Step 5.5: Review and Resolve Security Hotspots

The Quality Gate requires 100% of Security Hotspots to be reviewed. This is a manual step:

1. Go to **Security Hotspots** in SonarCloud
2. For each hotspot, read the guidance
3. Make a decision:
   - If it's a real concern: **Acknowledge** (then fix it)
   - If the context makes it safe: **Mark as Safe** (add a comment explaining why)
4. All hotspots must be reviewed before the gate passes

---

## Expected Final State

After completing all fixes:
- Vulnerabilities on new code: 0 (or only for patterns you haven't fixed yet)
- Security Hotspots reviewed: 100% (after manual review)
- Security Rating: A (no unresolved vulnerabilities)
- Quality Gate: PASSED

---

## Reflection Questions

Take a few minutes to think through these questions:

1. For SQL injection: What's the difference between parameterization and escaping? Why is parameterization preferred?

2. For hardcoded secrets: Even after fixing the code, the old secrets were in git history. How would you rotate credentials that were hardcoded in a real project?

3. For weak crypto: Why is bcrypt better than SHA-256 for passwords, even though SHA-256 is "stronger" in terms of collision resistance?

4. For command injection: Why is `subprocess.run(["ping", hostname])` safe while `subprocess.run(f"ping {hostname}", shell=True)` is not?

5. What did SonarCloud miss? Are there any security issues in the fixed code that a security engineer would still want to review?

---

## Next Steps

- [Exercise 03: Custom Quality Gate](exercise_03_custom_quality_gate.md)
- [docs/04_security_hotspots.md](../docs/04_security_hotspots.md) — Review the remaining Security Hotspots
