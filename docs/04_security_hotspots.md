# Security Hotspots vs. Vulnerabilities

One of the most important — and frequently misunderstood — distinctions in SonarCloud is the difference between Security Hotspots and Vulnerabilities. Getting this right is fundamental to effective security triage.

---

## The Core Distinction

| | Vulnerability | Security Hotspot |
|---|---|---|
| **SonarCloud's confidence** | High — code is almost certainly exploitable | Uncertain — may or may not be exploitable |
| **Human review required?** | No — fix it | Yes — human must decide |
| **What it means** | Confirmed security flaw | Security-sensitive code that COULD be a flaw |
| **OWASP/CWE mapping** | Always mapped | Always mapped |
| **Quality Gate impact** | Yes — affects Security Rating | Yes — Hotspots Reviewed % |
| **Correct response** | Fix the code | Review, then Acknowledge or Mark Safe |
| **Example** | SQL query built with string concat | Use of Random() — may or may not be cryptographic |

**The key question**: Can SonarCloud prove this is exploitable with the information available to its static analysis?
- If YES → Vulnerability
- If NO (but it looks risky) → Security Hotspot

---

## Why Hotspots Exist

Some code patterns are ONLY dangerous in certain contexts. SonarCloud cannot always determine the context statically.

**Example**: Using `random.random()` in Python.
- In a simulation: completely fine
- For generating a session token: security critical

SonarCloud can see that `random.random()` is a non-cryptographic RNG. It CANNOT know (in all cases) whether your specific use case requires cryptographic randomness. So it raises a Security Hotspot and asks you to review.

When you review:
- "I'm using this for a Monte Carlo simulation" → Mark as Safe
- "I'm using this to generate password reset tokens" → Acknowledge (becomes a Vulnerability) → Fix it

---

## Common Security Hotspot Categories

### Pseudo-Random Number Generators (PRNG)
- **Rule**: python:S2245, java:S2245, javascript:S2245
- **Flagged pattern**: Use of non-cryptographic random functions
- **When it's safe**: Simulations, games, non-security shuffling, testing
- **When it's a problem**: Tokens, session IDs, CSRF values, password resets, nonces
- **Key question**: Does the unpredictability of this value matter for security?

### Hashing Algorithms
- **Rule**: python:S4790, javascript:S4790
- **Flagged pattern**: Use of MD5, SHA-1, SHA-256 for anything
- **When it's safe**: Checksums for file integrity (not security), non-cryptographic fingerprinting, caching keys
- **When it's a problem**: Password storage, cryptographic signatures, HMAC keys
- **Key question**: Must this be collision-resistant? Must it be preimage-resistant?

### HTTP Configuration
- **Rule**: python:S5122, java:S5122 (CORS), S4834 (HTTP verbs)
- **Flagged pattern**: CORS policies, HTTP verb usage
- **When it's safe**: Properly restricted CORS with specific origins, appropriate verb usage
- **When it's a problem**: Wildcard CORS (`*`) with credentials, GET requests that modify state
- **Key question**: What origins can access this endpoint? Does the configuration match the intent?

### Cookie Configuration
- **Rule**: python:S2092 (Secure flag), S3330 (HttpOnly flag)
- **Flagged pattern**: Creating HTTP cookies
- **When it's safe**: If the cookie is already Secure+HttpOnly+SameSite=Strict
- **When it's a problem**: Missing Secure flag (cookie sent over HTTP), missing HttpOnly (accessible to JavaScript → XSS risk)
- **Key question**: Is this cookie properly secured?

### Encryption Modes
- **Rule**: python:S5542
- **Flagged pattern**: Use of any symmetric cipher (even AES)
- **When it's safe**: AES-GCM, AES-CBC with proper IV handling and authentication
- **When it's a problem**: AES-ECB, DES, RC4, hardcoded IVs
- **Key question**: Is this algorithm and mode current and correctly implemented?

### Path Traversal
- **Rule**: python:S6096, java:S6096
- **Flagged pattern**: File operations using paths that include user input
- **When it's safe**: After validation that the resolved path is within an allowed directory
- **When it's a problem**: No path validation — attacker can read `/etc/passwd` with `../../etc/passwd`
- **Key question**: Is the file path validated against a base directory?

### XML Processing (XXE)
- **Rule**: python:S2755
- **Flagged pattern**: XML parsing
- **When it's safe**: If external entity expansion is disabled
- **When it's a problem**: Default XML parser settings often allow XXE
- **Key question**: Is external entity resolution disabled?

---

## How to Review Security Hotspots

### Step 1: Navigate to Security Hotspots

1. Open your project in SonarCloud
2. Click **Security Hotspots** in the top navigation (NOT the Issues tab)
3. You'll see hotspots organized by security category (OWASP Top 10 sections)

**What you see in the list:**
- Category (e.g., "Weak Cryptography")
- File path and line number
- Rule title
- Status: To Review / Acknowledged / Safe

### Step 2: Open a Hotspot for Review

Click a hotspot to open the review panel. You'll see:
- The code with the flagged line highlighted
- Explanation: "Why is this a security hotspot?"
- Guidance: "Assess the risk" with specific questions to answer

**The questions SonarCloud asks for each hotspot type** are the key to proper review. For example, for a PRNG hotspot:
- "Review the code and confirm that the output of this PRNG is not used for a security-sensitive purpose such as authentication..."

### Step 3: Make a Decision

After reviewing, you have three options:

**Safe**: This code is reviewed and confirmed to be secure in context.
- Example: `random.random()` used only for data shuffling in a non-security context
- Effect: Hotspot removed from the "To Review" count, Security Review Rating maintained

**Acknowledged**: This IS a security concern that needs to be fixed.
- Effect: Hotspot becomes a full Vulnerability, affects the Security Rating
- Now you need to fix it like any other vulnerability

**Fixed**: Mark when the underlying code has been fixed.
- The hotspot is removed from the dashboard after the next analysis confirms the fix

### Step 4: Add a Comment (Recommended)

When marking a hotspot as Safe or Acknowledged, always add a comment explaining your reasoning. This creates an audit trail:

**Good Safe comment**: "This random() call generates a random display order for search results. It does not affect security — the same results are shown regardless of order, only the display sequence varies."

**Good Acknowledged comment**: "Confirmed: this token is used for password reset links. random.random() is not CSPRNG-safe. Converting to secrets.token_urlsafe() as tracked in issue #234."

---

## Hotspot Review Workflow in a Team

Security Hotspot review should be integrated into your development workflow:

### For New Hotspots (PR Review)
1. Developer opens a PR
2. SonarCloud analysis runs, finds a new hotspot
3. PR gets a failing check (if hotspots reviewed < 100% is in your Quality Gate)
4. Developer or security reviewer reviews the hotspot in SonarCloud
5. If Safe: approve and merge
6. If Acknowledged: create a bug/ticket, fix before merging (or track as known debt)

### For Existing Hotspots (Backlog)
1. Schedule regular "Security Hotspot Review" sessions
2. Work through hotspots by category (all PRNG hotspots at once, then all crypto hotspots)
3. Document decisions in SonarCloud comments
4. Track Acknowledged hotspots in your issue tracker

### Who Should Review?

Hotspots are designed for security review, but any developer can (and should) be able to review them with the guidance SonarCloud provides. For sensitive decisions:
- **Developer**: Review hotspots in their own code, mark Safe with justification
- **Security engineer**: Verify high-risk hotspot decisions, review Acknowledged items
- **Team lead**: Approve bulk decisions on architectural patterns (e.g., "all MD5 checksums in the data pipeline are non-security")

---

## Security Review Rating

The **Security Review Rating** measures how thoroughly your team reviews Security Hotspots. It's separate from the Security Rating (which measures vulnerabilities):

| Security Review Rating | Criteria |
|---|---|
| A | >= 80% of hotspots reviewed |
| B | >= 70% reviewed |
| C | >= 50% reviewed |
| D | >= 30% reviewed |
| E | < 30% reviewed |

**Note**: "Reviewed" means a decision was made (Safe or Acknowledged) — not necessarily that everything is safe.

### Impact on Quality Gate

The default Sonar Way gate requires: `New Security Hotspots Reviewed = 100%`

This means ALL new hotspots (from code in the current new code period) must be reviewed before the Quality Gate passes. This is intentional — it forces security review of all security-sensitive code on every change.

---

## False Positives vs. "Won't Fix"

There's an important distinction for managing hotspots and issues:

**False Positive**: SonarCloud raised an issue on code that is NOT actually vulnerable or security-sensitive. The rule misidentified the code.
- Mark as "False Positive" with a detailed comment explaining why
- Example: "SonarCloud flagged this random() call as security-sensitive, but this function is only called from unit tests for generating test fixture data"

**Won't Fix / Safe**: The code IS security-sensitive, but you've reviewed it and it's correctly implemented.
- For hotspots: use "Safe"
- For vulnerabilities: use "Won't Fix" (with justification)
- This is NOT the same as ignoring — it's a documented decision
- Example: "Won't Fix — this uses MD5 for file deduplication fingerprinting only. MD5 collision resistance is not required here and is documented in our architecture decision record ADR-042."

**Abuse of these statuses** (marking real issues as False Positive to pass the gate) is a serious process failure that can mask real vulnerabilities. It should be treated the same way as skipping a security review.
