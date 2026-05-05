# Exercise 04: PR Workflow with SonarCloud Decoration

## Objective

Experience the full SonarCloud PR review workflow as it works in a real team environment. You'll open pull requests with both vulnerable and clean code, observe inline PR comments and Quality Gate checks, and understand how SonarCloud integrates into code review.

**Estimated time**: 45-60 minutes

---

## Prerequisites

- [ ] Completed Exercises 01-03
- [ ] The `pr-analysis.yml` workflow is present in `.github/workflows/`
- [ ] SONAR_TOKEN is configured as a GitHub secret
- [ ] GitHub Actions write permissions configured (Settings > Actions > General > Workflow permissions > Read and write)
- [ ] Ideally: Branch protection configured to require the SonarCloud check

---

## Part 1: Configure PR Decoration (10 minutes)

### Step 1.1: Ensure Automatic Analysis Is Disabled

This is the most common mistake — if Automatic Analysis is enabled alongside GitHub Actions, you'll get duplicate analyses and conflicting PR decoration.

1. In SonarCloud, go to: your project > **Administration** > **Analysis Method**
2. If "Automatic Analysis" is shown and enabled: **turn it off**
3. Confirm that "GitHub Actions" is shown as the CI provider

### Step 1.2: Verify PR Decoration Settings

1. In SonarCloud: Project > **Administration** > **Pull Requests**
2. Confirm settings:
   - Provider: GitHub
   - Decoration enabled
3. Save if you made any changes

### Step 1.3: Enable Branch Protection (Recommended)

For the full experience, configure GitHub to require the SonarCloud check:

1. GitHub repository: **Settings** > **Branches**
2. Click **Add rule** for `main`
3. Enable: **Require status checks to pass before merging**
4. Search for and add: `SonarCloud Code Analysis`
5. Enable: **Require branches to be up to date before merging**
6. Click **Save changes**

**Note**: You need admin access to the repository. If you're working with a fork, you have admin access.

---

## Part 2: Open a PR with a Vulnerability (20 minutes)

### Step 2.1: Create a Feature Branch with Vulnerable Code

```bash
# Create and checkout a new feature branch
git checkout -b feature/user-lookup-api
```

Create a new file simulating a new feature being developed:

```bash
cat > src/user_api.py << 'EOF'
"""
User Lookup API Module
Simulates a new feature being added via a pull request.
This version has a SQL injection vulnerability — intentional for exercise purposes.
"""
import sqlite3
from typing import Optional


def get_user_profile(user_id: str) -> Optional[dict]:
    """
    Look up a user profile by ID.
    
    WARNING: This implementation has a SQL injection vulnerability.
    It is intentional — this is a PR exercise to demonstrate SonarCloud
    inline PR comments.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string interpolation — SonarCloud should catch this
    # and post an inline PR comment on this line.
    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    row = cursor.fetchone()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2]}
    return None


def search_users(search_term: str, role: str) -> list:
    """Search users by name with role filter."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # VULNERABLE: Another SQL injection in the same PR
    query = "SELECT id, username FROM users WHERE username LIKE '%" + search_term + "%' AND role = '" + role + "'"
    cursor.execute(query)
    
    return [{"id": r[0], "username": r[1]} for r in cursor.fetchall()]
EOF
```

### Step 2.2: Also Add a Hardcoded Secret (to test blocker detection)

```bash
cat >> src/user_api.py << 'EOF'


# Configuration — storing API key here for convenience
# (This is a vulnerability intentionally added for the PR exercise)
INTERNAL_API_KEY = "api_key_abc123_do_not_share_8675309"

def call_internal_service(endpoint: str) -> dict:
    """Call internal service using the API key."""
    import requests
    response = requests.get(
        f"https://internal-api.example.com/{endpoint}",
        headers={"X-API-Key": INTERNAL_API_KEY}
    )
    return response.json()
EOF
```

### Step 2.3: Commit and Push the Feature Branch

```bash
git add src/user_api.py
git commit -m "Add user lookup API module

Implements user profile lookup and search functionality.
TODO: Review before merging — needs security review."

git push origin feature/user-lookup-api
```

### Step 2.4: Open the Pull Request on GitHub

1. Go to your repository on GitHub
2. You'll see a yellow banner: "feature/user-lookup-api had recent pushes" with a "Compare & pull request" button
3. Click **Compare & pull request**
4. Fill in the PR:
   - **Title**: `Add user lookup API module`
   - **Description**:
     ```
     ## Changes
     - New `user_api.py` module for user profile lookups
     - Implements `get_user_profile()` and `search_users()` functions
     
     ## TODO
     - [ ] Security review (SonarCloud check pending)
     - [ ] Add tests
     ```
5. Click **Create pull request**

### Step 2.5: Observe the PR Checks

Watch the PR page for a few minutes. You'll see:

1. **Immediately after opening**: A yellow ⏳ "SonarCloud Code Analysis" check appears in the Checks section (below the PR description)

2. **After ~1-2 minutes**: The check updates to red ❌ "Quality Gate failed"

3. **Inline comments appear**: On the Files Changed tab, look for comment annotations on the lines with the SQL injection and hardcoded API key. The comments will look like:
   ```
   [SonarCloud] Make sure this SQL query is protected against injection attacks.
   This block constructs a SQL query from user-controlled data.
   Rule: python:S2077 — CRITICAL
   ```

4. **SonarCloud posts a summary comment** (if configured): In the PR conversation, SonarCloud may post an automated comment listing the issues found.

### Step 2.6: Navigate to SonarCloud for Details

In the PR checks section, click **Details** next to the failed SonarCloud check. This opens SonarCloud with the PR-specific analysis view showing:
- Only issues introduced in THIS PR (not all issues in the project)
- The Quality Gate status evaluated on new code only
- Inline highlighting of the affected lines

**Record what you see:**
1. How many issues were found in this PR? ___
2. What is the Quality Gate failure reason? ___
3. Which specific lines are flagged? ___

---

## Part 3: Fix the Issues and Re-submit (15 minutes)

### Step 3.1: Fix the Vulnerable Code

On the `feature/user-lookup-api` branch, fix the issues:

```python
# Replace src/user_api.py with secure versions:
cat > src/user_api.py << 'EOF'
"""
User Lookup API Module
Secure implementation using parameterized queries.
"""
import sqlite3
import os
from typing import Optional


def get_user_profile(user_id: int) -> Optional[dict]:
    """
    Look up a user profile by ID.
    Uses parameterized query — SonarCloud python:S2077 resolved.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: Parameterized query with ? placeholder
    query = "SELECT id, username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    row = cursor.fetchone()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2]}
    return None


def search_users(search_term: str, role: str) -> list:
    """Search users by name with role filter."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: Both parameters bound — wildcards in the parameter value, not SQL
    like_pattern = f"%{search_term}%"
    query = "SELECT id, username FROM users WHERE username LIKE ? AND role = ?"
    cursor.execute(query, (like_pattern, role))
    
    return [{"id": r[0], "username": r[1]} for r in cursor.fetchall()]


def call_internal_service(endpoint: str) -> dict:
    """Call internal service using API key from environment."""
    import requests
    
    # SAFE: API key from environment variable, not hardcoded
    api_key = os.environ.get('INTERNAL_API_KEY')
    if not api_key:
        raise EnvironmentError("INTERNAL_API_KEY environment variable is not set")
    
    response = requests.get(
        f"https://internal-api.example.com/{endpoint}",
        headers={"X-API-Key": api_key}
    )
    return response.json()
EOF
```

### Step 3.2: Push the Fix

```bash
git add src/user_api.py
git commit -m "Fix security issues in user lookup API

- Replace string-concatenated SQL with parameterized queries (S2077)
- Move API key to INTERNAL_API_KEY environment variable (S6437)
- Input type tightened: user_id is now int (prevents string injection)

All SonarCloud security issues addressed."

git push origin feature/user-lookup-api
```

### Step 3.3: Observe the PR Update

GitHub automatically triggers the PR analysis workflow again (because of the `synchronize` event).

Watch the PR:
1. The ❌ check should change to ⏳ (running again)
2. After analysis: ✅ "SonarCloud Code Analysis — All checks have passed" (if all issues are fixed and coverage is met)

**Note**: If coverage is below your threshold (60% in Exercise 03), the gate may still fail on coverage. This is acceptable — it means the gate works correctly. You would add tests in a real PR.

### Step 3.4: Review the "Before and After" in SonarCloud

In SonarCloud, navigate to your project and look at the PR analysis:
1. Go to: Project > Issues > filter by Pull Request number
2. You should see 0 open issues for this PR (after the fix)
3. Go back to Activity — you can see the two analyses for this PR (one with issues, one clean)

---

## Part 4: Open a Clean PR (5 minutes)

Now experience a PR that passes from the start:

```bash
git checkout main
git pull origin main
git checkout -b feature/add-utility-functions

cat > src/utilities.py << 'EOF'
"""Utility functions — clean code, no security issues."""
from typing import List
import re


def sanitize_filename(filename: str) -> str:
    """Remove dangerous characters from a filename."""
    # Allow only alphanumeric, dots, hyphens, underscores
    return re.sub(r'[^\w.\-]', '_', filename)


def paginate(items: List, page: int, per_page: int = 20) -> dict:
    """Paginate a list of items."""
    if page < 1:
        raise ValueError("Page must be >= 1")
    if per_page < 1 or per_page > 100:
        raise ValueError("per_page must be between 1 and 100")
    
    start = (page - 1) * per_page
    end = start + per_page
    
    return {
        "items": items[start:end],
        "page": page,
        "per_page": per_page,
        "total": len(items),
        "pages": (len(items) + per_page - 1) // per_page,
    }


def mask_email(email: str) -> str:
    """Mask an email address for display (e.g., logging)."""
    parts = email.split('@')
    if len(parts) != 2:
        return '***'
    local, domain = parts
    if len(local) <= 2:
        masked_local = '*' * len(local)
    else:
        masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"
EOF

git add src/utilities.py
git commit -m "Add utility functions: sanitize_filename, paginate, mask_email"
git push origin feature/add-utility-functions
```

Open a PR for this branch. The SonarCloud check should pass (assuming coverage threshold isn't blocking you).

---

## Part 5: Enforce the Gate via Branch Protection (5 minutes)

### Step 5.1: Try to Merge the Vulnerable PR

If branch protection is enabled (from Step 1.3):
1. Go back to the PR with the original vulnerable code (before you fixed it)
2. Or create a new branch with a vulnerability and open a PR
3. Observe: The "Merge pull request" button is **grey/disabled** when the check fails
4. Hover over it — it says "Required status checks must pass before merging"

This is the enforcement mechanism: even if a reviewer approves the PR, it cannot be merged until the SonarCloud check passes.

### Step 5.2: Observe Admin Override

As a repo admin, you CAN override this:
- The "Merge pull request" button becomes active with a warning
- Click the arrow next to it to see "Merge without waiting for requirements"
- **Do NOT use this for production security reviews** — document when it's used

---

## Part 6: Cleanup

Merge or close your PRs, and clean up branches:

```bash
# After merging or closing PRs on GitHub:
git checkout main
git pull origin main

# Delete local branches
git branch -d feature/user-lookup-api
git branch -d feature/add-utility-functions

# Delete remote branches (if not auto-deleted after merge)
git push origin --delete feature/user-lookup-api
git push origin --delete feature/add-utility-functions
```

---

## Reflection Questions

1. From the developer experience perspective, was the PR decoration workflow helpful? At what point in the workflow did you first see the security issues?

2. A developer says: "SonarCloud slows down our PRs because we have to wait for the check." How would you respond, and what alternatives might reduce the wait time while maintaining security?

3. What's the difference between SonarCloud posting an inline PR comment vs. a reviewer manually commenting on the same code? Which do you find more useful and why?

4. The PR analysis only evaluates NEW code. A developer copies existing vulnerable code from elsewhere in the codebase into a new file. Does SonarCloud catch this? Why or why not?

5. If you were setting up SonarCloud for a team of 10 developers, what configuration choices would you make to minimize friction while maintaining security enforcement?

---

## Summary: The Complete PR Workflow

You've now experienced the full DevSecOps PR workflow with SonarCloud:

```
1. Developer creates feature branch
2. Developer writes code (may have vulnerabilities)
3. Developer opens PR
4. GitHub Actions triggers pr-analysis.yml
5. Tests run, coverage generated
6. SonarCloud analyzes ONLY the PR diff (new code)
7. SonarCloud posts:
   a. Inline comments on affected lines
   b. Summary comment on PR
   c. GitHub Check (pass/fail)
8. If check fails:
   a. Developer sees inline comment on their changes
   b. Developer clicks "Details" → SonarCloud for full context
   c. Developer fixes issues, pushes to same branch
   d. Pipeline re-runs automatically
9. Once check passes:
   a. PR can be merged (if branch protection is configured)
   b. Security issues are resolved BEFORE they reach main
```

This is shift-left security in practice: security feedback at code review time, not at production deployment time.

---

## Next Steps

You've completed all four exercises! To continue mastering SonarCloud:

1. Apply SonarCloud to one of your own projects
2. Read [docs/07_advanced_config.md](../docs/07_advanced_config.md) for production-grade configuration
3. Explore SonarCloud's OWASP Top 10 security report for your project
4. Set up integration with additional tools (Bandit for Python, ESLint security plugins for JavaScript)
5. Investigate SonarCloud's dependency vulnerability scanning (separate from SAST)
