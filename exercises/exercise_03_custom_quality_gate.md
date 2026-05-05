# Exercise 03: Create and Enforce a Custom Quality Gate

## Objective

Design, create, and apply a custom Quality Gate that reflects a realistic security policy for a development team. You'll test the gate by deliberately introducing issues that should trigger it, verifying it blocks them, then fixing those issues.

**Estimated time**: 60-75 minutes

---

## Prerequisites

- [ ] Completed Exercise 01 and Exercise 02
- [ ] SonarCloud project with a mostly clean state (few or no open vulnerabilities)
- [ ] Admin access to your SonarCloud organization (you have this if you created the org)

---

## Part 1: Design Your Quality Gate (10 minutes)

Before clicking anything, design your gate on paper. Consider these questions:

**Security requirements:**
1. What's your tolerance for new vulnerabilities? (Zero? Only minor?)
2. Should ALL security hotspots be reviewed, or only new ones?
3. What's your minimum coverage requirement?

**Practical constraints:**
1. Is your team in an early stage? (More lenient coverage thresholds initially)
2. Are there regulatory requirements? (PCI DSS requires certain controls)
3. What would actually block legitimate work vs. what would block insecure code?

**Recommended starting point for this exercise:**
```
Goal: Security-focused gate that enforces zero new vulnerabilities
      while being practical for a team building new features.

Conditions:
  1. New Security Rating = A         (zero new vulnerabilities — non-negotiable)
  2. New Security Hotspots Reviewed = 100%   (all security-sensitive code reviewed)
  3. New Reliability Rating = A      (zero new bugs)
  4. New Coverage >= 60%             (lower than default to allow for new code)
  5. New Duplicated Lines (%) <= 5%  (slightly more lenient than default 3%)
  6. New Maintainability Rating = A  (no new technical debt issues)
```

---

## Part 2: Create the Custom Quality Gate in SonarCloud (15 minutes)

### Step 2.1: Navigate to Quality Gates

1. In SonarCloud, click your **organization name** in the top navigation
2. Look for **Quality Gates** in the left sidebar (it may be under a "Settings" or "Configuration" section)
3. Direct URL: `https://sonarcloud.io/organizations/YOUR-ORG-KEY/quality_gates`

**What you see:**
- "Sonar Way" — the default gate (cannot be edited directly)
- A "+ Create" button or "Copy" button

### Step 2.2: Create a New Gate

1. Either:
   - Click **Copy** next to "Sonar Way" (starts with Sonar Way's conditions), OR
   - Click **Create** (starts blank)
2. Name it: `DevSecOps Training Gate` (or your preferred name)
3. Click **Save** or **Copy**

### Step 2.3: Add Conditions

You're now on the gate configuration page. The gate has some default conditions (if you copied Sonar Way) or none (if you created from scratch).

**To add a new condition:**
1. Click **Add Condition**
2. Select: **On New Code** (for most conditions)
3. Choose the metric from the dropdown
4. Set the operator and value
5. Click **Add Condition**

**Add these conditions:**

**Condition 1: Security Rating**
- Scope: On New Code
- Metric: Security Rating
- Operator: is worse than
- Value: A
- (This means: fail if Security Rating drops below A, i.e., any new vulnerability)

**Condition 2: Security Hotspots Reviewed**
- Scope: On New Code
- Metric: Security Hotspots Reviewed
- Operator: is less than
- Value: 100%

**Condition 3: Reliability Rating**
- Scope: On New Code
- Metric: Reliability Rating
- Operator: is worse than
- Value: A

**Condition 4: Coverage**
- Scope: On New Code
- Metric: Coverage
- Operator: is less than
- Value: 60% (or your chosen threshold)

**Condition 5: Duplicated Lines**
- Scope: On New Code
- Metric: Duplicated Lines (%)
- Operator: is greater than
- Value: 5%

**Condition 6: Maintainability Rating**
- Scope: On New Code
- Metric: Maintainability Rating
- Operator: is worse than
- Value: A

**Optional: Add a strict blocker condition**
- Scope: On New Code
- Metric: Blocker Issues
- Operator: is greater than
- Value: 0
- (This explicitly blocks any BLOCKER-severity issue in new code)

### Step 2.4: Apply the Gate to Your Project

1. Go to: Your project > **Administration** > **Quality Gate**
2. In the "Quality Gate" section, click the dropdown
3. Select your newly created gate: "DevSecOps Training Gate"
4. Click **Save**

**Verify it's applied:**
The project dashboard should now show your gate's name in the Quality Gate section (or a small indicator).

---

## Part 3: Test the Gate — Introduce a Violation (15 minutes)

To verify the gate works, introduce a deliberate violation that should fail it, push it, and confirm SonarCloud blocks it.

### Step 3.1: Add a Hardcoded Secret (tests BLOCKER condition)

Create a new test file with a deliberate violation:

```bash
cat > src/test_gate_violation.py << 'EOF'
"""
Test file to verify the Quality Gate blocks vulnerabilities.
This file intentionally contains a vulnerability to test gate enforcement.
REMOVE this file after completing Exercise 03.
"""

# This hardcoded password should trigger python:S6437 (BLOCKER)
# and cause the Quality Gate to fail.
DATABASE_PASSWORD = "SuperSecretTestPassword123!"

def get_db_config():
    return {
        "host": "localhost",
        "password": DATABASE_PASSWORD  # Uses the hardcoded password
    }
EOF
```

### Step 3.2: Commit and Push the Violation

```bash
git add src/test_gate_violation.py
git commit -m "TEST: Adding gate violation to verify Quality Gate enforcement

This commit intentionally introduces a hardcoded credential to test
that our custom Quality Gate blocks vulnerable code.
This file will be removed in the next commit.

Expected: Quality Gate FAILS on python:S6437 (BLOCKER)"

git push origin main
```

### Step 3.3: Observe the Gate Failure

1. Go to GitHub Actions — watch the pipeline run
2. The "Check Quality Gate Status" step should fail
3. The pipeline overall should fail (red ✗)
4. In SonarCloud, the Quality Gate should show as FAILED
5. Click the failed status to see WHICH condition failed

**What you should see:**
```
Quality Gate failed.
Reason: New Security Rating is worse than A
        (current: E — 1 new blocker vulnerability)
```

### Step 3.4: Verify in SonarCloud

1. Go to SonarCloud > your project > Issues
2. Filter by Rule: `python:S6437`
3. You should see the issue in `src/test_gate_violation.py`
4. Note the severity: BLOCKER
5. Note that the Quality Gate failed specifically because of this

---

## Part 4: Verify the Gate Passes After Fix (10 minutes)

### Step 4.1: Remove the Violation

```bash
rm src/test_gate_violation.py
git add src/test_gate_violation.py
git commit -m "Remove gate violation test file

Verified that the Quality Gate correctly blocked the hardcoded credential.
Gate enforcement is working as expected.

Gate should now return to PASSED state."

git push origin main
```

### Step 4.2: Confirm Gate Recovery

1. Wait for the pipeline to complete
2. The Quality Gate should return to PASSED (assuming no other new issues)
3. In SonarCloud, the issue in `test_gate_violation.py` should be marked as resolved

---

## Part 5: Explore Gate Thresholds (15 minutes)

### Step 5.1: Test Coverage Threshold

Add a new Python file WITHOUT tests to see the coverage impact:

```bash
cat > src/new_feature.py << 'EOF'
"""
A new feature module with no test coverage.
Used to test the coverage condition of our Quality Gate.
"""

def calculate_discount(price: float, discount_percent: float) -> float:
    """Calculate discounted price."""
    if discount_percent < 0 or discount_percent > 100:
        raise ValueError("Discount must be between 0 and 100")
    return price * (1 - discount_percent / 100)

def apply_tax(price: float, tax_rate: float) -> float:
    """Apply tax to a price."""
    return price * (1 + tax_rate)

def format_currency(amount: float, currency: str = "USD") -> str:
    """Format a currency amount."""
    symbols = {"USD": "$", "EUR": "€", "GBP": "£"}
    symbol = symbols.get(currency, currency)
    return f"{symbol}{amount:.2f}"
EOF
```

Push and observe:
```bash
git add src/new_feature.py
git commit -m "Add new feature module (no tests yet)"
git push origin main
```

**What to observe:**
- Coverage for new code drops (no tests for this file)
- If the coverage drops below your 60% threshold, the gate should fail
- The coverage condition shows "X% < 60% required"

### Step 5.2: Add Tests to Recover Coverage

```bash
mkdir -p tests
cat > tests/test_new_feature.py << 'EOF'
"""Tests for the new_feature module."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.new_feature import calculate_discount, apply_tax, format_currency
import pytest

def test_calculate_discount():
    assert calculate_discount(100.0, 10.0) == 90.0
    assert calculate_discount(100.0, 0.0) == 100.0
    assert calculate_discount(100.0, 100.0) == 0.0

def test_calculate_discount_invalid():
    with pytest.raises(ValueError):
        calculate_discount(100.0, -1.0)
    with pytest.raises(ValueError):
        calculate_discount(100.0, 101.0)

def test_apply_tax():
    assert apply_tax(100.0, 0.1) == pytest.approx(110.0)
    assert apply_tax(50.0, 0.0) == 50.0

def test_format_currency():
    assert format_currency(9.99) == "$9.99"
    assert format_currency(9.99, "EUR") == "€9.99"
    assert format_currency(9.99, "GBP") == "£9.99"
    assert format_currency(9.99, "JPY") == "JPY9.99"
EOF
```

```bash
git add tests/test_new_feature.py
git commit -m "Add tests for new_feature module

Coverage should now meet the 60% threshold.
Tests cover: calculate_discount, apply_tax, format_currency
Including edge cases and error handling."

git push origin main
```

---

## Part 6: Compare Gates (5 minutes)

### Step 6.1: Temporarily Switch to Sonar Way Gate

To see the difference:
1. Go to: Project > Administration > Quality Gate
2. Change to: "Sonar Way"
3. Go to the dashboard — is the gate status different?
4. Change back to "DevSecOps Training Gate"

### Step 6.2: Note the Differences

What's different between Sonar Way and your custom gate?
- Coverage threshold (80% vs 60%)
- Duplication threshold (3% vs 5%)
- Any additional conditions you added

---

## Reflection Questions

1. What's the tradeoff between a strict gate (fails often) and a lenient gate (rarely fails)?

2. If your team's coverage is currently 40% on overall code, should you set the new code coverage requirement to 40% (match current), 60% (aspirational), or 80% (Sonar Way default)? What are the implications of each choice?

3. The default Sonar Way gate requires 80% coverage. Is 80% coverage sufficient to prevent security vulnerabilities from going undetected? What else would you need?

4. Should quality gates be different for different branches (feature branches vs. release branches)? How would you configure that?

5. A developer says "The Quality Gate is too strict — it's blocking legitimate work." What's the correct response? When (if ever) is it appropriate to lower gate thresholds?

---

## Cleanup

If you want to return to a clean state:
```bash
# Remove the test files created in this exercise
rm -f src/test_gate_violation.py
# Keep src/new_feature.py and tests/test_new_feature.py — they're useful examples

git add -A
git commit -m "Exercise 03 cleanup: remove gate violation test files"
git push origin main
```

---

## Next Steps

- [Exercise 04: PR Workflow](exercise_04_pr_workflow.md) — See PR decoration and gate enforcement in action on pull requests
- [docs/03_quality_gates.md](../docs/03_quality_gates.md) — Additional Quality Gate documentation
- Read about [gate enforcement via branch protection](../docs/06_pr_decoration.md#requiring-the-check-before-merging)
