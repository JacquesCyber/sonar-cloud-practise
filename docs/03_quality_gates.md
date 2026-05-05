# Quality Gates Deep Dive

A Quality Gate is the enforcement mechanism that turns SonarCloud from a reporting tool into a policy-enforcement tool. Understanding and configuring Quality Gates correctly is what makes SonarCloud effective in a DevSecOps pipeline.

---

## What is a Quality Gate?

A Quality Gate is a set of conditions that code must meet before it can be considered "releasable." Think of it as:
- A security policy written in measurable metrics
- A contract between the development team and the security/quality standards
- The automated equivalent of a security sign-off on every change

**Key principle**: Quality Gates evaluate **NEW code only** (by default). This makes them immediately actionable — you're responsible for new issues you introduce, not every historical issue in the codebase.

When a pipeline runs SonarCloud and the Quality Gate fails, the GitHub Check turns red. With proper configuration, this prevents merging until the issues are addressed.

---

## The Default "Sonar Way" Gate

SonarCloud provides a built-in "Sonar Way" Quality Gate that represents Sonar's recommended standards. You cannot modify it directly — but you can copy it and customize the copy.

### Sonar Way Conditions (as of 2024)

| Metric | Condition | Threshold | Why It Matters |
|---|---|---|---|
| New Code Coverage | is less than | 80% | New code without tests is untestable for future changes |
| New Duplicated Lines | is greater than | 3% | Duplication means security patches must be applied in multiple places |
| New Maintainability Rating | is worse than | A | Low maintainability = harder to audit and patch |
| New Reliability Rating | is worse than | A | New bugs reduce system stability |
| New Security Rating | is worse than | A | Zero tolerance for new vulnerabilities |
| New Security Hotspots Reviewed | is less than | 100% | All security-sensitive code must be reviewed by a human |

### Why These Thresholds?

**80% coverage**: Studies show that below 80% coverage, significant portions of new code never execute in tests. The remaining 20% leeway accounts for legitimate uncoverable code (platform-specific code, error handlers).

**100% hotspots reviewed**: Unlike vulnerabilities (which SonarCloud is confident about), hotspots are code that *might* be an issue. Every hotspot needs a human decision: is this a real problem or is the context safe? Allowing unreviewed hotspots means security-sensitive code slipped through without review.

**Rating A for security and reliability**: Zero tolerance for new confirmed issues on new code. Legacy issues are a separate remediation effort.

---

## Creating a Custom Quality Gate

### When to Create a Custom Gate

- Your team has different standards than the Sonar Way defaults
- You're adding SonarCloud to a legacy codebase and need a more lenient gate initially
- You have regulatory requirements that need specific thresholds
- You want different gates for different types of projects (libraries vs. user-facing apps)

### Step-by-Step: Create a Custom Gate

1. **Navigate to the Quality Gates page:**
   - Click your organization name in the top navigation
   - Click **Quality Gates** in the left sidebar (under "Settings")
   - Or go directly: `https://sonarcloud.io/organizations/YOUR_ORG/quality_gates`

2. **Create the gate:**
   - Click **Copy** next to "Sonar Way" to start from the recommended defaults
   - OR click **Create** to start from scratch
   - Enter a name: e.g., "Security-Focused Gate" or "Team Standard Gate"
   - Click **Save**

3. **Add or modify conditions:**
   Click **Add Condition** on the new gate page. Available metrics include:

   **For new code conditions:**
   - `New code coverage` — recommended: >= 80%
   - `New duplicated lines (%)` — recommended: <= 3%
   - `New security rating` — recommended: = A (no new vulnerabilities)
   - `New reliability rating` — recommended: = A (no new bugs)
   - `New maintainability rating` — recommended: = A
   - `New security hotspots reviewed` — recommended: = 100%
   - `New lines to cover` — useful for enforcing minimum test targets
   - `New blocker issues` — explicit count-based check: = 0
   - `New critical issues` — = 0 if you want to be strict

   **For overall code conditions (use sparingly):**
   - `Security rating` — sets minimum for the whole codebase
   - `Technical debt ratio` — keeps overall debt from growing unbounded
   - `Blocker issues` — hard limit on total blocker issues

4. **Set the condition value:**
   Each condition has:
   - **Metric**: What to measure
   - **Operator**: is less than / is greater than / is not / is
   - **Value**: The threshold (number or rating)

5. **Apply the gate to your project:**
   - Go to your project in SonarCloud
   - Click **Administration** > **Quality Gate**
   - Select your custom gate from the dropdown
   - Click **Save**

---

## Designing a Security-Focused Quality Gate

For a security-aware team, consider these additional conditions:

### Recommended Security-Focused Gate

```
# Block on any new vulnerability
New Security Rating = A

# Block until all security-sensitive code is reviewed
New Security Hotspots Reviewed = 100%

# Block on zero tolerance for certain issue types
New Blocker Issues = 0
New Critical Issues = 0

# Coverage requirements
New Coverage >= 75%    # Slightly lower than 80% to reduce false blocks on small changes

# Code quality
New Duplicated Lines (%) <= 3%
New Maintainability Rating = A
```

### Rationale for Zero Tolerance on Blocker/Critical

Blocker issues from SonarCloud's security rules include:
- Hardcoded credentials (python:S6437, S2068)
- Command injection (python:S2076)
- SQL injection (python:S2077)
- Missing SSL verification (python:S4830)

These are BLOCKER severity by default. Setting "New Blocker Issues = 0" specifically blocks these without needing separate conditions for each rule.

---

## Quality Gate Evaluation Logic

### The "New Code" Period

The Quality Gate evaluates ONLY code changed within the "new code" period. Understanding this is critical:

**Example scenario:**
- Your project has 50 existing SQL injection issues (legacy code)
- A developer adds 1 new SQL injection issue
- Quality Gate evaluates: Does the NEW code have a Security Rating of A?
- Answer: No (there's 1 new vulnerability) → FAIL

The developer sees a failing gate for 1 new issue, not 50 old ones. This is intentional — it makes the gate actionable.

**On the first analysis**, all code is considered "new." This means a legacy project running SonarCloud for the first time will likely have a failing gate. This is expected — see "Handling Legacy Code" below.

### Pass/Fail Status

SonarCloud reports the Quality Gate status:
- **PASSED** (shown as "OK" in the API): All conditions met
- **FAILED** (shown as "ERROR" in the API): One or more conditions not met
- **WARNING**: Deprecated, no longer used
- **NONE**: No Quality Gate assigned to this project

### How the CI Pipeline Fails

The sonarcloud-github-action creates a GitHub Check named "SonarCloud Code Analysis." This check:
- Appears in the PR Checks tab
- Shows PASSED (green checkmark) or FAILED (red X)
- Can be required to pass before merging (via GitHub branch protection rules)

To make the workflow actually exit with a non-zero code (failing the whole pipeline):
- Add `-Dsonar.qualitygate.wait=true` to the scanner arguments
- OR use the Quality Gate API check step in the workflow (as shown in `sonarcloud.yml`)

---

## Enforcing Quality Gates via Branch Protection

Quality Gates are only enforced if the CI check is required. To enforce:

1. Go to your GitHub repository
2. Click **Settings** > **Branches**
3. Click **Add rule** for your main branch (or click **Edit** if a rule exists)
4. Enable **"Require status checks to pass before merging"**
5. In the search box, type "SonarCloud" and select **"SonarCloud Code Analysis"**
6. Also enable **"Require branches to be up to date before merging"**
7. Click **Save changes**

**Result**: Developers cannot merge a PR if the SonarCloud Quality Gate fails. This is how you enforce the security policy at the git level.

---

## Handling Legacy Code

If you're adding SonarCloud to an existing codebase, you'll likely face a failing gate due to existing issues. Strategies:

### Strategy 1: "Clean As You Go"
- Set the new code period to a date in the past
- Old issues show in "Overall Code" but don't affect the Quality Gate
- New issues introduced after the date DO affect the gate
- Team fixes old issues incrementally as they work in those files

### Strategy 2: Set a Lenient Initial Gate
Create a custom gate that only blocks on the most critical issues:
```
New Security Rating = A              # Never allow new vulnerabilities
New Blocker Issues = 0               # Never allow new blockers
New Coverage >= 50%                  # Lower bar while adding tests to legacy code
```
Gradually tighten the thresholds over time.

### Strategy 3: Acknowledge Existing Issues
- Review all existing issues in SonarCloud
- Mark legitimate existing issues as "False Positive" or "Won't Fix" with justification
- Issues marked Won't Fix are excluded from metric counts
- This is honest and creates an audit trail

**Warning**: Don't mark real issues as False Positive to make the gate pass. This defeats the purpose of the tool and can mask real vulnerabilities.

---

## Quality Gate Metrics Reference

### Coverage Metrics

| Metric | Description |
|---|---|
| `new_coverage` | Line + branch coverage combined for new code |
| `new_line_coverage` | % of new executable lines covered |
| `new_branch_coverage` | % of new conditional branches covered |
| `new_lines_to_cover` | Number of new lines that need tests |

### Security Metrics

| Metric | Description |
|---|---|
| `new_security_rating` | Rating based on new vulnerability count and severity |
| `new_vulnerabilities` | Count of new confirmed vulnerabilities |
| `new_security_hotspots_reviewed` | % of new hotspots with a review decision |
| `new_security_review_rating` | Rating based on hotspot review completeness |

### Reliability Metrics

| Metric | Description |
|---|---|
| `new_reliability_rating` | Rating based on new bug count and severity |
| `new_bugs` | Count of new bugs |

### Maintainability Metrics

| Metric | Description |
|---|---|
| `new_maintainability_rating` | Rating based on technical debt ratio on new code |
| `new_technical_debt` | New technical debt in minutes |
| `new_code_smells` | Count of new code smells |
| `new_duplicated_lines_density` | % duplicated lines in new code |

---

## Testing Your Quality Gate

Use the vulnerable code in this template to verify your gate works:

1. Make sure the `src/vulnerable/` directory is included in `sonar.sources`
2. Push to your main branch
3. Check that the Quality Gate FAILS (the vulnerabilities in vulnerable/ should trigger it)
4. This confirms your gate is actually enforcing policy, not just showing metrics

A gate that never fails is a gate that isn't being tested. You want to know it works BEFORE you need it to catch a real issue.
