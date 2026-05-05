# Understanding SonarCloud Results

This guide explains how to navigate and interpret SonarCloud's analysis results, focusing on what matters most for a security-aware developer.

---

## The SonarCloud Dashboard

When you open a project in SonarCloud, the main dashboard is the first thing you see. Understanding its layout is essential for efficient triage.

### Dashboard Layout

**Top section — Quality Gate status:**
- A large green circle with a checkmark (PASSED) or red circle with an X (FAILED)
- This single indicator tells you whether your project meets your defined quality/security policy
- If it's red, check what conditions failed (hover or click for details)

**Metric summary cards — "On New Code" (primary):**
These metrics only reflect code added or modified since your defined "new code" period:
- Bugs (reliability issues)
- Vulnerabilities (confirmed security flaws)
- Security Hotspots (code requiring security review)
- Code Smells (maintainability issues)
- Coverage percentage
- Duplication percentage

**Metric summary cards — "Overall Code" (secondary):**
Same metrics but for the entire codebase. This is useful for understanding the full state of the project, but Quality Gates primarily evaluate new code.

**Navigation tabs:**
- **Issues**: All bugs, vulnerabilities, and code smells
- **Security Hotspots**: Security-sensitive code requiring review
- **Measures**: Detailed metric breakdowns
- **Code**: File browser with inline metric annotations
- **Activity**: Historical trends and analysis history
- **Administration**: Project settings (visible to maintainers)

---

## Understanding the Issues Tab

The Issues tab shows all detected problems. Learning to filter and triage efficiently is a core skill.

### Issue Categories

| Category | Icon | SonarCloud Meaning | Priority |
|---|---|---|---|
| Bug | Bug | Reliable issue causing incorrect behavior | High |
| Vulnerability | Lock | Confirmed security flaw, exploitable | Critical |
| Security Hotspot | Flame | Security-sensitive, needs human review | Review-based |
| Code Smell | Wrench | Maintainability issue, technical debt | Lower |

### Issue Severities

Each issue has a severity level:
- **BLOCKER**: Must fix immediately — likely to impact production (e.g., hardcoded password)
- **CRITICAL**: High probability of bug or security vulnerability in production
- **MAJOR**: Could cause significant problems in a specific situation
- **MINOR**: Small quality issue, low impact
- **INFO**: Informational, no impact on quality

### Filtering Issues Effectively

Use the filter panel on the left side of the Issues tab:

**For security work, filter by:**
```
Type: Vulnerability
Severity: BLOCKER, CRITICAL
Status: Open
```
This shows you the highest-priority issues requiring immediate attention.

**For security hotspot review:**
Navigate to the Security Hotspots tab instead — hotspots have their own workflow (see docs/04_security_hotspots.md).

**Other useful filters:**
- **Author**: Find issues in YOUR commits
- **Resolution**: Open / Fixed / False Positive / Won't Fix
- **Language**: Python, JavaScript, etc.
- **Rule**: Search by specific rule ID (e.g., `python:S2077`)
- **Component**: Filter by file or directory

### Reading an Individual Issue

Click any issue to open the detailed view:

1. **Issue title and rule ID**: e.g., "Make sure using a dynamically formatted SQL query is safe here. [python:S2077]"
2. **Code view**: The affected file with the problematic lines highlighted in red. Arrows show the data flow path (for taint-tracking rules).
3. **"Why is this an issue?" tab**: Explains the vulnerability, provides context, and links to OWASP/CWE
4. **"How to fix it?" tab**: Code examples showing the vulnerable pattern and the corrected pattern
5. **Flow visualization**: For taint tracking rules, SonarCloud shows the path from where user input enters ("source") to where it's used unsafely ("sink")

### The Data Flow View (Taint Analysis)

For injection vulnerabilities (SQL, XSS, command injection), SonarCloud shows a "Show flows" link. Click it to see:
- **Source**: Where user-controlled data enters (function parameter, HTTP request)
- **Path**: Each intermediate step where the data flows through your code
- **Sink**: The dangerous function where the tainted data is used

Example flow for SQL injection:
```
Line 45: user_input = request.args.get('id')     ← Source (user input)
Line 47: query_part = f"WHERE id={user_input}"   ← Flow step (string building)
Line 49: cursor.execute(query_part)               ← Sink (SQL execution)
```

This flow view is powerful for understanding complex multi-file injection chains.

---

## Understanding the Measures Tab

The Measures tab provides deep metric breakdowns, useful for understanding technical debt and planning remediation.

### Key Metric Groups

**Reliability:**
- Bugs count
- Reliability Rating: A (0 bugs) through E (at least 1 blocker)
- Shows bug density (bugs per 1000 lines)

**Security:**
- Vulnerabilities count
- Security Rating: A through E (same scale as Reliability)
- Open Security Hotspots count

**Maintainability:**
- Technical Debt: Time to fix all code smells
- Maintainability Rating: Debt ratio (debt/development time)
- Code smells count and density

**Coverage:**
- Line coverage: % of executable lines hit by tests
- Branch coverage: % of conditional branches exercised
- Uncovered lines and uncovered conditions counts

**Duplications:**
- Duplicated lines (%)
- Duplicated blocks count
- Duplicated files count

### Coverage Visualization

In the Code tab, files show line-by-line coverage:
- **Green lines**: Covered by tests
- **Red lines**: Not covered
- **Yellow/partial**: Branch partially covered
- **Gray**: Not executable (comments, blank lines, declarations)

**Important**: 80% coverage doesn't mean 80% of your security-critical paths are tested. Coverage alone is not a security metric — it measures test breadth, not test quality.

---

## Understanding the Security Reports

SonarCloud provides structured security reports mapped to industry standards.

### Accessing Security Reports

In your project: Go to **Issues** tab > **Security Reports** (below the left filter panel)
Or navigate directly via the URL: `https://sonarcloud.io/project/security_hotspots?id=YOUR_PROJECT_KEY`

### OWASP Top 10 View

SonarCloud maps all security issues to OWASP Top 10 categories:

| OWASP Category | Common SonarCloud Rules |
|---|---|
| A01:2021 Broken Access Control | S5122, S5527, S4502 |
| A02:2021 Cryptographic Failures | S5547, S4790, S4426, S5344 |
| A03:2021 Injection | S2077, S2076, S5247, S6299 |
| A04:2021 Insecure Design | Various |
| A05:2021 Security Misconfiguration | S5122, S4823, S4830 |
| A06:2021 Vulnerable Components | Dependency scanning |
| A07:2021 Auth Failures | S6437, S2068, S5344 |
| A08:2021 Software Integrity | Various |
| A09:2021 Security Logging | S4792, S6096 |
| A10:2021 Server-Side Request Forgery | S5144 |

**Using the OWASP view:**
- Click on any OWASP category to filter issues within it
- Use this for OWASP Top 10 compliance reporting
- The percentage next to each category shows what fraction of issues are in that category

### CWE Top 25 View

Similar to OWASP but mapped to CWE (Common Weakness Enumeration). Useful for:
- NIST/government compliance reporting
- Technical communication with security teams
- Cross-referencing with vulnerability databases

---

## Understanding Ratings and What They Mean

SonarCloud uses letter ratings (A-E) for security, reliability, and maintainability:

### Security Rating

| Rating | Criteria |
|---|---|
| A | 0 vulnerabilities |
| B | At least 1 MINOR vulnerability |
| C | At least 1 MAJOR vulnerability |
| D | At least 1 CRITICAL vulnerability |
| E | At least 1 BLOCKER vulnerability |

**Key insight**: A project with 1,000 minor vulnerabilities still gets a B. A project with 1 blocker vulnerability gets an E. This is intentional — the scale reflects what an attacker would target.

### The "New Code" vs. "Overall Code" Distinction

This is one of the most important concepts for day-to-day development:

**Overall Code metrics**: Reflect the entire codebase, including historical issues.
**New Code metrics**: Reflect only code changed since the "new code" period start.

**The Quality Gate evaluates NEW CODE only** (by default). This means:
- You're not penalized for legacy issues that existed before you started using SonarCloud
- You ARE accountable for new issues you introduce
- The workflow is: fix new issues as you create them, gradually remediate old issues

**Setting the new code period:**
1. Go to: Project > Administration > New Code
2. Options:
   - **Previous version**: Issues introduced since the last version tag
   - **Number of days**: Issues from the last N days (e.g., 30 days)
   - **Specific date**: Issues from after a specific date
   - **Reference branch**: Issues not present in the reference branch (best for PRs)

---

## Activity and Trends

The **Activity** tab shows historical analysis data:
- Quality Gate pass/fail over time
- Metric trends (rising technical debt? declining coverage?)
- Version markers (when you tagged releases)
- Analysis events (rule updates, baseline changes)

**Using trends:**
- A rising "Bugs" line indicates the team is introducing bugs faster than fixing them
- A declining "Coverage" line indicates tests aren't keeping pace with new code
- Quality Gate failures clustered around specific dates may correlate with rushed releases

---

## Common Misconceptions About SonarCloud Results

**Misconception 1: "All vulnerabilities are real exploits"**
Not all SonarCloud vulnerabilities are immediately exploitable. Some require specific conditions. However, treat all vulnerabilities seriously — the context that makes them unexploitable today may change.

**Misconception 2: "No Security Hotspots means the code is secure"**
Hotspots that were reviewed and marked "Safe" are removed from the count. A project with 0 hotspots either has no security-sensitive code or all hotspots were reviewed. Don't skip reviews to reduce the count.

**Misconception 3: "100% coverage means no security issues"**
Coverage measures whether lines are EXECUTED during tests, not whether tests CHECK for security issues. A function with 100% coverage can still have SQL injection if the tests don't use malicious inputs.

**Misconception 4: "A rating means the project is secure"**
Security Rating A means 0 confirmed vulnerabilities that SonarCloud detected via its rules. It doesn't cover: logic errors, business logic flaws, authorization bugs, or vulnerabilities that SonarCloud's rules don't cover (e.g., application-specific issues).

**Misconception 5: "SonarCloud is the only security tool I need"**
SonarCloud is a SAST tool. You also need: DAST (runtime testing), dependency scanning (SCA), secrets scanning, infrastructure scanning, and code reviews by human security engineers. Defense in depth applies to security tooling too.
