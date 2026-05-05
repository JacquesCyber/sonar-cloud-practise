# Exercise 01: Your First SonarCloud Scan

## Objective

Run a complete SonarCloud analysis on this repository and navigate the results. By the end of this exercise, you'll have:
- A working SonarCloud project linked to your GitHub repository
- A completed first analysis
- The ability to navigate SonarCloud's main views
- An understanding of what issues SonarCloud detected in the vulnerable examples

**Estimated time**: 45-60 minutes

---

## Prerequisites

- [ ] GitHub account
- [ ] SonarCloud account (free at sonarcloud.io — sign in with GitHub)
- [ ] This repository forked to your GitHub account
- [ ] `git` and a text editor installed locally

---

## Part 1: Environment Setup (15 minutes)

### Step 1.1: Fork and Clone the Repository

1. Go to this repository on GitHub
2. Click **Fork** (top right) → Fork to your personal account
3. Clone your fork:

```bash
git clone https://github.com/YOUR-USERNAME/SonarCloudDevesecopsTemplate.git
cd SonarCloudDevesecopsTemplate
```

### Step 1.2: Set Up SonarCloud Project

Follow the complete instructions in [docs/01_setup_guide.md](../docs/01_setup_guide.md), Steps 1-5.

At minimum, complete:
1. Create SonarCloud account (sign in with GitHub)
2. Create/join your organization
3. Add a new project — select your forked repository
4. Generate the SONAR_TOKEN
5. Add SONAR_TOKEN to your GitHub repository secrets

### Step 1.3: Update sonar-project.properties

Edit `sonar-project.properties` in your cloned repository:

```bash
# Open in your editor
code sonar-project.properties  # VS Code
# OR
nano sonar-project.properties
```

Update these two lines with your actual values:
```properties
sonar.projectKey=YOUR-ORG-KEY_SonarCloudDevesecopsTemplate
sonar.organization=YOUR-ORG-KEY
```

**How to find your values:**
- `sonar.organization`: In SonarCloud, click your org name → Administration → look for "Organization Key"
- `sonar.projectKey`: In SonarCloud, navigate to your project → Administration → "Update Key" — the current key is shown

Commit and push the change:
```bash
git add sonar-project.properties
git commit -m "Configure SonarCloud project settings"
git push origin main
```

---

## Part 2: Trigger the Analysis (10 minutes)

### Step 2.1: Watch the GitHub Actions Pipeline

1. Go to your forked repository on GitHub
2. Click the **Actions** tab
3. You should see the "SonarCloud Analysis" workflow running (triggered by your push)
4. Click on the running workflow to see live output

**Checkpoint**: You should see a workflow run in progress. If no workflow appears, check that the workflows are in `.github/workflows/` and that GitHub Actions is enabled for your fork.

### Step 2.2: Monitor the Pipeline Steps

Watch each step in the workflow:
- "Checkout repository" — should be fast
- "Set up Python" — installs Python
- "Install Python dependencies" — installs pytest, coverage
- "Run Python tests with coverage" — runs tests (may produce no output since there are no test files yet)
- **"SonarCloud Scan"** — the key step. Look for output like:
  ```
  INFO: Scanner configuration file: /opt/sonar-scanner/.../conf/sonar-scanner.properties
  INFO: Project root configuration file: .../sonar-project.properties
  INFO: Analyzing on SonarCloud
  INFO: ANALYSIS SUCCESSFUL
  ```
- "Check Quality Gate Status" — polls for the gate result

**Expected outcome**: The pipeline may FAIL on the Quality Gate check — this is expected. The vulnerable code in `src/vulnerable/` should trigger multiple vulnerabilities.

### Step 2.3: Access the Analysis Results

After the scan completes:
1. In the GitHub Actions log, find the line:
   ```
   INFO: ANALYSIS SUCCESSFUL, you can find the results at: https://sonarcloud.io/dashboard?id=...
   ```
2. Click that URL, or go to sonarcloud.io and find your project
3. Wait 1-2 minutes for processing to complete (the SonarCloud page shows a loading indicator)

---

## Part 3: Navigate the SonarCloud Dashboard (20 minutes)

### Step 3.1: Read the Project Dashboard

Look at the main dashboard and answer these questions (write your answers somewhere — you'll reference them later):

1. What is the Quality Gate status? (PASSED or FAILED)
2. How many Vulnerabilities were found on new code?
3. How many Security Hotspots need review?
4. What is the Security Rating? (A, B, C, D, or E)
5. What is the code coverage percentage?

**Expected results for this template's vulnerable code:**
- Quality Gate: FAILED
- Vulnerabilities: 6+ (SQL injection, command injection, hardcoded secrets, weak crypto)
- Security Hotspots: Several (random number generators, certificate verification, hashing)
- Security Rating: D or E (there should be CRITICAL and BLOCKER vulnerabilities)

If you see 0 vulnerabilities and a passing gate, check that `sonar.sources` in `sonar-project.properties` includes the `src/vulnerable` directory.

### Step 3.2: Explore the Issues Tab

1. Click **Issues** in the top navigation
2. You'll see a list of all detected issues

**Task A: Find the SQL Injection vulnerability**
- In the left filter panel, set: **Rule** = `python:S2077`
- You should see multiple issues in `sql_injection.py`
- Click one to open the detail view
- Navigate to the "Why is this an issue?" tab — read the explanation
- Click "Show flows" if available — trace the taint flow from source to sink

**Task B: Find the Hardcoded Secrets**
- Clear previous filter
- Set: **Rule** = `python:S6437` (or search for "S6437")
- You should see issues in `hardcoded_secrets.py`
- Click one — notice the severity is BLOCKER
- Look at the exact line flagged — can you see why SonarCloud is confident this is a secret?

**Task C: Browse by Severity**
- Clear all filters
- Set: **Severity** = BLOCKER
- List all BLOCKER issues — these are the most critical

**Record your findings:**
| Rule | File | Line | Vulnerability Type |
|---|---|---|---|
| python:S2077 | sql_injection.py | ? | SQL Injection |
| python:S6437 | hardcoded_secrets.py | ? | Hardcoded Credential |
| python:S2076 | command_injection.py | ? | Command Injection |

### Step 3.3: Navigate to Security Hotspots

1. Click **Security Hotspots** in the top navigation
2. You'll see hotspots organized by OWASP category
3. Look for "Weak Cryptography" — you should see hotspots from `insecure_crypto.py`
4. Click one to open the review panel
5. Read the "Assess the risk" guidance

**Task**: For each hotspot you find, determine:
- What code pattern triggered it?
- Is it a true positive (real security concern) or false positive?
- What would you do: Mark as Safe or Acknowledge?

### Step 3.4: Explore the Measures Tab

1. Click **Measures** in the top navigation
2. Click on **Security** in the left metrics list
3. Look at:
   - Vulnerabilities count
   - Security Rating
   - Security Hotspots

4. Click on **Coverage** in the left metrics list
5. Note the coverage percentage — it will be low because we haven't written tests yet

### Step 3.5: Browse Code with Annotations

1. Click **Code** in the top navigation
2. Navigate to: `src` > `vulnerable` > `sql_injection.py`
3. SonarCloud shows the file with inline annotations
4. Lines with issues have colored markers in the left gutter
5. Click a marked line to see the issue inline

---

## Part 4: Understanding the Quality Gate Failure (10 minutes)

### Step 4.1: Analyze Why the Gate Failed

Go back to the project dashboard and click on the Quality Gate status badge (FAILED).

This shows you which conditions failed and by how much:

**Likely failed conditions:**
- New Security Rating: E (expected A) — because of vulnerabilities
- New Security Hotspots Reviewed: 0% (expected 100%) — none reviewed yet

### Step 4.2: Understand New Code vs. Overall Code

On the dashboard, notice two columns: "On New Code" and "Overall Code".

Since this is a first analysis, ALL code is "new." In subsequent analyses with the same base, only changed code will be "new."

### Step 4.3: Map Issues to OWASP Categories

In SonarCloud, look at the Security section of the Issues tab or navigate to the Security Reports.

Map each vulnerability you found to an OWASP Top 10 category:
- SQL Injection → A03:2021 Injection
- Hardcoded Secrets → A02:2021 Cryptographic Failures / A07:2021 Auth Failures
- Command Injection → A03:2021 Injection
- Weak Cryptography → A02:2021 Cryptographic Failures

---

## Expected Outcomes

By the end of this exercise, you should be able to:
- [ ] Describe the overall security posture of this project based on SonarCloud results
- [ ] Find a specific issue by rule ID (e.g., find all python:S2077 issues)
- [ ] Read the taint flow for an injection vulnerability
- [ ] Explain the difference between Vulnerabilities and Security Hotspots as shown in SonarCloud
- [ ] Identify which OWASP categories are affected

---

## Troubleshooting

**Pipeline fails with "Not authorized":**
- Regenerate the SONAR_TOKEN in SonarCloud (My Account > Security > Generate Token)
- Delete and re-add the SONAR_TOKEN secret in GitHub (Settings > Secrets > Actions)

**"No issues found" in SonarCloud despite having vulnerable code:**
- Verify `sonar.sources=src/vulnerable,src/fixed` in `sonar-project.properties`
- Check that the files were committed and pushed (run `git status`)
- Look at the scanner output in the Actions log for any warnings about excluded files

**Workflow doesn't appear in Actions tab:**
- GitHub may have disabled Actions for the fork. Go to: Settings > Actions > General > Allow all actions

**Pipeline completes but SonarCloud shows "Last analysis pending":**
- SonarCloud is still processing. Wait 2-3 minutes and refresh.
- If still pending after 5 minutes, check the workflow log for the task URL and open it directly

---

## Next Steps

Once you've completed this exercise:
- Review the fixed versions of each vulnerable file in `src/fixed/`
- Proceed to [Exercise 02: Fix Vulnerabilities](exercise_02_fix_vulnerabilities.md)
- Read [docs/04_security_hotspots.md](../docs/04_security_hotspots.md) for guidance on reviewing the hotspots you found
