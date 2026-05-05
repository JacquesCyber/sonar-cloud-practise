# SonarCloud DevSecOps Mastery Template

A hands-on learning template for developers with security backgrounds who want to master SonarCloud as a SAST (Static Application Security Testing) tool in a DevSecOps pipeline.

---

## Prerequisites

You should already have:
- CompTIA Security+ (or equivalent security knowledge)
- Active development experience (Python, JavaScript, or similar)
- Basic Git and GitHub familiarity
- Understanding of CI/CD concepts
- A GitHub account (free tier works)
- A SonarCloud account (free for public repos at sonarcloud.io)

---

## What is SonarCloud?

SonarCloud is a cloud-based **Static Application Security Testing (SAST)** and **code quality** platform. It analyzes your source code without executing it, finding:

| Category | What It Finds | Security Relevance |
|---|---|---|
| **Vulnerabilities** | Exploitable security flaws | Direct OWASP/CWE issues — fix these first |
| **Security Hotspots** | Code requiring security review | Not necessarily bugs, but need human judgment |
| **Bugs** | Reliable issues that cause incorrect behavior | Indirect security impact via reliability |
| **Code Smells** | Maintainability issues | Technical debt — harder to audit insecure code |
| **Duplications** | Copy-paste code | Makes patching security issues harder |

### How SonarCloud Fits DevSecOps

```
Developer Commit
      |
      v
[GitHub Push / PR]
      |
      v
[GitHub Actions CI]
      |--- Build / Test
      |--- SonarCloud Analysis  <-- SAST happens here (shift-left)
      |--- Coverage Upload
      v
[SonarCloud Platform]
      |--- Quality Gate evaluation
      |--- Security Hotspot triage
      |--- PR Decoration (inline comments on PRs)
      v
[Gate: PASS or FAIL]
      |
      v--- PASS --> Merge allowed
      |
      v--- FAIL --> Developer notified, merge blocked
```

**Shift-left security** means catching vulnerabilities during development, before deployment — when they are cheapest to fix. SonarCloud is a core shift-left tool because it runs on every commit and PR, giving developers immediate feedback.

---

## Key Concepts

### Quality Gates
A **Quality Gate** is a set of conditions that your code must meet before it can be considered releasable. Think of it as a security and quality policy enforced automatically. The default "Sonar Way" gate includes:

- New code coverage >= 80%
- New duplicated lines <= 3%
- New maintainability rating = A
- New reliability rating = A
- **New security rating = A** (zero new vulnerabilities)
- **New security hotspots reviewed = 100%**

### Security Hotspots vs. Vulnerabilities
This distinction is critical and often misunderstood:

- **Vulnerability**: SonarCloud is confident this code is exploitable. Maps to a specific CWE. Must be fixed.
- **Security Hotspot**: Code that *could* be exploited depending on context. Requires a human security review to determine if it's actually a problem. You either "Acknowledge" (confirm it's a real issue → becomes a vulnerability) or "Mark as Safe" (confirm the context makes it safe).

### SAST vs. DAST vs. IAST
- **SAST** (SonarCloud): Analyzes source code statically. Fast, runs early in pipeline. Can produce false positives.
- **DAST**: Tests running applications (e.g., OWASP ZAP). Finds runtime issues. Slower.
- **IAST**: Instruments running code to detect issues during testing. Most accurate, most complex.

SonarCloud is SAST. It complements but does not replace DAST/IAST tools.

### Technical Debt
Measured in time (e.g., "3h 45min"). This is SonarCloud's estimate of how long it would take to fix all code smells. Relevant to security because:
- High technical debt = lower code readability = harder security audits
- Tangled, duplicated code = harder to patch consistently

### Rules and Rule IDs
Every issue SonarCloud raises has a **rule ID**. For example:
- `python:S2076` — OS command injection
- `python:S2077` — SQL injection
- `javascript:S5247` — XSS via dangerous HTML injection
- `python:S6437` — Hardcoded credentials

You can look up any rule at: `https://rules.sonarsource.com/`

---

## 4-Week Learning Roadmap

### Week 1: Foundation — Setup and First Scan
**Goal**: Get SonarCloud analyzing your first project and understand the dashboard.

| Day | Task | Resource |
|---|---|---|
| 1 | Create SonarCloud account, link GitHub | [Setup Guide](docs/01_setup_guide.md) |
| 2 | Fork/clone this repo, run first analysis | [Exercise 01](exercises/exercise_01_first_scan.md) |
| 3 | Navigate SonarCloud dashboard, understand each section | [Understanding Results](docs/02_understanding_results.md) |
| 4 | Study the vulnerable code examples, find them in SonarCloud | [Exercise 01](exercises/exercise_01_first_scan.md) |
| 5 | Review all Security Hotspots and Vulnerabilities found | [Security Hotspots Guide](docs/04_security_hotspots.md) |

**Week 1 Outcome**: You can run an analysis and navigate the SonarCloud UI confidently.

---

### Week 2: Deep Dive — Security Issues and Quality Gates
**Goal**: Understand how SonarCloud categorizes security issues and configure quality gates.

| Day | Task | Resource |
|---|---|---|
| 6 | Study the Quality Gate concept and default Sonar Way gate | [Quality Gates Guide](docs/03_quality_gates.md) |
| 7 | Fix the SQL injection vulnerability, re-run analysis | [Exercise 02](exercises/exercise_02_fix_vulnerabilities.md) |
| 8 | Fix XSS and hardcoded secrets, compare before/after metrics | [Exercise 02](exercises/exercise_02_fix_vulnerabilities.md) |
| 9 | Fix crypto and command injection issues | [Exercise 02](exercises/exercise_02_fix_vulnerabilities.md) |
| 10 | Create a custom Quality Gate, apply it to your project | [Exercise 03](exercises/exercise_03_custom_quality_gate.md) |

**Week 2 Outcome**: You can triage, fix, and verify security issues. You understand quality gates.

---

### Week 3: CI/CD Integration
**Goal**: Automate SonarCloud in a real CI/CD pipeline with PR decoration.

| Day | Task | Resource |
|---|---|---|
| 11 | Study the GitHub Actions workflows in `.github/workflows/` | [CI/CD Integration](docs/05_cicd_integration.md) |
| 12 | Set up SONAR_TOKEN secret in GitHub, enable the pipeline | [CI/CD Integration](docs/05_cicd_integration.md) |
| 13 | Configure PR decoration, open a test PR with vulnerable code | [PR Decoration Guide](docs/06_pr_decoration.md) |
| 14 | Observe inline PR comments from SonarCloud | [Exercise 04](exercises/exercise_04_pr_workflow.md) |
| 15 | Test Quality Gate blocking a failing PR | [Exercise 04](exercises/exercise_04_pr_workflow.md) |

**Week 3 Outcome**: Automated SAST on every push and PR with inline feedback.

---

### Week 4: Advanced Configuration and Mastery
**Goal**: Master sonar-project.properties, exclusions, and advanced features.

| Day | Task | Resource |
|---|---|---|
| 16 | Deep dive into sonar-project.properties options | [Advanced Config](docs/07_advanced_config.md) |
| 17 | Configure coverage reports (Python + JavaScript) | [Advanced Config](docs/07_advanced_config.md) |
| 18 | Set up file exclusions and test exclusions appropriately | [Advanced Config](docs/07_advanced_config.md) |
| 19 | Review SonarCloud's Security Report (OWASP Top 10 view) | [Understanding Results](docs/02_understanding_results.md) |
| 20 | Final review: build your own project's SonarCloud config | All docs |

**Week 4 Outcome**: You can configure SonarCloud for any project from scratch.

---

## Repository Structure

```
/
├── README.md                         # This file — learning path
├── sonar-project.properties          # SonarCloud project configuration
├── .github/
│   └── workflows/
│       ├── sonarcloud.yml            # Main branch analysis pipeline
│       └── pr-analysis.yml          # PR decoration pipeline
├── src/
│   ├── vulnerable/                   # Code with intentional security issues
│   │   ├── sql_injection.py          # SQL injection (python:S2077)
│   │   ├── xss_example.js            # XSS (javascript:S5247)
│   │   ├── hardcoded_secrets.py      # Hardcoded credentials (python:S6437)
│   │   ├── insecure_crypto.py        # Weak cryptography (python:S5547)
│   │   └── command_injection.py      # OS command injection (python:S2076)
│   └── fixed/                        # Corrected versions
│       ├── sql_safe.py
│       ├── xss_safe.js
│       ├── secrets_safe.py
│       ├── crypto_safe.py
│       └── command_safe.py
├── docs/
│   ├── 01_setup_guide.md
│   ├── 02_understanding_results.md
│   ├── 03_quality_gates.md
│   ├── 04_security_hotspots.md
│   ├── 05_cicd_integration.md
│   ├── 06_pr_decoration.md
│   └── 07_advanced_config.md
└── exercises/
    ├── exercise_01_first_scan.md
    ├── exercise_02_fix_vulnerabilities.md
    ├── exercise_03_custom_quality_gate.md
    └── exercise_04_pr_workflow.md
```

---

## Quick Start (5 minutes)

```bash
# 1. Fork this repository on GitHub

# 2. Go to sonarcloud.io and log in with GitHub

# 3. Click "+" > "Analyze new project" > select your fork

# 4. Add the SONAR_TOKEN secret to your GitHub repo:
#    Settings > Secrets and variables > Actions > New repository secret
#    Name: SONAR_TOKEN
#    Value: (token from SonarCloud > My Account > Security > Generate Token)

# 5. Update sonar-project.properties with your org/project key

# 6. Push a commit to trigger the pipeline

# 7. Watch the analysis run in GitHub Actions and results appear in SonarCloud
```

---

## SonarCloud Free Tier Limits

| Feature | Free (Public Repos) | Paid (Private Repos) |
|---|---|---|
| Repositories | Unlimited public | Paid plan required |
| Analysis | Unlimited | Lines of code based |
| PR Decoration | Yes | Yes |
| Security Reports | Yes | Yes |
| Quality Gates | Yes | Yes |
| Branch Analysis | Main + feature branches | Yes |

For learning purposes, **public repos are completely free and have full feature access**.

---

## Additional Resources

- [SonarCloud Documentation](https://docs.sonarsource.com/sonarcloud/)
- [SonarCloud Rule Explorer](https://rules.sonarsource.com/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SonarCloud Community Forum](https://community.sonarsource.com/)
- [GitHub Actions SonarCloud Action](https://github.com/SonarSource/sonarcloud-github-action)
