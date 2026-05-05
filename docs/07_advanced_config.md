# Advanced sonar-project.properties Configuration

This guide covers advanced configuration options for tuning SonarCloud to your project's specific needs, optimizing analysis performance, and handling complex project structures.

---

## Configuration Precedence

SonarCloud properties can be set in multiple places, with this precedence order (highest to lowest):

1. **Scanner command-line arguments**: `-Dsonar.projectKey=...` in the workflow `args`
2. **Environment variables**: `SONAR_PROJECT_KEY=...`
3. **`sonar-project.properties`** (the file in your repo root)
4. **Project administration settings** in the SonarCloud UI

For most settings, `sonar-project.properties` is the right place. Command-line arguments are useful for dynamic values (like version tags derived from the git tag).

---

## Dynamic Properties in GitHub Actions

Some properties are best set dynamically in your CI workflow:

```yaml
- uses: SonarSource/sonarcloud-github-action@master
  with:
    args: >
      -Dsonar.projectVersion=${{ github.ref_name }}
      -Dsonar.links.ci=https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}
      -Dsonar.links.issue=https://github.com/${{ github.repository }}/issues
      -Dsonar.links.scm=https://github.com/${{ github.repository }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

This sets the project version to the branch/tag name and adds useful links to the SonarCloud project dashboard.

---

## Source Configuration Deep Dive

### Understanding sonar.sources

```properties
# Single directory
sonar.sources=src

# Multiple directories (comma-separated)
sonar.sources=src/main,lib,api

# Project root (analyze everything not excluded)
sonar.sources=.
```

**Best practice**: Be specific. Pointing `sonar.sources=.` at the entire repo works but includes build artifacts, node_modules (if not excluded), and other noise that slows analysis.

### Understanding sonar.tests

```properties
# Tell SonarCloud which directories contain test code
sonar.tests=tests,src/__tests__,test

# What changes for test code:
# - Some rules don't apply (e.g., code complexity rules are relaxed)
# - Test files are excluded from maintainability/duplication ratings
# - Coverage is calculated for production code based on test execution
```

**Important**: Test code is still analyzed for security issues. A SQL injection in a test helper can still be a vulnerability if the helper is called from production paths.

### Source File Inclusion/Exclusion

```properties
# Analyze ONLY Python and JavaScript files
sonar.inclusions=**/*.py,**/*.js,**/*.ts

# Exclude entire directories
sonar.exclusions=**/node_modules/**,**/vendor/**,**/.venv/**

# Exclude generated code (migrations, protobuf, OpenAPI generated code)
sonar.exclusions=\
  **/migrations/**,\
  **/*_pb2.py,\
  **/*_pb2_grpc.py,\
  **/generated/**,\
  **/*.generated.ts,\
  **/openapi_client/**
```

**Ant-style patterns reference:**
- `*` — matches any sequence of characters, NOT including path separators
- `**` — matches any sequence of characters, including path separators
- `?` — matches any single character

Examples:
- `**/test_*.py` — any Python file starting with `test_` in any directory
- `src/*/config.js` — `config.js` in any direct subdirectory of `src`
- `**/*.min.js` — any minified JavaScript file anywhere

---

## Coverage Configuration

### Coverage Paths

```properties
# Python (pytest-cov or coverage.py XML output)
sonar.python.coverage.reportPaths=coverage.xml

# Multiple coverage files (merged by SonarCloud)
sonar.python.coverage.reportPaths=coverage-unit.xml,coverage-integration.xml

# JavaScript (LCOV format)
sonar.javascript.lcov.reportPaths=coverage/lcov.info

# TypeScript
sonar.typescript.lcov.reportPaths=coverage/lcov.info

# Java (JaCoCo XML)
sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml,\
  target/site/jacoco-integration/jacoco.xml

# Go
sonar.go.coverage.reportPaths=coverage.out
```

### Coverage Exclusions

```properties
# Exclude files from coverage measurement
# (Still analyzed for bugs/vulnerabilities, just not required to be covered)
sonar.coverage.exclusions=\
  **/tests/**,\
  **/*_test.py,\
  **/*.test.js,\
  **/*.spec.ts,\
  **/conftest.py,\
  **/fixtures/**,\
  **/migrations/**,\
  **/__init__.py,\
  **/cli.py,\
  **/manage.py
```

**Why exclude tests from coverage?** Tests test themselves — if a test function runs, it has 100% coverage trivially. Including test files in coverage statistics inflates your coverage number without adding meaningful value. Exclude them to get an honest picture of production code coverage.

---

## Issue Suppression

### Inline Suppression (//NOSONAR)

You can suppress a specific SonarCloud issue on a specific line by adding `// NOSONAR` comment:

```python
password = "test-password-for-local-dev-only"  # NOSONAR - intentional test credential
```

```javascript
const result = eval(safeExpression);  // NOSONAR
```

**Important rules for NOSONAR:**
1. Always add a comment AFTER `// NOSONAR` explaining WHY it's being suppressed
2. Never use NOSONAR to hide real vulnerabilities in production code
3. NOSONAR suppresses ALL rules on that line — be aware that new rules added later will also be suppressed
4. For specific rule suppression, use `// NOSONAR[rule:ID]` (some scanners support this)

**NOSONAR audit**: You can find all NOSONAR usages in SonarCloud:
- Issues > Filters > Resolution: Won't Fix / False Positive (these are UI-equivalent suppressions)
- For NOSONAR: Code search in your IDE for `// NOSONAR`

### Property-Based Suppression

For suppressing issues across multiple files or by rule:

```properties
# Suppress a specific rule in specific files
sonar.issue.ignore.multicriteria=e1,e2

sonar.issue.ignore.multicriteria.e1.ruleKey=python:S2077
sonar.issue.ignore.multicriteria.e1.resourceKey=**/test_fixtures/**

sonar.issue.ignore.multicriteria.e2.ruleKey=python:S4790
sonar.issue.ignore.multicriteria.e2.resourceKey=**/data_fingerprinting/**
```

**Use case**: You have a module that intentionally uses MD5 for data deduplication (non-security use), and you want to suppress the S4790 (weak hash) rule for that module only.

### Duplication Exclusions

```properties
# Don't flag duplications in these files (e.g., migration scripts, fixture data)
sonar.cpd.exclusions=\
  **/migrations/**,\
  **/test_fixtures/**,\
  **/*_seed.py
```

---

## External Report Import

SonarCloud can display findings from other tools alongside its own:

### Bandit (Python SAST)

```bash
# In CI pipeline:
bandit -r src/ -f json -o bandit-report.json -l -i
```

```properties
# sonar-project.properties:
sonar.python.bandit.reportPaths=bandit-report.json
```

### ESLint (JavaScript linting + security)

```bash
# In CI pipeline:
npx eslint src/ --format json --output-file eslint-report.json \
  --plugin security \
  --rule '{"security/detect-sql-injection": "error"}'
```

```properties
sonar.javascript.eslint.reportPaths=eslint-report.json
```

### SpotBugs (Java)

```bash
# Maven: run spotbugs and generate report
mvn spotbugs:check
```

```properties
sonar.java.spotbugs.reportPaths=target/spotbugsXml.xml
```

### Generic SARIF Format

Many tools (CodeQL, Semgrep, etc.) can output SARIF (Static Analysis Results Interchange Format):

```bash
# Example: running Semgrep
semgrep --config=p/owasp-top-ten --sarif > semgrep-results.sarif
```

```properties
sonar.sarifReportPaths=semgrep-results.sarif
```

SARIF import allows you to consolidate findings from multiple tools into a single SonarCloud view.

---

## SCM and Blame Integration

SonarCloud uses git blame to determine when issues were introduced and who introduced them. This requires full git history.

```properties
# Explicitly set the SCM provider (usually auto-detected)
sonar.scm.provider=git

# Force a specific revision (useful in unusual CI environments)
# sonar.scm.revision=abc123def456

# Disable SCM integration (not recommended — loses blame data)
# sonar.scm.disabled=true
```

**Why fetch-depth: 0 matters**: Without full git history, SonarCloud cannot:
- Determine whether code is "new" or "old" for Quality Gate evaluation
- Show when an issue was introduced
- Attribute issues to specific commits for PR decoration
- Accurately calculate the "new code" period

Always use `fetch-depth: 0` in your checkout step.

---

## Performance Tuning

### Analysis Scope Optimization

```properties
# If JavaScript/TypeScript analysis is slow due to large node_modules:
sonar.exclusions=**/node_modules/**

# Exclude build artifacts
sonar.exclusions=**/dist/**,**/build/**,**/.next/**,**/__pycache__/**

# Analyze only changed files (use with caution — can miss cross-file issues)
# Not recommended for security analysis — cross-file taint flows need full analysis
```

### Parallel File Analysis

The SonarScanner can analyze multiple files in parallel. This is configured automatically based on available CPU cores, but you can hint at it:

```properties
# Scanner worker thread count (default: auto-detected)
# sonar.scanner.workers=4
```

### Reducing Analysis Noise

```properties
# Exclude low-value files
sonar.exclusions=\
  **/*.min.js,\
  **/*.bundle.js,\
  **/coverage/**,\
  **/.pytest_cache/**,\
  **/.mypy_cache/**
```

---

## Multi-Module Projects

For projects with multiple Maven/Gradle modules or Python packages:

```properties
# Root sonar-project.properties:
sonar.projectKey=org_monorepo
sonar.organization=org

# Define modules
sonar.modules=module-a,module-b,module-c

# Module-specific settings (prefix with module ID)
module-a.sonar.sources=module-a/src
module-a.sonar.projectBaseDir=module-a

module-b.sonar.sources=module-b/src
module-b.sonar.projectBaseDir=module-b
```

Alternatively, each module can have its own `sonar-project.properties` and be analyzed as a separate project.

---

## Version Tagging and Leak Period

```properties
# Tag the analysis with a version
# This is used as the "new code" period anchor when set to "previous version"
sonar.projectVersion=2.4.1

# Better: Set dynamically in CI from git tags
# -Dsonar.projectVersion=$(git describe --tags --abbrev=0)
# Or from environment: -Dsonar.projectVersion=${{ github.ref_name }}
```

**With "previous version" new code period configured in SonarCloud:**
- Analysis tagged `2.4.0` sets the baseline
- Analysis tagged `2.4.1` shows as "new": issues introduced between 2.4.0 and 2.4.1
- This aligns security tracking with your release cadence

---

## sonar-project.properties Security Considerations

The properties file itself can expose sensitive information if misconfigured:

**Never put in sonar-project.properties:**
```properties
# WRONG - Never hardcode the token
sonar.token=abc123...

# WRONG - Never hardcode passwords
sonar.jdbc.password=...
```

**The SONAR_TOKEN is passed via environment variable in the workflow:**
```yaml
env:
  SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

**Safe to commit:**
- sonar.projectKey
- sonar.organization
- sonar.sources
- sonar.exclusions
- All configuration options except credentials

---

## Complete Advanced Template

Here's a production-ready `sonar-project.properties` for a Python+JavaScript web application:

```properties
# Project identification
sonar.projectKey=myorg_my-webapp
sonar.organization=myorg
sonar.projectName=My Web Application

# Source configuration
sonar.sources=backend/src,frontend/src
sonar.tests=backend/tests,frontend/tests
sonar.sourceEncoding=UTF-8

# Language-specific settings
sonar.python.version=3.12
sonar.javascript.node.maxspace=4096

# Coverage
sonar.python.coverage.reportPaths=backend/coverage.xml
sonar.javascript.lcov.reportPaths=frontend/coverage/lcov.info

# Exclusions
sonar.exclusions=\
  **/node_modules/**,\
  **/.venv/**,\
  **/migrations/**,\
  **/__pycache__/**,\
  **/dist/**,\
  **/*.min.js,\
  **/generated/**

sonar.coverage.exclusions=\
  **/tests/**,\
  **/*_test.py,\
  **/*.test.js,\
  **/*.spec.ts,\
  **/conftest.py,\
  **/manage.py,\
  **/wsgi.py

# External reports
sonar.python.bandit.reportPaths=backend/bandit-report.json

# Links (visible in SonarCloud UI)
sonar.links.homepage=https://myapp.example.com
sonar.links.ci=https://github.com/myorg/my-webapp/actions
sonar.links.issue=https://github.com/myorg/my-webapp/issues
sonar.links.scm=https://github.com/myorg/my-webapp

# Issue suppression (use sparingly, with justification in comments)
# sonar.issue.ignore.multicriteria=e1
# sonar.issue.ignore.multicriteria.e1.ruleKey=python:S4790
# sonar.issue.ignore.multicriteria.e1.resourceKey=**/data_hashing/**
```
