# CI/CD Integration Patterns

This guide covers how to integrate SonarCloud into GitHub Actions CI/CD pipelines effectively, including handling different project types, coverage, and pipeline optimization.

---

## Architecture Overview

```
Developer Push / PR
        |
        v
[GitHub Actions Trigger]
        |
        |--- sonarcloud.yml  (push to main/develop)
        |--- pr-analysis.yml (pull_request events)
        |
        v
[Build & Test Steps]
   - Install dependencies
   - Run unit tests
   - Generate coverage report (coverage.xml, lcov.info)
        |
        v
[SonarCloud Scan Step]
   - sonarcloud-github-action downloads SonarScanner
   - SonarScanner reads sonar-project.properties
   - Scanner uploads analysis to sonarcloud.io
        |
        v
[SonarCloud Processing] (async, typically 30-90 seconds)
   - Taint analysis
   - Rule execution
   - Quality Gate evaluation
        |
        v
[GitHub Check Created]
   - "SonarCloud Code Analysis" check
   - PASSED or FAILED based on Quality Gate
   - Inline PR comments (for PRs)
```

---

## The sonarcloud-github-action

The official GitHub Action from SonarSource handles:
1. Downloading the appropriate SonarScanner version
2. Reading `sonar-project.properties` from the repository root
3. Passing GitHub context to SonarCloud (branch, PR number, commit SHA)
4. Uploading analysis results to SonarCloud
5. Optionally waiting for Quality Gate result

**Usage in a workflow:**
```yaml
- name: SonarCloud Scan
  uses: SonarSource/sonarcloud-github-action@master
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

**Pinning to a specific version** (recommended for production):
```yaml
- uses: SonarSource/sonarcloud-github-action@v2.3.0  # Pin to a release tag
```
Using `@master` always pulls the latest, which may include breaking changes. For stability, pin to a version tag and periodically update.

---

## Coverage Integration

### Python Coverage with pytest

```yaml
- name: Install test dependencies
  run: pip install pytest pytest-cov coverage

- name: Run tests with coverage
  run: |
    pytest \
      --cov=src \                          # What to measure coverage for
      --cov-report=xml:coverage.xml \      # XML format for SonarCloud
      --cov-report=term-missing \          # Console output for debugging
      --cov-fail-under=70 \                # Fail if coverage drops below 70%
      -v
```

**`sonar-project.properties` setting:**
```properties
sonar.python.coverage.reportPaths=coverage.xml
```

**Multi-module Python projects:**
```yaml
- run: |
    pytest module_a/ --cov=module_a --cov-report=xml:coverage_a.xml
    pytest module_b/ --cov=module_b --cov-report=xml:coverage_b.xml
    # Merge coverage files
    coverage combine
    coverage xml -o coverage.xml
```

### JavaScript/TypeScript Coverage with Jest

```yaml
- name: Run Jest tests
  run: |
    npx jest \
      --coverage \
      --coverageReporters=lcov \    # LCOV format for SonarCloud
      --watchAll=false
  # Jest default output: coverage/lcov.info
```

**`sonar-project.properties` setting:**
```properties
sonar.javascript.lcov.reportPaths=coverage/lcov.info
# For TypeScript:
sonar.typescript.lcov.reportPaths=coverage/lcov.info
```

### TypeScript Coverage with nyc (Istanbul)

```yaml
- run: npx nyc --reporter=lcov npm test
  # Output: coverage/lcov.info
```

### Java Coverage with JaCoCo

```yaml
- name: Build and test
  run: mvn clean verify  # JaCoCo runs via Maven plugin

# sonar-project.properties:
# sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
```

### Go Coverage

```yaml
- run: |
    go test ./... -coverprofile=coverage.out
    # SonarCloud expects the standard Go coverage format
```

```properties
# sonar-project.properties
sonar.go.coverage.reportPaths=coverage.out
```

---

## Multi-Language Projects

For projects with multiple languages, configure each language's coverage separately:

```yaml
steps:
  - name: Python tests
    run: pytest --cov=backend --cov-report=xml:backend-coverage.xml

  - name: JavaScript tests
    run: npm test -- --coverage --coverageReporters=lcov

  - name: SonarCloud Scan
    uses: SonarSource/sonarcloud-github-action@master
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

```properties
# sonar-project.properties
sonar.sources=backend,frontend
sonar.python.coverage.reportPaths=backend-coverage.xml
sonar.javascript.lcov.reportPaths=coverage/lcov.info
```

---

## Handling the Quality Gate in CI

### Option 1: sonar.qualitygate.wait (Simple)

Add to `sonar-project.properties` or as a scanner arg:
```properties
sonar.qualitygate.wait=true
sonar.qualitygate.timeout=300   # Seconds to wait (default: 300)
```

Or as a GitHub Actions argument:
```yaml
- uses: SonarSource/sonarcloud-github-action@master
  with:
    args: >
      -Dsonar.qualitygate.wait=true
      -Dsonar.qualitygate.timeout=300
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

**Behavior**: The scanner waits for SonarCloud to process the analysis and returns a non-zero exit code if the Quality Gate fails. The workflow step fails, blocking the pipeline.

### Option 2: API Polling (More Control)

Poll the SonarCloud API for the gate status after analysis:

```yaml
- name: Wait for SonarCloud analysis
  run: |
    PROJECT_KEY="your-org_your-project"
    MAX_RETRIES=12
    SLEEP_SECONDS=15

    for i in $(seq 1 $MAX_RETRIES); do
      STATUS=$(curl -s -u "${{ secrets.SONAR_TOKEN }}:" \
        "https://sonarcloud.io/api/qualitygates/project_status?projectKey=${PROJECT_KEY}" \
        | python3 -c "import sys,json; data=json.load(sys.stdin); print(data['projectStatus']['status'])")

      echo "Attempt $i: Quality Gate = $STATUS"

      if [ "$STATUS" = "OK" ]; then
        echo "Quality Gate PASSED"
        exit 0
      elif [ "$STATUS" = "ERROR" ]; then
        echo "Quality Gate FAILED"
        exit 1
      elif [ "$STATUS" = "NONE" ]; then
        echo "No Quality Gate configured"
        exit 0
      fi

      # Still processing (IN_PROGRESS)
      echo "Analysis still processing, waiting ${SLEEP_SECONDS}s..."
      sleep $SLEEP_SECONDS
    done

    echo "Timeout waiting for Quality Gate result"
    exit 1
```

---

## Branch-Specific Analysis Behavior

### Main Branch Analysis
- Full analysis of all source files
- Sets the baseline for new code comparisons
- Results visible in the main project dashboard

### Feature Branch Analysis
- Compared against the main branch (or the configured long-lived branch)
- Shows issues that are NEW compared to the target
- Results visible in the "Branches" section of the project

### PR Analysis
- Analyzed as a "pull request" context (not a branch)
- Evaluates only new code in the PR diff
- Inline comments posted to the PR
- Check visible in PR Checks tab

**Automatic branch detection**: The `sonarcloud-github-action` reads GitHub Actions context variables to automatically set:
- `GITHUB_HEAD_REF` (PR source branch)
- `GITHUB_BASE_REF` (PR target branch)
- `GITHUB_REF` (branch on push)
- `GITHUB_SHA` (commit hash)

You generally don't need to set these manually.

---

## Caching for Faster Analysis

SonarCloud maintains its own cache, but local caching reduces network overhead:

```yaml
- name: Cache SonarCloud packages
  uses: actions/cache@v4
  with:
    path: ~/.sonar/cache
    key: ${{ runner.os }}-sonar
    restore-keys: ${{ runner.os }}-sonar

- name: Cache Python packages
  uses: actions/cache@v4
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('requirements*.txt') }}
    restore-keys: ${{ runner.os }}-pip-
```

The `~/.sonar/cache` directory stores downloaded analyzer plugins. Caching it saves 30-60 seconds on subsequent runs.

---

## Security Considerations for CI Integration

### Secrets Management in GitHub Actions

**Do:**
- Store SONAR_TOKEN as a repository secret (Settings > Secrets)
- For organizations: store as an organization secret for cross-repo access
- Use environment-level secrets for production deployments

**Don't:**
- Print the SONAR_TOKEN in any step
- Pass it as a command-line argument (visible in process list)
- Store it in `sonar-project.properties`
- Use the same token for multiple organizations

### Fork PR Security

Public repositories face a challenge: PRs from forks cannot access repository secrets (by design — GitHub prevents this to stop untrusted code from exfiltrating secrets).

**Implication**: Standard pull_request workflows cannot use SONAR_TOKEN for fork PRs.

**Solution: Two-workflow pattern:**

```yaml
# Workflow 1: build-and-test.yml (runs in fork context, no secrets)
on:
  pull_request:
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run tests
        run: pytest --cov=src --cov-report=xml
      - name: Save PR number
        run: echo ${{ github.event.number }} > pr_number.txt
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: pr-artifacts
          path: |
            coverage.xml
            pr_number.txt

# Workflow 2: sonarcloud-from-fork.yml (runs in base repo context, has secrets)
on:
  workflow_run:
    workflows: [build-and-test]
    types: [completed]
jobs:
  sonar:
    if: github.event.workflow_run.conclusion == 'success'
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
          fetch-depth: 0
      - name: Download artifacts
        uses: actions/download-artifact@v4
        with:
          name: pr-artifacts
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - name: Get PR number
        run: echo "PR_NUMBER=$(cat pr_number.txt)" >> $GITHUB_ENV
      - name: SonarCloud Scan
        uses: SonarSource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        with:
          args: >
            -Dsonar.pullrequest.key=${{ env.PR_NUMBER }}
            -Dsonar.pullrequest.branch=${{ github.event.workflow_run.head_branch }}
            -Dsonar.pullrequest.base=main
            -Dsonar.scm.revision=${{ github.event.workflow_run.head_sha }}
```

---

## Monorepo Configuration

For monorepos with multiple independent projects:

```yaml
# .github/workflows/sonarcloud.yml
jobs:
  sonar-service-a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: pytest services/service-a --cov=services/service-a --cov-report=xml:coverage-a.xml
      - uses: SonarSource/sonarcloud-github-action@master
        with:
          projectBaseDir: services/service-a  # Run from this directory
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}

  sonar-service-b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: pytest services/service-b --cov=services/service-b --cov-report=xml:coverage-b.xml
      - uses: SonarSource/sonarcloud-github-action@master
        with:
          projectBaseDir: services/service-b
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

Each service needs its own `sonar-project.properties` in its base directory.

---

## Debugging Failed Analysis

### Enable verbose logging

```yaml
- uses: SonarSource/sonarcloud-github-action@master
  with:
    args: -Dsonar.verbose=true
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

### Common error patterns and solutions

| Error | Cause | Fix |
|---|---|---|
| `Could not find a default branch to fall back on` | Shallow clone | Use `fetch-depth: 0` |
| `Not authorized` | Bad SONAR_TOKEN | Regenerate and re-store the secret |
| `Project not found` | Wrong projectKey | Check sonar-project.properties |
| `No report imported` | Coverage file missing | Verify the coverage generation step succeeded |
| `Branch 'main' not found` | Wrong branch name | Update sonar.branch.name or use correct branch |
| Analysis completes but no gate result | Automatic Analysis conflicts | Disable Automatic Analysis in SonarCloud |
