# Pull Request Decoration and Branch Analysis

PR decoration is one of SonarCloud's most powerful features for developer workflow integration. It brings security analysis results directly into the code review process, where developers are already reviewing code.

---

## What is PR Decoration?

PR decoration refers to SonarCloud adding information to a pull request:

1. **GitHub Check**: A pass/fail status in the PR's "Checks" tab labeled "SonarCloud Code Analysis"
2. **Inline comments**: Comments posted directly on the specific lines of code with issues
3. **PR summary comment**: A comment summarizing the analysis results (optional)
4. **Status badge**: The Quality Gate status badge in the PR description area

**What this looks like to a developer:**
- They open a PR and see a yellow ⏳ "SonarCloud Code Analysis" check running
- After analysis: green ✅ (gate passed) or red ❌ (gate failed)
- They can click the check to go directly to the SonarCloud analysis
- On lines they changed that have issues, they see inline comment annotations

---

## Prerequisites for PR Decoration

### 1. Automatic Analysis Must Be Disabled
If Automatic Analysis is enabled alongside GitHub Actions, you get duplicate analyses and conflicting PR decorations.

To check:
- Project > Administration > Analysis Method
- If "Automatic Analysis" is toggled on, turn it off

### 2. GitHub Actions Integration Must Be Enabled
- Project > Administration > Analysis Method
- Select "GitHub Actions" as the CI provider

### 3. GITHUB_TOKEN Must Have Write Permissions
The GITHUB_TOKEN is automatically provided but may need write permissions:

Go to: Repository Settings > Actions > General > Workflow permissions
- Select: "Read and write permissions"
- Check: "Allow GitHub Actions to create and approve pull requests"

Alternatively, in your workflow file:
```yaml
permissions:
  pull-requests: write
  checks: write
  contents: read
```

### 4. PR Analysis Workflow Must Use `pull_request` Event
Your workflow must trigger on `pull_request`, not just `push`:
```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened]
```

---

## How PR Analysis Works Technically

When SonarCloud analyzes a PR:

1. **Identifies the PR context**: The `sonarcloud-github-action` passes PR metadata from GitHub Actions context variables:
   - `sonar.pullrequest.key`: The PR number (e.g., 42)
   - `sonar.pullrequest.branch`: The head branch (e.g., `feature/my-feature`)
   - `sonar.pullrequest.base`: The base/target branch (e.g., `main`)

2. **Analyzes only PR-relevant code**: SonarCloud compares the PR branch against the base branch and focuses on changed lines

3. **"New Code" in PR context**: Issues are classified as "new" if they appear in lines that are added or modified in the PR diff

4. **Quality Gate evaluation**: The gate evaluates only issues on new code (the PR diff), not the entire project

5. **Decoration posting**: SonarCloud uses the GITHUB_TOKEN to post:
   - A GitHub Check result
   - Inline PR review comments on affected lines

---

## Configuring PR Decoration Settings

### In SonarCloud UI

1. Go to: Project > Administration > Pull Requests
2. Select your CI provider: **GitHub**
3. Verify the settings:
   - "Decoration": Should be enabled
   - "Summary": Post a summary comment to PRs (recommended)
   - "Annotations": Post inline comments on issue lines (recommended)

### Decoration Behavior by Issue Type

| Issue Type | Inline Comment? | Quality Gate Impact | Notes |
|---|---|---|---|
| New Vulnerability | Yes | Yes (Security Rating) | Always inline-commented |
| New Bug | Yes | Yes (Reliability Rating) | Inline-commented |
| New Code Smell | Yes | Yes (Maintainability Rating) | Inline-commented |
| New Security Hotspot | Yes | Yes (Hotspots Reviewed %) | Comment asks for review |
| Existing issues (unchanged lines) | No | No | Not surfaced in PR |

---

## Branch Analysis

Beyond PR decoration, SonarCloud provides full branch analysis for long-lived branches.

### Branch Types in SonarCloud

**Main branch**: Your primary branch (main, master). Analyzed fully on every push. Sets the historical baseline and comparison point for all other branches.

**Long-lived branches**: Branches that persist for weeks/months (develop, release/*, hotfix/*). Analyzed like the main branch — full analysis, own history.

**Short-lived branches**: Feature branches (feature/*, fix/*). Analyzed in comparison to their base branch. Issues NEW compared to the base are highlighted.

**Pull Requests**: Special analysis mode. Compared against the PR's target branch. Results visible in PR UI.

### Configuring Branch Patterns

In SonarCloud: Project > Administration > Branches and Pull Requests

**Long-lived branch regex pattern** (default: `main|master|develop|.*release.*`):
```
(main|master|develop|release/.+|hotfix/.+)
```

Branches matching this pattern get "long-lived" analysis treatment. Everything else is "short-lived."

### Why This Matters for Security

Short-lived feature branches only show NEW issues (compared to main). This means:
- Developers see issues they introduced, not legacy issues
- The Quality Gate passes/fails based on what they changed
- There's no excuse "but those issues were already there" — the gate only evaluates new code

Long-lived branches (develop, release) have their own full analysis, so you can track the state of code heading toward production.

---

## The PR Review Workflow with SonarCloud

Here's the ideal developer workflow with PR decoration:

### Step 1: Developer pushes code and opens a PR

```bash
git checkout -b feature/user-authentication
# ... make changes ...
git push origin feature/user-authentication
# Open PR on GitHub: feature/user-authentication → main
```

### Step 2: Automated analysis runs

- PR analysis workflow triggers (pr-analysis.yml)
- Tests run, coverage generated
- SonarCloud scanner runs
- 1-3 minutes later: GitHub Check updates

### Step 3: Developer reviews the Check

If the check passes:
- ✅ "SonarCloud Code Analysis — All checks passed"
- Developer (or reviewer) can look at the SonarCloud link for details

If the check fails:
- ❌ "SonarCloud Code Analysis — Quality Gate failed"
- Click "Details" → opens SonarCloud showing what failed

### Step 4: Review inline comments

On the PR Files tab:
- Lines with issues have comment annotations showing the rule and severity
- Example inline comment on a Python file:
  ```
  ⚠️ Make sure this SQL query is protected against injection attacks.
  This block constructs a SQL query from user-controlled data.
  SonarCloud: python:S2077 — CRITICAL
  ```

The developer can click the annotation to open SonarCloud and see the full explanation.

### Step 5: Fix issues and push updates

Developer fixes the flagged issues in their branch and pushes:

```bash
# Fix the SQL injection
git add src/
git commit -m "Fix SQL injection in user lookup"
git push
```

The PR analysis workflow re-triggers automatically on the new push (because of `synchronize` in `pull_request.types`). The check re-runs and should now pass.

### Step 6: Merge when green

Once all checks pass (including SonarCloud), the PR can be merged (with reviewer approval if required).

---

## Inline Comment Examples

### SQL Injection Comment
```
SonarCloud Code Analysis [python:S2077] Critical
Make sure using a dynamically formatted SQL query is safe here.
Change this code to not construct the query directly from user-controlled data.
See full details in SonarCloud →
```

### Hardcoded Secret Comment
```
SonarCloud Code Analysis [python:S6437] Blocker
Revoke and change this password, as it is compromised.
Credentials should not be hard-coded.
See full details in SonarCloud →
```

### Security Hotspot Comment
```
SonarCloud Code Analysis [python:S2245] Security Hotspot
Make sure that using this pseudorandom number generator is safe here.
If this is used for security purposes (e.g., token generation), use a CSPRNG.
Review required in SonarCloud →
```

---

## Requiring the Check Before Merging

To enforce that the SonarCloud gate must pass before merging:

1. Go to: Repository Settings > Branches
2. Click "Add branch protection rule" for `main`
3. Enable: **"Require status checks to pass before merging"**
4. In the search box, type `SonarCloud` and select **"SonarCloud Code Analysis"**
5. Enable: **"Require branches to be up to date before merging"**
6. Save

**After this configuration:**
- If SonarCloud check fails: the "Merge pull request" button is greyed out
- Admin bypass: Admins can still merge by selecting "Merge without waiting for requirements"
- This bypass should be used rarely and documented

---

## Troubleshooting PR Decoration

### "SonarCloud Code Analysis" check doesn't appear on PRs

Check:
1. Is the `pr-analysis.yml` workflow enabled? Check the Actions tab.
2. Does the workflow trigger on `pull_request`?
3. Is the PR from a fork? Fork PRs can't access secrets — see the two-workflow pattern in `05_cicd_integration.md`
4. Check the workflow run logs for errors

### Inline comments aren't appearing

Check:
1. Is decoration enabled? Project > Administration > Pull Requests
2. Does the GITHUB_TOKEN have write permissions for pull requests?
3. Are there actually new issues in the PR diff? Issues on unchanged lines don't get inline comments.

### The check passes but there are issues

This can happen if:
- The issues are on unchanged lines (not in the PR diff)
- The issues are severity INFO or MINOR and your Quality Gate doesn't check those
- The new code period doesn't include those lines

### Check fails for "Coverage" but there ARE tests

Check:
1. Did the test step run successfully? Look for errors in the Actions log.
2. Was the coverage file generated at the path specified in `sonar-project.properties`?
3. Is the coverage file relative path correct? It should be relative to the project root.
4. Did the test step run BEFORE the SonarCloud scan step? Order matters.
