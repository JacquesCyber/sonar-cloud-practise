# SonarCloud Setup Guide

This guide walks you through creating a SonarCloud account, connecting it to GitHub, and running your first analysis on this repository.

---

## Step 1: Create a SonarCloud Account

1. Navigate to [sonarcloud.io](https://sonarcloud.io)
2. Click **Log in** in the top right corner
3. Select **Log in with GitHub** (recommended — enables automatic repository access)
4. Authorize SonarCloud to access your GitHub account
   - You'll be asked for: read access to your profile, email, and repositories
   - For organizations: you may need org admin approval for the OAuth app

**What you'll see after login:**
The SonarCloud dashboard with an empty "My Projects" view. You'll also see any projects from organizations you belong to if other members have already set up SonarCloud.

---

## Step 2: Create or Join an Organization

SonarCloud organizes projects under **Organizations**, which mirror GitHub organizations. If you're working with a personal GitHub account, you'll use your personal organization.

### For a personal GitHub account:
1. After login, SonarCloud automatically creates a personal organization named after your GitHub username
2. Your organization key will be something like `yourgithubusername`

### For a GitHub organization:
1. Click the **+** icon in the top navigation
2. Select **Create an organization**
3. Select your GitHub organization from the list
4. Choose a plan:
   - **Free**: Public repositories only, unlimited analyses
   - **Paid**: Private repositories, priced by lines of code
5. Click **Create organization**

**Finding your organization key:**
- Go to: Organization settings (top navigation > your org name > Administration)
- Look for "Organization Key" — this is what goes in `sonar.organization` in `sonar-project.properties`

---

## Step 3: Set Up Automatic Analysis or CI-Based Analysis

SonarCloud offers two modes:

### Option A: Automatic Analysis (simplest, limited)
- SonarCloud uses the GitHub Actions runner directly, no pipeline needed
- Triggered automatically on pushes to the default branch and PRs
- **Limitations**: No custom configuration, no test coverage, no external reports
- **Best for**: Quick exploration, projects without complex analysis needs

To enable:
1. Create a new project (Step 4)
2. Select **Automatic Analysis** during setup
3. Done — SonarCloud analyzes on the next push

### Option B: GitHub Actions (recommended for this template)
- You control the analysis via GitHub Actions workflows
- Full coverage integration, external tool imports, custom properties
- Required for this template's features

To enable:
1. Create a new project (Step 4)
2. Select **GitHub Actions** during setup
3. SonarCloud generates a SONAR_TOKEN — save it
4. Add the workflows from this template (already done)

**Important**: You cannot use BOTH Automatic Analysis AND GitHub Actions for the same project. Disable Automatic Analysis if you switch to GitHub Actions.

To disable Automatic Analysis on an existing project:
- Go to: Project > Administration > Analysis Method > Turn off "Automatic Analysis"

---

## Step 4: Add a New Project

1. Click the **+** icon in the top navigation bar
2. Select **Analyze new project**
3. You'll see a list of your GitHub repositories
4. Find and select the repository you want to analyze (fork of this template, or your own repo)
5. Click **Set Up**

**What happens next:**
SonarCloud creates the project and gives you setup instructions. Keep this page open — you'll need the SONAR_TOKEN it generates.

---

## Step 5: Generate and Store the SONAR_TOKEN

The SONAR_TOKEN is how GitHub Actions authenticates with SonarCloud.

**Generate the token:**
1. During project setup, SonarCloud shows a "Generate a token" step
2. Enter a descriptive name: `github-actions-sonarcloud`
3. Click **Generate**
4. **Copy the token immediately** — you cannot view it again after closing this dialog
   - Format: a long alphanumeric string, approximately 40 characters

**Alternative: Generate from account settings:**
1. Click your avatar > My Account
2. Go to the **Security** tab
3. Under "Generate Tokens", enter a name and click "Generate"
4. Copy the token value

**Store the token as a GitHub secret:**
1. Go to your GitHub repository
2. Click **Settings** > **Secrets and variables** > **Actions**
3. Click **New repository secret**
4. Name: `SONAR_TOKEN` (exact name — this is what the workflow references)
5. Value: paste the token
6. Click **Add secret**

**Security rules for SONAR_TOKEN:**
- Never hardcode it in `sonar-project.properties` or any source file
- Never print it in CI logs (GitHub Actions automatically masks secrets in logs)
- Treat it like a password — rotate it if it may have been exposed
- Give it the minimum required scope (Project Analysis Token, not User Token)

---

## Step 6: Update sonar-project.properties

Open `sonar-project.properties` at the root of your repository and update these required values:

```properties
# Find your projectKey in SonarCloud: Project > Administration > Update Key
sonar.projectKey=your-org-key_your-repo-name

# Find your org key in SonarCloud: Organization > Administration > Organization Key
sonar.organization=your-org-key
```

**How to find your projectKey:**
1. In SonarCloud, navigate to your project
2. Go to Project > Administration > Update Key
3. The current key is shown at the top

**Default projectKey format:**
When you set up a project from GitHub, SonarCloud creates the key as: `<org-key>_<repo-name>`

Example: If your org key is `acme-corp` and your repo is `payment-service`, your project key is `acme-corp_payment-service`.

---

## Step 7: Configure Branch Analysis

For the GitHub Actions workflows to correctly identify which branch is being analyzed:

1. In SonarCloud, go to your project
2. Click **Administration** > **Branches and Pull Requests**
3. Under "Main Branch", set your main branch name (usually `main` or `master`)
4. The "Long-lived branches" pattern controls which branches get full analysis vs. short-lived analysis

**Branch analysis behavior:**
- **Main branch**: Full analysis, sets the baseline for comparisons
- **Long-lived branches** (e.g., `develop`, `release/*`): Full analysis
- **Short-lived branches** (feature branches): Compared against their base branch, Quality Gate evaluates only new code

---

## Step 8: Run Your First Analysis

**Trigger the analysis:**
```bash
# Push to your main branch to trigger sonarcloud.yml
git add .
git commit -m "Set up SonarCloud configuration"
git push origin main
```

**Monitor the analysis:**
1. Go to your GitHub repository
2. Click **Actions** tab
3. Find the "SonarCloud Analysis" workflow run
4. Click on it to see live logs
5. Look for the step "SonarCloud Scan" — it shows scanner output in real time

**Expected duration:** 1-3 minutes for a small project. Larger projects take longer.

**Successful output looks like:**
```
INFO: Analysis report generated in ...ms
INFO: Analysis report compressed in ...ms
INFO: Analysis report uploaded in ...ms
INFO: ANALYSIS SUCCESSFUL, you can find the results at: https://sonarcloud.io/dashboard?id=...
INFO: Note that you will be able to see a real-time updated project banner...
INFO: More about the report processing at https://sonarcloud.io/api/ce/task?id=...
INFO: Task total time: ...ms
INFO: ------------------------------------------------------------------------
INFO: EXECUTION SUCCESS
```

---

## Step 9: Navigate to Your SonarCloud Project

After the analysis completes (usually within 1-2 minutes of the workflow finishing):

1. Go to [sonarcloud.io](https://sonarcloud.io)
2. Click your organization
3. Find your project in the project list
4. Click on it to open the project dashboard

**What you should see on first analysis:**
- A summary of bugs, vulnerabilities, code smells, and coverage
- A Quality Gate status (likely FAILED on this template — by design, since we included vulnerable code)
- A Security Hotspots section with items to review

Congratulations — you have a working SonarCloud setup.

---

## Troubleshooting Common Setup Issues

### "Project not found" error in the workflow
- Verify `sonar.projectKey` and `sonar.organization` in `sonar-project.properties` match exactly what's in SonarCloud
- Keys are case-sensitive

### "Authentication failed" error
- Verify the `SONAR_TOKEN` secret is set correctly in GitHub
- Check that the secret name is exactly `SONAR_TOKEN` (uppercase)
- If the token was generated for a different project or organization, regenerate it

### Analysis runs but no results appear
- Check that Automatic Analysis is disabled if using GitHub Actions
- Wait 2-3 minutes after the workflow completes — SonarCloud processes asynchronously
- Check the workflow logs for the SonarCloud task URL and open it directly

### Coverage shows 0% even though tests ran
- Verify that `coverage.xml` was generated before the SonarCloud scan step
- Check that `sonar.python.coverage.reportPaths=coverage.xml` matches the actual file location
- Look at the workflow logs for the coverage generation step — are there errors?
- The coverage file path in `sonar-project.properties` is relative to the project root (where the scanner runs)

### "You're not authorized to run analysis on this project"
- The SONAR_TOKEN must be a token from the SonarCloud account that has analysis rights on the project
- Project Analysis Tokens are project-scoped; User Tokens work for all projects the user has access to
- Check that the token hasn't expired (tokens don't expire by default, but can be revoked)

### PR decoration not appearing
- Automatic Analysis must be DISABLED (it competes with GitHub Actions analysis)
- The workflow must use the `pull_request` event, not `push`
- The GITHUB_TOKEN in the workflow needs write permissions to PRs
  - Check: Settings > Actions > General > Workflow permissions = "Read and write permissions"
- The `sonar-project.properties` must have a valid `sonar.projectKey`
