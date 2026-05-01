# Contributing to GitHub Agentic Workflows Threat Detection

Thank you for your interest in contributing to GitHub Agentic Workflows Threat Detection! We welcome contributions from the community and are excited to work with you.

**⚠️ IMPORTANT: This project uses agentic development by a core team (inner-circle) primarily using Copilot coding agent or local coding agents.**

**🚫 Traditional Pull Requests Are Not Enabled for non-Core team members**: If you are not part of the core team, please do not create pull requests directly. Instead, you create detailed agentic plans in issues, discuss with the team, and a core team member will create and implement the PR for you using agents.

This document deals with the contribution process for non-Core team members.

## Prerequisites

> ⚠️ **Generic dev environments (e.g. manually installed Node.js, Go, or other tools) are not supported.**
> This project is designed to be developed inside a **Dev Container** or **GitHub Codespace**, which automatically configures all required tools and runtimes.

The recommended way to set up a development environment is to use the provided [Dev Container](.devcontainer/devcontainer.json):

- **GitHub Codespaces** (recommended): Open this repository in a Codespace — everything is pre-configured automatically, including Go, Node.js 24, Docker, and the GitHub CLI.
- **VS Code Dev Container**: Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers), then open the repository folder and choose **Reopen in Container**.

The Dev Container installs all required dependencies and runs `make deps` automatically on creation. No manual setup is needed.

If you encounter errors about Node.js or Go versions when running `make deps` or other build commands, this is a sign that you are not using the Dev Container. Please switch to a Dev Container or Codespace environment.

## 🤖 How Development Works

GitHub Agentic Workflows is developed by a core team using agentic development — primarily GitHub Copilot coding agent and local coding agents. This means:

- ✅ **Core team uses agents to create and manage pull requests** - via Copilot coding agent or local agents
- ✅ **Automated quality assurance** - CI runs all checks on all PRs
- ✅ **Community contributes through agentic plans** - you craft the plan, the core team executes it
- ❌ **Traditional pull requests from non-core members are not enabled** - contribute through issues instead

### Why This Approach?

This project practices what it preaches: agentic development is used to build agentic workflows. Benefits include:

- **Consistency**: All changes go through the same automated quality gates
- **Dogfooding**: We use our own tools to build our tools
- **Best practices**: Agents follow established patterns and guidelines automatically
- **Quality plans**: Encourages contributors to think through the full implementation before work begins

## 🚀 Quick Start for Community Contributors

⚠️ **If you are not part of the core team, do not create pull requests directly.** Instead, craft a detailed agentic plan in an issue and a core team member will pick it up and implement it using agents.

### Step 1: Analyze with an Agent (for bug reports)

**Before filing a contribution request**, use an agent to:

- Scan the source code to identify root causes (for bugs)
- Analyze execution patterns and trace the issue
- Research similar issues and solutions
- Propose specific fixes with code examples
- Create a comprehensive plan for the changes needed

### Step 2: Open an Issue with Your Agentic Plan

**Create an issue** with your detailed agentic plan:

- Describe what you want to contribute
- Include your agent's analysis and findings (for bugs)
- Explain the use case and expected behavior
- Provide a **complete, step-by-step plan** for the agent to follow
- Include specific implementation details and examples
- Tag with appropriate labels

### Step 3: Discuss and Refine with the Team

Once you've opened the issue:

1. **Core team reviews your plan**: A core team member will look at your issue and may ask clarifying questions
2. **Iterate on the plan**: Discuss and refine the implementation approach based on team feedback
3. **Plan gets approved**: A core team member signals they'll pick it up

### Step 4: A Core Team Member Implements the PR

A core team member will:

- Take your agentic plan and use a coding agent (Copilot or local) to implement it
- Read relevant documentation and specifications
- Make code changes following established patterns
- Run `make agent-finish` to validate changes
- Create a PR and handle review feedback and adjustments

**You don't create or own the PR** — the core team member does, using agents as their implementation tool.

## 🏗️ Project Structure

This structure is useful context when writing your agentic plan, so the core team's agent can navigate the codebase effectively:

```text
/
├── cmd/gh-aw/           # Main CLI application
├── pkg/                 # Core Go packages
│   ├── cli/             # CLI command implementations
│   ├── console/         # Console formatting utilities
│   ├── parser/          # Markdown frontmatter parsing
│   └── workflow/        # Workflow compilation and processing
├── scratchpad/               # Technical specifications the agent reads
├── skills/              # Specialized knowledge for agents
├── .github/             # Instructions and sample workflows
│   ├── instructions/    # Agent instructions
│   └── workflows/       # Sample workflows and CI
└── Makefile             # Build automation (agent uses this)
```

## 📋 Dependency License Policy

This project uses an MIT license and only accepts dependencies with compatible licenses.

### Allowed Licenses

The following open-source licenses are compatible with our MIT license:

- **MIT** - Most permissive, allows reuse with minimal restrictions
- **Apache-2.0** - Permissive license with patent grant
- **BSD-2-Clause, BSD-3-Clause** - Simple permissive licenses
- **ISC** - Simplified permissive license similar to MIT

### Disallowed Licenses

The following licenses are **not allowed** as they conflict with our MIT license or impose unacceptable restrictions:

- **GPL, LGPL, AGPL** - Copyleft licenses that would force us to release under GPL
- **SSPL** - Server Side Public License with restrictive requirements
- **Proprietary/Commercial** - Closed-source licenses requiring payment or special terms

## 🚫 Spam Prevention

**Be nice, don't spam.** The project maintainers reserve the right to clean up spam, unsolicited promotions, or off-topic content as needed to keep discussions focused and valuable for all contributors.

This includes but is not limited to:
- Repeated identical or similar comments across multiple issues or pull requests
- Unsolicited promotional content or advertisements
- Off-topic comments that don't contribute to the discussion
- Automated bot comments without prior approval

## 🤝 Community

- Join the `#continuous-ai` channel in the [GitHub Next Discord](https://gh.io/next-discord)
- Participate in discussions on GitHub issues
- Collaborate by crafting high-quality agentic plans for the core team to implement

## 📜 Code of Conduct

This project follows the GitHub Community Guidelines. Please be respectful and inclusive in all interactions.

## ❓ Getting Help

- **For bugs or features**: Open a GitHub issue with a detailed agentic plan
- **For questions**: Ask in issues, discussions, or Discord
- **For examples**: Look at existing issues and PRs created by core team members
- **Remember**: You don't create PRs - you create issues with plans that a core team member implements using agents

## 🚀 Release Process

> **For core team maintainers only.** Community members do not participate in releasing.

Releases are triggered manually by a core team member using the GitHub Actions release workflow.

> **Note:** The release workflow publishes the new version as a **prerelease** on GitHub. Once the release is verified, a maintainer must **manually promote it to a full release and move the `latest` tag** so that users installing with `version: latest` receive the new version.

### Steps

1. **Launch the release action**

   Go to [Actions → Release](https://github.com/github/gh-aw/actions/workflows/release.lock.yml) and click **Run workflow**. Select the release type (`patch`, `minor`, or `major`) and start the run.

   The workflow will build the release binaries, push a new git tag, and then pause — waiting for a required manual step before publishing.

2. **Complete the sync in `github/gh-aw-actions`**

   While the workflow is paused at the `gh-aw-actions-release` environment gate, complete the following steps in the [`github/gh-aw-actions`](https://github.com/github/gh-aw-actions) repository:

   a. **Run the sync-actions workflow** — go to [Actions → sync-actions](https://github.com/github/gh-aw-actions/actions/workflows/sync-actions.yml) and trigger it with the new release tag (e.g. `v1.2.3`).

   b. **Merge the PR** — the sync-actions workflow will open a pull request in `github/gh-aw-actions`. Review and merge it to bring the tag into that repository.

3. **Approve the environment gate**

   Return to the paused release run in [`github/gh-aw`](https://github.com/github/gh-aw/actions). Approve the **`gh-aw-actions-release`** environment gate. The workflow will verify that the new tag exists in `github/gh-aw-actions` and then publish the GitHub release as a **prerelease**.

4. **Promote to latest** _(manual step)_

   After verifying the prerelease is working correctly:

   a. **Edit the GitHub release** — go to the [Releases page](https://github.com/github/gh-aw/releases), open the new prerelease, uncheck **This is a pre-release**, and save. This promotes the release to a stable full release.

   b. **Move the `latest` tag** — GitHub's release API resolves `latest` to the most recent non-prerelease release. Promoting the release in step (a) is sufficient for the `latest` resolution to update automatically.

   Users who install with `version: latest` (the default) will now receive the new release.

### Summary

```
Launch release action
        │
        ▼
Workflow pushes tag & pauses
        │
        ▼
Run sync-actions in github/gh-aw-actions (with new tag)
        │
        ▼
Merge the sync-actions PR
        │
        ▼
Approve the gh-aw-actions-release environment gate
        │
        ▼
Release published as prerelease 🎉
        │
        ▼  (manual)
Promote prerelease → full release on GitHub Releases page
        │
        ▼
'latest' now resolves to the new version ✅
```

## 🎯 Why This Contribution Model?

This project is built by a core team using agentic development to demonstrate and dogfood the capabilities of GitHub Agentic Workflows:

- **Dogfooding**: We use our own tools to build our tools
- **Consistency**: All changes go through the same automated quality gates
- **Best practices**: Agents follow established guidelines automatically
- **Focus on outcomes**: Describe what you want, not how to build it
- **Quality plans**: Encourages contributors to think through the full implementation before work begins

Community members contribute by crafting detailed agentic plans that the core team picks up and implements. **This keeps the bar high** — well-thought-out plans lead to well-executed PRs.

The [Development Guide](DEVGUIDE.md) is the reference guide used by core team members and their agents.

Thank you for contributing to GitHub Agentic Workflows! 🤖🎉
