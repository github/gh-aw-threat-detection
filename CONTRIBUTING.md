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

### Step 1: Analyze with an Agent

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
├── .devcontainer/       # Codespaces and Dev Container setup
├── .github/
│   └── workflows/       # CI and release workflows
├── cmd/
│   └── threat-detect/   # Main CLI application
├── pkg/
│   ├── artifacts/       # Artifact loading and validation
│   ├── detector/        # Threat detection logic and prompt templates
│   └── engine/          # AI engine abstraction and adapters
├── scratchpad/          # Technical specifications and implementation notes
├── skills/              # Specialized knowledge for agents
├── specs/               # Project specification and requirements
├── DEVGUIDE.md          # Maintainer and agent reference guide
└── Makefile             # Build automation and agent validation targets
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

Releases follow a **prerelease → promote** two-phase model. See [DEVGUIDE.md](DEVGUIDE.md#release-process) for full details.

### Steps

1. **Push a version tag** — pushing a tag matching `v*` (e.g. `v1.2.3`) automatically triggers the [release workflow](.github/workflows/release.yml). It builds and pushes a version-tagged container image, records its digest, and creates a **prerelease** on GitHub (gated by the `release-publish` environment).

2. **Verify the prerelease** — confirm the prerelease behaves correctly before promoting. The `latest` container image and the GitHub "Latest" release badge do not move until promotion.

3. **Promote to stable** — trigger the [Promote Release workflow](.github/workflows/promote-release.yml) via **Actions → Promote Release → Run workflow**, entering the tag name (e.g. `v1.2.3`). This workflow (gated by the `release-promote` environment):
   - verifies the release is still a prerelease
   - pushes the recorded image digest as `latest`
   - marks the GitHub release as stable and explicitly selects it as Latest

### Summary

```
push tag (v*)
        │
        ▼
release workflow (release-publish gate)
        │
        ▼
Prerelease published + versioned container image pushed 🎉
        │
        ▼  (manual — after verification)
promote-release workflow (release-promote gate)
        │
        ▼
Container image tagged as latest + GitHub release marked stable ✅
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
