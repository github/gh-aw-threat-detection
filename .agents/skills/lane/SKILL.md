---
name: lane
description: Use lane in this repository when the user asks to create or work in an isolated worktree.
---

# lane

## Create a worktree

Create a worktree only when asked by the user. Otherwise, work in the current checkout.

```bash
lane new fix-login     # create a branch and worktree
lane enter fix-login   # print or enter the lane's directory
```

Capture the worktree path printed by `lane new` or `lane enter`. Use that path as
the working directory for every subsequent command; do not assume a `cd` persists
between command invocations. Work there, not in the parent checkout.

## Rules

- Do not pass `--dirty` unless the lane should inherit the parent checkout's uncommitted work.

## End gate

When the user asks to publish the work, run `lane push`, then create a PR for the
branch. Do not push or create a PR solely because the work in the lane is complete.
