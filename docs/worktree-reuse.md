# Worktree reuse (`worktree_reuse`)

An opt-in setting that lets a new coder task reuse a free, clean worktree of the same project instead of creating one. It saves re-installing ignored dependency directories such as `node_modules`. Default: off, and then nothing below applies: spawn creates a fresh worktree and `factory clean` removes merged worktrees, exactly as before.

## Config

| key | default | range | meaning |
|---|---|---|---|
| `worktree_reuse` | `0` | `0` or `1` | `1` turns reuse on |
| `worktree_pool_max` | `2` | `0`..`50` | most FREE pooled worktrees `factory clean` keeps per project; the rest are removed |

Enable it with `factory config worktree_reuse 1`; disable with `factory config worktree_reuse 0`. If `task_clones=1`, that mode wins and reuse is ignored.

## Lifecycle

1. **Clean releases.** `factory clean` finds a merged, pushed, clean worktree whose agent is gone. With reuse on it does not delete the directory: it detaches HEAD at `origin/<base>`, deletes the task branch, clears `tasks.worktree` and records a `free` row in `worktree_pool` (action `pooled`). Every safety refusal of clean (dirty, untracked files, unpushed commits, open PR, live agent, live pane, `kept: has config.worktree`, `git config refused`) still applies; see [Poisoned pooled worktree](#poisoned-pooled-worktree). After pooling, clean trims the free rows of each project to `worktree_pool_max`, oldest release first (action `removed`, reason `pool over cap`). A `claimed` row is never removed or trimmed.


Reset also unlinks (never follows) a symlinked `refs/` or `refs/worktree`, `refs/bisect`, `refs/rewritten` in the worktree admin dir before any git call, and its verification fails if one is left. The claim and the `tasks.worktree`/`branch` update happen in one transaction.
A failed `git branch -D` on release fails closed: clean checks the task branch out again in the directory (it is not left detached), does not pool it, leaves `tasks.worktree` set, and reports action `skip` with reason `branch delete failed: ...` (`branch delete failed, re-attach failed: ...` if the re-attach fails too). The next clean retries the release. The `total:` line of a run that trimmed free rows ends `, <p> pooled, <t> trimmed` (before ` [dry run]`), so a trim-only run is visible; without any trim it is unchanged.
2. **Spawn claims.** `factory spawn coder` for a task of the same project claims one free row in a single `BEGIN IMMEDIATE` transaction, so two tasks never get the same worktree. It then resets the worktree to `origin/<base>` on the new branch `factory/<task-id>` and re-runs the git config guard on it. The row becomes `claimed` with the task id; `reset_ok` is set after the reset is verified.

## What reset keeps and removes

- Kept: ignored files (`node_modules`, build caches, anything matched by `.gitignore`).
- Removed: untracked files and directories (including nested repositories), staged and modified tracked files, per-worktree git config (`config.worktree`), and merge, rebase, cherry-pick, revert and bisect state left by the previous task.

## Fallback and events

Any failure while claiming or resetting the pooled directory (ownership mismatch, git error, the pooled directory's own config guard refusal, no free row) falls back to a fresh worktree, so a task is never blocked by the pool. A forbidden `config.worktree` in ANY worktree's admin dir of the repo is different: it trips the repo-level guard first and `factory spawn` exits 4 (see [Poisoned pooled worktree](#poisoned-pooled-worktree)). Events:

| event | when |
|---|---|
| `worktree-pooled` | clean released a worktree to the pool |
| `worktree-reused` | spawn claimed and reset a pooled worktree (`path`, `task`, `from_task`) |
| `worktree-reuse-failed` | a claim or reset failed; spawn fell back to a fresh worktree (`step`, `error`) |
| `worktree-pool-trimmed` | clean removed a free row above `worktree_pool_max` |
| `worktree-gitdir-mismatch` | a worktree's `.git` did not point at its own admin directory (forged or symlinked); it is left alone and the director is told |

## Poisoned pooled worktree

1. The git config guard reads the `config.worktree` of every worktree of the repo. ONE worktree whose admin dir holds a forbidden key (for example `core.fsmonitor`) makes every `factory spawn` of that repo exit 4, pooled or not, and also with `worktree_reuse=0`.
2. `factory clean` never pools a dir whose admin dir has a `config.worktree` (action `skip`, reason `kept: has config.worktree`; a stale claim stays claimed). With a forbidden key it reports `git config refused` as before. Clean keeps the dir and reports it on every run until the file is gone.
3. The spawn error names the pooled path, its state and the file: `spawn refused: git config in <repo> would run code: <keys>; pooled worktree <path> (free) has <repo>/.git/worktrees/<name>/config.worktree: move that file out of the repository ...`. Finding it uses filesystem reads only; no git command runs after the refusal.
4. Recovery: inspect the file, then move it out of the repository (keep it to find out who wrote it), e.g. `mv <repo>/.git/worktrees/<name>/config.worktree /home/user/quarantine/`, and run the spawn again. The next claim resets the dir as usual.

## The `worktree_pool` table

One row per pooled directory: `path`, `project_id`, `state` (`free` or `claimed`), `task_id`, `reset_ok`, `claimed_at`, `released_at`. See [db-layout.md](db-layout.md).

## Non-goals

- No sharing of one worktree between concurrent tasks.
- No reuse for roles other than coder, and no reuse across projects.
- No pooling of worktrees that clean would refuse to remove.

## Accepted residual risk

Ownership of a pooled directory is checked (symlink- and forged-`.git`-safe) before each use, but there is a same-uid TOCTOU window between that check and the git command that follows. Another process running as the same user could swap the directory in between. Only a per-agent uid or a mount namespace closes it; see [git-hardening.md](git-hardening.md).

## Tests

`tests/test_clean.py` (`WorktreeReuseLifecycleTests`, the whole cycle through the CLI, including `test_poisoned_pooled_worktree_spawn_message` and `test_poisoned_unpooled_worktree_message_unchanged`), `CleanPoolTests` (including `test_forbidden_config_worktree_not_pooled`, `test_config_worktree_with_allowed_keys_not_pooled`, `test_stale_claim_with_config_worktree_stays_claimed`), and `tests/test_git_hardening.py` (`WorktreeReuseSpawnTests`).
