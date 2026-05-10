# Claude Code — Project Guidelines

## Git Workflow

- **Always use the PR workflow.** Never push directly to main.
- Make changes on a feature branch, push the branch, open a PR.
- Wait for user approval before merging unless explicitly told to merge directly.
- Use descriptive branch names: `feature/...`, `fix/...`, `release/...`

## Repository

- GitHub repo: `jdibby/traffgen`
- Default branch: `main`
- Use `mcp__github__push_files` or branch pushes + PR for all merges to main.

## Versioning

- Follows semantic versioning: `MAJOR.MINOR.PATCH`
- Current version defined in `generator.py` → `VERSION` constant and module docstring.
- Minor releases (`x.Y.0`) for bug fixes, doc updates, and small features.
- Major releases (`X.0.0`) for breaking changes or large new feature sets.
