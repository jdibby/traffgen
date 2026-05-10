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

## CI / Docker Hub

- Every merge to `main` triggers a GitHub Actions build that publishes a multi-arch
  Docker image (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) to Docker Hub as
  `jdibby/traffgen:latest` and `jdibby/traffgen:<sha>`.
- After a PR merges, check that the Docker build CI job passes.
- A second workflow (`docs-check.yml`) runs on PRs that touch `generator.py`,
  `README.md`, or `docs/**` — it emits warnings if suite names or the version
  number are missing from `README.md`.

## Versioning

- Follows semantic versioning: `MAJOR.MINOR.PATCH`
- Current version defined in `generator.py` → `VERSION` constant and module docstring.
- Minor releases (`x.Y.0`) for bug fixes, doc updates, and small features.
- Major releases (`X.0.0`) for breaking changes or large new feature sets.
