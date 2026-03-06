# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Migrated packaging to PEP 621 using `pyproject.toml`.
- Removed legacy `Pipfile`/`requirements*.txt` and corresponding lock files.
- Added GitHub Actions CI workflow with linting, type checks and tests.
- Introduced optional dev dependencies under `[project.optional-dependencies]`.
- Added comprehensive unit and integration tests; improved code quality.
- Updated README with new installation and development instructions.
- Added change log (this file).
- Switched from `coloredlogs` to `rich` for enhanced logging output.

## [0.1.0] - 2026-03-05
- Initial public release with extractor logic, CLI, and test suite.
