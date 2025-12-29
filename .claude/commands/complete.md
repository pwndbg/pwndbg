# Complete PR Checklist

Run all contribution checks before submitting a PR. This follows the pwndbg contributing guidelines.

## Instructions

Execute the following checks in order. Stop and fix any issues before proceeding to the next step.

### 1. Linting (Required)
Run the linting script:
```bash
./lint.sh
```
If there are formatting issues, run `./lint.sh -f` to auto-fix them, then run `./lint.sh` again to verify.

### 2. Unit Tests (Required)
Run the unit test suite:
```bash
./unit-tests.sh
```
All tests must pass.

### 3. mypy --strict Check (Required)
First, identify modified Python files compared to dev branch:
```bash
git diff dev --name-only --diff-filter=AM | grep '\.py$'
```

Then run mypy --strict on those files:
```bash
uv run mypy --strict <modified_files>
```

If there are errors:
- Add missing return type annotations (e.g., `-> None` for functions that don't return)
- Add parameter type annotations where missing
- Fix any other type errors

Re-run until all errors are resolved.

### 4. Documentation Verification (If Applicable)
If you modified any user-facing elements (commands, config values, function arguments), verify docs:
```bash
./scripts/verify-docs.sh
```

If verification fails, regenerate docs first:
```bash
./scripts/generate-docs.sh
```

### 5. Git Status Review
Show the current git status and diff summary:
```bash
git status
git diff --stat
```

### 6. Final Summary
After all checks pass, provide a summary:
- List all files changed
- Confirm all checks passed
- Note any warnings or items that need manual review

## Success Criteria
- All linting checks pass
- All unit tests pass
- No mypy --strict errors on modified files
- Documentation is verified (if applicable)
- Code is ready for PR submission
