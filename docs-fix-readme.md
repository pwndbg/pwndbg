# Documentation Default Version Fix

This fix addresses the issue that the default documentation version was not automatically set to the latest release version rather than the development branch.

## Problem

The documentation system uses Mike (based on MkDocs) to handle versioning. When a new release is published, the docs workflow creates documentation for that version and aliases it as "latest", but it doesn't set this "latest" version as the default version that users see when they visit the documentation site.

## Solution

This fix modifies the GitHub Actions workflow file `.github/workflows/docs-release.yml` to add an additional step that runs after the documentation deployment:

```yaml
- name: Set latest as default version
  run: |
    uv run --group docs mike set-default latest --push
```

This ensures that after each new release, the default documentation version that users see will be the "latest" release version rather than the development version.

## Developer

- Name: MXDI
- Email: ssddssdd1212m@gmail.com
