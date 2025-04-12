# Documentation Default Version Fix

This document outlines the manual step needed to set the default documentation version to "latest" after the next release is deployed.

## Problem

The documentation system uses Mike (based on MkDocs) to handle versioning. When a new release is published, the docs workflow creates documentation for that version and aliases it as "latest", but it doesn't set this "latest" version as the default version that users see when they visit the documentation site.

Currently, the default version is the development version, but we want users to see the latest stable release by default.

## Solution

After the next release is published and its documentation has been deployed by the release docs workflow, someone with direct write permissions to the gh-pages branch should run this command manually once:

```bash
uv run --group docs mike set-default latest --push
```

This command needs to be run only once. It sets the default version to "latest", which is always aliased to the most recent release during the documentation build process.

## When to Run This Command

Run this command only after the next release's documentation has been deployed by the CI workflow. There is no need to run this command after subsequent releases, as it only needs to be set once.

## Developer

- Name: MXDI
- Email: ssddssdd1212m@gmail.com
