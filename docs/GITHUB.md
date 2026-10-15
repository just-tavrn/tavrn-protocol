# GitHub setup of tavrn-protocol

What the repository expects on GitHub and what the owner has to switch on by hand. The repository starts
private; nothing runs on GitHub until `CI_ENABLED` is set.

## Already set (through `gh api` when the repository was created)

- Default branch `main`, squash merges allowed, branches deleted after merge.
- Issues on, wiki off, projects off.
- Labels from `scripts/github-labels.sh`: the common set plus `scripts/labels.txt` (rerun it after editing the list; it is idempotent).

## Variables (Settings → Secrets and variables → Actions → Variables)

| Variable | Value | Effect |
|---|---|---|
| `CI_ENABLED` | `true` | Every job of every workflow is gated by it (`ci.yml`, `release.yml`, `dependency-review.yml`, `cla.yml`, and the organization's gitleaks workflow). Unset or any other value: nothing runs. |
| `NPM_PUBLISH_ENABLED` | `true` | `release.yml` also publishes `@tavrn/protocol` to npm. Leave unset during the private phase; the release then only creates the GitHub release with the packed tarball. |

## Secrets

| Secret | Scope | Used by |
|---|---|---|
| `PUBLISH_CHECK_PRIVATE` | repository or organization | `ci.yml` (job `publish-check`): comma-separated private domains, hosts and addresses that must never appear in the tree. Without it the check fails on purpose. Dependabot's pull requests see only Dependabot secrets, so add it there too (`gh secret set PUBLISH_CHECK_PRIVATE --app dependabot`); without it their workflow sets `PUBLISH_CHECK_ALLOW_UNCONFIGURED=1` and only the private-pattern step is skipped, with a warning (the push to `main` runs the full check). Locally the same list lives in an untracked `.publish-check.private` (in the repository or its parent directory). |
| `CLA_PAT` | organization | `cla.yml`: fine-grained personal access token with Contents read and write on `just-tavrn/cla-signatures` (the signatures). |
| `NPM_TOKEN` | environment `release` (never a repository secret) | `release.yml`, job `publish`: an npm automation token with publish rights on the `@tavrn` scope. Only needed once `NPM_PUBLISH_ENABLED` is set. |

The environment `release` (Settings → Environments): deployment only from tags `v*`, required reviewer the owner,
`NPM_TOKEN` as its secret (`gh secret set NPM_TOKEN --env release`). Only the job `publish` declares it; it runs no
code of the repository and installs nothing.

## Settings to switch on by hand

- **Discussions** stay off here: the issue template's "Ask a question" link points to the Discussions of the
  umbrella repository `just-tavrn/tavrn` (category **Protocol**).
- **Private vulnerability reporting** (Settings → Code security): the issue template's security link points to
  `security/advisories/new`.
- **Secret scanning and push protection** (Settings → Code security; free for public repositories).
- **Dependabot alerts and security updates** (Settings → Code security). `dependabot.yml` already asks for
  weekly, grouped updates of the workflow actions.
- **Actions permissions**: allow the organization's reusable workflows (`just-tavrn/.github`) and the actions
  used in `.github/workflows/` (`actions/*`, `contributor-assistant/github-action` through the CLA workflow).
  While `just-tavrn/.github` is private, its Settings → Actions → General → Access must be set to "Accessible
  from repositories in the just-tavrn organization". Until that repository exists and is accessible, every
  push shows a failed `CI` run with "workflow file issue" (the `gitleaks` job references it); no job runs.
- **Dependabot** runs on GitHub's side as soon as `dependabot.yml` exists (it is not gated by `CI_ENABLED`). To
  keep it quiet during the private phase, pause it under Insights → Dependency graph → Dependabot.
- **Once the repository is public** (branch protection and rulesets are not available on private
  repositories of the free organization plan): protect `main` with a ruleset: pull request required, one
  approving review from `@just-tavrn/maintainers` (CODEOWNERS), required checks `Schemas, test vectors, SPDX
  headers, package`, `Publication hygiene`, `Secret scan (gitleaks)` and `Contributor license agreement`,
  linear history, no force pushes, no deletions; protect tags `v*` against deletion and updates, and let only
  organization owners create them (just-tavrn/.github `scripts/github-rulesets.sh`).
- **Team** `@just-tavrn/maintainers` must exist in the organization for CODEOWNERS to work.

## Releases

1. Update the documents and test vectors; set `version` in `package.json`.
2. Commit, tag `vX.Y.Z` (equal to the package version) and push the tag (only organization owners may).
3. With `CI_ENABLED` the release workflow's job `build` checks the tag against `package.json`, runs the tests and
   packs the tarball without any secret; `release` creates the GitHub release with it; with `NPM_PUBLISH_ENABLED`,
   `publish` waits for the owner's approval of the environment `release` and publishes that same tarball to npm
   with provenance after comparing it with `npm pack --ignore-scripts` of the tag (no install and no code of the repository in the job that holds `NPM_TOKEN`).

During the private phase the node (`tavrn-node`) and the JavaScript packages (`tavrn-js`) carry this
repository as a git submodule pinned to a tag. After a new tag, bump the submodule there.
