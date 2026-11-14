# Contributing

## Prerequisites

Install [mise](https://mise.jdx.dev/) to get the pinned Node and pnpm versions from `.mise.toml`:

```bash
mise install
pnpm install
```

## Checks

```bash
pnpm typecheck
pnpm test
pnpm build
```

All three must pass before opening a pull request.

## Branch and PR process

1. Create a feature branch from `main`.
2. Keep PRs focused: one logical change per PR.
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for PR titles and commit messages: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, etc.
4. If your change affects a published package, add a changeset (see below).

## Changesets

This repo uses [Changesets](https://github.com/changesets/changesets) to version and publish `@aptos-labs/inference-sdk` and `@aptos-labs/inference-verifier`.

Add a changeset for any change that affects a published package:

```bash
pnpm changeset
```

Pick the affected packages and a bump type, describe the change, and commit the generated `.changeset/*.md` file alongside your code.

| Type | When to use |
|---|---|
| `patch` | Bug fixes, internal refactors with no API impact |
| `minor` | New functionality, backwards-compatible |
| `major` | Breaking changes to the public API |

Changes that do **not** need a changeset: CI configuration, dev tooling, test-only changes, documentation. CI runs **Require Changeset** when `packages/*/src`, `packages/*/package.json`, `tsconfig.base.json` or `pnpm-lock.yaml` change; label a PR `skip-changeset` or prefix its title with `chore:` to opt out (see [`changeset-check.yml`](.github/workflows/changeset-check.yml)).

## Releasing

Releases are automated by [`release.yml`](.github/workflows/release.yml) on every push to `main`:

1. While changesets are pending, `changesets/action` opens or updates a **chore: version packages** PR. It runs `pnpm run version-packages`, which applies the changesets (bumps versions, writes each package's `CHANGELOG.md`, deletes the consumed changesets) and refreshes `pnpm-lock.yaml`.
2. Merging that PR publishes every package whose version is not yet on npm (`pnpm run release` = build + `changeset publish`), pushes a `<name>@<version>` git tag per package, and creates a GitHub Release from the changelog entry.

npm authentication uses [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC, `id-token: write`), so no npm token is stored. The release job requires provenance: `publishConfig.provenance` is set on both packages, and the workflow sets `NPM_CONFIG_PROVENANCE` and `npm_config_provenance`. `publish` fails if npm cannot attach the attestation, which it only does for a public package published from this public repository. Both packages are configured with this repository and the `release.yml` workflow as their trusted publisher (`npm trust list <package>` shows it). A new package has to exist on npm before it can be trusted: build first (`files` whitelists `dist`), check the tarballs, publish any dependency before its dependents, then add the trust with npm ≥ 11.15:

```bash
pnpm build
pnpm -r pack --pack-destination /tmp/pk && for f in /tmp/pk/*.tgz; do tar tzf "$f"; done
npm publish /tmp/pk/<tarball>.tgz --access public
npm trust github <package> --repo aptos-labs/aptos-inference-sdk-ts --file release.yml --allow-publish
```

`npm publish <tarball>` rather than `pnpm publish`: the pnpm→npm passthrough cannot complete the browser 2FA prompt, while the pnpm-built tarball already has `workspace:*` ranges resolved.

The release job commits and opens PRs as the Aptos Labs bot (`vars.APTOS_LABS_BOT_APP_ID` / `secrets.APTOS_LABS_BOT_APP_PRIVATE_KEY`). Repository settings must allow GitHub Actions to create pull requests (**Settings → Actions → General → Allow GitHub Actions to create and approve pull requests**).
