# Releasing

A release is a `v*` tag on `main`. CI then tests, builds the image `ghcr.io/ardean/swarmwatch:<version>` with
provenance and SBOM attestations, and creates the GitHub release from `CHANGELOG.md`.

1. In `CHANGELOG.md` turn `## vX.Y.Z - Unreleased` into `## vX.Y.Z - <date>`. The tag fails to build without a
   section of exactly that name.
2. Replace the previous version in `README.md`, `deploy/` and `bin/deploy` examples with the new one.
3. `gofmt -l .`, `go vet ./...` and `go test -race ./...` must be clean.
4. Commit, then `git tag vX.Y.Z` and push `main` and the tag.
5. Check that the workflow is green, the release page shows the changelog section, and
   `docker run --rm ghcr.io/ardean/swarmwatch:X.Y.Z version` prints `X.Y.Z`.

Versioning: while the version is 0.x a minor release may change behavior and says so under **Upgrading** in the
changelog. The `/api/v1` types in `pkg/api` only ever gain fields; a breaking change to them is `/api/v2`.
