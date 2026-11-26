# Distribution spec

Source of truth for how irc-serve ships: release artifacts, naming,
channels, trust, and the release process. Follows established OSS server
conventions (Caddy / Prometheus / etcd / Gitea / MinIO patterns).

Derived from 2026-11-26 distribution research (binary, package-manager,
and trust sweeps).

## Purpose

Users install without building. Every release is reproducible from a tag,
verifiable by checksum + attestation, and shaped the way operators expect:
same names, same layout, same install paths as every other server they run.

## Requirements

### Requirement: Release artifacts

Each stable release SHALL ship binary tarballs for every supported
platform, named and laid out per convention.

#### Scenario: Asset matrix
- **WHEN** a `v*` tag is pushed
- **THEN** the release carries `irc-serve-<ver>-<os>-<arch>.tar.gz` for
  linux-amd64, linux-arm64, darwin-arm64 — GOOS-GOARCH spellings
  (`amd64`, not `x64`; `darwin`, not `macos`), dash-separated, no vendor
  string, no TLS qualifier (TLS is always on — see TLS surface).

#### Scenario: Tarball contents
- **WHEN** a user extracts a tarball
- **THEN** it yields one prefixed directory
  `irc-serve-<ver>-<os>-<arch>/` containing the `irc-serve` binary,
  LICENSE, NOTICE, and README.md — never a bare binary polluting cwd.

#### Scenario: TLS is not a variant
- **WHEN** any release binary is built
- **THEN** TLS is compiled in (links libssl/libcrypto); there is no
  `tlsOFF`/`tlsON` matrix. Upstream TLS variants are extinct (Caddy,
  Prometheus, etcd ship one binary); the OFF build survives only as a CI
  cell proving the zero-dependency claim, never as a release artifact.

#### Scenario: Version truth
- **WHEN** a release binary runs `--help` or registers
- **THEN** the first line / 002 / 004 report exactly the release tag
  (`irc-serve-1.0.0` for tag `v1.0.0`); CI fails on mismatch
  (`test_version_truth`).

### Requirement: Checksums and trust

Releases SHALL prove integrity by checksum and authenticity by
attestation; tags and assets are immutable.

#### Scenario: Aggregated checksums
- **WHEN** a release publishes
- **THEN** one `SHA256SUMS` file covers every asset
  (`sha256sum -c` compatible, filenames exact). Per-asset `.sha256`
  sidecars are also shipped (cheap, script-friendly).

#### Scenario: Build provenance
- **WHEN** a release publishes
- **THEN** each tarball carries a Sigstore attestation bundle
  (GitHub `attest-build-provenance`, zero key management), verifiable
  with `gh attestation verify <file> --owner tweak-wiki`. Unsigned
  sha256 alone proves integrity, not authenticity.

#### Scenario: Tags are annotated and immutable
- **WHEN** a release is cut
- **THEN** the tag is annotated (`git tag -a vX.Y.Z`), never moved,
  never force-pushed; assets are never re-uploaded (cut vX.Y.Z+1
  instead). Immutable Releases is enabled in repo settings.

#### Scenario: Verification docs
- **WHEN** a user opens the release notes or README install section
- **THEN** they find copy-pasteable `sha256sum -c` and
  `gh attestation verify` blocks.

### Requirement: Distribution channels

Channels SHALL be added in impact order; each new channel follows the
minimal-correct shape for its ecosystem.

#### Scenario: Channel priority
- **WHEN** planning distribution work
- **THEN** the order is: (1) GitHub tarballs (done — the universal
  fallback every downstream packager consumes); (2) Docker image on
  `ghcr.io` (distroless multi-stage, non-root, tags `latest` +
  `1.2.3` + `1.2` + `1`); (3) own APT repo (`.deb`) + COPR (`.rpm`);
  (4) Homebrew tap; (5) AUR `-bin`; (6) upstream distro repos (defer).
  Snap/Flatpak are explicitly out (desktop formats, negative ROI for
  daemons).

#### Scenario: Debian package shape
- **WHEN** a `.deb` is built
- **THEN** it installs `/usr/bin/irc-serve`, a systemd unit via
  `dh_installsystemd`, config as a conffile (upgrades never clobber
  user edits), and creates the `irc-serve` system user idempotently
  (`sysusers.d` preferred, `adduser --system` fallback).

#### Scenario: RPM package shape
- **WHEN** a `.rpm` is built
- **THEN** it mirrors the deb via a single spec: `%systemd_*` macros,
  `%config(noreplace)` conffiles, `%sysusers_create_compat` user.

#### Scenario: Docker image shape
- **WHEN** the image builds
- **THEN** it is distroless/static multi-stage, runs non-root
  (uid 65532), `EXPOSE`s 6667/6697, `ENTRYPOINT` in exec form, with a
  `HEALTHCHECK` and `org.opencontainers.image.source` label.

### Requirement: Release process

Releases SHALL be cut the same way every time: bump, tag, notes,
binaries, verify.

#### Scenario: Version bump
- **WHEN** cutting release X.Y.Z
- **THEN** one PR updates the macro in `src/core/server.h`, the Debian
  changelog (newest entry matches), the Homebrew formula, the
  packaging README claim, and the SPEC_TRACKING transcript —
  `test_version_truth` + `check-packaging.py` enforce agreement.

#### Scenario: Tag and notes
- **WHEN** the bump merges
- **THEN** an annotated tag `vX.Y.Z` is pushed and a GitHub release
  created with notes shaped: Highlights, Breaking/Upgrade notes,
  Security fixes, Full Changelog link. Pre-releases use SemVer
  `-rc.N` suffixes and the prerelease flag (never `latest`).

#### Scenario: Binaries build automatically
- **WHEN** the tag lands (or manual dispatch with a tag)
- **THEN** the release workflow builds the full matrix, smoke-tests
  each binary (`--help` version), asserts linkage, packages
  tarball + checksums, and attaches everything to the release.
  No laptop-built artifacts, ever (provenance requires Actions builds).

#### Scenario: Old releases kept
- **WHEN** a new release ships
- **THEN** old releases and assets stay untouched, forever. Prune
  nothing except superseded `rc`/`nightly` builds, and document it if
  so.
