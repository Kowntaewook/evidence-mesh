# Release process

`VERSION` is the source of truth. Run `python scripts/sync_version.py` after
changing it and commit the synchronized Python/Electron/generated version files.
CI runs `--check`; an inconsistent version is a failed build.

Pushing `v0.4.0` runs `.github/workflows/build-windows.yml`: pinned dependencies,
TShark/source/license acquisition, Python regression and Ruff checks, PyInstaller,
frozen backend smoke, TypeScript, NSIS build, real installed Windows E2E, source
archive and SHA-256 generation, then artifact upload. The release job depends on
every preceding gate. Only that job receives `contents: write`.

The `codex/v0.4.0` branch exercises the same Windows build and E2E without creating
a tag or release. An explicitly published `release/v0.4.0` promotion branch can
run all gates and then create the matching tag and release. A tag created by
`GITHUB_TOKEN` does not start a second tag workflow; that promotion publishes the
artifacts tested in its own run. Ordinary user-pushed tags still use the tag
workflow. An existing tag must already point at the tested commit.

The job creates a **draft** release, uploads every asset and only then publishes
it. Upload failure leaves a draft. An already public release is never overwritten.
Required assets:

- `EvidenceMesh.Setup.0.4.0.exe`
- `EvidenceMesh.CorrespondingSource.0.4.0.zip`
- `Windows-E2E.json`
- `SHA256SUMS.txt`

The source archive includes the exact project commit, native source archives,
patches/build recipes, Python source distributions and full notices. The release
cannot be a binary-only TShark distribution. Asset hashes are checked again by
the release job. Release notes identify supported inputs, Windows requirements,
unsigned status and pending real-memory validation.

Current state: **NOT RELEASED**. The GitHub connection returned 403 on branch
creation in `Kowntaewook/evidence-mesh`; it must be connected to that repository
before a run can be started. No Windows run ID, installer hash or v0.4 release URL
is asserted as an executed result. The latest-release README link may still lead
to the older release until a v0.4 release passes these gates.
