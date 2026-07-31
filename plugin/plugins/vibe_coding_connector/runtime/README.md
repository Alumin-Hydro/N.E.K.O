# Pinned HAPI runtime

This directory describes the unmodified official HAPI `v0.25.1` release
artifacts used by the connector. The Windows x64 archive is included in the
plugin package so Windows users do not need Bun, npm, or a separate HAPI
installation.

- Release: <https://github.com/tiann/hapi/releases/tag/v0.25.1>
- Source commit:
  <https://github.com/tiann/hapi/commit/f0e7e6ad200256550a3cae35b05b9935ed10ad45>
- License: `AGPL-3.0-only`
- Official checksums:
  <https://github.com/tiann/hapi/releases/download/v0.25.1/checksums.txt>
- Bundled Windows asset: `bundles/hapi-v0.25.1-win32-x64.zip`

`manifest.json` locks the source URL, asset URL, size, archive SHA256, and
expected executable path. `prepare_bundle.py` only fetches assets already
listed in that manifest and verifies their byte count and SHA256 before
atomically placing them in `bundles/`; it never resolves a "latest" release.

Only Windows x64 is bundled in the immediate delivery. The same manifest
supports verified opt-in fetching on macOS and Linux. On those platforms the
panel reports that the runtime is not bundled unless the user explicitly
enables verified download or selects advanced external-HAPI mode.

HAPI extracts its own embedded Difftastic, ripgrep, and tunwg helper tools into
its isolated `HAPI_HOME` on first run. The exact license texts carried by the
fixed HAPI source are retained separately under `licenses/`, together with the
HAPI AGPL license and CLI NOTICE:

- `DIFFTASTIC-LICENSE-MIT.txt`
- `RIPGREP-LICENSE.txt`
- `TUNWG-LICENSE-MIT.txt`

`THIRD_PARTY_NOTICES.md` links each text to the immutable HAPI source commit
and explains how the official single executable embeds it. The connector does
not modify the HAPI executable or those helpers.
