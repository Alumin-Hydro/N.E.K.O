# Third-party notices

## HAPI 0.25.1

The Vibe Coding Connector redistributes the unmodified official Windows x64
HAPI release archive:

- Project: <https://github.com/tiann/hapi>
- Release: <https://github.com/tiann/hapi/releases/tag/v0.25.1>
- Source commit:
  <https://github.com/tiann/hapi/commit/f0e7e6ad200256550a3cae35b05b9935ed10ad45>
- Asset:
  <https://github.com/tiann/hapi/releases/download/v0.25.1/hapi-win32-x64.zip>
- Size: `68,793,339` bytes
- Official archive SHA256:
  `dfef0e27ecee40a18b59ae6e946cf7d177362f2f188d81703cc931f681550698`
- Derived `hapi.exe` SHA256 after extracting that verified archive:
  `f68c1ae3672d69f2aa31f969fa5cbc3a3173f847458e4a04d0a8f5cd09dcc99c`
- License: `AGPL-3.0-only`

The full HAPI license is retained at
`licenses/HAPI-LICENSE-AGPL-3.0.txt`. HAPI's CLI notice, including the
happy-cli MIT attribution, is retained at `licenses/HAPI-NOTICE.txt`.

The upstream archive contains only `hapi.exe`; it does not contain these
license files, so the connector packages them alongside the archive.

## Helper tools embedded by the official HAPI executable

HAPI's fixed `v0.25.1` source imports the following helper binaries and
license files into its Bun-compiled executable. On first use, that executable
copies the matching platform assets into its isolated `HAPI_HOME`.

- Difftastic (`difft.exe` on Windows): MIT License. The exact HAPI-carried
  license is retained at `licenses/DIFFTASTIC-LICENSE-MIT.txt`.
- ripgrep (`rg.exe` on Windows): dual-licensed under the Unlicense and MIT
  licenses. The exact HAPI-carried license declaration is retained at
  `licenses/RIPGREP-LICENSE.txt`.
- tunwg (`tunwg.exe` on Windows): MIT License. The exact HAPI-carried license
  is retained at `licenses/TUNWG-LICENSE-MIT.txt`.

The fixed source evidence is:

- [HAPI embedded asset list](https://github.com/tiann/hapi/blob/f0e7e6ad200256550a3cae35b05b9935ed10ad45/cli/src/runtime/embeddedAssets.bun.ts)
- [Difftastic license carried by HAPI](https://github.com/tiann/hapi/blob/f0e7e6ad200256550a3cae35b05b9935ed10ad45/cli/tools/licenses/difftastic-LICENSE)
- [ripgrep license declaration carried by HAPI](https://github.com/tiann/hapi/blob/f0e7e6ad200256550a3cae35b05b9935ed10ad45/cli/tools/licenses/ripgrep-LICENSE)
- [tunwg license carried by HAPI](https://github.com/tiann/hapi/blob/f0e7e6ad200256550a3cae35b05b9935ed10ad45/shared/tools/tunwg/LICENSE)

HAPI embeds identical second copies of the Difftastic and ripgrep license
files beside its tool archives. This connector retains one byte-identical
copy of each distinct license text. It does not modify or separately execute
these helper binaries; they remain components of the verified official HAPI
release executable.
