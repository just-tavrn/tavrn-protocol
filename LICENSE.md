# Licensing of the tavrn protocol

This repository carries two licenses, so that implementers can copy the machine-readable parts
into their code without attribution clauses meant for documents, while the specification text stays
attributable.

| What | Files | License |
|---|---|---|
| Schemas, test vectors and permission tables (machine-readable) | `openapi.json`, `testvectors/*.json`, the permission bit tables in `permissions.md` (the tables and the numeric values in them) | [Apache-2.0](LICENSE-APACHE), see also [NOTICE](NOTICE) |
| Specification prose | `PROTOCOL.md`, `ENCRYPTION.md`, `FEDERATION.md`, `VOICE.md`, `WHITEBOARD.md`, `FILES.md`, `APPLICATIONS.md`, `ENTITLEMENTS.md`, `SEARCH.md`, `LEGAL.md`, `MODERATION.md`, `CHANGELOG.md`, `README.md`, `docs/` and the explanatory text of `permissions.md` | [CC-BY-4.0](LICENSE-CC-BY-4.0) |
| Repository tooling | `package.json`, `scripts/`, `test/`, `.github/` | [Apache-2.0](LICENSE-APACHE) |

SPDX expression for the repository (and the npm package `@tavrn/protocol`) as a whole: `Apache-2.0 AND CC-BY-4.0`.

Attribution for the prose (CC-BY-4.0 section 3): name "the tavrn project", link to the specification
(the repository or the published file) and state whether you changed it, for example
"Based on the tavrn protocol specification by the tavrn project, licensed under CC-BY-4.0, modified".

Code samples inside the prose (JSON snippets, pseudo code) may additionally be used under Apache-2.0, so
an implementation that copies them stays under a single code license.

The name "tavrn" and the logo are not licensed by either license; see [TRADEMARK.md](TRADEMARK.md).
