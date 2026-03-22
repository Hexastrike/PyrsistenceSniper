# CHANGELOG


## v0.7.1 (2026-03-22)

### Bug Fixes

- Prevent column resize from triggering sort in HTML report
  ([`00c6036`](https://github.com/Hexastrike/PyrsistenceSniper/commit/00c603603463d5ea462af676fd681e03d9d74d34))

- Use official semantic-release action and skip CI on release commits
  ([`4667bb4`](https://github.com/Hexastrike/PyrsistenceSniper/commit/4667bb4f7f5e77f8478fb8b9f1d5e18d136df551))


## v0.7.0 (2026-03-22)

### Bug Fixes

- Add path traversal guard and debug logging to all plugin except blocks
  ([`e3a593a`](https://github.com/Hexastrike/PyrsistenceSniper/commit/e3a593a41d67afcd121f44a979844faaa0278f99))

- Bump version to 0.6.1.1
  ([`a90dc7d`](https://github.com/Hexastrike/PyrsistenceSniper/commit/a90dc7ddf06e664214925861d52cf4d945378797))

- Handle PermissionError on directory access, move tracebacks to debug level
  ([`c660fe6`](https://github.com/Hexastrike/PyrsistenceSniper/commit/c660fe6592a3f5620de644299463e3d044a8a4bd))

- Pass CODECOV_TOKEN to codecov upload action
  ([`961d813`](https://github.com/Hexastrike/PyrsistenceSniper/commit/961d813eea0059c9e9b3b162cf052e3ce9e07c54))

- Prevent standalone mode from loading sibling hive files
  ([`6350506`](https://github.com/Hexastrike/PyrsistenceSniper/commit/63505068eaf5b0eaa1a6da699e9759c0a48b86ce))

- Use absolute URLs in README for PyPI rendering
  ([`a6da982`](https://github.com/Hexastrike/PyrsistenceSniper/commit/a6da982b7d2e3389f6b0b9849d3945f85fde7a8d))

### Chores

- **release**: V0.7.0
  ([`27c2d35`](https://github.com/Hexastrike/PyrsistenceSniper/commit/27c2d358e172b288a5cfc9347a177228d433cc76))

### Documentation

- Clarify paths argument, add loose hive example, remove dead code
  ([`d48f0be`](https://github.com/Hexastrike/PyrsistenceSniper/commit/d48f0be9481394aee5cf687a2ded9807d925a723))

- Rewrite README with full check reference, detection profile guide, and pipeline overview
  ([`6bc1b35`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6bc1b354bff3b181394a557391a097a10ff6a28b))

- Rewrite README with usage examples and add Dockerfile
  ([`22695ef`](https://github.com/Hexastrike/PyrsistenceSniper/commit/22695efda7c6129b1f315fe324da538a2e899f8f))

- Update README title
  ([`7c1df07`](https://github.com/Hexastrike/PyrsistenceSniper/commit/7c1df07ef0f70edad04b8caacc9373a2043ca060))

### Features

- Add CI workflow with Codecov and replace signify/oscrypto with lief
  ([`1d464ac`](https://github.com/Hexastrike/PyrsistenceSniper/commit/1d464ac81765b5328486938c07972489901bb9b3))

- Add interactive dark-mode HTML report output with filtering, sorting, and column resizing
  ([`cc789f6`](https://github.com/Hexastrike/PyrsistenceSniper/commit/cc789f66f6e86e91beb58c6a4dcbbea935ea95dc))

- Add persistence detection plugins, XLSX output, and refactored code codebase
  ([`4a3d14a`](https://github.com/Hexastrike/PyrsistenceSniper/commit/4a3d14afc8c9e597ab38b6a2bdf8b03919833341))

- Add PyPI metadata, publish workflow, and pip install instructions
  ([`0a9bb44`](https://github.com/Hexastrike/PyrsistenceSniper/commit/0a9bb44c61505d7362a911d6b9dc3ec2bce1cff8))

- Add python-semantic-release for automated versioning
  ([`e7b173e`](https://github.com/Hexastrike/PyrsistenceSniper/commit/e7b173e00d4142b2f1175ea88487cd62de3ed3fc))

- Capitalize signer values and add wab.exe, 7-zip, explorer.exe whitelist rules
  ([`f1d3ccd`](https://github.com/Hexastrike/PyrsistenceSniper/commit/f1d3ccdaa9d099b5e761906637aac07f5458d581))

- Improve HTML report with checkbox filters, dual-axis scrolling, and column resize
  ([`cbe18f3`](https://github.com/Hexastrike/PyrsistenceSniper/commit/cbe18f33343034798bd8235f88fccacb65847704))

### Refactoring

- Add recurse flag to declarative plugin engine and pre-commit hooks
  ([`a70c445`](https://github.com/Hexastrike/PyrsistenceSniper/commit/a70c445fafc5778c43028141b1a8f4f8e65d2e0e))

- Change paths positional arg to single path
  ([`30cc48c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/30cc48c20277bd083b7b699f3a8c5ef5c8870d1b))

- Consolidate domain layer into core and simplify plugin architecture
  ([`95c168f`](https://github.com/Hexastrike/PyrsistenceSniper/commit/95c168f9d239693c02fc45e5dd9956fff8fdfa8d))

- Quality-pass all plugins, expand test coverage, clean up core internals
  ([`e107aa1`](https://github.com/Hexastrike/PyrsistenceSniper/commit/e107aa14b2c4aeda301f3560db4a191ba55e8815))

- Rename AllowRule to FilterRule
  ([`b17d6fc`](https://github.com/Hexastrike/PyrsistenceSniper/commit/b17d6fc94dc20bef0db2cb3bb25d146295c624d6))

- Simplify SignerExtractor by extracting catalog lookup and dropping unused Path from cache
  ([`bdb339e`](https://github.com/Hexastrike/PyrsistenceSniper/commit/bdb339e64e56abab25736e391139dd5998a427ed))

- Update directory structure, remove ForensicImage, add Context object
  ([`6148756`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6148756ba17b7cac03b87c593d4319b3aad3f85c))
