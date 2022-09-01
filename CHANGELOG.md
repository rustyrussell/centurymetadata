# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.2] - The One With 33-Byte Pubkeys

### Added

- Web page now has logo
- `fetchdepth` API to indicate how many hex characters each prefix is bundled with.
- `server/setup.sh`: script for setting up initial repository, and updating depth.

### Changed

- We now use normal 33-byte compressed pubkeys everywhere.
- Python code depends on secp256k1 package.

### Deprecated

### Removed

- fetchindex: we now use a simple depth to divide bundles.

### Fixed

- "make check" is now clean.

## [0.0.1] - Initial release

[0.0.1]: https://github.com/rustyrussell/centurymetadata/releases/tag/v0.0.1
[0.0.2]: https://github.com/rustyrussell/centurymetadata/releases/tag/v0.0.2
