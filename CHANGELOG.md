# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.3

### Fixed

- Files are now written atomically (write to a temporary file and rename) so a crash or concurrent reader can never see a partially written secrets file. The mode of an existing file is preserved.
- New secrets files are now created readable and writable only by the owner (mode 0600) instead of relying on the process umask. The mode of an existing file is still preserved.
- `secret_keys init` now uses an exclusive file create so it can no longer overwrite a file created between the existence check and the write.
- `SecretKeys#save` no longer raises `ArgumentError` when passed a `Pathname`.
- An unsupported `.version` value that is a string now raises `SecretKeys::VersionError` instead of a comparison `ArgumentError`; numeric strings like `"1"` are accepted.
- Input that does not parse to a Hash now raises a clear `ArgumentError` instead of failing with confusing errors; input that parses to nothing (e.g. only comments) loads as an empty document.
- A non-Hash value in the `.encrypted` key now raises a clear `ArgumentError`.
- `SecretKeys#encryption_key=` now raises `SecretKeys::EncryptionKeyError` when given a nil or empty key instead of silently keeping the old key.
- The `--secret-key-file` CLI option now reports a missing file as a clean error instead of an unhandled `Errno::ENOENT`.

## 1.0.2

### Changed

- Follow [RFC 4648](https://www.ietf.org/rfc/rfc4648.txt) base 64 encoding, removing line-feeds from the encoded data.

## 1.0.1 (June 01, 2020)

### Fixed

- Fix missing documentation links

## v1.0.0 (May 31, 2020)

### Added

- Initial release
