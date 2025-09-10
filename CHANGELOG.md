# Changelog
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 1.0.3 - 2025-09-10

### Changed

  * Enhanced the `Server` class to allow specifying a host key path directly
    in the constructor, with updated PHPDoc to reflect the revised
    parameters.
  * Bumped the `Server` version to **1.0.3** to mark the change.

### Added

  * Introduced Rector to the project for automated refactoring support and
    performed general code cleanup.

## 1.0.2 - 2025-09-05

### Changed

  * Prevented the server from sending a duplicate KEXINIT if the key exchange
    process was already in progress.

## 1.0.1 - 2025-09-05

### Changed

  * Updated handshake logic to support clients, such as **SyncTerm**, that expect the server to send its identifier first.
  * Adjusted handshake behavior so the server can initiate the KEXINIT exchange after a short timeout, instead of waiting indefinitely for the client.

### Added

  * Implemented client identifier parsing to detect support for the **EXT_INFO** message (RFC 8308), primarily for improved compatibility with **PuTTY**.

## 1.0.0 - 2025-07-02

  * Initial release