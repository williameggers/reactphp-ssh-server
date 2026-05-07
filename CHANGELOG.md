# Changelog
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 1.0.5 - 2026-05-07

### Fixed

  * Fixed channel input backpressure so paused channels buffer inbound client data and flush it in order when resumed, instead of emitting data immediately while the channel is paused.
  * Fixed outbound channel flow control to respect SSH remote window updates and underlying transport backpressure, queuing unsent channel data correctly and avoiding duplicate re-queueing of bytes already accepted by the transport.
  * Fixed AES-CTR packet parsing to handle partial packets safely, including packets split across ciphertext and MAC boundaries, without desynchronizing decryptor state.

## 1.0.4 - 2026-04-01

### Fixed

  * Corrected SSH channel shutdown behavior so `Channel::end()` and `Channel::close()` only close the active channel instead of terminating the underlying SSH connection.
  * Deferred channel EOF and close packets until pending exec and shell request replies have been sent, preventing reply and close ordering issues.
  * Improved server host key initialization so the server waits for host keys to be ready before accepting connections, including compatibility with loops that cannot watch regular files as streams.

### Changed

  * Updated the README and examples to reflect the clarified channel lifecycle and exposed server and connection APIs.
  * Hardened algorithm and key material handling with stricter validation during negotiation and PEM export.

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
