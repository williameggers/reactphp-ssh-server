# AGENTS.md

Guidance for coding agents working in `/workspaces/reactphp-ssh-server`.

## Repo Facts

- PHP library, namespace root `WilliamEggers\React\SSH\`.
- Source: `src/`. Tests: `tests/`. Examples: `examples/`.
- Minimum PHP `8.2`.
- Required extensions: `mbstring`, `openssl`, `sodium`; dev/test also needs `pcntl`.
- CI runs on PHP `8.2`, `8.3`, `8.4`.

## Existing Rule Files

- No prior `AGENTS.md` existed.
- No `.cursorrules` file exists.
- No `.cursor/rules/` directory exists.
- No `.github/copilot-instructions.md` file exists.

## Install

`composer install`

CI-style install:

`composer install --no-interaction --prefer-dist --optimize-autoloader`

## Build / Verify

- No separate build step exists.
- Treat tests plus static analysis as the verification pipeline.
- Whenever code changes are made, run the full CI validation suite before handoff.
- Minimum required verification after code changes:

```bash
composer cs:check
composer test
composer phpstan
```

## Test Commands

- Standard runner: Pest.
- Composer script: `composer test`
- All tests: `composer test`
- CI-style run: `composer test:ci`
- Single file: `composer test -- tests/Unit/PacketTest.php`
- Single test by name: `composer test -- --filter="extracts string and integers correctly"`
- Single file plus filter: `composer test -- tests/Unit/AuthenticationTest.php --filter="invalid credentials"`
- Architecture tests only: `composer test -- tests/Architecture`
- PHPUnit config file: `phpunit.xml.dist`

## Lint / Analysis / Refactoring

- PHPStan: `composer phpstan`
- PHP CS Fixer dry run: `composer cs:check`
- PHP CS Fixer apply: `composer cs:fix`
- Rector: `vendor/bin/rector process`
- Prefer manual edits over Rector unless a broad codemod is intended.

## Recommended Validation

Targeted checks are useful while iterating, but they do not replace the required full CI validation run after code changes.

Targeted change:

```bash
composer test -- tests/Unit/RelevantTest.php
composer phpstan
```

Broader change:

```bash
composer cs:check
composer test
composer phpstan
```

## Project Structure

- Core runtime classes: `Server`, `Connection`, `Channel`.
- Protocol and crypto logic: `Packet`, `PacketHandler`, `Kex`, `KexNegotiator`, `PublicKeyValidator`.
- Value objects live in `src/Values/`.
- Enums live in `src/Enums/`.
- Logging helpers live in `src/Loggers/` and `src/Concerns/`.

## Editing Rules

- Keep changes minimal and local.
- Reuse existing patterns before adding new abstractions.
- Match existing placement and naming.
- Do not add dependencies unless clearly needed.
- Preserve the ReactPHP event-driven, non-blocking model.

## Formatting

Derived from `.php-cs-fixer.php` and existing files:

- Use `declare(strict_types=1);` in PHP files.
- Existing files usually use `<?php declare(strict_types=1);` on one line.
- Use short arrays `[]`.
- Use LF line endings.
- Imports are ordered.
- Use single spaces around binary operators.
- Use spaces around `.` for concatenation.
- Style is PSR-12 plus additional php-cs-fixer rules.

## File Headers

- Source and test files usually include the BSD license header right after `declare(strict_types=1);`.
- New PHP files should follow the style of nearby files.

## Imports

- Prefer `use` statements over fully qualified names in method bodies.
- Function imports are used in the repo, for example `use function React\Promise\Timer\sleep;`.
- Remove unused imports.
- Let php-cs-fixer handle ordering.

## Types

- Add native parameter and return types whenever known.
- Prefer native types over PHPDoc when possible.
- Use PHPDoc for shaped arrays, resources, and details native types cannot express.
- PHPStan runs at max level; type precision matters.
- Do runtime validation when needed because `treatPhpDocTypesAsCertain` is `false`.

## Preferred Features

- Prefer `final` classes.
- Use `readonly` properties or `final readonly class` for immutable value objects when appropriate.
- Use enums for protocol constants where that pattern already exists.
- Constructor property promotion is common and preferred when clear.
- Use strict equality.

## Naming

- Classes and enums: PascalCase.
- Methods and properties: camelCase.
- Constants: UPPER_CASE.
- Tests use descriptive sentence-style names in `test()` or `it()`.
- Value objects are descriptive nouns like `TerminalInfo`, `WinSize`, `KeyboardInteractiveConfig`.

## Control Flow And Comments

- Prefer early returns for guards.
- Keep methods focused.
- Prefer direct code over unnecessary helper extraction.
- Code must be thoroughly documented where intent, protocol behavior, edge cases, or public API usage would otherwise be unclear.
- Add comments only for protocol-specific or non-obvious logic.
- Keep docblocks meaningful; prefer focused PHPDoc and explanatory comments over redundant line-by-line commentary.

## Error Handling

- Fail fast on invalid state or malformed protocol data.
- Common exception types here: `RuntimeException`, `InvalidArgumentException`, `UnexpectedValueException`, `LengthException`.
- Choose the most specific built-in exception that fits.
- Preserve previous exceptions when wrapping lower-level failures.
- Validate stringability before casting `mixed` values to string.
- Prefer explicit checks over silent fallback behavior in parsing and crypto code.

## Logging

- Logging is PSR-3 based.
- Default behavior often uses `NullLogger`.
- Reuse existing logger wiring through `WritesLogs` and setters.
- Keep log messages concrete and operational.

## Architecture Constraints

From `tests/Architecture/ArchitectureTest.php`:

- Use strict types and strict equality.
- Do not use `die`, `dd`, or `dump`.
- `Server`, `Connection`, and `Channel` are expected to be `final`.
- `src/Concerns` should contain traits.
- `src/Enums` should contain enums.

## Testing Conventions

- Tests are written with Pest.
- Shared helpers live in `tests/Pest.php`.
- Use `beforeEach()` and `afterEach()` for setup and cleanup.
- Prefer focused tests for changed behavior.
- Some tests spawn processes and sockets, so cleanup must stay reliable.
- Some tests are skipped in GitHub Actions, so local and CI behavior may differ.

## Examples And Public API

- `examples/` is included in PHPStan paths, so example code should type-check.
- Public API changes should stay consistent with the README and examples.

## Agent Workflow

- Read the target class and at least one nearby similar file before editing.
- Update tests when behavior changes.
- Prefer the smallest relevant test first, then widen verification if needed.
- After making any code change, run the full CI validation suite before finishing the task.
- If adding a new PHP file, match local header, strict types, naming, and `final`/`readonly` usage.
- Do not invent repository rules that are not present.

## Things Not To Assume

- No Makefile exists.
- Composer scripts exist for Pest, PHPStan, and PHP CS Fixer.
- Pest is the standard test CLI even though PHPUnit is installed.
- The project is not presented as hardened for untrusted public network exposure.
