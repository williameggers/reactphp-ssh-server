# Examples

These scripts demonstrate common ways to use `williameggers/reactphp-ssh-server`.

## Prerequisites

Install dependencies first:

```bash
composer install
```

Then run any example from the project root:

```bash
php examples/quickstart.php
```

Most examples listen on `127.0.0.1:2222`.

## Available Examples

### `quickstart.php`

Minimal SSH server example. Accepts a shell request, prints a greeting, and closes the connection after the client sends any data.

### `quickstart-with-logging.php`

Same basic flow as `quickstart.php`, but enables the built-in `ConsoleLogger` and also demonstrates handling `exec-request`.

### `echo-server.php`

Sets an authentication banner and echoes all channel input back to the client.

### `authentication.php`

Enables password authentication.

Test credentials:

- Username: `test`
- Password: `abc123`

### `keyboard-interactive.php`

Enables keyboard-interactive authentication with two prompts.

Test credentials:

- Username: `test`
- Password: `abc123`
- One-time code: `123456`

### `public-key-authentication.php`

Shows how to authorize users by comparing the presented public key against a trusted key list.

Update the placeholder keys in the example before using it.

### `limiting-server.php`

Wraps the SSH server in `React\Socket\LimitingServer` and allows only one concurrent connection.

### `remote-forwarding.php`

Enables remote TCP forwarding and demonstrates approving `tcpip-forward` requests for `127.0.0.1`.

Run the server:

```bash
php examples/remote-forwarding.php
```

On the SSH client machine, start a local web server:

```bash
php -S 127.0.0.1:3000
```

Open a remote forward through SSH:

```bash
ssh -p 2222 -N -R 127.0.0.1:8000:127.0.0.1:3000 test@127.0.0.1
```

Password:

- `abc123`

Then test from the SSH server machine:

```bash
curl http://127.0.0.1:8000
```

### `local-forwarding.php`

Enables local TCP forwarding and demonstrates approving `direct-tcpip` requests only for `127.0.0.1:3000`.

Run the server:

```bash
php examples/local-forwarding.php
```

On the SSH server machine, start a local web server:

```bash
php -S 127.0.0.1:3000
```

From the SSH client machine, open a local forward through SSH:

```bash
ssh -p 2222 -N -L 8000:127.0.0.1:3000 test@127.0.0.1
```

Password:

- `abc123`

Then test from the SSH client machine:

```bash
curl http://127.0.0.1:8000
```

## Notes

These examples are intended for local development, testing, and learning. Review the main project `README.md` for installation details, API usage, and the security disclaimer.
