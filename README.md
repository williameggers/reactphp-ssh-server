# SSH server for ReactPHP

[![CI status](https://github.com/williameggers/reactphp-ssh/workflows/CI/badge.svg)](https://github.com/williameggers/reactphp-ssh/actions)
[![Latest Stable Version](http://poser.pugx.org/williameggers/reactphp-ssh-server/v)](https://packagist.org/packages/williameggers/reactphp-ssh-server)
[![License](http://poser.pugx.org/williameggers/reactphp-ssh-server/license)](https://packagist.org/packages/williameggers/reactphp-ssh-server)

This project is an event-driven, standalone SSH server implementation for [ReactPHP](https://reactphp.org/) developed by William Eggers. It extends the code from Ashley Hindle’s excellent [Whisp PHP SSH server](https://github.com/WhispPHP/whisp), with substantial modifications and refactoring to suit ReactPHP.

## Overview

* Implements core SSH protocol functionality, including transport negotiation, authentication, and channel lifecycle management

* Built on a fully asynchronous, non-blocking architecture using ReactPHP for high concurrency and performance

* Simple to configure and extend with a clean event-driven API

* Customizable authentication and session behavior via intuitive callback handlers

* Supports widely-used encryption modes such as Galois/Counter Mode (GCM) and Counter Mode (CTR), along with modern host key algorithms including ssh-ed25519.

* Designed for testing, development, and internal tooling - **not security-hardened for exposure on public networks**. See [disclaimer](#disclaimer).

* Easily integrates into existing PHP applications or service layers requiring embedded SSH support

* Lightweight and dependency-friendly, making it ideal for microservices or containerized environments

**Table of Contents**

* [Disclaimer](#disclaimer)
* [Installation](#installation)
* [Quickstart example](#quickstart-example)
* [Server usage](#server-usage)
  * [Server](#server)
    * [Events](#server-events)
    * [Methods](#server-methods)
* [Connection usage](#connection-usage)
  * [Connection class](#connection-class)
    * [Events](#connection-events)
    * [Methods](#connection-methods)
  * [Channel class](#channel-class)
    * [Events](#channel-events)
    * [Methods](#channel-methods)
* [Supported algorithms](#supported-algorithms)
* [Unsupported features](#unsupported-features)
* [Contributions](#contributions)
* [License](#license)
* [Support and Credits](#support-and-credits)

## Disclaimer

This project is intended for educational, testing, and internal tooling use. It is not security-audited or recommended for exposure to untrusted clients or networks without significant review and hardening.

If you are looking for an SSH server with thorough testing and code audits to integrate with your PHP code, we recommend that you look into the OpenSSH project.

In no event shall the authors of reactphp-ssh-server be liable for anything that happens while using this library. Please read the [license](#license) for the full disclaimer.

## Installation

Install via Composer:

```bash
composer require williameggers/reactphp-ssh-server
```

This library requires **PHP 8.2 or higher** and the following PHP extensions:

* **ext-sodium** - for cryptographic operations (e.g. Ed25519, Curve25519)

* **ext-mbstring** - for multibyte string handling

* **ext-openssl** - for RSA and AES encryption support

Ensure these extensions are enabled in your environment before installing the package.

## Quickstart example

Here is an SSH server that establishes a channel via a shell request, then closes the connection if you send it anything:

```php
use React\Promise\Deferred;
use WilliamEggers\React\SSH\Server;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Channel;

$server = new Server('127.0.0.1:22');

$server->on('connection', function (Connection $connection) {
    /*
     * Handle a new SSH channel request (typically a shell).
     * This is where application-level interaction begins after authentication.
     * Use the Channel object to read from and write to the client.
     */
    $connection->on('channel.open', function (Channel $channel) {
        $channel->on('shell-request', function (Deferred $started) use ($channel) {
            $channel->write("Hello " . $channel->getConnection()->getRemoteAddress() . "!\r\n");
            $channel->write("Welcome to this amazing SSH server!\r\n");
            $channel->write("Here's a tip: don't say anything.\r\n");

            $channel->on('data', function ($data) use ($channel) {
                $channel->getConnection()->close();
            });

            $started->resolve(true);
        });
    });
});
```

See also the [examples](examples).

## Server usage

### Server

The `Server` is responsible for providing an interface for accepting
incoming SSH connections.

Besides defining a few methods, this interface also implements the
[`EventEmitterInterface`](https://github.com/igorw/evenement)
which allows you to react to certain events.

In order to accept SSH connections, you can simply pass a host and port combination like this:
```php
$server = new WilliamEggers\React\SSH\Server('127.0.0.1:2222');
```
Listening on the localhost address 127.0.0.1 means it will not be reachable from outside of this system. In order to change the host the socket is listening on, you can provide an IP address of an interface or use the special 0.0.0.0 address to listen on all interfaces:
```php
$server = new WilliamEggers\React\SSH\Server('0.0.0.0:2222');
```
If you want to listen on an IPv6 address, you MUST enclose the host in square brackets:
```php
$server = new WilliamEggers\React\SSH\Server('[::1]:2222');
```
In order to use a random port assignment, you can use the port 0:
```php
$server = new WilliamEggers\React\SSH\Server('127.0.0.1:0');
$address = $server->getAddress();
```
You can also specify a port number on its own, in which case the server will default to listening on the localhost address 127.0.0.1, which means it will not be reachable from outside of this system.
```php
$server = new WilliamEggers\React\SSH\Server(2222);
```
To override the inactivity timeout, specify it as the second parameter. In this example we start a server on localhost (127.0.0.1) on port 2222 with a connection inactivity timeout of 300 seconds.
```php
$server = new WilliamEggers\React\SSH\Server('127.0.0.1:2222', 300);
```

Decorators like `React\Socket\LimitingServer` are compatible. In the example below the number of concurrent SSH connections will be limited to 10:

```php
$server = new React\Socket\LimitingServer(
    new WilliamEggers\React\SSH\Server(2222),
    10
);

$server->on('connection', function (Connection $connection) {
    ...
});
```

> [!IMPORTANT]
> If the given URI appears to be valid, but listening on it fails (such as if port is already in use or port below 1024 may require root access etc.), it will throw a `RuntimeException`.

<h4 id="server-events">Server Events</h4>

* **connection** - emitted when a new connection has been established, i.e. a new client connects to the server:

    ```php
    $server->on('connection', function (WilliamEggers\React\SSH\Connection $connection) {
        echo 'new connection' . PHP_EOL;
    });
    ```

* **error** - emitted when there's an error accepting a new connection from a client.
    ```php
    $socket->on('error', function (Exception $e) {
        echo 'error: ' . $e->getMessage() . PHP_EOL;
    });
    ```

<h4 id="server-methods">Server Methods</h4>

* **setBanner(?string $banner): self**

    Sets the optional SSH authentication banner that is sent to clients before authentication begins. This can be used to display legal notices, welcome messages, or other information. Pass null to disable the banner. Returns the server instance for chaining.

* **enableAuthentication(): self**

    Enables user authentication on incoming SSH connections. When enabled, the ***authenticate*** event will be emitted during the connection handshake to allow the server to validate credentials. It returns the server instance for chaining.

    > **Important**
    >
    > Authentication is disabled by default.

* **disableAuthentication(): self**

    Disables user authentication. When disabled, all connections are considered authenticated automatically, and the authenticate event will not be emitted. This is useful for development or internal services, or services that provide an alternate authentication approach. Returns the server instance for chaining.

## Connection usage

### Connection class

The `Connection` class represents an individual incoming SSH connection and is emitted by the `Server` when a client connects.

It is responsible for managing the SSH protocol flow, including authentication (if enabled), channel negotiation, and connection closure. The `Connection` class implements the [`EventEmitterInterface`](https://github.com/igorw/evenement), enabling it to emit and respond to protocol-level events.

> [!IMPORTANT]
> Whilst `Connection` implements `DuplexStreamInterface` for internal protocol handling, **you should not read from or write to it directly**. Instead, interaction with the SSH client should occur via `Channel` objects, which are emitted during the **channel.open** event. The `Channel` encapsulates a virtual stream over which actual data is exchanged after authentication. [See RFC 4254 for further information.](https://www.rfc-editor.org/rfc/rfc4254#section-5)

The `Connection` object also exposes additional metadata such as the client's IP address ([getRemoteAddress()](#getremoteaddress)) and the server's local binding address ([getLocalAddress()](#getlocaladdress)).

Because the `Connection` implements the underlying [ConnectionInterface](https://reactphp.org/socket/#connectioninterface) you can use any of its events and methods as usual.

```php
$connection->on('error', function (Exception $e) {
    echo 'error: ' . $e->getMessage();
});

$connection->on('close', function () {
    echo 'closed';
});

$connection->close();
// …
```

<h4 id="connection-events">Connection Events</h4>

* **authenticate** - emitted when the client attempts to authenticate.

    This event allows the application to determine whether the provided credentials are valid. You are free to implement any logic here - from checking a hardcoded password to querying a database or invoking an external authentication service.

    The server must resolve the provided Deferred ```$authenticated``` with a boolean value (***true*** to accept, ***false*** to reject).

    > **Important**
    >
    > The authenticate event is only emitted if authentication is explicitly enabled by calling `enableAuthentication()` on the `Server` instance.
    > **Authentication is disabled by default.**
    >
    > If authentication is enabled, the deferred promise must be resolved within `Connection->deferredEventPromiseTimeout` seconds or authentication will be rejected.

    **Signature:** `function (string $username, string $method, array $credentials, Deferred $authenticated): void`

    **Callback parameters:**

    * `string $username` - The username provided by the client.

    * `string $method` - The authentication method requested (e.g., 'password', 'publickey', 'keyboard-interactive').

    * `array $credentials` - The authentication credentials, such as a password or public key blob. The meaning depends on the method.

    * `React\Promise\Deferred $authenticated` - A promise that must be resolved with true (to accept) or false (to reject) the authentication attempt.

    **Example**:

    ```php
    $connection->on('authenticate', function (string $username, string $method, array $credentials, Deferred $authenticated) {
        $isAuthenticated = false;
        $password = $credentials[0] ?? null;

        if (
            'password' === $method
            && 'test' === $username
            && 'abc123' === $password
        ) {
            $isAuthenticated = true;
        }

        $authenticated->resolve($isAuthenticated);
    });
    ```

* **channel.open** - emitted when the client opens a new channel.

    This typically occurs when the client initiates a session (e.g., for executing commands, starting a shell, or setting up port forwarding). Each channel is independent and associated with a specific purpose. Most servers only handle "session" type channels, which are used for shell access and exec commands.

    You should perform all read and write operations through the provided `Channel` instance - not directly on the `Connection`.

    > **Important**
    >
    > On receipt of a **channel.open** event, the developer should typically handle the `Channel` events [**shell-request**](#channel-shell-request-event) and/or [**exec-request**](#channel-exec-request-event), as these are the most common requests.

    **Signature:** `function (Channel $channel): void`

    **Callback parameters:**

    * ```Channel $channel``` - The newly opened channel instance. Use this object to read input from the client, write responses, or listen to channel-specific events - see below.

    **Example:**

    ```php
    $connection->on('channel.open', function (Channel $channel) {
        $channel->on('shell-request', function (Deferred $started) use ($channel) {
            $channel->write('Hello world!');
            $started->resolve(true);
        });
    });
    ```

* **channel.end** -  emitted when the client sends an EOF (end-of-file) signal for a channel, indicated by an ***SSH_MSG_CHANNEL_EOF*** message.

    This signals that no more data will be sent by the client on this channel, but the channel itself remains open - the server may still continue to send data until it chooses to close the channel explicitly.
    This event is useful for detecting when the client has finished its input stream (e.g., after running a command), but full cleanup should typically occur on channel.close.

    **Signature:** `function (Channel $channel): void`

    **Callback parameters:**

    * ```Channel $channel``` - The associated channel instance.


* **channel.close** - emitted when an existing channel closes.

    This signals that the client has finished all communication on that channel and expects it to be shut down. The channelId supplied by the event corresponds to the internal identifier assigned to that specific channel.

    This event is useful for cleanup or logging once a session or command has ended.

    **Signature:** `function (int $channelId): void`

* **close** - emitted when the connection is terminated.

    **Signature:** `function (): void`

<h4 id="connection-methods">Connection Methods</h4>

* **getRemoteAddress()**

    The `getRemoteAddress(): ?string` method returns the full remote address
    (URI) where this connection has been established with.

    ```php
    $address = $connection->getRemoteAddress();
    echo 'Connection with ' . $address . PHP_EOL;
    ```

    If the remote address can not be determined or is unknown at this time (such as
    after the connection has been closed), it MAY return a `NULL` value instead.

    Otherwise, it will return the full address (URI) as a string value, such
    as `tcp://127.0.0.1:8080`, `tcp://[::1]:80`, `tls://127.0.0.1:443`.
    If you only want the remote IP, you may use something like this:

    ```php
    $address = $connection->getRemoteAddress();
    $ip = trim(parse_url($address, PHP_URL_HOST), '[]');
    echo 'Connection with ' . $ip . PHP_EOL;
    ```

* **getLocalAddress()**

    The `getLocalAddress(): ?string` method returns the full local address
    (URI) where this connection has been established with.

    ```php
    $address = $connection->getLocalAddress();
    echo 'Connection with ' . $address . PHP_EOL;
    ```

    If the local address can not be determined or is unknown at this time (such as
    after the connection has been closed), it MAY return a `NULL` value instead.

    Otherwise, it will return the full address (URI) as a string value, such
    as `tcp://127.0.0.1:8080`, `tcp://[::1]:80`, `tls://127.0.0.1:443`.

    This method complements the [`getRemoteAddress()`](#getremoteaddress) method, so they should not be confused.

    If your `Server` instance is listening on multiple interfaces (e.g. using
    the address `0.0.0.0`), you can use this method to find out which interface
    actually accepted this connection (such as a public or local interface).

    If your system has multiple interfaces (e.g. a WAN and a LAN interface),
    you can use this method to find out which interface was actually
    used for this connection.

### Channel class

The `Channel` class represents an individual logical channel within an SSH connection. Channels are the mechanism through which application-layer communication (e.g. shell sessions, command execution, subsystems) is conducted over an SSH transport.

An instance of `Channel` is provided during a **channel.open** event on a `Connection`. All reading and writing of data at the application layer should take place through the `Channel` object - not the underlying `Connection`.

A single `Connection` can support multiple concurrent channels, allowing for operations such as multiple shell sessions, port forwarding, or subsystem requests over the same underlying connection. Each `Channel` operates independently and emits its own set of events.

In addition to channel-specific methods, the `Channel` class implements the [`EventEmitterInterface`](https://github.com/igorw/evenement), enabling it to emit and respond to protocol-level channel events.

<h4 id="channel-events">Channel Events</h4>

* **data** - emitted when the server receives data from the client on this channel.

    This event provides the raw string of data sent by the client, typically as part of an interactive shell session or during command execution. It is the primary way to receive client input, and can be used to process terminal input, capture command-line arguments, or respond interactively.

    **Signature:** `function (string $data) void`

    **Example**:

    ```php
    $channel->on('data', function (string $data) use ($channel) {
        // Log or process the data received from the client
        echo "Received data from client ({$channel->recipientChannel}): " . trim($data) . PHP_EOL;

        // Optionally, echo the data back to the client
        $channel->write("You said: " . $data);
    });
    ```

* <a id="channel-exec-request-event"></a>**exec-request**  - emitted when the client sends an exec request to run a single command (e.g., `ssh user@host ls -la`).

    The server should handle this by running the requested command and writing the output to the channel.

    How the command is interpreted or executed is left entirely up to the developer - this event is free-form by design, allowing integration with custom application logic, scripting environments, or sandboxed interpreters as needed.

    The server must resolve the provided Deferred ```$started``` with a boolean value (***true*** to send ***CHANNEL_SUCCESS*** to the client, ***false*** to send ***CHANNEL_FAILURE***).

    > **Important**
    >
    > The deferred promise must be resolved within `Connection->deferredEventPromiseTimeout` seconds or ***CHANNEL_FAILURE*** will be sent.

    **Signature:** `function (string $command, Deferred $started): void`

    **Callback parameters:**

    * `string $command` - The exact command string requested by the client.
    * `Deferred $started` - A ReactPHP Deferred promise to resolve when the command has started. Resolve with true if the command was accepted and executed, or false to indicate failure.

* <a id="channel-shell-request-event"></a>**shell-request** - emitted when the client requests an interactive shell session (e.g., launching a terminal after connecting).

    Typically, this means the server should spawn an interactive shell loop or similar REPL-style interface. Again, how this event is interpreted or executed is left entirely up to the developer.

    The server must resolve the provided Deferred ```$started``` with a boolean value (***true*** to send ***CHANNEL_SUCCESS*** to the client, ***false*** to send ***CHANNEL_FAILURE***).

    > **Important**
    >
    > The deferred promise must be resolved within `Connection->deferredEventPromiseTimeout` seconds or ***CHANNEL_FAILURE*** will be sent.

    **Signature:** `function (Deferred $started): void`

    **Callback parameters:**

    * `Deferred $started` - A ReactPHP Deferred promise to resolve when shell handling is complete. Resolve with true if the shell request was accepted and successfully executed, or false to indicate failure.

* **signal** - emitted when the client sends a POSIX-style signal (e.g., SIGINT, SIGTERM) over the channel.
This is often used to interrupt a long-running command or to cancel a session gracefully.

    **Signature:** `function (string $signalName) void`

* **window-change** - emitted when the client reports a change in its terminal dimensions (rows, columns, and optionally pixel sizes).

    Useful for adjusting the display or terminal layout in a shell session or terminal emulator backend - for example, resizing a pseudo-terminal or updating the UI in a text-based application.

    This event is functionally equivalent to the **NAWS (Negotiate About Window Size)** option in Telnet, allowing the server to respond to terminal size changes initiated by the client.

    **Signature:** `function (Values\WinSize $windowSize) void`

<h4 id="channel-methods">Channel Methods</h4>

* **close()**

    Closes the channel from the server side, sending an SSH_MSG_CHANNEL_CLOSE to the client. This indicates that no further data will be sent in either direction and the channel should be fully torn down.

* **getEnvironmentVariables(): array**

    Returns an associative array of environment variables that the client has requested to set for the session. This data is typically sent using SSH_MSG_CHANNEL_REQUEST with the "env" request type.

* **getEnvironmentVariable(string $name): mixed**

    Retrieves the value of a specific environment variable sent by the client. If the variable was not provided, it returns null.

* **getEncoding(): string**

    Resolves the character encoding requested by the client. This method inspects standard locale-related environment variables (LC_ALL, LC_CTYPE, LANG) in order of precedence to extract the character encoding portion from values like "en_US.UTF-8".

    The detected encoding will be returned in lowercase (e.g., "utf-8", "cp437")

    If no valid encoding is found, it defaults to "utf-8".

* **getTerminalInfo(): ?TerminalInfo**

    Returns an instance of [`TerminalInfo`](https://github.com/williameggers/reactphp-ssh/blob/master/src/Values/TerminalInfo.php) if the client has requested a pseudo-terminal (PTY) during session setup. This includes details such as terminal type, dimensions, and terminal mode flags. Returns null if no PTY was requested.

* **write($data)**

    Sends a string of data back to the client over the channel using SSH_MSG_CHANNEL_DATA. This is the primary method for server-side output in shell sessions, exec commands, or other interactive flows.

## Supported algorithms

### Key exchange methods

The following key exchange methods are supported:

* curve25519-sha256[]()@libssh.org
* diffie-hellman-group14-sha1

### Encryption algorithms

The following encryption algorithms are supported:

* aes128-ctr
* aes128-gcm[]()@openssh.com
* aes192-ctr
* aes256-ctr
* aes256-gcm[]()@openssh.com

### MAC algorithms

The following MAC algorithms are supported:

* hmac-sha2-256
* hmac-sha2-512
* hmac-sha1

## Unsupported features

This SSH server implementation is intentionally scoped to support core SSH protocol functionality such as connection management, authentication, and basic channel operations. The following features are not supported and are unlikely to be implemented in the future, as they fall outside the intended use cases of this project (e.g. testing, embedded tools, or controlled environments):

* `ssh-copy-id` **capability** - This server does not support automatically installing public keys via the ssh-copy-id tool. Public key management must be handled externally.

* **Port forwarding (local, remote, dynamic)** - SSH port forwarding features (e.g., -L, -R, or -D flags) are not supported. This includes tunneling TCP connections through the SSH transport.

* **Proxy functionality** - Acting as an SSH proxy or jump host is not supported, and this server will not relay SSH traffic between clients or other SSH servers.

* **SFTP subsystem** - File transfer via the SSH File Transfer Protocol (SFTP) is not implemented, and this server will not respond to SFTP subsystem requests.

## Contributions

Contributions are welcome and encouraged!

To contribute:

1. Fork the repository.
1. Create a new branch for your changes.
1. Submit a pull request with a clear description of what you've done and why.

Please try to follow existing coding style and conventions, and include tests if applicable.
Feel free to open an issue if you'd like to discuss a potential change or need guidance on where to start.

## License

BSD 2-Clause License

Copyright (c) 2025, William Eggers

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

Portions of this software are derived from the Whisp PHP SSH server
(https://github.com/WhispPHP/whisp) by Ashley Hindle, and are used under the
terms of the MIT License:

MIT License

Copyright (c) 2023 Ashley Hindle

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Support and Credits

This project is a derivative work based on Whisp PHP SSH by Ashley Hindle, and incorporates substantial modifications and adaptations. Whilst inspired by the original implementation, the codebase has been extensively modified and extended to support additional algorithms and features.

Licensed under the MIT License
Whisp provided the core implementation of SSH transport, packet handling, and protocol logic. This project builds on that foundation with modifications suitable for ReactPHP compatibility and extended use cases.