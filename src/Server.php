<?php declare(strict_types=1);
/**
 * Copyright (c) 2025, William Eggers, Ashley Hindle
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace WilliamEggers\React\SSH;

use Evenement\EventEmitter;
use React\EventLoop\Loop;
use React\EventLoop\LoopInterface;
use React\Socket\ConnectionInterface;
use React\Socket\ServerInterface;
use React\Socket\TcpServer;
use React\Stream\Util;
use WilliamEggers\React\SSH\Concerns\WritesLogs;
use WilliamEggers\React\SSH\Loggers\NullLogger;

final class Server extends EventEmitter implements ServerInterface
{
    use WritesLogs;

    /**
     * Current version of the ReactPHP SSH server library.
     *
     * This value is used in the server identification string during the SSH handshake.
     */
    public const VERSION = '1.0.3';

    /**
     * Server host keys for SSH identity.
     *
     * @var array<string, ServerHostKey>
     */
    private array $hostKeys;
    private ServerInterface $tcpServer;
    private LoopInterface $loop;

    private int $connectionId = 0;

    private ?string $banner = null;
    private bool $authenticationEnabled = false;

    /**
     * Constructs a new SSH server instance.
     *
     * Sets up the event loop, TCP listener, and default server host keys (Ed25519 and RSA).
     * Optionally accepts an idle timeout, event loop, socket context options, and a base directory for host keys.
     *
     * When a client connects, a `Connection` instance is created and configured with the current
     * banner, connection ID, idle timeout, logger, server host keys, and authentication settings.
     * The new connection is then emitted via the `connection` event.
     *
     * @param int|string         $uri                address or port to bind the TCP server to
     * @param null|int           $idleTimeoutSeconds optional idle timeout in seconds before disconnecting inactive clients
     * @param null|LoopInterface $loop               optional ReactPHP event loop to use. Defaults to the global loop if not provided.
     * @param array              $context            optional stream context options for the TCP server
     * @param null|string        $hostKeyPath        optional base directory for loading server host keys
     */
    public function __construct(int|string $uri, private ?int $idleTimeoutSeconds = 60, ?LoopInterface $loop = null, array $context = [], ?string $hostKeyPath = null)
    {
        $this->loop = $loop ?: Loop::get();
        $this->logger = new NullLogger();

        // Initialize and register server host keys for supported SSH host key algorithms.
        // These keys will be advertised during the key exchange phase to authenticate the server.
        $this->addServerHostKey(new ServerHostKey('ed25519', baseDir: $hostKeyPath));
        $this->addServerHostKey(new ServerHostKey('rsa', baseDir: $hostKeyPath));

        $this->tcpServer = new TcpServer($uri, $loop, $context);
        $this->tcpServer->on('connection', function (ConnectionInterface $connection): void {
            $connection = (new Connection($connection, $this->loop))
                ->setBanner($this->banner)
                ->setConnectionId(++$this->connectionId)
                ->setIdleTimeoutSeconds($this->idleTimeoutSeconds)
                ->setLogger($this->logger)
                ->setServerHostKeys($this->hostKeys)
                ->enableAuthentication($this->authenticationEnabled)
                ->handle()
            ;

            $this->emit('connection', [$connection]);
        });

        Util::forwardEvents($this->tcpServer, $this, ['error']);
    }

    /**
     * Enables user authentication for incoming SSH connections.
     *
     * When enabled, you must register a connection listener for
     * the 'authenticate' event to handle authentication logic.
     */
    public function enableAuthentication(): self
    {
        $this->authenticationEnabled = true;

        return $this;
    }

    /**
     * Disables user authentication for all incoming SSH connections.
     *
     * When disabled, all users are automatically treated as authenticated
     * without any credential checks.
     */
    public function disableAuthentication(): self
    {
        $this->authenticationEnabled = false;

        return $this;
    }

    /**
     * Sets the server's host key used during the SSH key exchange phase.
     *
     * The host key identifies the server to connecting clients and is used to
     * establish trust and verify server authenticity.
     */
    public function addServerHostKey(ServerHostKey $hostKey): self
    {
        $this->hostKeys[$hostKey->getHostKeyAlgorithm()] = $hostKey;

        return $this;
    }

    /**
     * Returns the full address (URI) this server is currently listening on.
     *
     * ```php
     * $address = $server->getAddress();
     * echo 'Server listening on ' . $address . PHP_EOL;
     * ```
     *
     * If the address can not be determined or is unknown at this time (such as
     * after the socket has been closed), it MAY return a `NULL` value instead.
     *
     * Otherwise, it will return the full address (URI) as a string value, such
     * as `tcp://127.0.0.1:8080`, `tcp://[::1]:80` or `tls://127.0.0.1:443`.
     * Note that individual URI components are application specific and depend
     * on the underlying transport protocol.
     *
     * If you only want the local port, you may use something like this:
     *
     * ```php
     * $address = $server->getAddress();
     * $port = parse_url($address, PHP_URL_PORT);
     * echo 'Server listening on port ' . $port . PHP_EOL;
     * ```
     *
     * @return ?string the full listening address (URI) or NULL if it is unknown (not applicable to this server socket or already closed)
     */
    public function getAddress(): ?string
    {
        return $this->tcpServer->getAddress();
    }

    /**
     * Pauses accepting new incoming connections.
     *
     * Removes the socket resource from the EventLoop and thus stop accepting
     * new connections. Note that the listening socket stays active and is not
     * closed.
     *
     * This means that new incoming connections will stay pending in the
     * operating system backlog until its configurable backlog is filled.
     * Once the backlog is filled, the operating system may reject further
     * incoming connections until the backlog is drained again by resuming
     * to accept new connections.
     *
     * Once the server is paused, no futher `connection` events SHOULD
     * be emitted.
     *
     * ```php
     * $socket->pause();
     *
     * $socket->on('connection', assertShouldNeverCalled());
     * ```
     *
     * This method is advisory-only, though generally not recommended, the
     * server MAY continue emitting `connection` events.
     *
     * Unless otherwise noted, a successfully opened server SHOULD NOT start
     * in paused state.
     *
     * You can continue processing events by calling `resume()` again.
     *
     * Note that both methods can be called any number of times, in particular
     * calling `pause()` more than once SHOULD NOT have any effect.
     * Similarly, calling this after `close()` is a NO-OP.
     *
     * @see self::resume()
     */
    public function pause(): void
    {
        $this->tcpServer->pause();
    }

    /**
     * Resumes accepting new incoming connections.
     *
     * Re-attach the socket resource to the EventLoop after a previous `pause()`.
     *
     * ```php
     * $socket->pause();
     *
     * Loop::addTimer(1.0, function () use ($socket) {
     *     $socket->resume();
     * });
     * ```
     *
     * Note that both methods can be called any number of times, in particular
     * calling `resume()` without a prior `pause()` SHOULD NOT have any effect.
     * Similarly, calling this after `close()` is a NO-OP.
     *
     * @see self::pause()
     */
    public function resume(): void
    {
        $this->tcpServer->resume();
    }

    /**
     * Shuts down this listening socket.
     *
     * This will stop listening for new incoming connections on this socket.
     *
     * Calling this method more than once on the same instance is a NO-OP.
     */
    public function close(): void
    {
        $this->tcpServer->close();
        $this->removeAllListeners();
    }

    /**
     * Sets the SSH login banner to be displayed during user authentication.
     *
     * @param ?string $banner The banner message to show to clients. If null, no banner will be sent.
     */
    public function setBanner(?string $banner): self
    {
        $this->banner = $banner;

        return $this;
    }
}
