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

use Evenement\EventEmitterInterface;
use Evenement\EventEmitterTrait;
use Psr\Log\LoggerInterface;
use React\EventLoop\LoopInterface;
use React\EventLoop\TimerInterface;
use React\Promise\Deferred;
use React\Promise\Promise;
use React\Promise\PromiseInterface;

use function React\Promise\Timer\sleep;
use function React\Promise\Timer\timeout;

use React\Socket\ConnectionInterface;
use React\Socket\Connector;
use React\Socket\ConnectorInterface;
use React\Socket\TcpServer;
use React\Stream\Util;
use React\Stream\WritableStreamInterface;
use WilliamEggers\React\SSH\Concerns\WritesLogs;
use WilliamEggers\React\SSH\Enums\ChannelOpenFailureReason;
use WilliamEggers\React\SSH\Enums\DisconnectReason;
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Enums\TerminalMode;
use WilliamEggers\React\SSH\Values\KeyboardInteractiveConfig;
use WilliamEggers\React\SSH\Values\WinSize;

final class Connection implements ConnectionInterface, EventEmitterInterface
{
    use EventEmitterTrait;
    use WritesLogs;

    private \DateTimeImmutable $connectedAt;
    private \DateTimeImmutable $lastActivity;
    private ?int $idleTimeoutSeconds = 60; // Disconnect after 60 seconds of no data (from client or PTY)

    /**
     * Server host keys for SSH identity.
     *
     * @var array<string, ServerHostKey>
     */
    private array $serverHostKeys;
    private ?KexNegotiator $kexNegotiator = null;
    private PacketHandler $packetHandler;
    private PublicKeyValidator $publicKeyValidator;
    private ?KeyboardInteractiveConfig $keyboardInteractiveConfig = null;
    private TimerInterface $idleCheck;

    /**
     * @var array<int, Channel>
     */
    private array $activeChannelsByLocalId = [];

    /**
     * @var array<string, array{requestedAddress: string, requestedPort: int, effectiveAddress: string, effectivePort: int, server: TcpServer, channels: array<int, ConnectionInterface>, pendingChannels: array<int, ConnectionInterface>}>
     */
    private array $remoteForwardListeners = [];

    /**
     * @var array<int, array{type: string, socket: ConnectionInterface, listenerKey: string, connectedAddress: string, connectedPort: int, originatorAddress: string, originatorPort: int, timeoutTimer: TimerInterface}>
     */
    private array $pendingOutboundChannelOpens = [];

    private int $nextServerChannelId = 0;

    private string $serverVersion = 'SSH-2.0-ReactPHP-SSH_' . Server::VERSION;
    private string $inputBuffer = '';
    private ?string $username = null;
    private ?string $sessionId = null;
    private ?string $authenticatedPublicKey = null;
    private ?string $lastAuthMethod = null;
    // Needed for key exchange negotiation, and for actual encryption/decryption
    private ?string $clientVersion = null;
    private ?string $banner = null;

    private bool $bannerSent = false;
    private bool $serverIdentiferSent = false;
    private bool $kexInitSent = false;
    private bool $authenticationEnabled = false;
    private bool $authenticated = true;
    private bool $directTcpipEnabled = false;
    private bool $remoteForwardingEnabled = false;

    /**
     * Indicates whether the connected SSH client supports the EXT_INFO (RFC 8308) message.
     * Default is true; this may be set to false based on client version string (e.g., PuTTY).
     */
    private bool $supportsExtInfo = true;

    private int $connectionId;
    private int $maxPacketSize = 1024 * 1024; // This gets updated when the client opens a channel
    private int $authenticationFailureCount = 0;
    private float $deferredEventPromiseTimeout = 10.0; // The deferred event promises must resolve within the configured timeout period
    private float $pendingForwardedChannelOpenTimeout = 10.0; // Outbound channel open requests (e.g. from direct-tcpip) must complete within this timeout period
    private bool $transportBackpressured = false;

    /**
     * @var array<int, ConnectionInterface>
     */
    private array $directTcpipSockets = [];

    /**
     * @var array<int, PromiseInterface<ConnectionInterface>>
     */
    private array $pendingDirectTcpipConnects = [];

    private ConnectorInterface $connector;

    public function __construct(private ConnectionInterface $connection, private LoopInterface $loop)
    {
        $this->connectedAt = new \DateTimeImmutable();
        $this->lastActivity = new \DateTimeImmutable();
        $this->publicKeyValidator = new PublicKeyValidator(new Loggers\NullLogger());
        $this->packetHandler(new PacketHandler($this->connection));
        $this->setLogger(new Loggers\NullLogger());
        $this->connector = new Connector($this->loop);

        Util::forwardEvents($this->connection, $this, ['close', 'error']);
        $this->connection->on('drain', function (): void {
            $this->transportBackpressured = false;
            $this->flushPendingChannelData();
        });
    }

    /**
     * Sets a PSR-compliant logger instance for this connection and propagates it to dependent components.
     *
     * This logger is used to record debug, info, warning, and error messages during the lifecycle
     * of the connection. It is also passed to internal components such as the public key validator
     * and packet handler to ensure consistent logging across subsystems.
     *
     * @param LoggerInterface $logger a PSR-compliant logger instance
     */
    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        $this->publicKeyValidator->setLogger($logger);
        $this->packetHandler->setLogger($logger);

        return $this;
    }

    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        $messagePrepend = strtoupper(sprintf('[%s #%d]', str_replace('WilliamEggers\React\SSH\\', '', self::class), $this->connectionId));
        $this->logger->log($level, $messagePrepend . ' ' . $message, $context);
    }

    /**
     * Sets the internal connection identifier for this SSH connection instance.
     *
     * This ID is typically assigned by the server to uniquely identify and track the connection
     * throughout its lifecycle (e.g., for logging, metrics, or channel association).
     *
     * @param int $id the unique connection identifier
     */
    public function setConnectionId(int $id): self
    {
        $this->connectionId = $id;

        return $this;
    }

    /**
     * Retrieves the internal connection identifier assigned to this connection.
     *
     * @return int the unique ID representing this SSH connection
     */
    public function getConnectionId(): int
    {
        return $this->connectionId;
    }

    /**
     * Sets the list of available server host keys for the connection.
     *
     * This method is used to register one or more supported server host keys,
     * indexed by their corresponding algorithm names. These keys will be used
     * during key exchange negotiation and for verifying the server's identity.
     *
     * @param array<string, ServerHostKey> $serverHostKeys an associative array of algorithm names to ServerHostKey instances
     */
    public function setServerHostKeys(array $serverHostKeys): self
    {
        $this->serverHostKeys = $serverHostKeys;

        return $this;
    }

    /**
     * Retrieves the server's host key instance for the given algorithm name.
     *
     * Returns the associated `ServerHostKey` object if one is available for the specified
     * algorithm (e.g., `ssh-ed25519`, `rsa-sha2-256`). Returns null if the algorithm is not supported.
     *
     * @param string $hostKeyAlgorithm the name of the host key algorithm
     *
     * @return null|ServerHostKey the corresponding host key, or null if not found
     */
    public function getServerHostKey(string $hostKeyAlgorithm): ?ServerHostKey
    {
        return $this->serverHostKeys[$hostKeyAlgorithm] ?? null;
    }

    /**
     * Returns the timestamp of when the connection was first established.
     *
     * This is set once when the connection is accepted by the server and remains
     * constant throughout the lifetime of the connection.
     *
     * @return \DateTimeImmutable the connection start time
     */
    public function getConnectedAt(): \DateTimeImmutable
    {
        return $this->connectedAt;
    }

    /**
     * Returns the timestamp of the last recorded activity on the connection.
     *
     * Activity includes packet read/write or channel interaction. This timestamp
     * is typically used to monitor idle connections or implement timeout logic.
     *
     * @return \DateTimeImmutable the last time the connection was active
     */
    public function getLastActivity(): \DateTimeImmutable
    {
        return $this->lastActivity;
    }

    /**
     * Specifies the idle timeout (in seconds) after which the server will disconnect an inactive connection.
     *
     * Setting this to `null` disables automatic disconnection based on inactivity.
     *
     * @param null|int $seconds number of idle seconds before disconnecting, or null to disable
     */
    public function setIdleTimeoutSeconds(?int $seconds): self
    {
        $this->idleTimeoutSeconds = $seconds;

        return $this;
    }

    /**
     * Enables or disables SSH authentication for this connection.
     *
     * By default, authentication is disabled. Calling this method with `true` allows the
     * `authenticate` event to be emitted and handled. When set to `false`, the server skips
     * authentication and proceeds directly to channel handling.
     *
     * @param bool $enabled whether authentication should be enabled
     */
    public function enableAuthentication(bool $enabled = false): self
    {
        $this->authenticationEnabled = $enabled;
        $this->authenticated = ! $enabled;

        return $this;
    }

    /**
     * Enables or disables direct TCP/IP forwarding for this connection.
     *
     * When disabled, inbound `direct-tcpip` channel open requests are rejected.
     * When enabled, each request must still be explicitly approved by a
     * `direct-tcpip` event listener before the outbound TCP connection is created.
     */
    public function enableDirectTcpip(bool $enabled = true): self
    {
        $this->directTcpipEnabled = $enabled;

        return $this;
    }

    /**
     * Disables direct TCP/IP forwarding for this connection.
     */
    public function disableDirectTcpip(): self
    {
        return $this->enableDirectTcpip(false);
    }

    /**
     * Enables or disables remote TCP forwarding for this connection.
     *
     * When disabled, `tcpip-forward` and `cancel-tcpip-forward` global requests are rejected.
     * When enabled, each `tcpip-forward` request must still be explicitly approved by a
     * `global-request.tcpip-forward` event listener.
     */
    public function enableRemoteForwarding(bool $enabled = true): self
    {
        $this->remoteForwardingEnabled = $enabled;

        return $this;
    }

    /**
     * Disables remote TCP forwarding for this connection.
     */
    public function disableRemoteForwarding(): self
    {
        return $this->enableRemoteForwarding(false);
    }

    /**
     * Overrides the outbound socket connector used for direct TCP/IP requests.
     */
    public function setConnector(ConnectorInterface $connector): self
    {
        $this->connector = $connector;

        return $this;
    }

    /**
     * Sets an optional SSH banner message to be displayed to the client upon connection.
     *
     * This message is typically shown before authentication and can be used to present legal notices,
     * system information, or welcome text. If `null`, no banner is sent.
     *
     * @param null|string $banner the banner text, or null to disable it
     */
    public function setBanner(?string $banner): self
    {
        $this->banner = $banner;

        return $this;
    }

    public function handle(): self
    {
        /*
         * Wait up to 0.5 seconds for the client to send its SSH version string.
         * If the client hasn't identified itself by then, assume it's waiting for the server's version first.
         * Send the server identifier to trigger the client's next step in the handshake.
         */
        sleep(0.5)->then(function (): void {
            if (is_null($this->clientVersion)) {
                $this->logger->debug('Timeout waiting for client to identify itself. Sending identifier.');
                $this->serverIdentiferSent = true;
                $this->connection->write($this->serverVersion . "\r\n");
            }
        });

        $this->connection->on('data', function (mixed $data): void {
            $this->handleSshClientData($data);
        });

        $this->connection->on('close', function (): void {
            $this->cleanup();
        });

        $this->idleCheck = $this->loop->addPeriodicTimer(5.0, function (): void {
            $inactiveSeconds = $this->dateIntervalToSeconds(
                $this->lastActivity->diff(new \DateTimeImmutable())
            );
            if (
                is_int($this->idleTimeoutSeconds)
                && $inactiveSeconds > $this->idleTimeoutSeconds
            ) {
                $this->info("Connection inactive for {$inactiveSeconds} seconds, disconnecting");
                $this->disconnect('Connection inactive for too long');
            }
        });

        return $this;
    }

    /**
     * Disconnect the SSH connection with a reason.
     */
    public function disconnect(string $reasonDescription = 'Connection closed', DisconnectReason $reasonCode = DisconnectReason::DISCONNECT_BY_APPLICATION): void
    {
        $this->writePacked(
            MessageType::DISCONNECT,
            [$reasonCode->value, $reasonDescription, 'en']
        );

        $this->info("Initiated disconnect: {$reasonDescription}");

        // Close the underlying connection
        $this->connection->close();
    }

    /**
     * Write data to the client on the specified channel.
     *
     * Do not interact with this method directly. Use the write method in the Channel instance.
     */
    public function writeChannelData(Channel $channel, string $data): int
    {
        if ('' === $data || $channel->hasSentClose() || $channel->hasReceivedClose()) {
            return 0;
        }

        try {
            if ($channel->hasPendingRequestReply()) {
                $channel->queueOutboundData($data);

                return strlen($data);
            }

            if ($this->transportBackpressured || $channel->hasPendingOutboundData()) {
                $channel->queueOutboundData($data);
                $this->flushPendingChannelData();

                return strlen($data);
            }

            $acceptedBytes = $this->writeChannelDataChunks($channel, $data);
            if ($acceptedBytes < strlen($data)) {
                $channel->queueOutboundData(substr($data, $acceptedBytes));
            }

            return strlen($data);
        } catch (\OverflowException $e) {
            $this->warning('Channel outbound buffer exceeded close threshold', [
                'channel_id' => $channel->getSenderChannel(),
                'buffered_bytes' => $channel->getPendingOutboundByteCount(),
            ]);
            $this->closeChannel($channel);

            return 0;
        }
    }

    /**
     * Sends SSH_MSG_CHANNEL_EOF for a channel if it is still open.
     */
    public function sendChannelEof(Channel $channel): void
    {
        $channelId = $channel->getSenderChannel();
        if (! isset($this->activeChannelsByLocalId[$channelId])) {
            return;
        }

        $this->writePacked(MessageType::CHANNEL_EOF, $channel->getRecipientChannel());
    }

    /**
     * Sends SSH_MSG_CHANNEL_CLOSE for a channel and marks it locally closed.
     */
    public function closeChannel(Channel $channel): void
    {
        $channelId = $channel->getSenderChannel();

        if (! isset($this->activeChannelsByLocalId[$channelId]) || $channel->hasSentClose()) {
            return;
        }

        $this->writePacked(MessageType::CHANNEL_CLOSE, $channel->getRecipientChannel());
        $channel->markCloseSent();

        if ($channel->hasReceivedClose()) {
            $this->removeActiveChannel($channel);
            $this->emit('channel.close', [$channelId]);
        }
    }

    /**
     * Returns the full remote address (URI) where this connection has been established.
     */
    public function getRemoteAddress(): ?string
    {
        return $this->connection->getRemoteAddress();
    }

    /**
     * Returns the full local address (full URI with scheme, IP and port) where this
     * connection has been established.
     */
    public function getLocalAddress(): ?string
    {
        return $this->connection->getLocalAddress();
    }

    /**
     * Indicates whether the underlying stream is still open for reading.
     *
     * This delegates to the underlying connection's `isReadable()` method.
     *
     * @return bool true if data can still be read from the connection; false otherwise
     */
    public function isReadable(): bool
    {
        return $this->connection->isReadable();
    }

    /**
     * Indicates whether the underlying stream is still open for writing.
     *
     * This delegates to the underlying connection's `isWritable()` method.
     *
     * @return bool true if data can still be written to the connection; false otherwise
     */
    public function isWritable(): bool
    {
        return $this->connection->isWritable();
    }

    /**
     * Gracefully closes the connection and performs cleanup.
     *
     * This will initiate the disconnect process (e.g., send SSH_MSG_DISCONNECT), and
     * remove all event listeners registered on the connection to ensure proper resource cleanup.
     */
    public function close(): void
    {
        $this->disconnect();
        $this->removeAllListeners();
    }

    /**
     * Pauses reading incoming data events.
     */
    public function pause(): void
    {
        $this->connection->pause();
    }

    /**
     * Resumes reading incoming data events.
     *
     * Re-attach the data source after a previous `pause()`.
     */
    public function resume(): void
    {
        $this->connection->resume();
    }

    /**
     * Successfully ends the stream (after optionally sending some final data).
     *
     * This method can be used to successfully end the stream, i.e. close
     * the stream after sending out all data that is currently buffered.
     */
    public function end(mixed $data = null): void
    {
        $this->connection->end($data);
    }

    /**
     * Pipes all the data from this readable source into the given writable destination.
     */
    public function pipe(WritableStreamInterface $dest, array $options = []): WritableStreamInterface
    {
        return $this->connection->pipe($dest, $options);
    }

    /**
     * Alias for writeConnection.
     *
     * Do not use this method to communicate during your session.
     * You should be using the write method in the Channel instance.
     */
    public function write(mixed $data): bool
    {
        if (! is_scalar($data) && ! (\is_object($data) && method_exists($data, '__toString'))) {
            throw new \InvalidArgumentException('Data must be stringable');
        }

        return ($this->writeConnection((string) $data) ?: 0) > 0;
    }

    /**
     * Retrieves the active Channel instance for the given channel ID.
     *
     * Returns the Channel if it exists and is still open, or null if the channel
     * has not been opened or has already been closed.
     *
     * @param int $channelId the channel ID assigned by the client
     */
    public function getChannel(int $channelId): ?Channel
    {
        return $this->activeChannelsByLocalId[$channelId] ?? null;
    }

    /**
     * Returns the authenticated username for this connection.
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * Indicates whether the connection has completed authentication for connection-protocol messages.
     *
     * When authentication is disabled, connections are treated as authenticated immediately after setup.
     */
    public function isAuthenticated(): bool
    {
        return $this->authenticated;
    }

    /**
     * Sets the configuration for keyboard-interactive authentication.
     *
     * Allows customization of the title, instructional message, and individual prompts
     * that will be presented to the client during authentication. Providing a configuration
     * implicitly enables keyboard-interactive authentication for this connection.
     *
     * @param KeyboardInteractiveConfig $config the configuration object defining prompt behavior
     */
    public function setKeyboardInteractiveConfig(KeyboardInteractiveConfig $config): self
    {
        $this->keyboardInteractiveConfig = $config;

        return $this;
    }

    private function packetHandler(?PacketHandler $packetHandler = null): PacketHandler|self
    {
        if (is_null($packetHandler)) {
            return $this->packetHandler;
        }

        $this->packetHandler = $packetHandler;

        return $this;
    }

    /**
     * Switch to encrypted mode
     * We need to derive keys from the shared secret :exploding_head:
     * Then tell the packet handler to encrypt/decrypt all packets going forward.
     */
    private function handleNewKeys(Packet $packet): void
    {
        if ($this->packetHandler->hasCompletedInitialKeyExchange()) {
            // Rekey scenario - send NEWKEYS response
            $this->debug('Rekey in progress - received NEWKEYS from client, sending our NEWKEYS response');
            $this->writeConnection(chr(MessageType::NEWKEYS->value));

            // Switch to new keys (only after both sides have sent NEWKEYS)
            $this->debug('Switching to new keys after rekey');
            $this->packetHandler->switchToNewKeys();
            $this->debug('Completed rekey process');
        } else {
            // Initial key exchange
            $this->debug('Initial key exchange - sending NEWKEYS response');
            $this->writeConnection(chr(MessageType::NEWKEYS->value));

            $this->debug('Deriving initial encryption keys');
            $this->packetHandler->deriveKeys();

            $this->debug('Initial encryption established');
        }
    }

    /**
     * Client requests a service - we need to respond with a SERVICE_ACCEPT or SERVICE_DENIED
     * Can be ssh-userauth (RFC 4252) - requested first
     * or ssh-connection (RFC 4254).
     */
    private function handleServiceRequest(Packet $packet): void
    {
        [$serviceName] = $packet->extractFormat('%s');
        $this->info("Service request: {$serviceName}");

        // Accept the user auth service
        if ('ssh-userauth' === $serviceName) {
            // Before accepting, send EXT_INFO if supported (RFC 8308)
            if ($this->supportsExtInfo) {
                $this->sendExtInfo();
            }

            $this->writePacked(MessageType::SERVICE_ACCEPT, 'ssh-userauth');
        }
    }

    /**
     * Should support multiple authentication methods as defined in RFC 4252 (The SSH Authentication Protocol).
     *
     * Common authentication methods include:
     * publickey - Using SSH keys
     * password - Plain password auth
     * keyboard-interactive - Challenge-response
     * hostbased - Host-based authentication
     * none - Used to query available methods or for no-auth scenarios
     */
    private function handleUserAuthRequest(Packet $packet): void
    {
        [$username, $service, $method] = $packet->extractFormat('%s%s%s');

        $this->username = (string) $username;

        $this->info("Auth request: user={$username}, service={$service}, method={$method}");

        if (! is_null($this->banner) && false === $this->bannerSent) {
            $this->writePacked(MessageType::USERAUTH_BANNER, [$this->banner, '']);
            $this->bannerSent = true;
        }

        // Handle the 'none' authentication method
        if ('none' === $method) {
            if (is_null($this->lastAuthMethod)) {
                $this->info('Initial auth request - client querying available methods');
                $this->lastAuthMethod = $method;
                $availableAuthMethods = [
                    'publickey',
                    'password',
                    'none',
                ];
                // If the keyboard-interactive mode has been configured, substitute it as an available method.
                if (! is_null($this->keyboardInteractiveConfig)) {
                    array_splice($availableAuthMethods, 1, 1, 'keyboard-interactive');
                }
                // List all supported methods
                $this->writePacked(MessageType::USERAUTH_FAILURE, [
                    implode(',', $availableAuthMethods),
                    false,
                ]);

                return;
            }

            if (! $this->authenticationEnabled) {
                $this->info("Client explicitly chose 'none' auth method after trying: {$this->lastAuthMethod}");
                $this->markAuthenticated();
                $this->writePacked(MessageType::USERAUTH_SUCCESS);
            } else {
                $this->writePacked(MessageType::USERAUTH_FAILURE);
            }

            return;
        }
        $this->lastAuthMethod = (string) $method;

        // Handle keyboard-interactive auth - accept automatically
        if ('keyboard-interactive' === $method) {
            if (! $this->authenticationEnabled) {
                $this->markAuthenticated();
                $this->writePacked(MessageType::USERAUTH_SUCCESS);

                return;
            }

            /*
             * Sends a prompt to the client requesting one or more inputs using
             * SSH_MSG_USERAUTH_INFO_REQUEST (message code 60).
             *
             * Fields:
             * - name (string):          Optional display name shown by the client
             * - instruction (string):   Optional instructions for the user
             * - language_tag (string):  Usually empty (""); generally ignored
             * - num_prompts (uint32):   Number of prompts being sent
             * - prompt[n] (string):     The prompt text (e.g., "Password:")
             * - echo[n] (boolean):      Whether the input should be echoed (false = hidden)
             */
            if (! is_null($this->keyboardInteractiveConfig)) {
                $this->writePacked(MessageType::USERAUTH_PK_OK, $this->keyboardInteractiveConfig->generatePacketConfig());
            }

            return;
        }

        // Handle password authentication
        if ('password' === $method) {
            if (! $this->authenticationEnabled) {
                $this->markAuthenticated();
                $this->writePacked(MessageType::USERAUTH_SUCCESS);

                return;
            }

            $deferred = new Deferred();
            $this->info("Accepting password auth for user: {$username}");
            [$isPasswordChange, $password] = $packet->extractFormat('%b%s');
            $this->emit('authenticate', [(string) $username, $method, [$password], $deferred]);

            /** @var PromiseInterface<bool> $authenticatePromise */
            $authenticatePromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
            $authenticatePromise->then(
                function (bool $authSuccess): void {
                    if (! $authSuccess) {
                        ++$this->authenticationFailureCount;

                        if ($this->authenticationFailureCount < 3) {
                            $this->writePacked(MessageType::USERAUTH_FAILURE, [implode(',', ['password', 'none']), false]);
                        } else {
                            $this->writePacked(MessageType::USERAUTH_FAILURE, ['none', false]);
                        }

                        return;
                    }

                    $this->markAuthenticated();
                    $this->writePacked(MessageType::USERAUTH_SUCCESS);
                }
            )->catch(
                function (): void {
                    $this->writePacked(MessageType::USERAUTH_FAILURE);
                    $this->disconnect('Timeout validating credentials');
                }
            );

            return;
        }

        // Authing with public key, we want to add this to our environment variable for apps to use
        // But only once we've verified the signature
        if ('publickey' === $method && $this->authenticationEnabled) {
            $this->info('Received public key auth request');

            // Explicitly parse the publickey request fields according to RFC 4252
            [$hasSignature] = $packet->extractFormat('%b');
            [$keyAlgorithmName] = $packet->extractFormat('%s'); // e.g. rsa-sha2-256
            [$publicKeyBlob] = $packet->extractFormat('%s'); // e.g. ssh-rsa exponent modulus | ssh-ed25519 key (32 bytes) | ecdsa-sha2-nistp256 curve_name key

            $this->info('Parsed pk auth request: hasSig=' . ($hasSignature ? '1' : '0') . ", keyAlgo='{$keyAlgorithmName}'");

            if ($hasSignature) {
                $this->info('Request has signature, extracting signature blob');
                [$signatureBlob] = $packet->extractFormat('%s');

                // Validate the signature
                $isValid = $this->publicKeyValidator->validateSignature(
                    keyAlgorithm: (string) $keyAlgorithmName, // Pass the actual key algorithm type
                    keyBlob: (string) $publicKeyBlob,    // Pass the key data blob
                    signatureBlob: (string) $signatureBlob,    // Pass the full signature blob (validator will parse)
                    sessionId: (string) $this->sessionId,
                    username: (string) $username,
                    service: (string) $service
                );
                $isValidString = $isValid ? 'true' : 'false';
                $this->info("Signature validation result: {$isValidString}");

                // They offered a public key, and they successfully validated they have the private key
                if ($isValid) {
                    $this->info("Public key signature validated successfully for user: {$username}");
                    $authenticatedPublicKey = $this->publicKeyValidator->getSshKeyFromBlob((string) $publicKeyBlob); // Store the validated key blob

                    $deferred = new Deferred();
                    $this->emit('authenticate', [(string) $username, $method, [$authenticatedPublicKey], $deferred]);

                    /** @var PromiseInterface<bool> $authenticatePromise */
                    $authenticatePromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
                    $authenticatePromise->then(
                        function (bool $authSuccess) use ($authenticatedPublicKey): void {
                            if (! $authSuccess) {
                                $availableAuthMethods = [
                                    'publickey',
                                    'password',
                                    'none',
                                ];
                                // If the keyboard-interactive mode has been configured, substitute it as an available method.
                                if (! is_null($this->keyboardInteractiveConfig)) {
                                    array_splice($availableAuthMethods, 1, 1, 'keyboard-interactive');
                                }
                                $this->writePacked(MessageType::USERAUTH_FAILURE, [implode(',', $availableAuthMethods), false]);

                                return;
                            }

                            $this->markAuthenticated();
                            $this->writePacked(MessageType::USERAUTH_SUCCESS);
                            $this->authenticatedPublicKey = $authenticatedPublicKey;
                        }
                    )->catch(
                        function (): void {
                            $this->writePacked(MessageType::USERAUTH_FAILURE);
                            $this->disconnect('Timeout validating credentials');
                        }
                    );

                    return;
                }

                $this->warning("Public key signature validation failed for user: {$username}");
                $this->writePacked(MessageType::USERAUTH_FAILURE, [implode(',', ['publickey', 'none']), false]);

                return;
            }
            // Client is checking if the key is acceptable (no signature provided yet)
            $this->info("Public key provided without signature, sending PK_OK for user: {$username}");
            if (in_array($keyAlgorithmName, $this->kexNegotiator?->getAcceptedUserKeyAlgorithms() ?? [])) {
                $this->writePacked(MessageType::USERAUTH_PK_OK, [$keyAlgorithmName, $publicKeyBlob]);
            } else {
                $this->warning("Public key algorithm {$keyAlgorithmName} not supported");
                $this->writePacked(MessageType::USERAUTH_FAILURE, [implode(',', ['publickey', 'none']), false]);
            }

            return;
        }

        if (! $this->authenticationEnabled) {
            // If we reached here, let them through without key authentication
            $this->info('Allowing access without key authentication');
            $this->markAuthenticated();
            $this->writePacked(MessageType::USERAUTH_SUCCESS);
        } else {
            $availableAuthMethods = [
                'password',
                'none',
            ];
            // If the keyboard-interactive mode has been configured, substitute it as an available method.
            if (! is_null($this->keyboardInteractiveConfig)) {
                array_splice($availableAuthMethods, 0, 1, 'keyboard-interactive');
            }
            $this->writePacked(MessageType::USERAUTH_FAILURE, [implode(',', $availableAuthMethods), false]);
        }
    }

    /**
     * Handle SSH_MSG_USERAUTH_INFO_RESPONSE (code 61).
     *
     * Contains the user’s answers to server specified prompts.
     *
     * Field	        Type	Description
     * num_responses	uint32	Number of responses (must match prompt count)
     * responses[n]	    string	User input
     */
    private function handleUserAuthInfoResponse(Packet $packet): void
    {
        [$numResponses] = $packet->extractFormat('%u');

        $responses = [];
        for ($i = 0; $i < $numResponses; ++$i) {
            $responses[] = $packet->extractFormat('%s')[0];
        }

        $deferred = new Deferred();
        $this->info("Accepting keyboard-interactive auth for user: {$this->username}");
        $this->emit('authenticate', [(string) $this->username, 'keyboard-interactive', $responses, $deferred]);

        /** @var PromiseInterface<bool> $authenticatePromise */
        $authenticatePromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
        $authenticatePromise->then(function (bool $authSuccess): void {
            if (! $authSuccess) {
                ++$this->authenticationFailureCount;

                if ($this->authenticationFailureCount < 3) {
                    $this->writePacked(MessageType::USERAUTH_FAILURE, ['keyboard-interactive', false]);
                } else {
                    $this->writePacked(MessageType::USERAUTH_FAILURE, ['none', false]);
                }

                return;
            }

            $this->markAuthenticated();
            $this->writePacked(MessageType::USERAUTH_SUCCESS);
        })->catch(function (\Throwable $e): void {
            $this->writePacked(MessageType::USERAUTH_FAILURE);
            $this->disconnect('Timeout validating credentials');
        });
    }

    private function handleChannelOpen(Packet $packet): false|int
    {
        // Format: string (channel type) + 3 uint32s (sender channel, window size, max packet)
        [$channelType, $remoteChannel, $initialWindowSize, $maxPacketSize] = $packet->extractFormat('%s%u%u%u');
        $this->maxPacketSize = (int) $maxPacketSize;

        $this->info("Channel open request: type={$channelType}, sender={$remoteChannel}, window={$initialWindowSize}, max_packet={$maxPacketSize}");

        if ('direct-tcpip' === $channelType) {
            $this->handleDirectTcpipChannelOpen(
                packet: $packet,
                remoteChannel: (int) $remoteChannel,
                initialWindowSize: (int) $initialWindowSize,
                maxPacketSize: (int) $maxPacketSize,
            );

            return 0;
        }

        if ('session' !== $channelType) {
            return $this->rejectChannelOpen(
                remoteChannel: (int) $remoteChannel,
                reason: ChannelOpenFailureReason::UNKNOWN_CHANNEL_TYPE,
                description: "Inbound channel type {$channelType} not allowed"
            );
        }

        $localChannel = $this->nextServerChannelId++;

        // Create new channel
        $channel = new Channel(
            $this,
            (int) $remoteChannel,
            (int) $localChannel,
            (int) $initialWindowSize,
            (int) $maxPacketSize,
            (string) $channelType
        );
        $channel->setLogger($this->logger);
        $this->registerActiveChannel($channel);

        // Send channel open confirmation
        $result = $this->writePacked(MessageType::CHANNEL_OPEN_CONFIRMATION, [$remoteChannel, $localChannel, $initialWindowSize, $maxPacketSize]);
        if ($result) {
            $this->emit('channel.open', [$channel]);
        }

        return $result;
    }

    /**
     * Handles an inbound `direct-tcpip` channel open request from the client.
     */
    private function handleDirectTcpipChannelOpen(Packet $packet, int $remoteChannel, int $initialWindowSize, int $maxPacketSize): void
    {
        [$destinationAddress, $destinationPort, $originatorAddress, $originatorPort] = $packet->extractFormat('%s%u%s%u');
        if (! is_string($destinationAddress) || ! is_int($destinationPort) || ! is_string($originatorAddress) || ! is_int($originatorPort)) {
            $this->rejectChannelOpen(
                remoteChannel: $remoteChannel,
                reason: ChannelOpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
                description: 'Invalid direct-tcpip channel open payload'
            );

            return;
        }

        if (! $this->directTcpipEnabled) {
            $this->rejectChannelOpen(
                remoteChannel: $remoteChannel,
                reason: ChannelOpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
                description: 'Inbound channel type direct-tcpip not allowed'
            );

            return;
        }

        $listeners = $this->listeners('direct-tcpip');
        if (0 === count($listeners)) {
            $this->rejectChannelOpen(
                remoteChannel: $remoteChannel,
                reason: ChannelOpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
                description: 'Inbound channel type direct-tcpip requires explicit approval'
            );

            return;
        }

        $info = [
            'destinationAddress' => $destinationAddress,
            'destinationPort' => $destinationPort,
            'originatorAddress' => $originatorAddress,
            'originatorPort' => $originatorPort,
        ];

        $deferred = new Deferred();
        $handled = false;
        $accept = function () use (&$handled, $remoteChannel, $initialWindowSize, $maxPacketSize, $destinationAddress, $destinationPort): void {
            if ($handled) {
                throw new \RuntimeException('Direct TCP/IP request already handled');
            }

            $handled = true;
            $this->openDirectTcpipSocket($remoteChannel, $initialWindowSize, $maxPacketSize, $destinationAddress, $destinationPort);
        };
        $reject = function () use (&$handled, $remoteChannel): void {
            if ($handled) {
                return;
            }

            $handled = true;
            $this->rejectChannelOpen(
                remoteChannel: $remoteChannel,
                reason: ChannelOpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
                description: 'Direct TCP/IP request denied by server policy'
            );
        };

        $this->emit('direct-tcpip', [$info, $deferred]);

        /** @var PromiseInterface<bool> $requestPromise */
        $requestPromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
        $requestPromise->then(function (bool $allowed) use ($accept, $reject): void {
            if ($allowed) {
                $accept();

                return;
            }

            $reject();
        })->catch(static function () use ($reject): void {
            $reject();
        });
    }

    /**
     * Handles incoming SSH_MSG_CHANNEL_OPEN requests from the client.
     *
     * This method is responsible for validating and processing channel open requests,
     * such as session channels. It rejects disallowed or unsupported channel types
     * (e.g., `direct-tcpip`) and performs the necessary setup for valid channels.
     *
     * @param Packet $packet the parsed SSH packet containing the channel open request
     */
    private function handleChannelRequest(Packet $packet): void
    {
        [$recipientChannel, $requestType, $wantReply] = $packet->extractFormat('%u%s%b');
        $wantReplyText = $wantReply ? 'true' : 'false';
        $this->info("Channel request: channel={$recipientChannel}, type={$requestType}, want_reply={$wantReplyText}");

        $channelSuccessReply = $this->packetHandler->packValue(MessageType::CHANNEL_SUCCESS, $recipientChannel);
        $channelFailureReply = $this->packetHandler->packValue(MessageType::CHANNEL_FAILURE, $recipientChannel);

        if (! isset($this->activeChannelsByLocalId[$recipientChannel])) {
            $this->error("Channel {$recipientChannel} not found");
            if ($wantReply) {
                $this->writeConnection($channelFailureReply);
            }

            return;
        }

        $channel = $this->activeChannelsByLocalId[$recipientChannel];
        $channelSuccessReply = $this->packetHandler->packValue(MessageType::CHANNEL_SUCCESS, $channel->getRecipientChannel());
        $channelFailureReply = $this->packetHandler->packValue(MessageType::CHANNEL_FAILURE, $channel->getRecipientChannel());

        // Handle different request types
        switch ($requestType) {
            case 'pty-req':
                /** @var Promise<bool> $handlePtyRequestPromise */
                $handlePtyRequestPromise = $this->handlePtyRequest($channel, $packet);
                $handlePtyRequestPromise->then(function (bool $success) use ($wantReply, $channelSuccessReply, $channelFailureReply): void {
                    if ($wantReply) {
                        $this->writeConnection($success ? $channelSuccessReply : $channelFailureReply);
                    }
                });

                break;

            case 'exec':
                /*
                 * Exec is used to run a command on the server, usually you'd do `ssh server 'tail -f log.log'`.
                 *
                 * Emit a channel-exec-request event if at least one registered listener is bound, otherwise just send success.
                 */
                if (count($channel->listeners('exec-request')) > 0) {
                    [$command] = $packet->extractFormat('%s');
                    $this->info("Received exec request with command: {$command}");

                    if ($wantReply) {
                        $channel->beginRequestReply();
                    }

                    $deferred = new Deferred();
                    $channel->emit('exec-request', [$command, $deferred]);

                    /** @var PromiseInterface<bool> $execRequestPromise */
                    $execRequestPromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
                    $execRequestPromise->then(function (bool $started) use ($channel, $wantReply, $channelSuccessReply, $channelFailureReply): void {
                        if ($wantReply) {
                            $this->writeConnection($started ? $channelSuccessReply : $channelFailureReply);
                            $channel->completeRequestReply();
                            $this->flushPendingChannelData($channel);
                            $channel->flushQueuedCloseOperations();
                        }
                    })->catch(function (\Throwable $e) use ($channel, $wantReply, $channelFailureReply): void {
                        if ($wantReply) {
                            $this->error($e->getMessage());
                            $this->writeConnection($channelFailureReply);
                            $channel->completeRequestReply();
                            $this->flushPendingChannelData($channel);
                            $channel->flushQueuedCloseOperations();
                        }
                    });

                    return;
                }

                if ($wantReply) {
                    $this->info('Sending exec-request FAILURE');
                    $this->writeConnection($channelFailureReply);
                }

                break;

            case 'shell':
                if (count($channel->listeners('shell-request')) > 0) {
                    if ($wantReply) {
                        $channel->beginRequestReply();
                    }

                    $deferred = new Deferred();
                    $channel->emit('shell-request', [$deferred]);

                    /** @var PromiseInterface<bool> $shellRequestPromise */
                    $shellRequestPromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
                    $shellRequestPromise->then(function (bool $started) use ($channel, $wantReply, $channelSuccessReply, $channelFailureReply): void {
                        if ($wantReply) {
                            $this->writeConnection($started ? $channelSuccessReply : $channelFailureReply);
                            $channel->completeRequestReply();
                            $this->flushPendingChannelData($channel);
                            $channel->flushQueuedCloseOperations();
                        }
                    })->catch(function (\Throwable $e) use ($channel, $wantReply, $channelFailureReply): void {
                        if ($wantReply) {
                            $this->error($e->getMessage());
                            $this->writeConnection($channelFailureReply);
                            $channel->completeRequestReply();
                            $this->flushPendingChannelData($channel);
                            $channel->flushQueuedCloseOperations();
                        }
                    });

                    return;
                }

                if ($wantReply) {
                    $this->info('Sending shell-request FAILURE');
                    $this->writeConnection($channelFailureReply);
                }

                break;

            case 'window-change':
                $this->handleWindowChange($channel, $packet);

                // No reply needed for window-change
                break;

            case 'env':
                // Client setting an environment variable
                [$name, $value] = $packet->extractFormat('%s%s');
                $this->info("Received env request: name={$name}, value={$value}");

                $channel->setEnvironmentVariable((string) $name, (string) $value);

                if ($wantReply) {
                    $this->writeConnection($channelSuccessReply);
                }

                break;

            case 'signal':
                // Client sent a signal (like Ctrl+C)
                [$signalName] = $packet->extractFormat('%s');
                $this->info("Received signal: {$signalName}");
                $channel->emit('signal', [$signalName]);

                break;

            default:
                // Unknown request type
                $this->info("Unhandled channel request type: {$requestType}");
                if ($wantReply) {
                    $this->writeConnection($channelFailureReply);
                }

                break;
        }
    }

    /**
     * This is a big one. For basic SSH sessions for a TUI everything before here is just setting up the connection.
     * Now we get the actual keypresses. This is where interactivity can happen.
     *
     * Get data/keypresses from the SSH client, forward to the channel instance.
     */
    private function handleChannelData(Packet $packet): void
    {
        [$recipientChannel, $data] = $packet->extractFormat('%u%s');

        if (! isset($this->activeChannelsByLocalId[$recipientChannel])) {
            $this->error("Channel {$recipientChannel} not found");

            return;
        }

        $channel = $this->activeChannelsByLocalId[$recipientChannel];
        $terminalInfo = $channel->getTerminalInfo();

        // Only convert CR to NL if ICRNL mode is enabled
        if ($terminalInfo && isset($terminalInfo->modes[TerminalMode::ICRNL->value])) {
            // Convert CR (0x0D) to NL (0x0A) if it's a single CR
            // This preserves CRLF sequences but converts lone CR to NL
            $data = preg_replace('/\r(?!\n)/', "\n", (string) $data);
        }

        try {
            // Forward the data to the server from the client.
            // A false result means the channel is currently buffering paused input.
            $delivered = $channel->writeToServer((string) $data);
        } catch (\OverflowException $e) {
            $this->warning('Channel inbound buffer exceeded disconnect threshold', [
                'channel_id' => $recipientChannel,
                'buffered_bytes' => $channel->getPendingInboundByteCount(),
            ]);
            $this->disconnect('Protocol error: channel inbound buffer overflow');

            return;
        }

        if (! $delivered) {
            $this->debug(sprintf(
                'Channel %d backpressure active for %d inbound bytes',
                $recipientChannel,
                strlen((string) $data)
            ));

            return;
        }

        $this->emit('channel.data', [$recipientChannel, $data]);
    }

    private function handleChannelClose(Packet $packet): void
    {
        [$channelId] = $packet->extractFormat('%u');

        if (! isset($this->activeChannelsByLocalId[$channelId])) {
            return;
        }

        $channel = $this->activeChannelsByLocalId[$channelId];
        $channel->markCloseReceived();

        if (! $channel->hasSentClose()) {
            $this->writePacked(MessageType::CHANNEL_CLOSE, $channel->getRecipientChannel());
            $channel->markCloseSent();
        }

        $localChannelId = $channel->getSenderChannel();
        $this->removeActiveChannel($channel);
        $this->emit('channel.close', [$localChannelId]);
    }

    /**
     * The recipient of this message MUST send back an SSH_MSG_CHANNEL_EOF
     * message unless it has already sent this message for the channel.
     * The channel remains open after this message, and more data may still
     * be sent in the other direction.
     */
    private function handleChannelEof(Packet $packet): void
    {
        [$channelId] = $packet->extractFormat('%u');

        if (! isset($this->activeChannelsByLocalId[$channelId])) {
            return;
        }

        $channel = $this->activeChannelsByLocalId[$channelId];
        if (in_array($channel->getChannelType(), ['forwarded-tcpip', 'direct-tcpip'], true)) {
            $channel->markInputClosedSilently();
        } else {
            $channel->markInputClosed();
        }

        $this->emit('channel.end', [$channel]);
    }

    /**
     * Handle data from the SSH client stream.
     */
    private function handleSshClientData(mixed $data): void
    {
        if (false === $data) {
            $this->error('Error reading from SSH client stream.');
            $this->info("Connection #{$this->connectionId} closed by peer");
        } elseif ('' === $data) {
            $this->debug('Data is empty');
            $this->disconnect();
        } else {
            if (! is_scalar($data) && ! (\is_object($data) && method_exists($data, '__toString'))) {
                throw new \InvalidArgumentException('Data must be stringable');
            }

            $this->handleData((string) $data);
            $this->lastActivity = new \DateTimeImmutable();
        }
    }

    /**
     * Handle raw protocol data received from the client.
     */
    private function handleData(string $data): void
    {
        if (is_null($this->clientVersion)) {
            $this->clientVersion = trim($data);
            // If we haven't already transmitted the server identifier, transmit it now.
            if (! $this->serverIdentiferSent) {
                $this->connection->write($this->serverVersion . "\r\n");
            }
            $this->info("Client version set: {$this->clientVersion}, we sent {$this->serverVersion}");

            if (false !== stripos($this->clientVersion ?? '', 'PuTTY')) {
                // PuTTY does not support EXT_INFO
                $this->supportsExtInfo = false;
            } elseif (false !== stripos($this->clientVersion ?? '', 'OpenSSH')) {
                // OpenSSH >= 7.8 supports EXT_INFO
                preg_match('/OpenSSH_([0-9.]+)/', $this->clientVersion ?? '', $matches);
                if (! empty($matches[1]) && version_compare($matches[1], '7.8', '>=')) {
                    $this->supportsExtInfo = true;
                } else {
                    $this->supportsExtInfo = false;
                }
            } else {
                // Default: assume true unless known otherwise
                $this->supportsExtInfo = true;
            }

            /*
             * After a short delay, check if the initial key exchange has completed.
             * If not, assume the client didn't send a KEXINIT and proactively send the server's KEXINIT
             * to initiate the key exchange process. This handles clients that wait for the server to start it.
             */
            sleep(0.5)->then(function (): void {
                if (
                    ! $this->packetHandler->hasCompletedInitialKeyExchange()
                    && false === $this->kexInitSent
                ) {
                    $this->kexNegotiator = new KexNegotiator($this->clientVersion ?? '', $this->serverVersion);
                    $this->kexInitSent = true;
                    $response = $this->kexNegotiator->response();
                    $this->writeConnection($response);
                }
            });

            return;
        }

        $this->inputBuffer .= $data;
        $badPacketCount = 0;

        while (true) {
            if (strlen($this->inputBuffer) < 4) {
                break;
            }

            try {
                $cipher = $this->kexNegotiator?->getNegotiatedAlgorithm('encryption_ctos') ?? '';
                $macAlgorithm = $this->kexNegotiator?->getNegotiatedAlgorithm('mac_ctos');
                $macLength = match ($cipher) {
                    'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com' => 16,
                    'aes128-ctr', 'aes192-ctr', 'aes256-ctr' => match ($macAlgorithm) {
                        'hmac-sha2-512' => 64,
                        'hmac-sha2-256' => 32,
                        'hmac-sha1' => 20,
                        default => 0
                    },
                    default => 0
                };

                if (! $this->packetHandler->isEncryptionActive()) {
                    $packetLength = (unpack('N', substr($this->inputBuffer, 0, 4)) ?: [])[1] ?? null;
                    if (! is_int($packetLength)) {
                        throw new \UnexpectedValueException('Expected int-castable value at offset 1');
                    }
                    $totalNeeded = 4 + $packetLength;

                    if (strlen($this->inputBuffer) < $totalNeeded) {
                        break;
                    }

                    [$packet, $bytesUsed] = $this->packetHandler->fromData($this->inputBuffer);
                    if (! is_int($bytesUsed)) {
                        throw new \RuntimeException('Unexpected value for bytesUsed');
                    }

                    $this->inputBuffer = substr($this->inputBuffer, $bytesUsed);

                    if (! $packet instanceof Packet) {
                        throw new \RuntimeException('Unexpected data parsing packet');
                    }

                    $this->handlePacket($packet);

                    continue;
                }

                // AES-CTR mode: the 4-byte packet length field is encrypted along with the rest of the packet,
                // so we cannot determine the full packet size up front. Instead, defer to the packet handler
                // to decrypt and parse the entire packet from the buffer. If successful, consume the used bytes
                // and process the resulting packet.
                if (in_array($cipher, ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'])) {
                    [$packet, $bytesUsed] = $this->packetHandler->fromData($this->inputBuffer);
                    if (! is_int($bytesUsed)) {
                        throw new \RuntimeException('Invalid bytes consumed');
                    }

                    if (null === $packet) {
                        if (0 === $bytesUsed) {
                            $this->debug('Packet parsing returned null with 0 bytes used, likely incomplete packet');

                            break;
                        }

                        // We were sent bad data. We are just going to disconnect, the client is probably bad/misbehaving
                        $this->error("Failed to parse packet, bad packet received. Bytes used: {$bytesUsed}");
                        ++$badPacketCount;
                        if ($badPacketCount > 3) {
                            $this->disconnect('Protocol error: too many bad packets');
                        }

                        continue;
                    }

                    $this->inputBuffer = substr($this->inputBuffer, $bytesUsed);

                    if (! $packet instanceof Packet) {
                        throw new \RuntimeException('Unexpected data parsing packet');
                    }

                    $this->handlePacket($packet);

                    continue;
                }

                // GCM and other modes where length is plaintext
                $packetLength = (unpack('N', substr($this->inputBuffer, 0, 4)) ?: [])[1] ?? null;
                if (! is_int($packetLength)) {
                    throw new \UnexpectedValueException('Expected int-castable value at offset 1');
                }
                $totalNeeded = 4 + $packetLength + $macLength;

                if ($totalNeeded > $this->maxPacketSize) {
                    $this->error("Protocol error: packet too large ({$totalNeeded} > {$this->maxPacketSize}), bad packet received");
                    $this->disconnect('Protocol error: packet too large, bad packet received');

                    break;
                }

                if (strlen($this->inputBuffer) < $totalNeeded) {
                    break;
                }

                [$packet, $bytesUsed] = $this->packetHandler->fromData($this->inputBuffer);
                if (! is_int($bytesUsed)) {
                    throw new \RuntimeException('Unexpected value for bytesUsed');
                }

                if (null === $packet) {
                    if (0 === $bytesUsed) {
                        $this->debug('Packet parsing returned null with 0 bytes used, likely incomplete packet');

                        break;
                    }

                    // We were sent bad data. We are just going to disconnect, the client is probably bad/misbehaving
                    $this->error("Failed to parse packet, bad packet received. Bytes used: {$bytesUsed}");
                    ++$badPacketCount;
                    if ($badPacketCount > 3) {
                        $this->disconnect('Protocol error: too many bad packets');
                    }

                    continue;
                }

                $this->inputBuffer = substr($this->inputBuffer, $bytesUsed);

                if (! $packet instanceof Packet) {
                    throw new \RuntimeException('Unexpected data parsing packet');
                }

                $this->handlePacket($packet);
            } catch (\Exception $e) {
                $this->error('Error processing packet: ' . $e->getMessage());
                $this->inputBuffer = substr($this->inputBuffer, 1);
            }

            if (strlen($this->inputBuffer) > 1048576) {
                $this->error('Input buffer too large, disconnecting');
                $this->disconnect('Protocol error: buffer overflow');

                return;
            }
        }
    }

    /**
     * Handle an SSH packet.
     */
    private function handlePacket(Packet $packet): Packet
    {
        $this->debug("Handling packet: {$packet->type->name}, packet length: " . strlen($packet->message));

        // Special debug for NEWKEYS which is crucial for rekeying
        if (MessageType::NEWKEYS === $packet->type) {
            $this->debug('Received NEWKEYS packet during '
                . ($this->packetHandler->hasRekeyInProgress() ? 'rekey process' : 'initial key exchange'));
        }

        if (! $this->isAuthenticated() && ! $this->isAllowedBeforeAuthentication($packet->type)) {
            $this->disconnectForUnauthorizedPacket($packet->type);

            return $packet;
        }

        match ($packet->type) {
            MessageType::DISCONNECT => $this->handleDisconnect($packet),
            MessageType::KEXINIT => $this->handleKexInit($packet),
            MessageType::KEXDH_INIT => $this->handleKexDHInit($packet),
            MessageType::NEWKEYS => $this->handleNewKeys($packet),
            MessageType::SERVICE_REQUEST => $this->handleServiceRequest($packet),
            MessageType::USERAUTH_REQUEST => $this->handleUserAuthRequest($packet), // 'Can we login please?'
            MessageType::USERAUTH_INFO_RESPONSE => $this->handleUserAuthInfoResponse($packet),
            MessageType::CHANNEL_OPEN => $this->handleChannelOpen($packet), // 'I want to open a channel'
            MessageType::CHANNEL_OPEN_CONFIRMATION => $this->handleChannelOpenConfirmation($packet),
            MessageType::CHANNEL_OPEN_FAILURE => $this->handleChannelOpenFailure($packet),
            MessageType::CHANNEL_REQUEST => $this->handleChannelRequest($packet), // 'Lets use this channel for [shell, exec, subsystem, x11, forward, auth-agent, etc..]'
            MessageType::CHANNEL_WINDOW_ADJUST => $this->handleChannelWindowAdjust($packet),
            MessageType::CHANNEL_DATA => $this->handleChannelData($packet), // 'I'm sending you some data' (key press in our case usually)
            MessageType::CHANNEL_EOF => $this->handleChannelEof($packet),
            MessageType::CHANNEL_CLOSE => $this->handleChannelClose($packet),
            MessageType::IGNORE => $this->handleIgnore($packet),
            MessageType::DEBUG => $this->handleDebug($packet),
            MessageType::UNIMPLEMENTED => $this->handleUnimplemented($packet),
            MessageType::GLOBAL_REQUEST => $this->handleGlobalRequest($packet),
            default => $this->info('Unsupported packet type: ' . $packet->type->name),
        };

        return $packet;
    }

    /**
     * Marks the connection as authenticated after a successful userauth exchange.
     */
    private function markAuthenticated(): void
    {
        $this->authenticated = true;
    }

    /**
     * Determines whether the given packet type is valid before user authentication completes.
     *
     * This permits only transport and authentication-phase messages until the client has been
     * explicitly authenticated.
     */
    private function isAllowedBeforeAuthentication(MessageType $type): bool
    {
        return match ($type) {
            MessageType::DISCONNECT,
            MessageType::IGNORE,
            MessageType::DEBUG,
            MessageType::UNIMPLEMENTED,
            MessageType::KEXINIT,
            MessageType::KEXDH_INIT,
            MessageType::NEWKEYS,
            MessageType::SERVICE_REQUEST,
            MessageType::USERAUTH_REQUEST,
            MessageType::USERAUTH_INFO_RESPONSE => true,
            default => false,
        };
    }

    /**
     * Disconnects the client after receiving a connection-protocol packet before authentication.
     */
    private function disconnectForUnauthorizedPacket(MessageType $type): void
    {
        $this->warning('Received connection-protocol packet before authentication completed', [
            'message_type' => $type->name,
        ]);

        $this->disconnect(
            'Protocol error: received ' . $type->name . ' before authentication completed',
            DisconnectReason::PROTOCOL_ERROR
        );
    }

    /**
     * Rejects a client channel-open request without creating server-side channel state.
     */
    private function rejectChannelOpen(int $remoteChannel, ChannelOpenFailureReason $reason, string $description): false|int
    {
        $this->warning($description, [
            'remote_channel' => $remoteChannel,
            'reason' => $reason->name,
        ]);

        return $this->writePacked(MessageType::CHANNEL_OPEN_FAILURE, [
            $remoteChannel,
            $reason->value,
            $description,
            'en',
        ]);
    }

    /**
     * Packs a message of the given type and writes it to the connection.
     *
     * Converts the provided value (or values) into a properly formatted SSH packet
     * using the PacketHandler, and sends it over the connection stream.
     *
     * @param MessageType $type  the SSH message type to send
     * @param mixed       $value a single value or an array of values to be packed with the message
     *
     * @return false|int number of bytes written, or false on failure
     */
    private function writePacked(MessageType $type, mixed $value = null): false|int
    {
        $packet = $this->packetHandler->packValues($type, is_array($value) ? $value : [$value]);

        return $this->writeConnection($packet);
    }

    /**
     * Write raw data back to the client.
     *
     * Do not use this method to communicate during your session.
     * You should be using the write method in the Channel instance.
     *
     * @return false|int - number of bytes written or false if failed
     */
    private function writeConnection(?string $data): false|int
    {
        if (is_null($data)) {
            return false;
        }

        $packet = $this->packetHandler->constructPacket($data);
        if (false === $packet) {
            $this->error('Failed to construct packet');

            return false;
        }

        $result = $this->connection->write($packet);

        if (false === $result) {
            return false;
        }

        return strlen($packet);
    }

    private function handleChannelWindowAdjust(Packet $packet): void
    {
        [$channelId, $bytesToAdd] = $packet->extractFormat('%u%u');

        $channel = $this->activeChannelsByLocalId[$channelId] ?? null;
        if (! $channel instanceof Channel) {
            $this->debug("Ignoring window adjust for unknown channel {$channelId}");

            return;
        }

        if ($bytesToAdd <= 0) {
            $this->debug("Ignoring non-positive window adjust for channel {$channelId}");

            return;
        }

        $channel->increaseRemoteWindow((int) $bytesToAdd);
        $this->flushPendingChannelData($channel);
    }

    private function flushPendingChannelData(?Channel $priorityChannel = null): void
    {
        $channels = null === $priorityChannel
            ? array_values($this->activeChannelsByLocalId)
            : array_merge([$priorityChannel], array_values(array_filter(
                $this->activeChannelsByLocalId,
                static fn (Channel $channel): bool => $channel !== $priorityChannel
            )));

        foreach ($channels as $channel) {
            while ($channel->hasPendingOutboundData() && $channel->getWindowSize() > 0 && $this->connection->isWritable() && ! $this->transportBackpressured) {
                $chunk = $channel->shiftPendingOutboundChunk();
                if (! is_string($chunk)) {
                    break;
                }

                $writtenBytes = $this->writeChannelDataChunks($channel, $chunk);
                if ($writtenBytes < strlen($chunk)) {
                    $channel->prependPendingOutboundChunk(substr($chunk, $writtenBytes));

                    return;
                }
            }

            if ($this->transportBackpressured) {
                return;
            }
        }
    }

    private function writeChannelDataChunks(Channel $channel, string $data): int
    {
        $maxChunkSize = max(1, $channel->getMaxPacketSize() - 1024); // Leave room for packet overhead
        $offset = 0;
        $totalLength = strlen($data);

        while ($offset < $totalLength && $channel->getWindowSize() > 0) {
            $availableWindow = $channel->getWindowSize();
            $remainingBytes = $totalLength - $offset;
            $chunkLength = min($remainingBytes, $availableWindow, $maxChunkSize);
            if ($chunkLength <= 0) {
                break;
            }

            $chunk = substr($data, $offset, $chunkLength);
            $result = $this->writePacked(MessageType::CHANNEL_DATA, [$channel->getRecipientChannel(), $chunk]);
            if (false === $result) {
                $channel->consumeRemoteWindow(strlen($chunk));
                $offset += strlen($chunk);
                $this->transportBackpressured = true;

                break;
            }

            $actualChunkLength = strlen($chunk);
            $channel->consumeRemoteWindow($actualChunkLength);
            $offset += $actualChunkLength;
        }

        return $offset;
    }

    private function handleDisconnect(Packet $packet): void
    {
        [$reasonCode, $description] = $packet->extractFormat('%u%s');
        $this->disconnect("Client requested disconnect: {$description} (code: {$reasonCode})");
    }

    private function handleIgnore(Packet $packet): void
    {
        // Just ignore this packet, as per RFC
        $this->debug('Received IGNORE message');
    }

    private function handleDebug(Packet $packet): void
    {
        [$alwaysDisplay, $message] = $packet->extractFormat('%b%s');
        $this->debug("Received DEBUG message: {$message}");
    }

    private function handleUnimplemented(Packet $packet): void
    {
        [$seqNum] = $packet->extractFormat('%u');
        $this->debug("Received UNIMPLEMENTED for sequence number: {$seqNum}");
    }

    private function handleGlobalRequest(Packet $packet): void
    {
        [$requestType, $wantReply] = $packet->extractFormat('%s%b');
        $wantReplyText = $wantReply ? 'true' : 'false';
        $this->debug("Received GLOBAL_REQUEST: {$requestType}, want_reply={$wantReplyText}");

        match ($requestType) {
            'tcpip-forward' => $this->handleTcpipForwardRequest($packet, (bool) $wantReply),
            'cancel-tcpip-forward' => $this->handleCancelTcpipForwardRequest($packet, (bool) $wantReply),
            default => $this->replyToGlobalRequest((bool) $wantReply, false),
        };
    }

    /**
     * Finalizes a server-initiated `forwarded-tcpip` channel open after client confirmation.
     *
     * This promotes the pending outbound open into an active channel and wires the
     * accepted TCP socket into the normal SSH channel data flow.
     */
    private function handleChannelOpenConfirmation(Packet $packet): void
    {
        [$localChannel, $remoteChannel, $initialWindow, $maxPacketSize] = $packet->extractFormat('%u%u%u%u');
        if (! is_int($localChannel) || ! is_int($remoteChannel) || ! is_int($initialWindow) || ! is_int($maxPacketSize)) {
            throw new \UnexpectedValueException('Invalid channel open confirmation payload');
        }

        $pending = $this->takePendingOutboundChannelOpen($localChannel);
        if (! is_array($pending)) {
            $this->debug("Ignoring channel open confirmation for unknown local channel {$localChannel}");

            return;
        }

        $channel = new Channel(
            $this,
            (int) $remoteChannel,
            (int) $localChannel,
            (int) $initialWindow,
            (int) $maxPacketSize,
            (string) $pending['type']
        );
        $channel->setLogger($this->logger);
        $this->registerActiveChannel($channel);

        $socket = $pending['socket'];
        $this->attachForwardedSocketHandlers($channel, $socket, (string) $pending['listenerKey']);
        $this->detachRemoteForwardChannelSocket((string) $pending['listenerKey'], $localChannel);
        $this->registerRemoteForwardChannelSocket((string) $pending['listenerKey'], $localChannel, $socket, true);
        $socket->resume();
    }

    /**
     * Cleans up a pending server-initiated `forwarded-tcpip` channel open after client rejection.
     */
    private function handleChannelOpenFailure(Packet $packet): void
    {
        [$localChannel, $reasonCode, $description] = $packet->extractFormat('%u%u%s%s');
        if (! is_int($localChannel) || ! is_int($reasonCode) || ! is_string($description)) {
            throw new \UnexpectedValueException('Invalid channel open failure payload');
        }

        $pending = $this->takePendingOutboundChannelOpen($localChannel);
        if (! is_array($pending)) {
            $this->debug("Ignoring channel open failure for unknown local channel {$localChannel}");

            return;
        }

        $this->detachRemoteForwardChannelSocket((string) $pending['listenerKey'], $localChannel);
        $pending['socket']->close();

        $this->warning("Forwarded channel open failed: {$description}", [
            'local_channel' => $localChannel,
            'reason_code' => $reasonCode,
        ]);
    }

    /**
     * Handles an incoming `tcpip-forward` global request.
     *
     * Remote forwarding must be enabled explicitly and each request must be approved
     * by a `global-request.tcpip-forward` event listener before a listening socket is created.
     */
    private function handleTcpipForwardRequest(Packet $packet, bool $wantReply): void
    {
        if (! $this->remoteForwardingEnabled) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        [$bindAddress, $bindPort] = $packet->extractFormat('%s%u');
        if (! is_string($bindAddress) || ! is_int($bindPort)) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        $listeners = $this->listeners('global-request.tcpip-forward');
        if (0 === count($listeners)) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        $deferred = new Deferred();
        $handled = false;
        $accept = function () use (&$handled, $wantReply, $bindAddress, $bindPort): void {
            if ($handled) {
                throw new \RuntimeException('Forward request already handled');
            }

            $handled = true;
            $this->createRemoteForwardListener($bindAddress, $bindPort, $wantReply);
        };
        $reject = function () use (&$handled, $wantReply): void {
            if ($handled) {
                return;
            }

            $handled = true;
            $this->replyToGlobalRequest($wantReply, false);
        };

        $this->emit('global-request.tcpip-forward', [$bindAddress, $bindPort, $deferred]);

        /** @var PromiseInterface<bool> $requestPromise */
        $requestPromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
        $requestPromise->then(function (bool $allowed) use ($accept, $reject): void {
            if ($allowed) {
                $accept();

                return;
            }

            $reject();
        })->catch(static function () use ($reject): void {
            $reject();
        });
    }

    /**
     * Handles an incoming `cancel-tcpip-forward` global request.
     */
    private function handleCancelTcpipForwardRequest(Packet $packet, bool $wantReply): void
    {
        if (! $this->remoteForwardingEnabled) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        [$bindAddress, $bindPort] = $packet->extractFormat('%s%u');
        if (! is_string($bindAddress) || ! is_int($bindPort)) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        $bindAddress = $this->normalizeRemoteForwardBindAddress($bindAddress);

        $this->emit('global-request.cancel-tcpip-forward', [$bindAddress, $bindPort]);

        $listenerKey = $this->remoteForwardListenerKey($bindAddress, $bindPort);
        if (! isset($this->remoteForwardListeners[$listenerKey])) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        $this->closeRemoteForwardListener($listenerKey);
        $this->replyToGlobalRequest($wantReply, true);
    }

    /**
     * Creates and registers a server-side TCP listener for an approved remote forward.
     */
    private function createRemoteForwardListener(string $bindAddress, int $bindPort, bool $wantReply): void
    {
        $bindAddress = $this->normalizeRemoteForwardBindAddress($bindAddress);

        if (! $this->isValidRemoteForwardRequest($bindAddress, $bindPort)) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        $listenerKey = $this->remoteForwardListenerKey($bindAddress, $bindPort);
        if (isset($this->remoteForwardListeners[$listenerKey])) {
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        $bindTarget = $this->toTcpServerBindTarget($bindAddress, $bindPort);

        try {
            $server = new TcpServer($bindTarget, $this->loop);
        } catch (\Throwable $e) {
            $this->warning('Failed to create remote forward listener: ' . $e->getMessage(), [
                'bind_address' => $bindAddress,
                'bind_port' => $bindPort,
            ]);
            $this->replyToGlobalRequest($wantReply, false);

            return;
        }

        [$effectiveAddress, $effectivePort] = $this->parseSocketAddress($server->getAddress());
        $this->remoteForwardListeners[$listenerKey] = [
            'requestedAddress' => $bindAddress,
            'requestedPort' => $bindPort,
            'effectiveAddress' => $effectiveAddress,
            'effectivePort' => $effectivePort,
            'server' => $server,
            'channels' => [],
            'pendingChannels' => [],
        ];

        $server->on('connection', function (ConnectionInterface $socket) use ($listenerKey): void {
            $this->handleRemoteForwardAcceptedSocket($listenerKey, $socket);
        });
        $server->on('close', function () use ($listenerKey): void {
            unset($this->remoteForwardListeners[$listenerKey]);
        });

        if (0 === $bindPort) {
            $this->replyToGlobalRequest($wantReply, true, [$effectivePort]);

            return;
        }

        $this->replyToGlobalRequest($wantReply, true);
    }

    /**
     * Opens a server-initiated `forwarded-tcpip` channel for an accepted forwarded TCP socket.
     */
    private function handleRemoteForwardAcceptedSocket(string $listenerKey, ConnectionInterface $socket): void
    {
        $listener = $this->remoteForwardListeners[$listenerKey] ?? null;
        if (! is_array($listener)) {
            $socket->close();

            return;
        }

        // Hold inbound TCP bytes until the client confirms the forwarded channel.
        $socket->pause();

        [$originatorAddress, $originatorPort] = $this->parseSocketAddress($socket->getRemoteAddress());
        $localChannel = $this->nextServerChannelId++;
        $timeoutTimer = $this->loop->addTimer($this->pendingForwardedChannelOpenTimeout, function () use ($localChannel): void {
            $pending = $this->takePendingOutboundChannelOpen($localChannel);
            if (! is_array($pending)) {
                return;
            }

            $this->detachRemoteForwardChannelSocket((string) $pending['listenerKey'], $localChannel);
            $pending['socket']->close();
            $this->warning('Timed out waiting for forwarded channel open confirmation', [
                'local_channel' => $localChannel,
                'listener_key' => $pending['listenerKey'],
            ]);
        });

        $this->pendingOutboundChannelOpens[$localChannel] = [
            'type' => 'forwarded-tcpip',
            'socket' => $socket,
            'listenerKey' => $listenerKey,
            'connectedAddress' => $listener['requestedAddress'],
            'connectedPort' => 0 === $listener['requestedPort'] ? $listener['effectivePort'] : $listener['requestedPort'],
            'originatorAddress' => $originatorAddress,
            'originatorPort' => $originatorPort,
            'timeoutTimer' => $timeoutTimer,
        ];
        $this->registerRemoteForwardChannelSocket($listenerKey, $localChannel, $socket, false);
        $this->emit('forwarded-tcpip.connection', [[
            'bindAddress' => $listener['requestedAddress'],
            'bindPort' => 0 === $listener['requestedPort'] ? $listener['effectivePort'] : $listener['requestedPort'],
            'originatorAddress' => $originatorAddress,
            'originatorPort' => $originatorPort,
        ], $socket]);

        $result = $this->writePacked(MessageType::CHANNEL_OPEN, [
            'forwarded-tcpip',
            $localChannel,
            1024 * 1024,
            32768,
            $listener['requestedAddress'],
            0 === $listener['requestedPort'] ? $listener['effectivePort'] : $listener['requestedPort'],
            $originatorAddress,
            $originatorPort,
        ]);

        if (false === $result) {
            $pending = $this->takePendingOutboundChannelOpen($localChannel);
            if (! is_array($pending)) {
                return;
            }

            $this->detachRemoteForwardChannelSocket((string) $pending['listenerKey'], $localChannel);
            $pending['socket']->close();
        }
    }

    /**
     * Bridges a confirmed `forwarded-tcpip` SSH channel to its accepted TCP socket.
     */
    private function attachForwardedSocketHandlers(Channel $channel, ConnectionInterface $socket, string $listenerKey): void
    {
        $this->attachTcpipSocketHandlers(
            channel: $channel,
            socket: $socket,
            onSocketClose: function () use ($listenerKey, $channel): void {
                $this->detachRemoteForwardChannelSocket($listenerKey, $channel->getSenderChannel());
            },
            onChannelClose: function () use ($listenerKey, $channel): void {
                $this->detachRemoteForwardChannelSocket($listenerKey, $channel->getSenderChannel());
            }
        );
    }

    /**
     * Bridges a confirmed `direct-tcpip` SSH channel to its outbound TCP socket.
     */
    private function attachDirectTcpipSocketHandlers(Channel $channel, ConnectionInterface $socket): void
    {
        $this->attachTcpipSocketHandlers(
            channel: $channel,
            socket: $socket,
            onSocketClose: function () use ($channel): void {
                unset($this->directTcpipSockets[$channel->getSenderChannel()]);
            },
            onChannelClose: function () use ($channel): void {
                unset($this->directTcpipSockets[$channel->getSenderChannel()]);
            }
        );
    }

    /**
     * Wires a TCP socket into a stream-oriented SSH channel lifecycle.
     */
    private function attachTcpipSocketHandlers(Channel $channel, ConnectionInterface $socket, callable $onSocketClose, callable $onChannelClose): void
    {
        $socket->on('data', function (mixed $data) use ($channel): void {
            if (! is_scalar($data) && ! (is_object($data) && method_exists($data, '__toString'))) {
                return;
            }

            $channel->write((string) $data);
        });
        $socket->on('end', function () use ($channel): void {
            $channel->end();
        });
        $socket->on('close', function () use ($channel, $onSocketClose): void {
            $onSocketClose();
            $channel->close();
        });
        $channel->on('data', static function (string $data) use ($socket): void {
            $socket->write($data);
        });
        $channel->on('close', function () use ($socket, $onChannelClose): void {
            $onChannelClose();
            $socket->close();
        });
    }

    /**
     * Attempts to connect an approved `direct-tcpip` request to its destination.
     */
    private function openDirectTcpipSocket(int $remoteChannel, int $initialWindowSize, int $maxPacketSize, string $destinationAddress, int $destinationPort): void
    {
        $connectTarget = $this->toConnectTarget($destinationAddress, $destinationPort);

        /** @var PromiseInterface<ConnectionInterface> $connectPromise */
        $connectPromise = $this->connector->connect($connectTarget);
        $this->pendingDirectTcpipConnects[$remoteChannel] = $connectPromise;

        $connectPromise->then(function (ConnectionInterface $socket) use ($remoteChannel, $initialWindowSize, $maxPacketSize): void {
            unset($this->pendingDirectTcpipConnects[$remoteChannel]);

            if (! $this->connection->isWritable()) {
                $socket->close();

                return;
            }

            $localChannel = $this->nextServerChannelId++;
            $channel = new Channel(
                $this,
                $remoteChannel,
                $localChannel,
                $initialWindowSize,
                $maxPacketSize,
                'direct-tcpip'
            );
            $channel->setLogger($this->logger);
            $this->registerActiveChannel($channel);
            $this->directTcpipSockets[$localChannel] = $socket;

            $result = $this->writePacked(MessageType::CHANNEL_OPEN_CONFIRMATION, [$remoteChannel, $localChannel, $initialWindowSize, $maxPacketSize]);
            if (false === $result) {
                unset($this->directTcpipSockets[$localChannel]);
                $this->removeActiveChannel($channel);
                $socket->close();

                return;
            }

            $this->attachDirectTcpipSocketHandlers($channel, $socket);
            $this->emit('channel.open', [$channel]);
        })->catch(function (\Throwable $e) use ($remoteChannel): void {
            unset($this->pendingDirectTcpipConnects[$remoteChannel]);
            $this->rejectChannelOpen(
                remoteChannel: $remoteChannel,
                reason: ChannelOpenFailureReason::CONNECT_FAILED,
                description: 'Direct TCP/IP connect failed: ' . $e->getMessage()
            );
        });
    }

    /**
     * Sends a success or failure reply for a global request when the client asked for one.
     *
     * @param array<int, int|string> $values optional success payload fields
     */
    private function replyToGlobalRequest(bool $wantReply, bool $success, array $values = []): void
    {
        if (! $wantReply) {
            return;
        }

        $this->writePacked($success ? MessageType::REQUEST_SUCCESS : MessageType::REQUEST_FAILURE, $values);
    }

    /**
     * Validates whether a remote-forward bind request is supported by the current policy.
     */
    private function isValidRemoteForwardRequest(string $bindAddress, int $bindPort): bool
    {
        if ($bindPort < 0 || $bindPort > 65535) {
            return false;
        }

        $bindAddress = $this->normalizeRemoteForwardBindAddress($bindAddress);

        return in_array($bindAddress, ['127.0.0.1', '0.0.0.0', '::1', '::', 'localhost'], true)
            || false !== filter_var($bindAddress, FILTER_VALIDATE_IP);
    }

    /**
     * Converts an SSH bind address and port into a ReactPHP `TcpServer` bind target.
     */
    private function toTcpServerBindTarget(string $bindAddress, int $bindPort): string
    {
        $bindAddress = $this->normalizeRemoteForwardBindAddress($bindAddress);

        if (str_contains($bindAddress, ':') && ! str_starts_with($bindAddress, '[')) {
            return sprintf('[%s]:%d', $bindAddress, $bindPort);
        }

        return sprintf('%s:%d', $bindAddress, $bindPort);
    }

    /**
     * Converts a direct TCP/IP destination into a ReactPHP connector target.
     */
    private function toConnectTarget(string $destinationAddress, int $destinationPort): string
    {
        if (str_contains($destinationAddress, ':') && ! str_starts_with($destinationAddress, '[')) {
            return sprintf('[%s]:%d', $destinationAddress, $destinationPort);
        }

        return sprintf('%s:%d', $destinationAddress, $destinationPort);
    }

    /**
     * Canonicalizes remote-forward bind addresses so equivalent IPv6 forms share one listener key.
     */
    private function normalizeRemoteForwardBindAddress(string $bindAddress): string
    {
        $bindAddress = strtolower($bindAddress);

        if (str_starts_with($bindAddress, '[') && str_ends_with($bindAddress, ']')) {
            return substr($bindAddress, 1, -1);
        }

        return $bindAddress;
    }

    /**
     * Parses a ReactPHP socket URI into host and port components.
     *
     * @return array{0: string, 1: int}
     */
    private function parseSocketAddress(?string $address): array
    {
        if (! is_string($address)) {
            return ['0.0.0.0', 0];
        }

        $host = parse_url($address, PHP_URL_HOST);
        $port = parse_url($address, PHP_URL_PORT);

        return [
            is_string($host) ? trim($host, '[]') : '0.0.0.0',
            is_int($port) ? $port : 0,
        ];
    }

    /**
     * Builds the internal array key used to track remote-forward listeners.
     */
    private function remoteForwardListenerKey(string $bindAddress, int $bindPort): string
    {
        $bindAddress = $this->normalizeRemoteForwardBindAddress($bindAddress);

        return $bindAddress . ':' . $bindPort;
    }

    /**
     * Registers an active channel under the server-local channel id maps.
     */
    private function registerActiveChannel(Channel $channel): void
    {
        $this->activeChannelsByLocalId[$channel->getSenderChannel()] = $channel;
    }

    /**
     * Removes an active channel from connection bookkeeping and finalizes its close state.
     */
    private function removeActiveChannel(Channel $channel): void
    {
        unset($this->activeChannelsByLocalId[$channel->getSenderChannel()]);
        $channel->finalizeClose();
    }

    /**
     * Tracks an accepted forwarded TCP socket under its listener state.
     */
    private function registerRemoteForwardChannelSocket(string $listenerKey, int $channelId, ConnectionInterface $socket, bool $active): void
    {
        if (! isset($this->remoteForwardListeners[$listenerKey])) {
            return;
        }

        $bucket = $active ? 'channels' : 'pendingChannels';
        $this->remoteForwardListeners[$listenerKey][$bucket][$channelId] = $socket;
    }

    /**
     * Removes a forwarded TCP socket from listener bookkeeping.
     */
    private function detachRemoteForwardChannelSocket(string $listenerKey, int $channelId): void
    {
        if (! isset($this->remoteForwardListeners[$listenerKey])) {
            return;
        }

        unset(
            $this->remoteForwardListeners[$listenerKey]['channels'][$channelId],
            $this->remoteForwardListeners[$listenerKey]['pendingChannels'][$channelId]
        );
    }

    /**
     * Removes a pending outbound channel open and cancels its timeout.
     *
     * @return null|array{type: string, socket: ConnectionInterface, listenerKey: string, connectedAddress: string, connectedPort: int, originatorAddress: string, originatorPort: int, timeoutTimer: TimerInterface}
     */
    private function takePendingOutboundChannelOpen(int $localChannel): ?array
    {
        $pending = $this->pendingOutboundChannelOpens[$localChannel] ?? null;
        if (! is_array($pending)) {
            return null;
        }

        unset($this->pendingOutboundChannelOpens[$localChannel]);
        $this->loop->cancelTimer($pending['timeoutTimer']);

        return $pending;
    }

    /**
     * Closes a remote-forward listener and all sockets or channels associated with it.
     */
    private function closeRemoteForwardListener(string $listenerKey): void
    {
        $listener = $this->remoteForwardListeners[$listenerKey] ?? null;
        if (! is_array($listener)) {
            return;
        }

        foreach (array_merge($listener['channels'], $listener['pendingChannels']) as $channelId => $socket) {
            $this->takePendingOutboundChannelOpen($channelId);

            $channel = $this->activeChannelsByLocalId[$channelId] ?? null;
            if ($channel instanceof Channel) {
                $this->removeActiveChannel($channel);
            }

            $socket->close();
        }

        $listener['server']->close();
        unset($this->remoteForwardListeners[$listenerKey]);
    }

    private function handleKexInit(Packet $packet): void
    {
        // If we've already done an initial key exchange, this is a rekey request
        if ($this->packetHandler->hasCompletedInitialKeyExchange()) {
            $this->debug('Received rekey request from client');
            $this->packetHandler->toggleRekeyInProgress();
            // SSH_MSG_KEXINIT is sent once at the beginning of the key exchange,
            // and re-sent if a rekey is initiated.
            $this->kexInitSent = false;
        }

        if (! $this->kexInitSent) {
            $this->kexNegotiator = new KexNegotiator($this->clientVersion ?? '', $this->serverVersion, $packet);
            $this->kexInitSent = true;
            $response = $this->kexNegotiator->response();
            $this->writeConnection($response);
        } else {
            // We've already sent a KEX INIT and we're not in a rekey, so just record
            // the client packet for algorithm negotiation.
            $this->kexNegotiator?->setClientKexInit($packet);
        }

        try {
            $negotiatedAlgorithms = $this->kexNegotiator?->negotiateAlgorithms();
            $this->debug('Negotiated algorithms: ' . json_encode($negotiatedAlgorithms));
        } catch (\Throwable $e) {
            $this->disconnect($e->getMessage(), DisconnectReason::KEY_EXCHANGE_FAILED);
        }
    }

    /**
     * Diffie Hellman key exchange
     * Lots going on here which enables encryption to work, but crosses through a lot of areas.
     */
    private function handleKexDHInit(Packet $packet): void
    {
        if (is_null($this->kexNegotiator)) {
            throw new \Exception('KexNegotiator not initialized');
        }

        if (0 === count($this->serverHostKeys)) {
            throw new \Exception('Host keys not set');
        }

        $negotiatedAlgorithms = $this->kexNegotiator->getNegotiatedAlgorithms() ?? throw new \RuntimeException('Failure obtaining negotiated algorithms');

        // Create the Kex object
        $kex = new Kex(
            $packet,
            $this->kexNegotiator,
            match ($negotiatedAlgorithms['hostkey']) {
                'ssh-ed25519' => $this->serverHostKeys['ed25519'],
                'rsa-sha2-256' => $this->serverHostKeys['rsa'],
                'rsa-sha2-512' => $this->serverHostKeys['rsa'],
                default => throw new \RuntimeException('Unhandled hostkey type')
            },
            $this->logger
        );

        // CRITICAL: Manage the session ID at the Connection level
        if (null === $this->sessionId) {
            // For the very first key exchange, get the session ID from the Kex object
            // after calling response() which computes it
            $kexResponse = $kex->response();
            $this->sessionId = $kex->getSessionId();
            $this->debug('Initial SSH session ID established');
        } else {
            // For rekeys, set the session ID on the Kex object before generating the response
            $kex->setSessionId($this->sessionId);
            $this->debug('Using existing session ID for rekey');
            $kexResponse = $kex->response();
        }

        // Send the response
        $this->writeConnection($kexResponse);

        // If we're rekeying, pass the Kex for key derivation but don't set it yet
        if ($this->packetHandler->hasRekeyInProgress()) {
            $this->packetHandler->deriveKeys($kex);
        } else {
            // For initial key exchange, set the Kex immediately
            $this->packetHandler->setKex($kex);
            $this->packetHandler->setEncryptionMethods($negotiatedAlgorithms['encryption_ctos'], $negotiatedAlgorithms['encryption_stoc']);
            $this->packetHandler->setMacMethods($negotiatedAlgorithms['mac_ctos'], $negotiatedAlgorithms['mac_stoc']);
        }
    }

    /**
     * Send SSH_MSG_EXT_INFO according to RFC 8308
     * This explicitly tells the client which signature algorithms we support for user auth.
     */
    private function sendExtInfo(): void
    {
        $supportedSigAlgs = [
            'ssh-ed25519',
            'rsa-sha2-256',  // RSA + SHA-256 signature algorithm
            'rsa-sha2-512',  // RSA + SHA-512 signature algorithm
            'ssh-rsa',       // For compatibility with older clients that don't recognize rsa-sha2-*
        ];

        $payload = pack('N', 1); // Number of extensions
        $payload .= $this->packetHandler->packString('server-sig-algs');
        $payload .= $this->packetHandler->packString(implode(',', $supportedSigAlgs));

        // Send the raw payload with the correct message type byte prepended
        $this->writeConnection(MessageType::chr(MessageType::EXT_INFO) . $payload);
        $this->info('Sent EXT_INFO with server-sig-algs: ' . implode(',', $supportedSigAlgs));
    }

    /**
     * Handle a window-change request from the client
     * This updates the terminal size in the PTY.
     */
    private function handleWindowChange(Channel $channel, Packet $packet): void
    {
        [$widthChars, $heightRows, $widthPixels, $heightPixels] = $packet->extractFormat('%u%u%u%u');

        $this->debug(sprintf(
            'Window change request: cols=%d, rows=%d, width_px=%d, height_px=%d',
            $widthChars,
            $heightRows,
            $widthPixels,
            $heightPixels
        ));

        // Update terminal size
        $winSize = new WinSize((int) $heightRows, (int) $widthChars, (int) $widthPixels, (int) $heightPixels);
        $channel->emit('window-change', [$winSize]);

        $this->debug('Window size updated successfully');
    }

    /**
     * Handle a pty-req request from the client
     * This sets up the terminal parameters for the PTY.
     *
     * @return Promise<mixed>
     */
    private function handlePtyRequest(Channel $channel, Packet $packet): Promise
    {
        $this->debug('Handling PTY request');

        // Extract terminal parameters
        [$term, $widthChars, $heightRows, $widthPixels, $heightPixels] = $packet->extractFormat('%s%u%u%u%u');

        $this->debug(sprintf(
            'PTY request parameters: term=%s, cols=%d, rows=%d, width_px=%d, height_px=%d',
            $term,
            $widthChars,
            $heightRows,
            $widthPixels,
            $heightPixels
        ));

        // Parse terminal modes
        $modes = [];

        // First get the length of the modes string
        $modesLength = (unpack('N', substr($packet->message, $packet->offset, 4)) ?: [])[1] ?? null;
        if (! is_int($modesLength)) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }
        $packet->offset += 4;

        if ($modesLength > 0) {
            $this->debug("Found terminal modes string of length: {$modesLength}");

            // Read the modes string
            $modesString = substr($packet->message, $packet->offset, $modesLength);
            $packet->offset += $modesLength;

            // Parse the modes
            $offset = 0;
            while ($offset < strlen($modesString)) {
                // Read opcode (1 byte)
                $opcode = ord($modesString[$offset]);
                ++$offset;

                // TTY_OP_END signals end of modes
                if (0 === $opcode) {
                    break;
                }

                // Read value (uint32)
                $value = (unpack('N', substr($modesString, $offset, 4)) ?: [])[1] ?? null;
                if (! is_int($value)) {
                    throw new \UnexpectedValueException('Expected int-castable value at offset 1');
                }
                $offset += 4;

                $modes[$opcode] = $value;

                // Try to find the enum case for this opcode
                $modeName = 'UNKNOWN';
                foreach (TerminalMode::cases() as $case) {
                    if ($case->value === $opcode) {
                        $modeName = $case->name;

                        break;
                    }
                }

                $this->debug(sprintf('Terminal mode: %s (0x%02X) = %d', $modeName, $opcode, $value));
            }
        }

        return new Promise(function (callable $resolve, callable $reject) use ($channel, $term, $widthChars, $heightRows, $widthPixels, $heightPixels, $modes): void {
            try {
                // Store terminal info in the channel
                $channel->setTerminalInfo(
                    (string) $term,
                    (int) $widthChars,
                    (int) $heightRows,
                    (int) $widthPixels,
                    (int) $heightPixels,
                    $modes
                );

                // Generate a PTY event for this channel
                if (0 === count($channel->listeners('pty-request'))) {
                    $resolve(true);

                    return;
                }

                $deferred = new Deferred();
                $channel->emit('pty-request', [$deferred]);

                /** @var PromiseInterface<bool> $ptyRequestPromise */
                $ptyRequestPromise = timeout($deferred->promise(), $this->deferredEventPromiseTimeout);
                $ptyRequestPromise->then(static function (bool $started) use ($resolve): void {
                    $resolve($started);
                })->catch(static function (\Throwable $e) use ($reject): void {
                    $reject($e);
                });
            } catch (\Exception $e) {
                $this->error('Failed to handle PTY request: ' . $e->getMessage());
                $this->error('Stack trace: ' . $e->getTraceAsString());

                $reject($e);
            }
        });
    }

    /**
     * Performs cleanup operations for the SSH connection.
     *
     * This method is called when the connection is being closed or reset.
     * It forcefully closes all active channels and cancels the idle timeout timer
     * to prevent further activity or resource leaks.
     */
    private function cleanup(): void
    {
        foreach ($this->pendingDirectTcpipConnects as $connectPromise) {
            $connectPromise->cancel();
        }

        foreach ($this->directTcpipSockets as $socket) {
            $socket->close();
        }

        foreach (array_keys($this->remoteForwardListeners) as $listenerKey) {
            $this->closeRemoteForwardListener($listenerKey);
        }

        // Close all active channels
        array_map(static fn (Channel $channel) => $channel->finalizeClose(), $this->activeChannelsByLocalId);
        $this->activeChannelsByLocalId = [];
        $this->directTcpipSockets = [];
        $this->pendingDirectTcpipConnects = [];
        $this->pendingOutboundChannelOpens = [];

        if (isset($this->idleCheck)) {
            $this->loop->cancelTimer($this->idleCheck);
        }
    }

    /**
     * Converts a DateInterval to a total number of seconds.
     *
     * This utility method is used to determine timeouts or expiration thresholds
     * by converting interval-based durations into a simple integer representation.
     *
     * @param \DateInterval $interval the interval to convert
     *
     * @return int the total number of seconds represented by the interval
     */
    private function dateIntervalToSeconds(\DateInterval $interval): int
    {
        $start = new \DateTimeImmutable('@0'); // Epoch time
        $end = $start->add($interval);

        return $end->getTimestamp();
    }
}
