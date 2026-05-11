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
use React\Stream;
use React\Stream\DuplexStreamInterface;
use React\Stream\ReadableStreamInterface;
use React\Stream\Util;
use React\Stream\WritableStreamInterface;
use WilliamEggers\React\SSH\Concerns\WritesLogs;
use WilliamEggers\React\SSH\Loggers\NullLogger;
use WilliamEggers\React\SSH\Values\TerminalInfo;

final class Channel implements EventEmitterInterface, ReadableStreamInterface, WritableStreamInterface
{
    use EventEmitterTrait;
    use WritesLogs;

    private const INBOUND_BUFFER_WARNING_THRESHOLD_BYTES = 1048576;
    private const INBOUND_BUFFER_DISCONNECT_THRESHOLD_BYTES = 10485760;
    private const OUTBOUND_BUFFER_WARNING_THRESHOLD_BYTES = 1048576;
    private const OUTBOUND_BUFFER_CLOSE_THRESHOLD_BYTES = 10485760;

    private ?TerminalInfo $terminalInfo = null;
    private DuplexStreamInterface $senderChannelStream;

    private bool $inputClosed = false;
    private bool $outputClosed = false;
    private bool $eofSent = false;
    private bool $closeSent = false;
    private bool $closeReceived = false;
    private bool $requestReplyPending = false;
    private bool $queueEofAfterReply = false;
    private bool $queueCloseAfterReply = false;
    private bool $paused = false;

    /**
     * @var list<string>
     */
    private array $pendingInboundChunks = [];
    private int $pendingInboundBytes = 0;
    private bool $hasLoggedInboundBufferWarning = false;

    private array $env = [];

    /**
     * @var list<string>
     */
    private array $pendingOutboundChunks = [];
    private int $pendingOutboundBytes = 0;
    private bool $hasLoggedOutboundBufferWarning = false;

    public function __construct(
        private readonly Connection $connection,
        private readonly int $recipientChannel, // Their channel ID
        private readonly int $senderChannel, // Our channel ID
        private int $windowSize,
        private int $maxPacketSize,
        private readonly string $channelType // "session", "x11", etc.
    ) {
        $this->logger = new NullLogger();
        $this->senderChannelStream = new Stream\ThroughStream();

        Util::forwardEvents($this->senderChannelStream, $this, ['data', 'end', 'error', 'close', 'pipe', 'drain']);
    }

    /**
     * Store terminal information from pty-req.
     */
    public function setTerminalInfo(
        string $term,
        int $widthChars,
        int $heightRows,
        int $widthPixels,
        int $heightPixels,
        array $modes
    ): void {
        $this->terminalInfo = new TerminalInfo(
            $term,
            $widthChars,
            $heightRows,
            $widthPixels,
            $heightPixels,
            $modes
        );
    }

    /**
     * Get the connection associated with this channel.
     */
    public function getConnection(): Connection
    {
        return $this->connection;
    }

    /**
     * Get the channel ID assigned by the client (remote side).
     *
     * This is the recipient channel number that the server uses to send messages back to the client.
     *
     * @return int the remote (client-assigned) channel ID
     */
    public function getRecipientChannel(): int
    {
        return $this->recipientChannel;
    }

    /**
     * Get the channel ID assigned by the server (local side).
     *
     * This is the sender channel number used when initiating the channel from the server's perspective.
     *
     * @return int the local (server-assigned) channel ID
     */
    public function getSenderChannel(): int
    {
        return $this->senderChannel;
    }

    /**
     * Get the current window size for the channel (in bytes).
     *
     * This represents the maximum amount of data (in bytes) that can be sent to the client
     * before requiring a window adjustment.
     *
     * @return int the current available window size in bytes
     */
    public function getWindowSize(): int
    {
        return $this->windowSize;
    }

    public function increaseRemoteWindow(int $bytes): void
    {
        if ($bytes <= 0) {
            return;
        }

        $newWindowSize = $this->windowSize + $bytes;
        if ($newWindowSize < 0) {
            throw new \OverflowException('Remote channel window overflowed');
        }

        $this->windowSize = $newWindowSize;
    }

    public function consumeRemoteWindow(int $bytes): void
    {
        if ($bytes <= 0) {
            return;
        }

        $this->windowSize = max(0, $this->windowSize - $bytes);
    }

    /**
     * Get the maximum packet size allowed for this channel.
     *
     * This defines the largest single payload (in bytes) that can be sent
     * in one SSH_MSG_CHANNEL_DATA message over this channel.
     *
     * @return int the maximum packet size in bytes
     */
    public function getMaxPacketSize(): int
    {
        return $this->maxPacketSize;
    }

    public function queueOutboundData(string $data): void
    {
        $this->queueOutboundChunk($data);
    }

    public function hasPendingOutboundData(): bool
    {
        return [] !== $this->pendingOutboundChunks;
    }

    public function shiftPendingOutboundChunk(): ?string
    {
        $chunk = array_shift($this->pendingOutboundChunks);
        if (! is_string($chunk)) {
            return null;
        }

        $this->pendingOutboundBytes -= strlen($chunk);
        if ($this->pendingOutboundBytes < 0) {
            $this->pendingOutboundBytes = 0;
        }

        if ($this->pendingOutboundBytes <= self::OUTBOUND_BUFFER_WARNING_THRESHOLD_BYTES) {
            $this->hasLoggedOutboundBufferWarning = false;
        }

        return $chunk;
    }

    public function prependPendingOutboundChunk(string $data): void
    {
        $this->queueOutboundChunk($data, true);
    }

    public function getPendingOutboundByteCount(): int
    {
        return $this->pendingOutboundBytes;
    }

    /**
     * Get the type of this channel as requested by the client.
     *
     * Common types include "session", "x11", "direct-tcpip", etc., and define
     * the purpose or behavior of the channel. Most servers typically handle
     * "session" channels for shell access or command execution.
     *
     * @return string the channel type requested by the client
     */
    public function getChannelType(): string
    {
        return $this->channelType;
    }

    /**
     * Get terminal information if available.
     */
    public function getTerminalInfo(): ?TerminalInfo
    {
        return $this->terminalInfo;
    }

    /**
     * Mark input as closed (EOF received).
     */
    public function markInputClosed(): void
    {
        // Send EOF to the process
        $this->writeToServer("\x04"); // Ctrl+D (EOF)
        $this->inputClosed = true;
    }

    /**
     * Marks the channel input as closed without emitting a local EOF byte.
     *
     * This is used for non-terminal channels such as `forwarded-tcpip`, where
     * the remote EOF should stop reads without injecting terminal control input.
     */
    public function markInputClosedSilently(): void
    {
        $this->inputClosed = true;
    }

    public function isReadable(): bool
    {
        return $this->senderChannelStream->isReadable() && ! $this->inputClosed;
    }

    public function isWritable(): bool
    {
        return $this->connection->isWritable() && ! $this->outputClosed;
    }

    public function pause(): void
    {
        if ($this->paused) {
            return;
        }

        $this->paused = true;
        $this->debug("Paused channel input for {$this->recipientChannel}");
    }

    public function resume(): void
    {
        if (! $this->paused) {
            return;
        }

        $this->paused = false;
        $this->debug(sprintf(
            'Resuming channel input for %d with %d queued bytes across %d chunks',
            $this->recipientChannel,
            $this->pendingInboundBytes,
            count($this->pendingInboundChunks)
        ));
        $this->flushPendingInboundChunks();
    }

    public function pipe(WritableStreamInterface $dest, array $options = []): WritableStreamInterface
    {
        return Util::pipe($this, $dest, $options);
    }

    public function close(): void
    {
        if ($this->closeSent || $this->closeReceived) {
            return;
        }

        if ($this->requestReplyPending) {
            $this->queueCloseAfterReply = true;
            $this->outputClosed = true;

            return;
        }

        $this->connection->closeChannel($this);
    }

    public function markCloseSent(): void
    {
        $this->outputClosed = true;
        $this->closeSent = true;
    }

    public function markCloseReceived(): void
    {
        $this->inputClosed = true;
        $this->outputClosed = true;
        $this->closeReceived = true;
    }

    public function hasSentClose(): bool
    {
        return $this->closeSent;
    }

    public function hasReceivedClose(): bool
    {
        return $this->closeReceived;
    }

    public function beginRequestReply(): void
    {
        $this->requestReplyPending = true;
    }

    public function completeRequestReply(): void
    {
        $this->requestReplyPending = false;
    }

    public function hasPendingRequestReply(): bool
    {
        return $this->requestReplyPending;
    }

    public function shouldSendQueuedEof(): bool
    {
        return $this->queueEofAfterReply && ! $this->eofSent;
    }

    public function shouldSendQueuedClose(): bool
    {
        return $this->queueCloseAfterReply && ! $this->closeSent && ! $this->closeReceived;
    }

    public function flushQueuedCloseOperations(): void
    {
        if ($this->shouldSendQueuedEof()) {
            $this->connection->sendChannelEof($this);
            $this->eofSent = true;
            $this->queueEofAfterReply = false;
        }

        if ($this->shouldSendQueuedClose()) {
            $this->queueCloseAfterReply = false;
            $this->connection->closeChannel($this);
        }
    }

    public function finalizeClose(): void
    {
        $this->inputClosed = true;
        $this->outputClosed = true;
        $this->paused = false;
        $this->pendingInboundChunks = [];
        $this->pendingInboundBytes = 0;
        $this->hasLoggedInboundBufferWarning = false;
        $this->pendingOutboundChunks = [];
        $this->pendingOutboundBytes = 0;
        $this->hasLoggedOutboundBufferWarning = false;
        $this->senderChannelStream->close();
        $this->removeAllListeners();
    }

    /**
     * Write to the client.
     */
    public function write(mixed $data): bool
    {
        if (! is_scalar($data) && ! (\is_object($data) && method_exists($data, '__toString'))) {
            throw new \InvalidArgumentException('Data must be stringable');
        }

        return $this->connection->writeChannelData($this, (string) $data) > 0;
    }

    /**
     * Internal: Write data from the SSH client to the application layer.
     *
     * This method is used internally by the server to forward incoming data
     * from the SSH client to the application-level stream (e.g., a shell or command handler).
     *
     * Developers should not call this method directly — use `Channel::on('data')`
     * to handle client input instead.
     *
     * @param string $data the data received from the client
     *
     * @return bool true if data was successfully written to the stream, false otherwise
     */
    public function writeToServer(string $data): bool
    {
        if ($this->inputClosed) {
            return false;
        }

        if ($this->paused) {
            $nextBufferedBytes = $this->pendingInboundBytes + strlen($data);
            if ($nextBufferedBytes > self::INBOUND_BUFFER_DISCONNECT_THRESHOLD_BYTES) {
                throw new \OverflowException(sprintf(
                    'Channel %d inbound buffer exceeded disconnect threshold: %d bytes queued',
                    $this->recipientChannel,
                    $nextBufferedBytes
                ));
            }

            $this->pendingInboundChunks[] = $data;
            $this->pendingInboundBytes = $nextBufferedBytes;

            if (
                ! $this->hasLoggedInboundBufferWarning
                && $this->pendingInboundBytes > self::INBOUND_BUFFER_WARNING_THRESHOLD_BYTES
            ) {
                $this->hasLoggedInboundBufferWarning = true;
                $this->warning(sprintf(
                    'Channel %d inbound buffer exceeded warning threshold: %d bytes queued',
                    $this->recipientChannel,
                    $this->pendingInboundBytes
                ));
            } else {
                $this->debug(sprintf(
                    'Queued %d inbound bytes for paused channel %d (%d bytes pending)',
                    strlen($data),
                    $this->recipientChannel,
                    $this->pendingInboundBytes
                ));
            }

            return false;
        }

        return $this->senderChannelStream->write($data);
    }

    public function isInputPaused(): bool
    {
        return $this->paused;
    }

    public function getPendingInboundByteCount(): int
    {
        return $this->pendingInboundBytes;
    }

    public function end(mixed $data = null): void
    {
        if ($this->closeSent || $this->closeReceived) {
            return;
        }

        if (! is_null($data)) {
            if (! is_scalar($data) && ! (\is_object($data) && method_exists($data, '__toString'))) {
                throw new \InvalidArgumentException('Data must be stringable');
            }
            $this->connection->writeChannelData($this, (string) $data);
        }

        if (! $this->eofSent) {
            if ($this->requestReplyPending) {
                $this->queueEofAfterReply = true;
                $this->queueCloseAfterReply = true;
                $this->outputClosed = true;

                return;
            }

            $this->connection->sendChannelEof($this);
            $this->eofSent = true;
        }

        $this->connection->closeChannel($this);
    }

    /**
     * Set an environment variable for the command.
     */
    public function setEnvironmentVariable(string $name, string $value): void
    {
        $this->env[$name] = $value;
        $this->debug("Set environment variable: {$name}={$value}");
    }

    public function getEnvironmentVariables(): array
    {
        return $this->env;
    }

    public function getEnvironmentVariable(string $name): mixed
    {
        return $this->env[$name] ?? null;
    }

    /**
     * Determines the character encoding requested by the client.
     *
     * This method inspects standard locale-related environment variables
     * (LC_ALL, LC_CTYPE, LANG) in order of precedence to extract the
     * character encoding portion from values like "en_US.UTF-8".
     *
     * If no valid encoding is found, it defaults to "utf-8".
     *
     * @return string The detected encoding in lowercase (e.g., "utf-8", "cp437").
     */
    public function getEncoding(): string
    {
        // Order of preference for locale environment variables
        $envVars = ['LC_ALL', 'LC_CTYPE', 'LANG'];

        foreach ($envVars as $var) {
            $locale = $this->getEnvironmentVariable($var);
            if (is_string($locale) && preg_match('/\.(\S+)/', (string) $locale, $matches)) {
                // Normalize and return the encoding part (e.g., UTF-8, CP437)
                return mb_strtolower(trim($matches[1]));
            }
        }

        return 'utf-8';
    }

    private function flushPendingInboundChunks(): void
    {
        while (! $this->paused && [] !== $this->pendingInboundChunks) {
            $chunk = array_shift($this->pendingInboundChunks);
            if (! is_string($chunk)) {
                continue;
            }

            $this->pendingInboundBytes -= strlen($chunk);
            if ($this->pendingInboundBytes < 0) {
                $this->pendingInboundBytes = 0;
            }

            if ($this->pendingInboundBytes <= self::INBOUND_BUFFER_WARNING_THRESHOLD_BYTES) {
                $this->hasLoggedInboundBufferWarning = false;
            }

            if (! $this->senderChannelStream->write($chunk)) {
                $this->paused = true;
                array_unshift($this->pendingInboundChunks, $chunk);
                $this->pendingInboundBytes += strlen($chunk);

                return;
            }
        }
    }

    /**
     * Queues outbound channel data while enforcing warning and close thresholds.
     *
     * When buffering crosses the warning threshold, a warning is logged once. If the
     * queued bytes would exceed the close threshold, an OverflowException is thrown
     * before the new chunk is added.
     */
    private function queueOutboundChunk(string $data, bool $prepend = false): void
    {
        if ('' === $data) {
            return;
        }

        $nextBufferedBytes = $this->pendingOutboundBytes + strlen($data);
        if ($nextBufferedBytes > self::OUTBOUND_BUFFER_CLOSE_THRESHOLD_BYTES) {
            throw new \OverflowException(sprintf(
                'Channel %d outbound buffer exceeded close threshold: %d bytes queued',
                $this->recipientChannel,
                $nextBufferedBytes
            ));
        }

        if ($prepend) {
            array_unshift($this->pendingOutboundChunks, $data);
        } else {
            $this->pendingOutboundChunks[] = $data;
        }

        $this->pendingOutboundBytes = $nextBufferedBytes;

        if (
            ! $this->hasLoggedOutboundBufferWarning
            && $this->pendingOutboundBytes > self::OUTBOUND_BUFFER_WARNING_THRESHOLD_BYTES
        ) {
            $this->hasLoggedOutboundBufferWarning = true;
            $this->warning(sprintf(
                'Channel %d outbound buffer exceeded warning threshold: %d bytes queued',
                $this->recipientChannel,
                $this->pendingOutboundBytes
            ));
        }
    }
}
