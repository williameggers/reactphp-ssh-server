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

    private ?TerminalInfo $terminalInfo = null;
    private DuplexStreamInterface $senderChannelStream;

    private bool $inputClosed = false;
    private bool $outputClosed = false;

    private array $env = [];

    public function __construct(
        private readonly Connection $connection,
        private readonly int $recipientChannel, // Their channel ID
        private readonly int $senderChannel, // Our channel ID
        private readonly int $windowSize,
        private readonly int $maxPacketSize,
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
        $this->inputClosed = true;

        // Send EOF to the process
        $this->senderChannelStream->write("\x04"); // Ctrl+D (EOF)
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
        $this->senderChannelStream->pause();
    }

    public function resume(): void
    {
        $this->senderChannelStream->resume();
    }

    public function pipe(WritableStreamInterface $dest, array $options = []): WritableStreamInterface
    {
        return Util::pipe($this, $dest, $options);
    }

    public function close(): void
    {
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
        if (! $this->inputClosed) {
            return $this->senderChannelStream->write($data);
        }

        return false;
    }

    public function end(mixed $data = null): void
    {
        if (! is_null($data)) {
            if (! is_scalar($data) && ! (\is_object($data) && method_exists($data, '__toString'))) {
                throw new \InvalidArgumentException('Data must be stringable');
            }
            $this->connection->writeChannelData($this, (string) $data);
        }

        $this->connection->end(null);
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
                return mb_strtolower(mb_trim($matches[1]));
            }
        }

        return 'utf-8';
    }
}
