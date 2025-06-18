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

use WilliamEggers\React\SSH\Enums\MessageType;

final class Packet
{
    public readonly MessageType $type;
    public readonly string $message;
    public int $offset = 0;

    public function __construct(
        private readonly string $payload,
    ) {
        // An SSH package payload starts with the message type (MessageType), followed by the message
        $this->type = MessageType::from(ord($payload[0]));
        $this->message = substr($payload, 1); // remove the message type
    }

    /**
     * Extracts a string from the message payload.
     *
     * @return array{0: string, 1: int}
     */
    public function extractString(string $data, int &$offset): array
    {
        $unpackResult = unpack('N', substr($data, $offset, 4));
        if (false === $unpackResult) {
            throw new \RuntimeException('Failure determining packetLength');
        }
        if (! is_int($unpackResult[1]) && ! is_float($unpackResult[1]) && ! is_string($unpackResult[1])) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }
        $length = (int) $unpackResult[1];
        $string = substr($data, $offset + 4, $length);
        $offset += 4 + $length;

        return [$string, $offset];
    }

    /**
     * Extracts values from the message payload based on a format string
     * Format specifiers:
     * %s - length-prefixed string
     * %u - 32-bit unsigned integer
     * %b - boolean (1 byte).
     *
     * @param string $format Format string like '%s%u%u%u' for string + 3 integers
     *
     * @return array<int, bool|int|string> Array of extracted values
     */
    public function extractFormat(string $format): array
    {
        $values = [];

        if (empty($format)) {
            throw new \InvalidArgumentException('Empty format specifier');
        }

        // First validate all format specifiers
        preg_match_all('/%([^sub])/', $format, $invalidMatches);
        if (! empty($invalidMatches[1])) {
            throw new \InvalidArgumentException("Unknown format specifier: {$invalidMatches[1][0]}");
        }

        // Extract format specifiers using regex to match %s, %u, %b
        preg_match_all('/%([sub])/', $format, $matches);
        $specifiers = $matches[1] ?? []; // @phpstan-ignore-line

        foreach ($specifiers as $spec) {
            if ($this->offset >= strlen($this->message)) {
                return $values;
            }

            switch ($spec) {
                case 's':
                    [$values[], $this->offset] = $this->extractString($this->message, $this->offset);

                    break;

                case 'u':
                    $value = (unpack('N', substr($this->message, $this->offset, 4)) ?: [0])[1] ?? 0;
                    if (! is_int($value)) {
                        throw new \RuntimeException('Unable to unpack 4-byte unsigned int.');
                    }
                    $values[] = (int) $value;
                    $this->offset += 4;

                    break;

                case 'b':
                    [
                        $values[] = (bool) ord(substr($this->message, $this->offset, 1)),
                        ++$this->offset,
                    ];

                    break;

                default:
                    throw new \InvalidArgumentException("Unknown format specifier: {$spec}");
            }
        }

        return $values;
    }

    public static function fromData(string $data): self
    {
        $unpackResult = unpack('N', substr($data, 0, 4)); // First byte is the packet length
        if (false === $unpackResult) {
            throw new \RuntimeException('Failure determining packetLength');
        }
        if (! is_int($unpackResult[1]) && ! is_float($unpackResult[1]) && ! is_string($unpackResult[1])) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }

        $packetLength = (int) $unpackResult[1]; // First byte is the packet length

        $payload = substr($data, 4, $packetLength - 1);
        $paddingLength = ord($payload[0]); // Second byte is the padding length, random bytes are added to ensure the packet is a length that divides by 8/16/something (TODO: Add accurate notes)

        // Therefore the actual payload is the part of the data after the lengths, and before the padding
        $payload = substr($payload, 1, $packetLength - $paddingLength - 1);

        return new self($payload);
    }
}
