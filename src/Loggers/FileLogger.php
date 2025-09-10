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

namespace WilliamEggers\React\SSH\Loggers;

use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use React\Stream\WritableResourceStream;

/**
 * FileLogger writes log messages to a file using a WritableResourceStream.
 *
 * Note: This logger is not safe to use with event loop libraries such as libuv in ReactPHP,
 * as it relies on PHP's native file resources which may not be compatible with all event loop implementations.
 */
final class FileLogger extends AbstractLogger
{
    private readonly WritableResourceStream $stream;

    public function __construct(private readonly string $logFile)
    {
        $this->stream = new WritableResourceStream(fopen($logFile, 'a')
            ?: throw new \RuntimeException('Failure opening ' . $logFile));
        $this->stream->write(str_repeat('-', 80) . PHP_EOL);
    }

    public function __destruct()
    {
        $this->stream->close();
    }

    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        if (! is_scalar($level) && ! (\is_object($level) && method_exists($level, '__toString'))) {
            throw new \InvalidArgumentException('Log level must be stringable');
        }

        if (LogLevel::DEBUG === $level) {
            // return;
        }

        $logMessage = sprintf('%s [%s] %s %s', (new \DateTime())->format('Y-m-d H:i:s'), (string) $level, $message, PHP_EOL);
        $this->stream->write($logMessage);
    }
}
