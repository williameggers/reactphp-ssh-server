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

namespace WilliamEggers\Tests\React\SSH\Support;

use Evenement\EventEmitterTrait;
use React\Socket\ConnectionInterface;
use React\Stream\Util;
use React\Stream\WritableStreamInterface;

final class InMemoryConnection implements ConnectionInterface
{
    use EventEmitterTrait;

    private bool $readable = true;
    private bool $writable = true;
    private bool $paused = false;

    /**
     * @var list<string>
     */
    private array $writes = [];

    public function isReadable(): bool
    {
        return $this->readable;
    }

    public function isWritable(): bool
    {
        return $this->writable;
    }

    public function pause(): void
    {
        $this->paused = true;
    }

    public function resume(): void
    {
        $this->paused = false;
        $this->emit('drain');
    }

    public function pipe(WritableStreamInterface $dest, array $options = []): WritableStreamInterface
    {
        return Util::pipe($this, $dest, $options);
    }

    public function write($data): bool
    {
        if (! $this->writable) {
            return false;
        }

        $this->writes[] = (string) $data;

        return ! $this->paused;
    }

    public function end($data = null): void
    {
        if (null !== $data) {
            $this->write($data);
        }

        $this->close();
    }

    public function close(): void
    {
        if (! $this->readable && ! $this->writable) {
            return;
        }

        $this->readable = false;
        $this->writable = false;
        $this->paused = false;
        $this->emit('close');
        $this->removeAllListeners();
    }

    public function getRemoteAddress(): ?string
    {
        return 'tcp://127.0.0.1:2222';
    }

    public function getLocalAddress(): ?string
    {
        return 'tcp://127.0.0.1:22';
    }

    /**
     * @return list<string>
     */
    public function getWrites(): array
    {
        return $this->writes;
    }

    public function isPaused(): bool
    {
        return $this->paused;
    }
}
