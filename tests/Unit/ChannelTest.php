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

use React\EventLoop\StreamSelectLoop;
use WilliamEggers\React\SSH\Channel;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\Tests\React\SSH\Support\InMemoryConnection;

test('writeToServer emits immediately when not paused', function (): void {
    $channel = channelForTests();
    $received = [];

    $channel->on('data', function (string $data) use (&$received): void {
        $received[] = $data;
    });

    expect($channel->writeToServer('abc'))->toBeTrue();
    expect($received)->toBe(['abc']);
    expect($channel->getPendingInboundByteCount())->toBe(0);
});

test('writeToServer queues and does not emit while paused', function (): void {
    $channel = channelForTests();
    $received = [];

    $channel->pause();
    $channel->on('data', function (string $data) use (&$received): void {
        $received[] = $data;
    });

    expect($channel->writeToServer('abc'))->toBeFalse();
    expect($received)->toBe([]);
    expect($channel->isInputPaused())->toBeTrue();
    expect($channel->getPendingInboundByteCount())->toBe(3);
});

test('resume flushes queued chunks in order', function (): void {
    $channel = channelForTests();
    $received = [];

    $channel->on('data', function (string $data) use (&$received): void {
        $received[] = $data;
    });

    $channel->pause();
    $channel->writeToServer('a');
    $channel->writeToServer('b');
    $channel->writeToServer('c');

    $channel->resume();

    expect($received)->toBe(['a', 'b', 'c']);
    expect($channel->isInputPaused())->toBeFalse();
    expect($channel->getPendingInboundByteCount())->toBe(0);
});

test('finalizeClose clears queued input', function (): void {
    $channel = channelForTests();

    $channel->pause();
    $channel->writeToServer('abc');
    $channel->finalizeClose();

    expect($channel->isInputPaused())->toBeFalse();
    expect($channel->getPendingInboundByteCount())->toBe(0);
    expect($channel->writeToServer('later'))->toBeFalse();
});

test('remote window bookkeeping tracks queued outbound data', function (): void {
    $channel = channelForTests();

    $channel->consumeRemoteWindow(65535);
    $channel->queueOutboundData('abc');
    $channel->queueOutboundData('def');
    $channel->increaseRemoteWindow(2);

    expect($channel->getWindowSize())->toBe(2);
    expect($channel->getPendingOutboundByteCount())->toBe(6);
    expect($channel->shiftPendingOutboundChunk())->toBe('abc');
    expect($channel->getPendingOutboundByteCount())->toBe(3);

    $channel->prependPendingOutboundChunk('xy');

    expect($channel->shiftPendingOutboundChunk())->toBe('xy');
    expect($channel->shiftPendingOutboundChunk())->toBe('def');
    expect($channel->getPendingOutboundByteCount())->toBe(0);
    expect($channel->hasPendingOutboundData())->toBeFalse();
});

test('buffer cap behavior is enforced while paused', function (): void {
    $channel = channelForTests();
    $channel->pause();

    expect($channel->writeToServer(str_repeat('a', 1048576)))->toBeFalse();
    expect($channel->writeToServer('b'))->toBeFalse();
    expect($channel->getPendingInboundByteCount())->toBe(1048577);
});

function channelForTests(): Channel
{
    $transport = new InMemoryConnection();
    $connection = new Connection($transport, new StreamSelectLoop());

    return new Channel($connection, 1, 1, 65535, 32768, 'session');
}
