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
use React\Promise\Deferred;
use WilliamEggers\React\SSH\Channel;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Packet;
use WilliamEggers\React\SSH\PacketHandler;
use WilliamEggers\Tests\React\SSH\Support\InMemoryConnection;

test('exit sends eof, the exit status, and close in order', function (): void {
    [, $channel, $transport] = openChannelForExitStatusTests();

    $channel->exit(3);

    $packets = writtenPackets($transport);
    expect(array_map(fn (Packet $packet): MessageType => $packet->type, $packets))->toBe([
        MessageType::CHANNEL_EOF,
        MessageType::CHANNEL_REQUEST,
        MessageType::CHANNEL_CLOSE,
    ]);
    expect($packets[1]->extractFormat('%u%s%b%u'))->toBe([1, 'exit-status', false, 3]);
    expect($channel->hasSentClose())->toBeTrue();
});

test('exit sends final data before the exit status', function (): void {
    [, $channel, $transport] = openChannelForExitStatusTests();

    $channel->exit(0, 'bye');

    $packets = writtenPackets($transport);
    expect(array_map(fn (Packet $packet): MessageType => $packet->type, $packets))->toBe([
        MessageType::CHANNEL_DATA,
        MessageType::CHANNEL_EOF,
        MessageType::CHANNEL_REQUEST,
        MessageType::CHANNEL_CLOSE,
    ]);
    expect($packets[0]->extractFormat('%u%s'))->toBe([1, 'bye']);
    expect($packets[2]->extractFormat('%u%s%b%u'))->toBe([1, 'exit-status', false, 0]);
});

test('exit waits for a pending request reply before sending the exit status', function (): void {
    [$connection, $channel, $transport] = openChannelForExitStatusTests();
    $started = null;

    $channel->on('shell-request', static function (Deferred $deferred) use (&$started): void {
        $started = $deferred;
    });

    $method = new ReflectionMethod($connection, 'handleChannelRequest');
    $method->invoke($connection, new Packet((new PacketHandler(new InMemoryConnection()))->packValues(MessageType::CHANNEL_REQUEST, [1, 'shell', true])));

    $channel->exit(2);
    expect($transport->getWrites())->toBe([]);

    $started->resolve(true);

    $packets = writtenPackets($transport);
    expect(array_map(fn (Packet $packet): MessageType => $packet->type, $packets))->toBe([
        MessageType::CHANNEL_SUCCESS,
        MessageType::CHANNEL_EOF,
        MessageType::CHANNEL_REQUEST,
        MessageType::CHANNEL_CLOSE,
    ]);
    expect($packets[2]->extractFormat('%u%s%b%u'))->toBe([1, 'exit-status', false, 2]);
});

test('exit does nothing once the channel is closed', function (): void {
    [, $channel, $transport] = openChannelForExitStatusTests();

    $channel->end();
    $writes = count($transport->getWrites());
    $channel->exit(1);

    expect($transport->getWrites())->toHaveCount($writes);
});

test('end does not send an exit status', function (): void {
    [, $channel, $transport] = openChannelForExitStatusTests();

    $channel->end();

    expect(array_map(fn (Packet $packet): MessageType => $packet->type, writtenPackets($transport)))->toBe([
        MessageType::CHANNEL_EOF,
        MessageType::CHANNEL_CLOSE,
    ]);
});

test('exit rejects statuses outside the uint32 range', function (int $status): void {
    [, $channel] = openChannelForExitStatusTests();

    expect(fn () => $channel->exit($status))->toThrow(InvalidArgumentException::class);
})->with([-1, 0x100000000]);

/**
 * @return array{Connection, Channel, InMemoryConnection}
 */
function openChannelForExitStatusTests(): array
{
    $transport = new InMemoryConnection();
    $connection = new Connection($transport, new StreamSelectLoop());
    $connection->setConnectionId(1);
    $channel = new Channel($connection, 1, 1, 65535, 32768, 'session');

    $localChannels = new ReflectionProperty($connection, 'activeChannelsByLocalId');
    $localChannels->setValue($connection, [1 => $channel]);

    return [$connection, $channel, $transport];
}

/**
 * @return list<Packet>
 */
function writtenPackets(InMemoryConnection $transport): array
{
    return array_map(fn (string $data): Packet => Packet::fromData($data), $transport->getWrites());
}
