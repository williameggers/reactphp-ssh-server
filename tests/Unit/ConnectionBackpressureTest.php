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
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Packet;
use WilliamEggers\React\SSH\PacketHandler;
use WilliamEggers\Tests\React\SSH\Support\InMemoryConnection;

test('handleChannelData respects paused channel buffering', function (): void {
    [$connection, $channel] = connectionWithChannelForTests();
    $received = [];

    $channel->pause();
    $channel->on('data', function (string $data) use (&$received): void {
        $received[] = $data;
    });

    invokeHandleChannelData($connection, channelDataPacket(1, 'abc'));

    expect($received)->toBe([]);
    expect($channel->getPendingInboundByteCount())->toBe(3);
});

test('resuming channel after handleChannelData flushes queued data', function (): void {
    [$connection, $channel] = connectionWithChannelForTests();
    $received = [];

    $channel->pause();
    $channel->on('data', function (string $data) use (&$received): void {
        $received[] = $data;
    });

    invokeHandleChannelData($connection, channelDataPacket(1, 'a'));
    invokeHandleChannelData($connection, channelDataPacket(1, 'b'));
    invokeHandleChannelData($connection, channelDataPacket(1, 'c'));

    $channel->resume();

    expect($received)->toBe(['a', 'b', 'c']);
    expect($channel->getPendingInboundByteCount())->toBe(0);
});

test('handleChannelData only emits connection channel.data when delivery is immediate', function (): void {
    [$connection, $channel] = connectionWithChannelForTests();
    $events = [];

    $connection->on('channel.data', function (int $channelId, string $data) use (&$events): void {
        $events[] = [$channelId, $data];
    });

    $channel->pause();
    invokeHandleChannelData($connection, channelDataPacket(1, 'abc'));
    expect($events)->toBe([]);

    $channel->resume();
    invokeHandleChannelData($connection, channelDataPacket(1, 'xyz'));
    expect($events)->toBe([[1, 'xyz']]);
});

test('handleChannelData disconnects when paused inbound buffering exceeds the disconnect threshold', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $channel->pause();
    invokeHandleChannelData($connection, channelDataPacket(1, str_repeat('a', 10485760)));

    expect($channel->getPendingInboundByteCount())->toBe(10485760);

    invokeHandleChannelData($connection, channelDataPacket(1, 'b'));

    expect($transport->isWritable())->toBeFalse();
    expect($transport->getWrites())->toHaveCount(1);
    expect(Packet::fromData($transport->getWrites()[0])->type)->toBe(MessageType::DISCONNECT);
});

test('writeChannelData queues remainder when remote window is exhausted', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $channel->consumeRemoteWindow(65532);

    $written = $connection->writeChannelData($channel, 'hello');

    expect($written)->toBe(5);
    expect($channel->getWindowSize())->toBe(0);
    expect($channel->getPendingOutboundByteCount())->toBe(2);
    expect($transport->getWrites())->toHaveCount(1);
});

test('writeChannelData closes the channel when outbound buffering exceeds the close threshold', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $channel->consumeRemoteWindow(65535);

    expect($connection->writeChannelData($channel, str_repeat('a', 10485760)))->toBe(10485760);
    expect($channel->getPendingOutboundByteCount())->toBe(10485760);

    expect($connection->writeChannelData($channel, 'b'))->toBe(0);
    expect($channel->getPendingOutboundByteCount())->toBe(10485760);
    expect($channel->hasSentClose())->toBeTrue();
    expect($transport->isWritable())->toBeTrue();

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::CHANNEL_CLOSE);
});

test('channel window adjust flushes queued outbound data', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $channel->consumeRemoteWindow(65535);
    $connection->writeChannelData($channel, 'hello');

    expect($channel->getPendingOutboundByteCount())->toBe(5);
    expect($transport->getWrites())->toBe([]);

    invokeHandleChannelWindowAdjust($connection, channelWindowAdjustPacket(1, 5));

    expect($channel->getWindowSize())->toBe(0);
    expect($channel->getPendingOutboundByteCount())->toBe(0);
    expect($transport->getWrites())->toHaveCount(1);
});

test('partial channel window adjust only flushes part of queued outbound data', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $channel->consumeRemoteWindow(65535);
    $connection->writeChannelData($channel, 'hello');

    invokeHandleChannelWindowAdjust($connection, channelWindowAdjustPacket(1, 2));

    expect($channel->getWindowSize())->toBe(0);
    expect($channel->getPendingOutboundByteCount())->toBe(3);
    expect($transport->getWrites())->toHaveCount(1);
});

test('transport backpressure does not requeue bytes already accepted by the transport', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $transport->pause();

    $written = $connection->writeChannelData($channel, 'hello');

    expect($written)->toBe(5);
    expect($channel->getPendingOutboundByteCount())->toBe(0);
    expect($channel->getWindowSize())->toBe(65530);
    expect($transport->getWrites())->toHaveCount(1);
});

test('transport drain flushes channel data queued after backpressure', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $transport->pause();
    $connection->writeChannelData($channel, 'hello');
    $connection->writeChannelData($channel, 'world');

    expect($channel->getPendingOutboundByteCount())->toBe(5);
    expect($transport->getWrites())->toHaveCount(1);

    $transport->resume();

    expect($channel->getPendingOutboundByteCount())->toBe(0);
    expect($transport->getWrites())->toHaveCount(2);
});

test('shell request without reply does not buffer startup output behind deferred resolution', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $channel->on('shell-request', static function ($started) use ($channel): void {
        $channel->write('ansi-probe');
    });

    invokeHandleChannelRequest($connection, channelRequestPacket(1, 'shell', false));

    expect($channel->hasPendingRequestReply())->toBeFalse();
    expect($channel->getPendingOutboundByteCount())->toBe(0);
    expect($transport->getWrites())->toHaveCount(1);
    expect(Packet::fromData($transport->getWrites()[0])->type)->toBe(MessageType::CHANNEL_DATA);
});

test('exec request without reply does not buffer startup output behind deferred resolution', function (): void {
    [$connection, $channel, $transport] = connectionWithChannelForTests();

    $channel->on('exec-request', static function (string $command, $started) use ($channel): void {
        $channel->write('exec-output');
    });

    invokeHandleChannelRequest($connection, channelRequestPacket(1, 'exec', false, ['whoami']));

    expect($channel->hasPendingRequestReply())->toBeFalse();
    expect($channel->getPendingOutboundByteCount())->toBe(0);
    expect($transport->getWrites())->toHaveCount(1);
    expect(Packet::fromData($transport->getWrites()[0])->type)->toBe(MessageType::CHANNEL_DATA);
});

function connectionWithChannelForTests(): array
{
    $transport = new InMemoryConnection();
    $connection = new Connection($transport, new StreamSelectLoop());
    $connection->setConnectionId(1);
    $channel = new Channel($connection, 1, 1, 65535, 32768, 'session');

    $localChannels = new ReflectionProperty($connection, 'activeChannelsByLocalId');
    $localChannels->setValue($connection, [1 => $channel]);

    return [$connection, $channel, $transport];
}

function channelDataPacket(int $channelId, string $data): Packet
{
    return new Packet(MessageType::chr(MessageType::CHANNEL_DATA) . pack('N', $channelId) . pack('N', strlen($data)) . $data);
}

function channelWindowAdjustPacket(int $channelId, int $bytesToAdd): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_WINDOW_ADJUST, [$channelId, $bytesToAdd]));
}

function channelRequestPacket(int $channelId, string $requestType, bool $wantReply, array $payload = []): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_REQUEST, [$channelId, $requestType, $wantReply, ...$payload]));
}

function invokeHandleChannelData(Connection $connection, Packet $packet): void
{
    $method = new ReflectionMethod($connection, 'handleChannelData');
    $method->invoke($connection, $packet);
}

function invokeHandleChannelWindowAdjust(Connection $connection, Packet $packet): void
{
    $method = new ReflectionMethod($connection, 'handleChannelWindowAdjust');
    $method->invoke($connection, $packet);
}

function invokeHandleChannelRequest(Connection $connection, Packet $packet): void
{
    $method = new ReflectionMethod($connection, 'handleChannelRequest');
    $method->invoke($connection, $packet);
}
