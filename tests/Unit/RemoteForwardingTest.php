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
use React\Socket\Connector;
use WilliamEggers\React\SSH\Channel;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Enums\ChannelOpenFailureReason;
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Packet;
use WilliamEggers\React\SSH\PacketHandler;
use WilliamEggers\Tests\React\SSH\Support\FakeConnector;
use WilliamEggers\Tests\React\SSH\Support\InMemoryConnection;

test('unknown global requests return failure without disconnecting', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();

    invokeHandleGlobalRequest($connection, globalRequestPacket('keepalive@openssh.com', true));

    expect($transport->isWritable())->toBeTrue();
    expect($transport->getWrites())->toHaveCount(1);
    expect(Packet::fromData($transport->getWrites()[0])->type)->toBe(MessageType::REQUEST_FAILURE);
});

test('pre-auth global requests disconnect when authentication is enabled', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();
    $connection->enableAuthentication(true);

    invokeHandlePacket($connection, globalRequestPacket('keepalive@openssh.com', true));

    expect($connection->isAuthenticated())->toBeFalse();
    expect($transport->isWritable())->toBeFalse();
    expect($transport->getWrites())->toHaveCount(1);
    expect(Packet::fromData($transport->getWrites()[0])->type)->toBe(MessageType::DISCONNECT);
});

test('pre-auth channel open disconnects when authentication is enabled', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();
    $connection->enableAuthentication(true);
    $channelOpened = false;
    $connection->on('channel.open', static function () use (&$channelOpened): void {
        $channelOpened = true;
    });

    invokeHandlePacket($connection, channelOpenPacket('session', 0, 65535, 32768));

    expect($channelOpened)->toBeFalse();
    expect($transport->isWritable())->toBeFalse();
    expect($transport->getWrites())->toHaveCount(1);
    expect(Packet::fromData($transport->getWrites()[0])->type)->toBe(MessageType::DISCONNECT);
});

test('channel open remains allowed when authentication is disabled', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();
    $channelOpened = false;
    $connection->on('channel.open', static function () use (&$channelOpened): void {
        $channelOpened = true;
    });

    invokeHandlePacket($connection, channelOpenPacket('session', 0, 65535, 32768));

    expect($connection->isAuthenticated())->toBeTrue();
    expect($channelOpened)->toBeTrue();
    expect($transport->isWritable())->toBeTrue();
    expect($transport->getWrites())->toHaveCount(1);
    expect(Packet::fromData($transport->getWrites()[0])->type)->toBe(MessageType::CHANNEL_OPEN_CONFIRMATION);
});

test('direct-tcpip channel open is rejected with administratively prohibited failure', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();
    $channelOpened = false;
    $connection->on('channel.open', static function () use (&$channelOpened): void {
        $channelOpened = true;
    });

    invokeHandlePacket($connection, directTcpipChannelOpenPacket('127.0.0.1', 8080, '127.0.0.1', 4567, 7, 65535, 32768));

    expect($channelOpened)->toBeFalse();
    expect($transport->isWritable())->toBeTrue();
    expect(activeChannelsByLocalId($connection))->toBe([]);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);

    $response = Packet::fromData($writes[0]);
    expect($response->type)->toBe(MessageType::CHANNEL_OPEN_FAILURE);

    [$recipientChannel, $reasonCode, $description] = $response->extractFormat('%u%u%s%s');
    expect($recipientChannel)->toBe(7);
    expect($reasonCode)->toBe(ChannelOpenFailureReason::ADMINISTRATIVELY_PROHIBITED->value);
    expect($description)->toContain('direct-tcpip');
});

test('direct-tcpip channel open is rejected when enabled without an approval handler', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests(enableDirectTcpip: true);

    invokeHandlePacket($connection, directTcpipChannelOpenPacket('127.0.0.1', 8080, '127.0.0.1', 4567, 7, 65535, 32768));

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);

    $response = Packet::fromData($writes[0]);
    expect($response->type)->toBe(MessageType::CHANNEL_OPEN_FAILURE);

    [$recipientChannel, $reasonCode, $description] = $response->extractFormat('%u%u%s%s');
    expect($recipientChannel)->toBe(7);
    expect($reasonCode)->toBe(ChannelOpenFailureReason::ADMINISTRATIVELY_PROHIBITED->value);
    expect($description)->toContain('approval');
});

test('direct-tcpip channel open is rejected when handler denies the request', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableDirectTcpip: true);
    $connection->on('direct-tcpip', static function (array $info, Deferred $allowed): void {
        $allowed->resolve(false);
    });

    invokeHandlePacket($connection, directTcpipChannelOpenPacket('127.0.0.1', 8080, '127.0.0.1', 4567, 7, 65535, 32768));
    runLoopOnce($loop);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);

    $response = Packet::fromData($writes[0]);
    expect($response->type)->toBe(MessageType::CHANNEL_OPEN_FAILURE);

    [$recipientChannel, $reasonCode, $description] = $response->extractFormat('%u%u%s%s');
    expect($recipientChannel)->toBe(7);
    expect($reasonCode)->toBe(ChannelOpenFailureReason::ADMINISTRATIVELY_PROHIBITED->value);
    expect($description)->toContain('denied');
});

test('direct-tcpip channel open is rejected with connect failed when outbound connect fails', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableDirectTcpip: true);
    $connector = new FakeConnector();
    $connection->setConnector($connector);
    $connection->on('direct-tcpip', static function (array $info, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandlePacket($connection, directTcpipChannelOpenPacket('127.0.0.1', 8080, '127.0.0.1', 4567, 7, 65535, 32768));
    runLoopOnce($loop);
    $connector->rejectNext(new RuntimeException('Connection refused'));
    runLoopOnce($loop);

    expect($connector->getConnectTargets())->toBe(['127.0.0.1:8080']);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);

    $response = Packet::fromData($writes[0]);
    expect($response->type)->toBe(MessageType::CHANNEL_OPEN_FAILURE);

    [$recipientChannel, $reasonCode, $description] = $response->extractFormat('%u%u%s%s');
    expect($recipientChannel)->toBe(7);
    expect($reasonCode)->toBe(ChannelOpenFailureReason::CONNECT_FAILED->value);
    expect($description)->toContain('Connection refused');
});

test('direct-tcpip channel open is confirmed only after outbound connect succeeds', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableDirectTcpip: true);
    $connector = new FakeConnector();
    $connection->setConnector($connector);
    $requestedInfo = null;
    $connection->on('direct-tcpip', static function (array $info, Deferred $allowed) use (&$requestedInfo): void {
        $requestedInfo = $info;
        $allowed->resolve(true);
    });

    invokeHandlePacket($connection, directTcpipChannelOpenPacket('127.0.0.1', 8080, '127.0.0.1', 4567, 7, 65535, 32768));
    runLoopOnce($loop);

    expect($requestedInfo)->toBe([
        'destinationAddress' => '127.0.0.1',
        'destinationPort' => 8080,
        'originatorAddress' => '127.0.0.1',
        'originatorPort' => 4567,
    ]);
    expect($connector->getConnectTargets())->toBe(['127.0.0.1:8080']);
    expect($transport->getWrites())->toBe([]);

    $connector->resolveNext(new InMemoryConnection());
    runLoopOnce($loop);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::CHANNEL_OPEN_CONFIRMATION);
    expect(activeChannelsByLocalId($connection))->toHaveCount(1);
});

test('direct-tcpip bridges data, eof, and close after confirmation', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableDirectTcpip: true);
    $connector = new FakeConnector();
    $connection->setConnector($connector);
    $connection->on('direct-tcpip', static function (array $info, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    $channelEnded = false;
    $channelClosed = false;
    $connection->on('channel.end', static function () use (&$channelEnded): void {
        $channelEnded = true;
    });
    $connection->on('channel.close', static function () use (&$channelClosed): void {
        $channelClosed = true;
    });

    invokeHandlePacket($connection, directTcpipChannelOpenPacket('127.0.0.1', 8080, '127.0.0.1', 4567, 7, 65535, 32768));
    runLoopOnce($loop);

    $socket = new InMemoryConnection();
    $connector->resolveNext($socket);
    runLoopOnce($loop);

    $activeChannels = activeChannelsByLocalId($connection);
    $channel = array_values($activeChannels)[0];

    clearTransportWrites($transport);
    $socket->emit('data', ['hello over tcp']);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::CHANNEL_DATA);

    clearTransportWrites($transport);
    invokeHandlePacket($connection, remoteForwardChannelDataPacket($channel->getSenderChannel(), 'hello over ssh'));
    expect($socket->getWrites())->toContain('hello over ssh');

    invokeHandlePacket($connection, channelEofPacket($channel->getSenderChannel()));
    expect($channelEnded)->toBeTrue();
    expect($channel->isReadable())->toBeFalse();

    clearTransportWrites($transport);
    $socket->close();
    $writes = $transport->getWrites();
    expect($writes)->not->toBe([]);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::CHANNEL_CLOSE);
    expect($channelClosed)->toBeFalse();

    invokeHandlePacket($connection, channelClosePacket($channel->getSenderChannel()));
    expect($channelClosed)->toBeTrue();
});

test('unknown inbound channel type is rejected with unknown channel type failure', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();

    invokeHandlePacket($connection, channelOpenPacket('x11', 9, 65535, 32768));

    expect(activeChannelsByLocalId($connection))->toBe([]);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);

    $response = Packet::fromData($writes[0]);
    expect($response->type)->toBe(MessageType::CHANNEL_OPEN_FAILURE);

    [$recipientChannel, $reasonCode, $description] = $response->extractFormat('%u%u%s%s');
    expect($recipientChannel)->toBe(9);
    expect($reasonCode)->toBe(ChannelOpenFailureReason::UNKNOWN_CHANNEL_TYPE->value);
    expect($description)->toContain('x11');
});

test('tcpip-forward is rejected by default when remote forwarding is disabled', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::REQUEST_FAILURE);
    expect(remoteForwardListeners($connection))->toBe([]);
});

test('tcpip-forward is rejected when enabled without an approval handler', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests(enableRemoteForwarding: true);

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::REQUEST_FAILURE);
    expect(remoteForwardListeners($connection))->toBe([]);
});

test('tcpip-forward on port zero returns allocated port and keeps listener state when approved', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests();
    $connection->enableRemoteForwarding();
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));
    runLoopOnce($loop);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);

    $response = Packet::fromData($writes[0]);
    expect($response->type)->toBe(MessageType::REQUEST_SUCCESS);

    [$allocatedPort] = $response->extractFormat('%u');
    expect($allocatedPort)->toBeInt()->toBeGreaterThan(0);

    $listeners = remoteForwardListeners($connection);
    expect($listeners)->toHaveCount(1);
});

test('tcpip-forward accepts bracketed ipv6 and stores a normalized listener key', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableRemoteForwarding: true);
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['[::1]', 0]));
    runLoopOnce($loop);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::REQUEST_SUCCESS);

    $listeners = remoteForwardListeners($connection);
    expect($listeners)->toHaveCount(1)->toHaveKey('::1:0');
    expect($listeners['::1:0']['requestedAddress'])->toBe('::1');
});

test('remote forward listener keys normalize bracketed and unbracketed ipv6 addresses to the same value', function (): void {
    [$connection] = remoteForwardConnectionForTests(enableRemoteForwarding: true);

    expect(invokeRemoteForwardListenerKey($connection, '::1', 22))->toBe('::1:22');
    expect(invokeRemoteForwardListenerKey($connection, '[::1]', 22))->toBe('::1:22');
    expect(invokeRemoteForwardListenerKey($connection, '[::]', 22))->toBe(':::22');
});

test('cancel-tcpip-forward is rejected when remote forwarding is disabled', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests();

    invokeHandleGlobalRequest($connection, globalRequestPacket('cancel-tcpip-forward', true, ['127.0.0.1', 8000]));

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::REQUEST_FAILURE);
});

test('cancel-tcpip-forward removes existing listener when enabled', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests();
    $connection->enableRemoteForwarding();
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));
    runLoopOnce($loop);

    $listeners = remoteForwardListeners($connection);
    $listener = array_values($listeners)[0];
    $port = $listener['requestedPort'];
    if (0 === $port) {
        $port = $listener['effectivePort'];
    }

    clearTransportWrites($transport);
    invokeHandleGlobalRequest($connection, globalRequestPacket('cancel-tcpip-forward', true, ['127.0.0.1', $listener['requestedPort']]));

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::REQUEST_SUCCESS);
    expect(remoteForwardListeners($connection))->toBe([]);
    expect(canOpenSocket('127.0.0.1', $port))->toBeFalse();
});

test('cancel-tcpip-forward removes an ipv6 listener created with the alternate address form', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableRemoteForwarding: true);
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['[::1]', 0]));
    runLoopOnce($loop);

    $listeners = remoteForwardListeners($connection);
    expect($listeners)->toHaveKey('::1:0');

    clearTransportWrites($transport);
    invokeHandleGlobalRequest($connection, globalRequestPacket('cancel-tcpip-forward', true, ['::1', 0]));

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::REQUEST_SUCCESS);
    expect(remoteForwardListeners($connection))->toBe([]);
});

test('accepted forwarded tcp connection opens forwarded-tcpip channel', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests();
    $connection->enableRemoteForwarding();
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));
    runLoopOnce($loop);

    $listeners = remoteForwardListeners($connection);
    $listener = array_values($listeners)[0];
    $port = $listener['effectivePort'];

    clearTransportWrites($transport);
    connectClientToForwardListener($loop, $port);
    runLoopOnce($loop, 0.05);

    $writes = $transport->getWrites();
    expect($writes)->not->toBe([]);

    $openPacket = Packet::fromData($writes[0]);
    expect($openPacket->type)->toBe(MessageType::CHANNEL_OPEN);

    [$channelType, $localChannel] = $openPacket->extractFormat('%s%u%u%u');
    expect($channelType)->toBe('forwarded-tcpip');
    expect($localChannel)->toBeInt();

    $pending = pendingOutboundChannelOpens($connection);
    expect($pending)->toHaveKey($localChannel);
});

test('channel open confirmation promotes forwarded socket into active channel', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests();
    $connection->enableRemoteForwarding();
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));
    runLoopOnce($loop);

    $listener = array_values(remoteForwardListeners($connection))[0];
    clearTransportWrites($transport);
    connectClientToForwardListener($loop, $listener['effectivePort']);
    runLoopOnce($loop, 0.05);

    $openPacket = Packet::fromData($transport->getWrites()[0]);
    [, $localChannel] = $openPacket->extractFormat('%s%u%u%u');

    invokeHandleChannelOpenConfirmation($connection, channelOpenConfirmationPacket(100, $localChannel, 65535, 32768));

    $activeChannels = activeChannelsByLocalId($connection);
    expect($activeChannels)->toHaveKey($localChannel);
    expect($activeChannels[$localChannel])->toBeInstanceOf(Channel::class);
    expect(pendingOutboundChannelOpens($connection))->not->toHaveKey($localChannel);
});

test('accepted forwarded socket is paused before confirmation and resumed after confirmation', function (): void {
    [$connection, $transport] = remoteForwardConnectionForTests(enableRemoteForwarding: true);
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));

    $listenerKey = array_key_first(remoteForwardListeners($connection));
    expect($listenerKey)->toBeString();

    $socket = new InMemoryConnection();
    invokeHandleRemoteForwardAcceptedSocket($connection, $listenerKey, $socket);

    expect($socket->isPaused())->toBeTrue();

    $openPacket = Packet::fromData($transport->getWrites()[1]);
    [, $localChannel] = $openPacket->extractFormat('%s%u%u%u');

    invokeHandleChannelOpenConfirmation($connection, channelOpenConfirmationPacket(100, $localChannel, 65535, 32768));

    expect($socket->isPaused())->toBeFalse();
});

test('pending forwarded socket closes after confirmation timeout', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableRemoteForwarding: true);
    setPendingForwardedChannelOpenTimeout($connection, 0.01);
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));

    $listenerKey = array_key_first(remoteForwardListeners($connection));
    expect($listenerKey)->toBeString();

    $socket = new InMemoryConnection();
    invokeHandleRemoteForwardAcceptedSocket($connection, $listenerKey, $socket);

    $openPacket = Packet::fromData($transport->getWrites()[1]);
    [, $localChannel] = $openPacket->extractFormat('%s%u%u%u');

    runLoopOnce($loop, 0.03);

    $listeners = remoteForwardListeners($connection);
    expect($socket->isWritable())->toBeFalse();
    expect(pendingOutboundChannelOpens($connection))->not->toHaveKey($localChannel);
    expect($listeners[$listenerKey]['pendingChannels'])->not->toHaveKey($localChannel);
});

test('channel open confirmation cancels pending forwarded socket timeout', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableRemoteForwarding: true);
    setPendingForwardedChannelOpenTimeout($connection, 0.01);
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));

    $listenerKey = array_key_first(remoteForwardListeners($connection));
    expect($listenerKey)->toBeString();

    $socket = new InMemoryConnection();
    invokeHandleRemoteForwardAcceptedSocket($connection, $listenerKey, $socket);

    $openPacket = Packet::fromData($transport->getWrites()[1]);
    [, $localChannel] = $openPacket->extractFormat('%s%u%u%u');

    invokeHandleChannelOpenConfirmation($connection, channelOpenConfirmationPacket(100, $localChannel, 65535, 32768));
    runLoopOnce($loop, 0.03);

    expect(activeChannelsByLocalId($connection))->toHaveKey($localChannel);
    expect(pendingOutboundChannelOpens($connection))->not->toHaveKey($localChannel);
    expect($socket->isWritable())->toBeTrue();
});

test('channel open failure closes pending forwarded socket', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests();
    $connection->enableRemoteForwarding();
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(true);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));
    runLoopOnce($loop);

    $listener = array_values(remoteForwardListeners($connection))[0];
    clearTransportWrites($transport);
    connectClientToForwardListener($loop, $listener['effectivePort']);
    runLoopOnce($loop, 0.05);

    $openPacket = Packet::fromData($transport->getWrites()[0]);
    [, $localChannel] = $openPacket->extractFormat('%s%u%u%u');

    invokeHandleChannelOpenFailure($connection, channelOpenFailurePacket($localChannel, 1, 'nope'));

    expect(pendingOutboundChannelOpens($connection))->not->toHaveKey($localChannel);
});

test('tcpip-forward is rejected when approval handler denies the request', function (): void {
    [$connection, $transport, $loop] = remoteForwardConnectionForTests(enableRemoteForwarding: true);
    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $allowed->resolve(false);
    });

    invokeHandleGlobalRequest($connection, globalRequestPacket('tcpip-forward', true, ['127.0.0.1', 0]));
    runLoopOnce($loop);

    $writes = $transport->getWrites();
    expect($writes)->toHaveCount(1);
    expect(Packet::fromData($writes[0])->type)->toBe(MessageType::REQUEST_FAILURE);
    expect(remoteForwardListeners($connection))->toBe([]);
});

function remoteForwardConnectionForTests(bool $enableRemoteForwarding = false, bool $enableDirectTcpip = false): array
{
    $transport = new InMemoryConnection();
    $loop = new StreamSelectLoop();
    $connection = new Connection($transport, $loop);
    $connection->setConnectionId(1);
    $connection->enableDirectTcpip($enableDirectTcpip);
    $connection->enableRemoteForwarding($enableRemoteForwarding);

    return [$connection, $transport, $loop];
}

function globalRequestPacket(string $requestType, bool $wantReply, array $payload = []): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::GLOBAL_REQUEST, [$requestType, $wantReply, ...$payload]));
}

function channelOpenConfirmationPacket(int $remoteChannel, int $localChannel, int $window, int $packetSize): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_OPEN_CONFIRMATION, [$localChannel, $remoteChannel, $window, $packetSize]));
}

function channelOpenFailurePacket(int $localChannel, int $reasonCode, string $description): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_OPEN_FAILURE, [$localChannel, $reasonCode, $description, '']));
}

function channelOpenPacket(string $channelType, int $senderChannel, int $window, int $packetSize): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_OPEN, [$channelType, $senderChannel, $window, $packetSize]));
}

function directTcpipChannelOpenPacket(string $destinationAddress, int $destinationPort, string $originatorAddress, int $originatorPort, int $senderChannel, int $window, int $packetSize): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_OPEN, [
        'direct-tcpip',
        $senderChannel,
        $window,
        $packetSize,
        $destinationAddress,
        $destinationPort,
        $originatorAddress,
        $originatorPort,
    ]));
}

function remoteForwardChannelDataPacket(int $recipientChannel, string $data): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_DATA, [$recipientChannel, $data]));
}

function channelEofPacket(int $recipientChannel): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_EOF, [$recipientChannel]));
}

function channelClosePacket(int $recipientChannel): Packet
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    return new Packet($packetHandler->packValues(MessageType::CHANNEL_CLOSE, [$recipientChannel]));
}

function invokeHandleGlobalRequest(Connection $connection, Packet $packet): void
{
    $method = new ReflectionMethod($connection, 'handleGlobalRequest');
    $method->invoke($connection, $packet);
}

function invokeHandlePacket(Connection $connection, Packet $packet): void
{
    $method = new ReflectionMethod($connection, 'handlePacket');
    $method->invoke($connection, $packet);
}

function invokeHandleChannelOpenConfirmation(Connection $connection, Packet $packet): void
{
    $method = new ReflectionMethod($connection, 'handleChannelOpenConfirmation');
    $method->invoke($connection, $packet);
}

function invokeHandleChannelOpenFailure(Connection $connection, Packet $packet): void
{
    $method = new ReflectionMethod($connection, 'handleChannelOpenFailure');
    $method->invoke($connection, $packet);
}

function invokeHandleRemoteForwardAcceptedSocket(Connection $connection, string $listenerKey, InMemoryConnection $socket): void
{
    $method = new ReflectionMethod($connection, 'handleRemoteForwardAcceptedSocket');
    $method->invoke($connection, $listenerKey, $socket);
}

function invokeRemoteForwardListenerKey(Connection $connection, string $bindAddress, int $bindPort): string
{
    $method = new ReflectionMethod($connection, 'remoteForwardListenerKey');

    return $method->invoke($connection, $bindAddress, $bindPort);
}

function remoteForwardListeners(Connection $connection): array
{
    $property = new ReflectionProperty($connection, 'remoteForwardListeners');

    return $property->getValue($connection);
}

function pendingOutboundChannelOpens(Connection $connection): array
{
    $property = new ReflectionProperty($connection, 'pendingOutboundChannelOpens');

    return $property->getValue($connection);
}

function activeChannelsByLocalId(Connection $connection): array
{
    $property = new ReflectionProperty($connection, 'activeChannelsByLocalId');

    return $property->getValue($connection);
}

function setPendingForwardedChannelOpenTimeout(Connection $connection, float $timeout): void
{
    $property = new ReflectionProperty($connection, 'pendingForwardedChannelOpenTimeout');
    $property->setValue($connection, $timeout);
}

function clearTransportWrites(InMemoryConnection $transport): void
{
    $property = new ReflectionProperty($transport, 'writes');
    $property->setValue($transport, []);
}

function runLoopOnce(StreamSelectLoop $loop, float $delay = 0.01): void
{
    $loop->addTimer($delay, static function () use ($loop): void {
        $loop->stop();
    });

    $loop->run();
}

function connectClientToForwardListener(StreamSelectLoop $loop, int $port): void
{
    $connector = new Connector($loop);
    $socket = null;

    $connector->connect('127.0.0.1:' . $port)->then(static function ($connection) use (&$socket): void {
        $socket = $connection;
    });

    $loop->addTimer(0.02, static function () use (&$socket): void {
        $socket?->close();
    });
}

function canOpenSocket(string $host, int $port): bool
{
    set_error_handler(static fn (): bool => true);
    $socket = fsockopen($host, $port, $errno, $errstr, 0.05);
    restore_error_handler();

    if (! is_resource($socket)) {
        return false;
    }

    fclose($socket);

    return true;
}
