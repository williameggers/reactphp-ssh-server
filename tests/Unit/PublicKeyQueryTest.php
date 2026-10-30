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

use React\EventLoop\Loop;
use React\EventLoop\StreamSelectLoop;
use React\Promise\Deferred;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\KexNegotiator;
use WilliamEggers\React\SSH\Packet;
use WilliamEggers\React\SSH\PacketHandler;
use WilliamEggers\React\SSH\Values\KeyboardInteractiveConfig;
use WilliamEggers\Tests\React\SSH\Support\InMemoryConnection;

test('every supported key is acceptable without a publickey-query listener', function (): void {
    [$connection, $transport] = connectionForPublicKeyQueryTests();

    queryPublicKey($connection, ed25519KeyBlob());

    expect(writtenMessageTypes($transport))->toBe([MessageType::USERAUTH_PK_OK]);
});

test('a publickey-query listener can accept a key before the client signs with it', function (): void {
    [$connection, $transport] = connectionForPublicKeyQueryTests();
    $blob = ed25519KeyBlob();
    $queried = null;

    $connection->on('publickey-query', function (string $username, string $publicKey, Deferred $acceptable) use (&$queried): void {
        $queried = [$username, $publicKey];
        $acceptable->resolve(true);
    });

    queryPublicKey($connection, $blob);

    expect($queried)->toBe(['dev', 'ssh-ed25519 ' . base64_encode($blob)]);
    expect(writtenMessageTypes($transport))->toBe([MessageType::USERAUTH_PK_OK]);

    $pkOk = Packet::fromData($transport->getWrites()[0]);
    expect($pkOk->extractFormat('%s%s'))->toBe(['ssh-ed25519', $blob]);
});

test('a publickey-query listener can reject a key so the client never signs with it', function (bool $keyboardInteractive, string $methods): void {
    [$connection, $transport] = connectionForPublicKeyQueryTests();

    if ($keyboardInteractive) {
        $connection->setKeyboardInteractiveConfig(new KeyboardInteractiveConfig());
    }

    $connection->on('publickey-query', function (string $username, string $publicKey, Deferred $acceptable): void {
        $acceptable->resolve(false);
    });

    queryPublicKey($connection, ed25519KeyBlob());

    expect(writtenMessageTypes($transport))->toBe([MessageType::USERAUTH_FAILURE]);
    expect(Packet::fromData($transport->getWrites()[0])->extractFormat('%s%b'))->toBe([$methods, false]);
})->with([
    'password' => [false, 'publickey,password,none'],
    'keyboard-interactive' => [true, 'publickey,keyboard-interactive,none'],
]);

test('a publickey-query that is not answered in time rejects the key', function (): void {
    $loop = new StreamSelectLoop();
    Loop::set($loop);
    [$connection, $transport] = connectionForPublicKeyQueryTests();
    (new ReflectionProperty($connection, 'deferredEventPromiseTimeout'))->setValue($connection, 0.01);

    $connection->on('publickey-query', function (string $username, string $publicKey, Deferred $acceptable): void {
        // Never answered.
    });

    queryPublicKey($connection, ed25519KeyBlob());
    $loop->addTimer(0.05, fn () => $loop->stop());
    $loop->run();

    expect(writtenMessageTypes($transport))->toBe([MessageType::USERAUTH_FAILURE]);
});

test('unsupported key algorithms are rejected without asking the listener', function (): void {
    [$connection, $transport] = connectionForPublicKeyQueryTests();
    $asked = false;

    $connection->on('publickey-query', function () use (&$asked): void {
        $asked = true;
    });

    queryPublicKey($connection, ed25519KeyBlob(), 'ssh-dss');

    expect($asked)->toBeFalse();
    expect(writtenMessageTypes($transport))->toBe([MessageType::USERAUTH_FAILURE]);
});

/**
 * @return array{Connection, InMemoryConnection}
 */
function connectionForPublicKeyQueryTests(): array
{
    $transport = new InMemoryConnection();
    $connection = new Connection($transport, new StreamSelectLoop());
    $connection->setConnectionId(1);
    $connection->enableAuthentication(true);

    (new ReflectionProperty($connection, 'kexNegotiator'))->setValue($connection, new KexNegotiator('SSH-2.0-client', 'SSH-2.0-server'));

    return [$connection, $transport];
}

function ed25519KeyBlob(): string
{
    return pack('N', 11) . 'ssh-ed25519' . pack('N', 32) . random_bytes(32);
}

/**
 * Sends a publickey request without a signature, as clients do to ask whether a key is acceptable.
 */
function queryPublicKey(Connection $connection, string $blob, string $algorithm = 'ssh-ed25519'): void
{
    $packet = new Packet((new PacketHandler(new InMemoryConnection()))->packValues(MessageType::USERAUTH_REQUEST, ['dev', 'ssh-connection', 'publickey', false, $algorithm, $blob]));

    (new ReflectionMethod($connection, 'handleUserAuthRequest'))->invoke($connection, $packet);
}

/**
 * @return list<MessageType>
 */
function writtenMessageTypes(InMemoryConnection $transport): array
{
    return array_map(fn (string $data): MessageType => Packet::fromData($data)->type, $transport->getWrites());
}
