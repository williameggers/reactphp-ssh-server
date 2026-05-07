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

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Hash;
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Packet;
use WilliamEggers\React\SSH\PacketHandler;
use WilliamEggers\Tests\React\SSH\Support\InMemoryConnection;

test('fromData parses a complete AES-CTR packet in one chunk', function (): void {
    $packetHandler = packetHandlerForAesCtrTests();
    $payload = MessageType::chr(MessageType::CHANNEL_DATA)
        . pack('N', 7)
        . pack('N', 3)
        . 'abc';

    $encryptedPacket = $packetHandler->constructPacket($payload);

    [$packet, $bytesUsed] = $packetHandler->fromData($encryptedPacket);

    expect($packet)->toBeInstanceOf(Packet::class);
    expect($bytesUsed)->toBe(strlen($encryptedPacket));
    expect($packet->type)->toBe(MessageType::CHANNEL_DATA);
    expect($packet->extractFormat('%u%s'))->toBe([7, 'abc']);
});

test('fromData returns null with zero bytes used until a split AES-CTR packet is complete', function (): void {
    $packetHandler = packetHandlerForAesCtrTests();
    $payload = MessageType::chr(MessageType::CHANNEL_DATA)
        . pack('N', 4)
        . pack('N', 6)
        . 'abcdef';

    $encryptedPacket = $packetHandler->constructPacket($payload);
    $buffer = '';

    foreach (str_split($encryptedPacket) as $index => $byte) {
        $buffer .= $byte;
        [$packet, $bytesUsed] = $packetHandler->fromData($buffer);

        if ($index < strlen($encryptedPacket) - 1) {
            expect($packet)->toBeNull();
            expect($bytesUsed)->toBe(0);

            continue;
        }

        expect($packet)->toBeInstanceOf(Packet::class);
        expect($bytesUsed)->toBe(strlen($buffer));
        expect($packet->extractFormat('%u%s'))->toBe([4, 'abcdef']);
    }
});

test('partial retries do not desynchronize AES-CTR decryptor state', function (): void {
    $packetHandler = packetHandlerForAesCtrTests();
    $payload = MessageType::chr(MessageType::CHANNEL_DATA)
        . pack('N', 9)
        . pack('N', 7)
        . 'payload';

    $encryptedPacket = $packetHandler->constructPacket($payload);
    $splitOffset = 11;
    $partial = substr($encryptedPacket, 0, $splitOffset);

    [$packet, $bytesUsed] = $packetHandler->fromData($partial);
    expect($packet)->toBeNull();
    expect($bytesUsed)->toBe(0);

    [$completedPacket, $completedBytesUsed] = $packetHandler->fromData($encryptedPacket);
    expect($completedPacket)->toBeInstanceOf(Packet::class);
    expect($completedBytesUsed)->toBe(strlen($encryptedPacket));
    expect($completedPacket->extractFormat('%u%s'))->toBe([9, 'payload']);
});

test('a valid AES-CTR packet split between ciphertext and mac parses successfully', function (): void {
    $packetHandler = packetHandlerForAesCtrTests();
    $payload = MessageType::chr(MessageType::CHANNEL_DATA)
        . pack('N', 3)
        . pack('N', 5)
        . 'split';

    $encryptedPacket = $packetHandler->constructPacket($payload);
    $macLength = 32;
    $ciphertextOnly = substr($encryptedPacket, 0, -$macLength);

    [$packet, $bytesUsed] = $packetHandler->fromData($ciphertextOnly);
    expect($packet)->toBeNull();
    expect($bytesUsed)->toBe(0);

    [$packet, $bytesUsed] = $packetHandler->fromData($encryptedPacket);
    expect($packet)->toBeInstanceOf(Packet::class);
    expect($bytesUsed)->toBe(strlen($encryptedPacket));
    expect($packet->extractFormat('%u%s'))->toBe([3, 'split']);
});

function packetHandlerForAesCtrTests(): PacketHandler
{
    $packetHandler = new PacketHandler(new InMemoryConnection());

    $setProperty = static function (string $name, mixed $value) use ($packetHandler): void {
        $property = new ReflectionProperty($packetHandler, $name);
        $property->setValue($packetHandler, $value);
    };

    $encryptKey = str_repeat('k', 32);
    $encryptIv = str_repeat('i', 16);
    $macKey = str_repeat('m', 32);

    $encryptor = new AES('ctr');
    $encryptor->setKey($encryptKey);
    $encryptor->setIV($encryptIv);
    $encryptor->disablePadding();
    $encryptor->enableContinuousBuffer();

    $decryptor = new AES('ctr');
    $decryptor->setKey($encryptKey);
    $decryptor->setIV($encryptIv);
    $decryptor->disablePadding();
    $decryptor->enableContinuousBuffer();

    $hash = new Hash('sha256');
    $hash->setKey($macKey);

    $setProperty('encryptionActive', true);
    $setProperty('hasCompletedInitialKeyExchange', true);
    $setProperty('encryptionMethod_CtoS', 'aes256-ctr');
    $setProperty('encryptionMethod_StoC', 'aes256-ctr');
    $setProperty('macMethod_CtoS', 'hmac-sha2-256');
    $setProperty('macMethod_StoC', 'hmac-sha2-256');
    $setProperty('encryptKey_CtoS', $encryptKey);
    $setProperty('encryptKey_StoC', $encryptKey);
    $setProperty('encryptIV_CtoS', $encryptIv);
    $setProperty('encryptIV_StoC', $encryptIv);
    $setProperty('macKey_CtoS', $macKey);
    $setProperty('macKey_StoC', $macKey);
    $setProperty('decryptor', $decryptor);
    $setProperty('encryptor', $encryptor);
    $setProperty('hash_CtoS', clone $hash);
    $setProperty('hash_StoC', clone $hash);
    $setProperty('packetSeq_CtoS', 0);
    $setProperty('packetSeq_StoC', 0);

    return $packetHandler;
}
