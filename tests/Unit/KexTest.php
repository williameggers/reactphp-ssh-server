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

use WilliamEggers\React\SSH\Crypto\MlKem768OpenSsl;
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Kex;
use WilliamEggers\React\SSH\KexNegotiator;
use WilliamEggers\React\SSH\Packet;
use WilliamEggers\React\SSH\ServerHostKey;

/**
 * A Kex forced onto the hybrid algorithm so payload validation can be exercised on hosts
 * whose libcrypto does not provide ML-KEM-768.
 */
function kexForcedToHybridExchange(Packet $initPacket): Kex
{
    $negotiator = new KexNegotiator('SSH-2.0-test-client', 'SSH-2.0-test-server');

    (new ReflectionProperty(KexNegotiator::class, 'negotiatedAlgorithms'))->setValue($negotiator, [
        'kex' => Kex::KEX_MLKEM768X25519_SHA256,
        'hostkey' => 'ssh-ed25519',
        'encryption_ctos' => 'aes256-gcm@openssh.com',
        'encryption_stoc' => 'aes256-gcm@openssh.com',
        'mac_ctos' => 'hmac-sha2-256',
        'mac_stoc' => 'hmac-sha2-256',
        'compression_ctos' => 'none',
        'compression_stoc' => 'none',
    ]);

    // The client blob is validated before the host key is touched, so an uninitialised host
    // key keeps this test free of key generation and file system work.
    return new Kex($initPacket, $negotiator, (new ReflectionClass(ServerHostKey::class))->newInstanceWithoutConstructor());
}

test('a hybrid client blob of the wrong size is rejected', function (): void {
    // A well-formed SSH string that is far too short for a 1184 + 32 byte hybrid key blob.
    $payload = chr(MessageType::KEXDH_INIT->value) . pack('N', 32) . str_repeat("\0", 32);

    $kex = kexForcedToHybridExchange(new Packet($payload));

    // The message also proves the exchange was routed onto the hybrid code path.
    expect(fn (): string => $kex->response())->toThrow(
        UnexpectedValueException::class,
        'Invalid mlkem768x25519-sha256 client key exchange payload',
    );
});

test('an incomplete hybrid client blob is rejected', function (): void {
    // The declared length runs past the end of the message, so the packet parser refuses it
    // rather than handing the exchange a short key.
    $payload = chr(MessageType::KEXDH_INIT->value) . pack('N', 1216) . str_repeat("\0", 10);

    $kex = kexForcedToHybridExchange(new Packet($payload));

    expect(fn (): string => $kex->response())->toThrow(
        UnexpectedValueException::class,
        'Incomplete SSH string',
    );
});

test('a classical shared secret is encoded as an mpint', function (): void {
    $kex = (new ReflectionClass(Kex::class))->newInstanceWithoutConstructor();

    // A secret with its top bit set gains a leading zero byte when encoded as a positive
    // mpint, which distinguishes the mpint encoding from the plain string encoding.
    $secret = "\xff" . str_repeat("\x01", 31);
    (new ReflectionProperty(Kex::class, 'sharedSecret'))->setValue($kex, $secret);

    expect($kex->encodedSharedSecret())->toBe(pack('N', 33) . "\0" . $secret);
});

test('a hybrid shared secret is encoded as a string', function (): void {
    $kex = (new ReflectionClass(Kex::class))->newInstanceWithoutConstructor();

    $secret = hash('sha256', 'hybrid', true);
    (new ReflectionProperty(Kex::class, 'sharedSecret'))->setValue($kex, $secret);
    (new ReflectionProperty(Kex::class, 'sharedSecretIsString'))->setValue($kex, true);

    expect($kex->encodedSharedSecret())->toBe(pack('N', MlKem768OpenSsl::SHARED_SECRET_BYTES) . $secret);
});
