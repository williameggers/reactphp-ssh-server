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

/**
 * Builds a client SSH_MSG_KEXINIT packet advertising the given key exchange methods,
 * with the remaining name-lists filled in with otherwise acceptable values.
 *
 * @param list<string> $kexAlgorithms
 */
function hybridKexInitPacket(array $kexAlgorithms): Packet
{
    $nameList = fn (array $names): string => pack('N', strlen(implode(',', $names))) . implode(',', $names);

    $payload = chr(MessageType::KEXINIT->value)
        . str_repeat("\0", 16)                        // Cookie
        . $nameList($kexAlgorithms)                   // Key exchange methods
        . $nameList(['ssh-ed25519'])                  // Server host key algorithms
        . $nameList(['aes256-gcm@openssh.com'])       // Encryption client->server
        . $nameList(['aes256-gcm@openssh.com'])       // Encryption server->client
        . $nameList(['hmac-sha2-256'])                // MAC client->server
        . $nameList(['hmac-sha2-256'])                // MAC server->client
        . $nameList(['none'])                         // Compression client->server
        . $nameList(['none'])                         // Compression server->client
        . $nameList([])                               // Languages client->server
        . $nameList([])                               // Languages server->client
        . "\0"                                        // first_kex_packet_follows
        . pack('N', 0);                               // Reserved

    return new Packet($payload);
}

/**
 * @param list<string> $kexAlgorithms
 */
function hybridKexNegotiator(array $kexAlgorithms): KexNegotiator
{
    return new KexNegotiator(
        'SSH-2.0-test-client',
        'SSH-2.0-test-server',
        hybridKexInitPacket($kexAlgorithms),
    );
}

test('offers mlkem768x25519-sha256 when libcrypto provides ML-KEM-768', function (): void {
    if (! MlKem768OpenSsl::isAvailable()) {
        $this->markTestSkipped('OpenSSL does not provide ML-KEM-768.');
    }

    $negotiator = hybridKexNegotiator([Kex::KEX_MLKEM768X25519_SHA256, Kex::KEX_CURVE25519_SHA256]);

    $serverKexInit = $negotiator->response();
    $negotiated = $negotiator->negotiateAlgorithms();

    expect($serverKexInit)->toContain(Kex::KEX_MLKEM768X25519_SHA256)
        ->and($negotiated['kex'])->toBe(Kex::KEX_MLKEM768X25519_SHA256)
    ;
});

test('soft-disables mlkem768x25519-sha256 when the backend is unavailable', function (): void {
    if (MlKem768OpenSsl::isAvailable()) {
        $this->markTestSkipped('OpenSSL provides ML-KEM-768, so the hybrid method is expected to be offered.');
    }

    $negotiator = hybridKexNegotiator([Kex::KEX_MLKEM768X25519_SHA256, Kex::KEX_CURVE25519_SHA256]);

    $serverKexInit = $negotiator->response();
    $negotiated = $negotiator->negotiateAlgorithms();

    // The hybrid method must not be advertised when ext-ffi or ML-KEM support is missing, and
    // negotiation must fall through to a classical method rather than failing the exchange.
    expect($serverKexInit)->not->toContain(Kex::KEX_MLKEM768X25519_SHA256)
        ->and($negotiated['kex'])->toBe(Kex::KEX_CURVE25519_SHA256)
    ;
});

test('keeps curve25519 available for clients without post-quantum support', function (): void {
    $negotiator = hybridKexNegotiator([Kex::KEX_CURVE25519_SHA256]);

    $serverKexInit = $negotiator->response();
    $negotiated = $negotiator->negotiateAlgorithms();

    expect($serverKexInit)->toContain(Kex::KEX_CURVE25519_SHA256)
        ->and($negotiated['kex'])->toBe(Kex::KEX_CURVE25519_SHA256)
    ;
});

test('keeps the legacy diffie-hellman fallback advertised', function (): void {
    $negotiator = hybridKexNegotiator(['diffie-hellman-group14-sha256']);

    $serverKexInit = $negotiator->response();
    $negotiated = $negotiator->negotiateAlgorithms();

    expect($serverKexInit)->toContain('diffie-hellman-group14-sha256')
        ->and($negotiated['kex'])->toBe('diffie-hellman-group14-sha256')
    ;
});

test('honours a client that prefers curve25519 over the hybrid method', function (): void {
    $negotiator = hybridKexNegotiator([Kex::KEX_CURVE25519_SHA256, Kex::KEX_MLKEM768X25519_SHA256]);

    $negotiator->response();
    $negotiated = $negotiator->negotiateAlgorithms();

    // RFC 4253 §7.1: the client's preference order wins for the first shared algorithm.
    expect($negotiated['kex'])->toBe(Kex::KEX_CURVE25519_SHA256);
});
