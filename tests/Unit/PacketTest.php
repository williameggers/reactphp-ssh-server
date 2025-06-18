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

use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Packet;

test('extracts string and integers correctly', function () {
    // Create a packet with: string("hello") + uint32(123) + uint32(456)
    $message = pack('N', 5) . 'howdy' . pack('N', 123) . pack('N', 456);
    $packet = new Packet(chr(MessageType::CHANNEL_OPEN->value) . $message);

    [$str, $int1, $int2] = $packet->extractFormat('%s%u%u');

    expect($str)->toBe('howdy')
        ->and($int1)->toBe(123)
        ->and($int2)->toBe(456)
    ;
});

test('extracts boolean values correctly', function () {
    // Create a packet with: string("test") + bool(true) + bool(false)
    $message = pack('N', 5) . 'howdy' . chr(1) . chr(0);
    $packet = new Packet(chr(MessageType::CHANNEL_OPEN->value) . $message);

    [$str, $bool1, $bool2] = $packet->extractFormat('%s%b%b');

    expect($str)->toBe('howdy')
        ->and($bool1)->toBeTrue()
        ->and($bool2)->toBeFalse()
    ;
});

test('handles empty string correctly', function () {
    // Create a packet with: string("") + uint32(123)
    $message = pack('N', 0) . pack('N', 123);
    $packet = new Packet(chr(MessageType::CHANNEL_OPEN->value) . $message);

    [$str, $int] = $packet->extractFormat('%s%u');

    expect($str)->toBe('')
        ->and($int)->toBe(123)
    ;
});

test('throws exception for unknown format specifier', function () {
    $message = pack('N', 5) . 'howdy';
    $packet = new Packet(chr(MessageType::CHANNEL_OPEN->value) . $message);

    expect(fn () => $packet->extractFormat('%x')) // 'x' is not a valid specifier
        ->toThrow(InvalidArgumentException::class, 'Unknown format specifier: x')
    ;
});

test('handles multiple strings correctly', function () {
    // Create a packet with: string("hello") + string("world") + uint32(123)
    $message = pack('N', 5) . 'howdy' . pack('N', 5) . 'world' . pack('N', 123);
    $packet = new Packet(chr(MessageType::CHANNEL_OPEN->value) . $message);

    [$str1, $str2, $int] = $packet->extractFormat('%s%s%u');

    expect($str1)->toBe('howdy')
        ->and($str2)->toBe('world')
        ->and($int)->toBe(123)
    ;
});

test('handles long strings correctly', function () {
    $longString = str_repeat('a', 1000);
    // Create a packet with: string(1000 chars) + uint32(123)
    $message = pack('N', 1000) . $longString . pack('N', 123);
    $packet = new Packet(chr(MessageType::CHANNEL_OPEN->value) . $message);

    [$str, $int] = $packet->extractFormat('%s%u');

    expect($str)->toBe($longString)
        ->and($int)->toBe(123)
    ;
});

test('handles all formats together at once', function () {
    $message = pack('N', 5) . 'howdy' . pack('N', 420) . chr(1);
    $packet = new Packet(chr(MessageType::CHANNEL_OPEN->value) . $message);

    [$str, $int1, $bool] = $packet->extractFormat('%s%u%b');

    expect($str)->toBe('howdy')
        ->and($int1)->toBe(420)
        ->and($bool)->toBeTrue();
});

// SSH_MSG_USERAUTH_REQUEST simulation
it('extracts username, service, and method from SSH_MSG_USERAUTH_REQUEST', function () {
    $username = 'testuser';
    $service = 'ssh-connection';
    $method = 'password';

    $payload = chr(50) .
               pack('N', strlen($username)) . $username .
               pack('N', strlen($service)) . $service .
               pack('N', strlen($method)) . $method;

    $packet = new Packet($payload);
    expect($packet->type)->toBe(MessageType::USERAUTH_REQUEST);
    expect($packet->extractFormat('%s%s%s'))->toBe(['testuser', 'ssh-connection', 'password']);
});
