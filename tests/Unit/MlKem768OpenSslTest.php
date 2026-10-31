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

test('the availability probe reports a boolean and never throws', function (): void {
    // This is the soft-disable contract: whether or not ext-ffi and an ML-KEM capable
    // libcrypto are present, probing must answer rather than raise.
    expect(MlKem768OpenSsl::isAvailable())->toBeBool();
});

test('a bad REACT_SSH_LIBCRYPTO path fails with a RuntimeException naming the setting', function (): void {
    if (! extension_loaded('ffi')) {
        $this->markTestSkipped('ext-ffi is not loaded, so libcrypto is never resolved.');
    }

    $configured = getenv('REACT_SSH_LIBCRYPTO');
    putenv('REACT_SSH_LIBCRYPTO=' . sys_get_temp_dir() . '/definitely-not-libcrypto.so.3');

    try {
        $thrown = null;

        try {
            MlKem768OpenSsl::create();
        } catch (Throwable $e) {
            $thrown = $e;
        }

        // An operator who mistypes the path needs the setting named, not an opaque FFI error.
        expect($thrown)->toBeInstanceOf(RuntimeException::class)
            ->and($thrown->getMessage())->toContain('REACT_SSH_LIBCRYPTO')
            ->and($thrown->getPrevious())->toBeInstanceOf(Throwable::class)
        ;
    } finally {
        if (false === $configured) {
            putenv('REACT_SSH_LIBCRYPTO');
        } else {
            putenv('REACT_SSH_LIBCRYPTO=' . $configured);
        }
    }
});

test('an encapsulation key of the wrong length is rejected', function (): void {
    if (! MlKem768OpenSsl::isAvailable()) {
        $this->markTestSkipped('OpenSSL does not provide ML-KEM-768.');
    }

    expect(fn (): array => MlKem768OpenSsl::create()->encapsulate(str_repeat("\0", 100)))
        ->toThrow(RuntimeException::class)
    ;
});
