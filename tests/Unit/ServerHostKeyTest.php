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

use React\EventLoop\ExtUvLoop;
use React\EventLoop\StreamSelectLoop;
use WilliamEggers\React\SSH\ServerHostKey;

beforeEach(function (): void {
    $this->baseDir = sys_get_temp_dir() . '/reactphp_ssh_host_key_test_' . uniqid();
});

afterEach(function (): void {
    if (! isset($this->baseDir) || ! is_dir($this->baseDir)) {
        return;
    }

    foreach (glob($this->baseDir . '/*') ?: [] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }

    rmdir($this->baseDir);
});

test('generates host keys and marks them ready', function (): void {
    $hostKey = new ServerHostKey('ed25519', baseDir: $this->baseDir);

    expect($hostKey->isReady())->toBeTrue();
    expect($hostKey->getPrivateKey())->not->toBe('');
    expect($hostKey->getPublicKey())->not->toBe('');
    expect(file_exists($this->baseDir . '/ssh_host_ed25519_key'))->toBeTrue();
    expect(file_exists($this->baseDir . '/ssh_host_ed25519_key.pub'))->toBeTrue();
});

test('loads existing host keys asynchronously once the loop runs', function (): void {
    mkdir($this->baseDir, 0700, true);
    file_put_contents($this->baseDir . '/ssh_host_ed25519_key', 'private-key');
    file_put_contents($this->baseDir . '/ssh_host_ed25519_key.pub', 'public-key');

    $loop = new StreamSelectLoop();
    $hostKey = new ServerHostKey('ed25519', baseDir: $this->baseDir, loop: $loop);

    expect($hostKey->isReady())->toBeFalse();

    $loop->run();

    expect($hostKey->isReady())->toBeTrue();
    expect($hostKey->getPrivateKey())->toBe('private-key');
    expect($hostKey->getPublicKey())->toBe('public-key');
});

test('uv loop uses compatible host key io path when extension is available', function (): void {
    if (! extension_loaded('uv')) {
        test()->markTestSkipped('ext-uv is not available');
    }

    $hostKey = new ServerHostKey('ed25519', baseDir: $this->baseDir, loop: new ExtUvLoop());

    expect($hostKey->isReady())->toBeTrue();
    expect($hostKey->getPrivateKey())->not->toBe('');
    expect($hostKey->getPublicKey())->not->toBe('');
});
