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

use WilliamEggers\React\SSH\Values\TerminalInfo;

it('constructs a TerminalInfo instance with expected values', function () {
    $info = new TerminalInfo(
        term: 'xterm-256color',
        widthChars: 80,
        heightRows: 24,
        widthPixels: 800,
        heightPixels: 600,
        modes: ['ECHO' => 1, 'ICANON' => 1]
    );

    expect($info->term)->toBe('xterm-256color');
    expect($info->widthChars)->toBe(80);
    expect($info->heightRows)->toBe(24);
    expect($info->widthPixels)->toBe(800);
    expect($info->heightPixels)->toBe(600);
    expect($info->modes)->toMatchArray(['ECHO' => 1, 'ICANON' => 1]);
});

it('accepts zero or minimal values for pixel and character dimensions', function () {
    $info = new TerminalInfo(
        term: 'vt100',
        widthChars: 0,
        heightRows: 0,
        widthPixels: 0,
        heightPixels: 0,
        modes: []
    );

    expect($info->term)->toBe('vt100');
    expect($info->widthChars)->toBe(0);
    expect($info->heightRows)->toBe(0);
    expect($info->widthPixels)->toBe(0);
    expect($info->heightPixels)->toBe(0);
    expect($info->modes)->toBe([]);
});

it('supports extended terminal modes', function () {
    $modes = [
        'ECHO' => 1,
        'ICANON' => 0,
        'ISIG' => 1,
        'IXON' => 0,
    ];

    $info = new TerminalInfo(
        term: 'screen',
        widthChars: 120,
        heightRows: 30,
        widthPixels: 1024,
        heightPixels: 768,
        modes: $modes
    );

    expect($info->modes)->toMatchArray($modes);
});
