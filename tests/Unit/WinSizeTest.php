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

use WilliamEggers\React\SSH\Values\WinSize;

it('constructs a WinSize instance with all parameters provided', function (): void {
    $size = new WinSize(
        rows: 24,
        cols: 80,
        widthPixels: 800,
        heightPixels: 600
    );

    expect($size->rows)->toBe(24);
    expect($size->cols)->toBe(80);
    expect($size->widthPixels)->toBe(800);
    expect($size->heightPixels)->toBe(600);
});

it('constructs a WinSize instance with only required parameters', function (): void {
    $size = new WinSize(
        rows: 30,
        cols: 100
    );

    expect($size->rows)->toBe(30);
    expect($size->cols)->toBe(100);
    expect($size->widthPixels)->toBe(0);
    expect($size->heightPixels)->toBe(0);
});

it('accepts zero dimensions for rows and columns', function (): void {
    $size = new WinSize(0, 0);

    expect($size->rows)->toBe(0);
    expect($size->cols)->toBe(0);
});

it('handles very large terminal sizes', function (): void {
    $size = new WinSize(
        rows: 1000,
        cols: 3000,
        widthPixels: 7680,
        heightPixels: 4320
    );

    expect($size->rows)->toBeGreaterThan(999);
    expect($size->cols)->toBeGreaterThan(2999);
    expect($size->widthPixels)->toBe(7680);
    expect($size->heightPixels)->toBe(4320);
});
