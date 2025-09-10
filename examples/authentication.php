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

require __DIR__ . '/../vendor/autoload.php';

use React\Promise\Deferred;
use WilliamEggers\React\SSH\Channel;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Server;

$server = (new Server('127.0.0.1:22'))
    ->enableAuthentication()
;

$server->on('connection', static function (Connection $connection): void {
    /**
     * @param Deferred<bool> $authenticated Deferred that must be resolved with a boolean indicating authentication success.
     */
    $connection->on('authenticate', static function (string $username, string $method, array $credentials, Deferred $authenticated): void {
        $isAuthenticated = false;
        $password = $credentials[0] ?? null;

        if (
            'password' === $method
            && 'test' === $username
            && 'abc123' === $password
        ) {
            $isAuthenticated = true;
        }

        $authenticated->resolve($isAuthenticated);
    });

    $connection->on('channel.open', static function (Channel $channel): void {
        $channel->on('shell-request', static function (Deferred $started) use ($channel): void {
            $channel->end('Authenticated as ' . $channel->getConnection()->getUsername() . "!\r\n");

            $started->resolve(true);
        });
    });
});
