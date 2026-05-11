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

/*
 * Remote forwarding example.
 *
 * Start this SSH server:
 *   php examples/remote-forwarding.php
 *
 * On the SSH client side, create a simple PHP page in the directory you want to serve:
 *   printf '<?php echo "Hello from the forwarded PHP server\\n";' > index.php
 *
 * Start PHP's built-in web server on the SSH client side:
 *   php -S 127.0.0.1:3000
 *
 * Open a remote forward with OpenSSH:
 *   ssh -p 2222 -N -R 127.0.0.1:8000:127.0.0.1:3000 test@127.0.0.1
 *
 * Password:
 *   abc123
 *
 * This asks the SSH server to listen on 127.0.0.1:8000 and tunnel accepted
 * connections back to 127.0.0.1:3000 on the SSH client side.
 *
 * To test the tunnel from the SSH server machine:
 *   curl http://127.0.0.1:8000
 */

require __DIR__ . '/../vendor/autoload.php';

use React\Promise\Deferred;
use WilliamEggers\React\SSH\Channel;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Server;

$server = (new Server('127.0.0.1:2222'))
    ->enableAuthentication()
    ->enableRemoteForwarding()
;

$server->on('connection', static function (Connection $connection): void {
    $connection->on('authenticate', static function (string $username, string $method, array $credentials, Deferred $authenticated): void {
        $password = $credentials[0] ?? null;

        $authenticated->resolve(
            'password' === $method
            && 'test' === $username
            && 'abc123' === $password
        );
    });

    $connection->on('global-request.tcpip-forward', static function (string $bindAddress, int $bindPort, Deferred $allowed): void {
        $approved = '127.0.0.1' === $bindAddress;
        $allowed->resolve($approved);

        fwrite(
            STDOUT,
            sprintf("%s remote forward request for %s:%d\n", $approved ? 'Approved' : 'Rejected', $bindAddress, $bindPort)
        );
    });

    $connection->on('global-request.cancel-tcpip-forward', static function (string $bindAddress, int $bindPort): void {
        fwrite(STDOUT, sprintf("Cancelled remote forward for %s:%d\n", $bindAddress, $bindPort));
    });

    $connection->on('forwarded-tcpip.connection', static function (array $info): void {
        $bindAddress = is_string($info['bindAddress'] ?? null) ? $info['bindAddress'] : 'unknown';
        $bindPort = is_int($info['bindPort'] ?? null) ? $info['bindPort'] : 0;
        $originatorAddress = is_string($info['originatorAddress'] ?? null) ? $info['originatorAddress'] : 'unknown';
        $originatorPort = is_int($info['originatorPort'] ?? null) ? $info['originatorPort'] : 0;

        fwrite(
            STDOUT,
            sprintf(
                "Forwarded TCP connection: bind=%s:%d origin=%s:%d\n",
                $bindAddress,
                $bindPort,
                $originatorAddress,
                $originatorPort
            )
        );
    });

    $connection->on('channel.open', static function (Channel $channel): void {
        $channel->on('shell-request', static function (Deferred $started) use ($channel): void {
            $started->resolve(true);
            $channel->end("Remote forwarding example server\r\n");
        });
    });
});

fwrite(STDOUT, "Listening on 127.0.0.1:2222\n");
