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
 * Local forwarding example.
 *
 * Start this SSH server:
 *   php examples/local-forwarding.php
 *
 * On the SSH server machine, create a simple PHP page in the directory you want to serve:
 *   printf '<?php echo "Hello from the SSH server side\\n";' > index.php
 *
 * Start PHP's built-in web server on the SSH server side:
 *   php -S 127.0.0.1:3000
 *
 * From the SSH client machine, open a local forward with OpenSSH:
 *   ssh -p 2222 -N -L 8000:127.0.0.1:3000 test@127.0.0.1
 *
 * Password:
 *   abc123
 *
 * This asks the SSH server to open outbound TCP connections to 127.0.0.1:3000
 * whenever the SSH client connects to its own local 127.0.0.1:8000 listener.
 *
 * To test the tunnel from the SSH client machine:
 *   curl http://127.0.0.1:8000
 */

require __DIR__ . '/../vendor/autoload.php';

use React\Promise\Deferred;
use WilliamEggers\React\SSH\Channel;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Server;

$server = (new Server('127.0.0.1:2222'))
    ->enableAuthentication()
    ->enableDirectTcpip()
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

    $connection->on('direct-tcpip', static function (array $info, Deferred $allowed): void {
        $destinationAddress = is_string($info['destinationAddress'] ?? null) ? $info['destinationAddress'] : 'unknown';
        $destinationPort = is_int($info['destinationPort'] ?? null) ? $info['destinationPort'] : 0;
        $originatorAddress = is_string($info['originatorAddress'] ?? null) ? $info['originatorAddress'] : 'unknown';
        $originatorPort = is_int($info['originatorPort'] ?? null) ? $info['originatorPort'] : 0;

        $approved = '127.0.0.1' === $destinationAddress && 3000 === $destinationPort;
        $allowed->resolve($approved);

        fwrite(
            STDOUT,
            sprintf(
                "%s direct-tcpip request to %s:%d from %s:%d\n",
                $approved ? 'Approved' : 'Rejected',
                $destinationAddress,
                $destinationPort,
                $originatorAddress,
                $originatorPort
            )
        );
    });

    $connection->on('channel.open', static function (Channel $channel): void {
        $channel->on('shell-request', static function (Deferred $started) use ($channel): void {
            $started->resolve(true);
            $channel->end("Local forwarding example server\r\nOnly direct-tcpip to 127.0.0.1:3000 is allowed.\r\n");
        });
    });
});

fwrite(STDOUT, "Listening on 127.0.0.1:2222\n");
