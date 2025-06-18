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

use phpseclib3\Net\SSH2;

beforeEach(function () {
    // Use a random available port for testing
    $this->port = rand(49152, 65535);
    $this->host = '127.0.0.1';

    // TODO: Refactor so we can test with a basic Server class instance
    $this->serverScript = sys_get_temp_dir() . '/reactphp_ssh_auth_test_server_' . uniqid() . '.php';
    $autoloadPath = realpath(__DIR__ . '/../../vendor/autoload.php');
    file_put_contents(
        $this->serverScript,
        <<<PHP
<?php
require '{$autoloadPath}';
use React\\Promise\\Deferred;
use WilliamEggers\\React\\SSH\\Channel;
use WilliamEggers\\React\\SSH\\Connection;
use WilliamEggers\\React\\SSH\\Loggers\\ConsoleLogger;
use WilliamEggers\\React\\SSH\\Server;

\$server = new Server('tcp://{$this->host}:{$this->port}');
\$server->setLogger(new ConsoleLogger());
\$server->setBanner('PEST AuthenticationTest');
\$server->enableAuthentication();
\$server->info('Listening on {$this->host}:{$this->port}');

\$server->on('connection', function (Connection \$connection) {
    \$connection->info('Connection accepted from ' . \$connection->getRemoteAddress());
    \$connection->on('authenticate', function (string \$username, string \$method, array \$credentials, Deferred \$authenticated) {
        \$isAuthenticated = false;
        \$password = \$credentials[0] ?? null;

        if (
            'test' === \$username
            && 'password' === \$method
            && 'abc123' === \$password
        ) {
            \$isAuthenticated = true;
        }

        \$authenticated->resolve(\$isAuthenticated);
    });
    \$connection->on('channel.open', function (Channel \$channel) {
        \$channel->on('shell-request', function (Deferred \$started) use (\$channel) {
            \$channel->write('Authenticated as ' . \$channel->getConnection()->getUsername() . "!\r\n");

            \$started->resolve(true);
        });
    });
});
PHP
    );
});

afterEach(function () {
    if (isset($this->server)) {
        $this->server->stop();
    }

    if (file_exists($this->serverScript)) {
        unlink($this->serverScript);
    }

    // Clean up any open pipes
    if (isset($this->pipes)) {
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
    }

    // Clean up process if it's still running
    if (isset($this->process) && is_resource($this->process)) {
        proc_terminate($this->process, SIGKILL);
    }
});

test('successful authenticated connection using phpseclib ssh client', function () {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $client->setTimeout(1);
    expect($client->login('test', 'abc123'))->toBeTrue();
    expect($client->isAuthenticated())->toBeTrue();
    expect($client->getBannerMessage())->toBe('PEST AuthenticationTest');
    expect($client->read())
        ->toContain("Authenticated as test!\r\n")
    ;
    expect($client->isConnected())->toBeTrue('phpseclib ssh2 client connected successfully');

    $client->disconnect();
});

test('connection using phpseclib ssh client with invalid credentials', function () {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $client->setTimeout(1);
    expect($client->login('test', 'incorrectpassword'))->toBeFalse();
    expect($client->isAuthenticated())->toBeFalse();
    expect($client->getBannerMessage())->toBe('PEST AuthenticationTest');

    $client->disconnect();
});
