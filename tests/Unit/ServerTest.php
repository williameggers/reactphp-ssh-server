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

beforeEach(function (): void {
    // Use a random available port for testing
    $this->port = random_int(49152, 65535);
    $this->host = '127.0.0.1';
    // $this->server = new Server($this->port, $this->host);

    // TODO: Refactor so we can test with a basic Server class instance
    $this->serverScript = sys_get_temp_dir() . '/reactphp_ssh_test_server_' . uniqid() . '.php';
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
\$server->setBanner('PEST ServerTest');
\$server->info('Listening on {$this->host}:{$this->port}');

\$server->on('connection', function (Connection \$connection) {
    \$connection->info('Connection accepted from ' . \$connection->getRemoteAddress());
    \$connection->on('channel.open', function (Channel \$channel) {
        \$channel->on('shell-request', function (Deferred \$started) use (\$channel) {
            \$channel->write('Hello ' . \$channel->getConnection()->getRemoteAddress() . "!\r\n");
            \$channel->on('data', function (\$data) use (\$channel) {
                \$channel->getConnection()->close();
            });
            \$started->resolve(true);
        });
    });
});
PHP
    );
});

afterEach(function (): void {
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
        $status = proc_get_status($this->process);
        if (true == $status['running']) { // process ran too long, kill it
            // get the parent pid of the process we want to kill
            $ppid = $status['pid'];
            // use ps to get all the children of this process, and kill them
            $pids = preg_split('/\s+/', shell_exec('ps -o pid --no-heading --ppid ' . $ppid) ?? '');
            foreach ($pids as $pid) {
                if (is_numeric($pid)) {
                    posix_kill((int) $pid, 9); // 9 is the SIGKILL signal
                }
            }

            proc_close($this->process);
        }
    }
});

test('creates and configures TCP socket correctly', function (): void {
    // Start server in background using the script
    ['process' => $this->process, 'pid' => $pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    // Try to connect to the socket
    $socket = @fsockopen($this->host, $this->port, $errno, $errstr, 1);
    expect($pid)->toBeRunning();
    expect($socket)->toBeResource();
    expect($errno)->toBe(0);
    fclose($socket);
});

test('accepts and handles new connections', function (): void {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    // Act
    $clientSocket = fsockopen($this->host, $this->port, $errno, $errstr, 1);
    expect($clientSocket)->toBeResource();

    // Wait for connection message in server output
    $startTime = microtime(true);
    $connectionAccepted = false;

    while (microtime(true) - $startTime < 0.2) { // 200ms timeout
        $line = fgets($this->pipes[1]); // Read from stdout
        if ($line && str_contains($line, '#1] Connection accepted from')) {
            $connectionAccepted = true;

            break;
        }
        usleep(10000); // 10ms sleep
    }

    // Assert
    expect($connectionAccepted)->toBeTrue("Server didn't log connection acceptance");

    // Cleanup
    fclose($clientSocket);
});

test('manages multiple connections', function (): void {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    // Act
    $connections = [];
    for ($i = 0; $i < 3; ++$i) {
        $clientSocket = @fsockopen($this->host, $this->port, $errno, $errstr, 1);
        expect($clientSocket)->toBeResource();
        $connections[] = $clientSocket;
    }

    // Check if each connection was handled by the server
    $childPids = [];
    $startTime = microtime(true);
    $i = 0;

    while ((microtime(true) - $startTime) < 1) { // 1000ms timeout
        $read = [$this->pipes[1]]; // stdout
        $write = $except = [];

        // Wait for data with 10ms timeout
        if (stream_select($read, $write, $except, 0, 10000) > 0) {
            $line = fgets($this->pipes[1]);
            if ($line && str_contains($line, 'Connection accepted from')) {
                $childPids[] = $line;
            }
        }

        ++$i;
    }

    expect(count($childPids))->toBe(3);

    // Cleanup
    foreach ($connections as $socket) {
        fclose($socket);
    }
})->skip(inGithubActions(), 'Not working on GitHub CI atm, but works wonderfully locally and on test servers');

test('successful connection using phpseclib ssh client', function (): void {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $client->login('test', 'test');
    $client->setTimeout(1);

    expect($client->getBannerMessage())->toBe('PEST ServerTest');
    expect($client->isAuthenticated())->toBeTrue();
    expect($client->read())
        ->toContain('Hello tcp://' . $this->host)
    ;
    expect($client->isConnected())->toBeTrue('phpseclib ssh2 client connected successfully');

    $client->disconnect();
});