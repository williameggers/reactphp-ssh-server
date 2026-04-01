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
    $this->port = random_int(49152, 65535);
    $this->host = '127.0.0.1';
    $this->serverScript = sys_get_temp_dir() . '/reactphp_ssh_channel_lifecycle_' . uniqid() . '.php';
});

afterEach(function (): void {
    if (file_exists($this->serverScript)) {
        unlink($this->serverScript);
    }

    if (isset($this->pipes)) {
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
    }

    if (isset($this->process) && is_resource($this->process)) {
        $status = proc_get_status($this->process);
        if (true == $status['running']) {
            $ppid = $status['pid'];
            $pids = preg_split('/\s+/', shell_exec('ps -o pid --no-heading --ppid ' . $ppid) ?? '');
            foreach ($pids as $pid) {
                if (is_numeric($pid)) {
                    posix_kill((int) $pid, 9);
                }
            }

            proc_close($this->process);
        }
    }
});

test('channel end closes only the current channel and keeps the SSH connection usable', function (): void {
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
\$server->info('Listening on {$this->host}:{$this->port}');

\$server->on('connection', function (Connection \$connection) {
    \$connection->on('channel.open', function (Channel \$channel) {
        \$channel->on('shell-request', function (Deferred \$started) use (\$channel): void {
            \$started->resolve(true);
            \$channel->end("shell completed\r\n");
        });
    });
});
PHP
    );

    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $client->setTimeout(1);

    expect($client->login('test', 'test'))->toBeTrue();
    expect($client->read())->toBe("shell completed\r\n");
    expect($client->isConnected())->toBeTrue();

    $client->disconnect();
});

test('channel close closes only the current channel and leaves the SSH connection connected', function (): void {
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
\$server->info('Listening on {$this->host}:{$this->port}');

\$server->on('connection', function (Connection \$connection) {
    \$connection->on('channel.open', function (Channel \$channel) {
        \$channel->on('shell-request', function (Deferred \$started) use (\$channel): void {
            \$channel->write("closing shell\r\n");
            \$started->resolve(true);
            \$channel->close();
        });
    });
});
PHP
    );

    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $client->setTimeout(1);

    expect($client->login('test', 'test'))->toBeTrue();
    expect($client->read())->toBe("closing shell\r\n");
    expect($client->isConnected())->toBeTrue();

    $client->disconnect();
});
