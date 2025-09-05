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

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Net\SSH2;

beforeEach(function () {
    // Use a random available port for testing
    $this->port = rand(49152, 65535);
    $this->host = '127.0.0.1';
    $this->rsaTestKeys = generateTestKeyPair('rsa');
    $this->ed25519TestKeys = generateTestKeyPair('ed25519');
    $this->extraEd25519TestKeys = generateTestKeyPair('ed25519');

    // TODO: Refactor so we can test with a basic Server class instance
    $this->serverScript = sys_get_temp_dir() . '/reactphp_ssh_auth_test_server_' . uniqid() . '.php';
    $autoloadPath = realpath(__DIR__ . '/../../vendor/autoload.php');
    file_put_contents(
        $this->serverScript,
        <<<PHP
<?php
require '{$autoloadPath}';
use phpseclib3\\Crypt\\PublicKeyLoader;
use React\\Promise\\Deferred;
use WilliamEggers\\React\\SSH\\Channel;
use WilliamEggers\\React\\SSH\\Connection;
use WilliamEggers\\React\\SSH\\Loggers\\ConsoleLogger;
use WilliamEggers\\React\\SSH\\Server;

\$authorizedPublicKeys = [
    'test' => [
        '{$this->ed25519TestKeys['public']}',
    ],
    'test2' => [
        '{$this->rsaTestKeys['public']}',
    ]
];

\$server = new Server('tcp://{$this->host}:{$this->port}');
\$server->setLogger(new ConsoleLogger());
\$server->setBanner('PEST AuthenticationTest');
\$server->enableAuthentication();
\$server->info('Listening on {$this->host}:{$this->port}');

\$server->on('connection', function (Connection \$connection) use (\$authorizedPublicKeys) {
    \$connection->info('Connection accepted from ' . \$connection->getRemoteAddress());
    \$connection->on('authenticate', function (string \$username, string \$method, array \$credentials, Deferred \$authenticated) use (\$authorizedPublicKeys) {
        \$isAuthenticated = false;

        switch (\$method) {
            case 'password':
                \$password = \$credentials[0] ?? null;

                if (
                    'test' === \$username && 'abc123' === \$password
                ) {
                    \$isAuthenticated = true;
                }

                break;

            case 'publickey':
                \$publicKeyString = \$credentials[0] ?? null;

                try {
                    /**
                     * Create a public key object from the public key string, then extract its fingerprint.
                     *
                     * @var string \$clientFingerprint
                     */
                    \$publicKeyFingerprint = PublicKeyLoader::loadPublicKey(\$publicKeyString)->getFingerprint('sha256');

                    /**
                     * Precompute fingerprints for each trusted key for comparison purposes.
                     *
                     * @var array<string> \$authorizedFingerprints
                     */
                    \$authorizedFingerprints = array_map(
                        fn (\$keyString) => PublicKeyLoader::loadPublicKey(\$keyString)->getFingerprint('sha256'),
                        \$authorizedPublicKeys[\$username] ?? []
                    );

                    foreach (\$authorizedFingerprints ?? [] as \$authorizedFingerprint) {
                        if (hash_equals(\$authorizedFingerprint, \$publicKeyFingerprint)) {
                            \$isAuthenticated = true;

                            break;
                        }
                    }
                } catch (Throwable \$e) {
                    // Invalid key format — log or ignore as needed
                }

                break;
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

test('connection using phpseclib ssh client with private ed25519 key', function () {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $privateKey = PublicKeyLoader::load($this->ed25519TestKeys['private']);
    $this->assertInstanceOf(PrivateKey::class, $privateKey);
    $client->setTimeout(1);
    expect($client->login('test', $privateKey))->toBeTrue();
    expect($client->isAuthenticated())->toBeTrue();
    expect($client->getBannerMessage())->toBe('PEST AuthenticationTest');

    $client->disconnect();
});

test('connection using phpseclib ssh client with incorrect private key', function () {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $privateKey = PublicKeyLoader::load($this->rsaTestKeys['private']);
    $this->assertInstanceOf(PrivateKey::class, $privateKey);
    $client->setTimeout(1);
    expect($client->login('test', $privateKey))->toBeFalse();
    expect($client->isAuthenticated())->toBeFalse();
    expect($client->getBannerMessage())->toBe('PEST AuthenticationTest');

    $client->disconnect();
});

test('connection using phpseclib ssh client with private rsa key', function () {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $privateKey = PublicKeyLoader::load($this->rsaTestKeys['private']);
    $this->assertInstanceOf(PrivateKey::class, $privateKey);
    $client->setTimeout(1);
    expect($client->login('test2', $privateKey))->toBeTrue();
    expect($client->isAuthenticated())->toBeTrue();
    expect($client->getBannerMessage())->toBe('PEST AuthenticationTest');

    $client->disconnect();
});

test('connection using phpseclib ssh client with non-authorized private ed25519 key', function () {
    // Arrange
    ['process' => $this->process, 'pid' => $this->pid, 'pipes' => $this->pipes] = start_server_and_wait_for_listening($this->serverScript, $this->host, $this->port);

    $client = new SSH2($this->host, $this->port);
    $privateKey = PublicKeyLoader::load($this->extraEd25519TestKeys['private']);
    $this->assertInstanceOf(PrivateKey::class, $privateKey);
    $client->setTimeout(1);
    expect($client->login('test', $privateKey))->toBeFalse();
    expect($client->isAuthenticated())->toBeFalse();
    expect($client->getBannerMessage())->toBe('PEST AuthenticationTest');

    $client->disconnect();
});