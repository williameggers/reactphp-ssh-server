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

namespace WilliamEggers\React\SSH;

use Evenement\EventEmitterInterface;
use Evenement\EventEmitterTrait;
use React\EventLoop\ExtUvLoop;
use React\EventLoop\Loop;
use React\EventLoop\LoopInterface;

use function React\Promise\Stream\buffer;

use React\Stream\ReadableResourceStream;

/**
 * Manages the server's host key. If this key changes, you'll see SSH connection errors due to 'known_hosts'.
 */
final class ServerHostKey implements EventEmitterInterface
{
    use EventEmitterTrait;

    private string $privateKey;
    private string $publicKey;
    private bool $ready = false;
    private ?\Throwable $loadError = null;

    public function __construct(
        private string $hostKeyAlgorithm = 'ed25519',
        private ?string $name = 'ssh',
        private ?string $baseDir = null,
        private ?LoopInterface $loop = null
    ) {
        [$baseDir, $privateKeyPath, $publicKeyPath] = $this->initializePaths();

        if ($this->keyFilesExist($privateKeyPath, $publicKeyPath)) {
            $this->loadExistingKeys($privateKeyPath, $publicKeyPath);

            return;
        }

        $this->generateAndPersistKeys($privateKeyPath, $publicKeyPath, $baseDir);
    }

    public function getHostKeyAlgorithm(): string
    {
        return $this->hostKeyAlgorithm;
    }

    public function getPrivateKey(): string
    {
        $this->assertReady();

        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        $this->assertReady();

        return $this->publicKey;
    }

    public function isReady(): bool
    {
        return $this->ready;
    }

    public function getOpensslPrivateKey(): \OpenSSLAsymmetricKey
    {
        $this->assertReady();

        return openssl_get_privatekey($this->privateKey) ?: throw new \RuntimeException('Failure reading private key');
    }

    public function getOpensslPublicKey(): \OpenSSLAsymmetricKey
    {
        $this->assertReady();

        return openssl_get_publickey($this->publicKey) ?: throw new \RuntimeException('Failure reading public key');
    }

    public function getLoadError(): ?\Throwable
    {
        return $this->loadError;
    }

    private function getHomeDir(): string
    {
        $home = getenv('HOME') ?: '';
        if (empty($home) && function_exists('posix_getpwuid')) {
            $info = posix_getpwuid(posix_getuid()) ?: throw new \RuntimeException('Could not retrieve user info');
            $home = $info['dir'];
        }

        return $home;
    }

    /**
     * @return array{0: string, 1: string, 2: string}
     */
    private function initializePaths(): array
    {
        // We add the name so we can have multiple servers on the same machine
        $baseDir = $this->baseDir ?? $this->getHomeDir() . '/.reactphp-' . $this->name . '/';
        if (! is_dir($baseDir)) {
            $created = mkdir($baseDir, 0700, true);
            if (! $created) {
                throw new \RuntimeException('Failed to find or create baseDir: ' . $baseDir);
            }
        }

        if (empty($baseDir)) {
            throw new \RuntimeException('No baseDir set to store server\'s SSH host keypair');
        }

        return [
            $baseDir,
            $baseDir . '/ssh_host_' . $this->hostKeyAlgorithm . '_key',
            $baseDir . '/ssh_host_' . $this->hostKeyAlgorithm . '_key.pub',
        ];
    }

    private function keyFilesExist(string $privateKeyPath, string $publicKeyPath): bool
    {
        return file_exists($privateKeyPath) && file_exists($publicKeyPath);
    }

    private function loadExistingKeys(string $privateKeyPath, string $publicKeyPath): void
    {
        if ($this->shouldUseBlockingFileIo()) {
            $this->loadKeysUsingBlockingIo($privateKeyPath, $publicKeyPath);

            return;
        }

        $this->loadKeysUsingStreams($privateKeyPath, $publicKeyPath);
    }

    private function generateAndPersistKeys(string $privateKeyPath, string $publicKeyPath, string $baseDir): void
    {
        $this->generateKeys();
        $this->writeKeysUsingBlockingIo($privateKeyPath, $publicKeyPath, $baseDir);
    }

    private function generateKeys(): void
    {
        switch ($this->hostKeyAlgorithm) {
            case 'ed25519':
                $keyPair = sodium_crypto_sign_keypair();
                $this->privateKey = sodium_crypto_sign_secretkey($keyPair);
                $this->publicKey = sodium_crypto_sign_publickey($keyPair);

                break;

            case 'rsa':
                $config = [
                    'private_key_bits' => 2048,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA,
                ];

                $res = openssl_pkey_new($config) ?: throw new \RuntimeException('Failure generating RSA private key');

                openssl_pkey_export($res, $privateKeyPem);

                if (! is_string($privateKeyPem)) {
                    throw new \UnexpectedValueException('RSA private key has unexpected format');
                }

                $keyDetails = openssl_pkey_get_details($res) ?: throw new \RuntimeException('Failure extracting RSA public key');
                $publicKeyPem = $keyDetails['key'];
                if (! is_string($publicKeyPem)) {
                    throw new \RuntimeException('Failure extracting RSA public key');
                }

                $this->privateKey = $privateKeyPem;
                $this->publicKey = $publicKeyPem;

                break;

            default:
                throw new \RuntimeException('Unsupported host key algorithm: ' . $this->hostKeyAlgorithm);
        }
    }

    private function loadKeysUsingStreams(string $privateKeyPath, string $publicKeyPath): void
    {
        try {
            $privateKeyResource = fopen($privateKeyPath, 'r') ?: throw new \RuntimeException("Failed to open {$privateKeyPath}");
            buffer(new ReadableResourceStream($privateKeyResource, $this->getLoop()))
                ->then(function (mixed $privateContents) use ($publicKeyPath): void {
                    if ('' === $privateContents) {
                        throw new \UnexpectedValueException('Invalid server private key');
                    }

                    $this->privateKey = $privateContents;

                    $publicKeyResource = fopen($publicKeyPath, 'r') ?: throw new \RuntimeException("Failed to open {$publicKeyPath}");
                    buffer(new ReadableResourceStream($publicKeyResource, $this->getLoop()))
                        ->then(function (mixed $publicContents): void {
                            if ('' === $publicContents) {
                                throw new \UnexpectedValueException('Invalid server public key');
                            }

                            $this->publicKey = $publicContents;
                            $this->markReady();
                        }, function (\Throwable $throwable): void {
                            $this->markError($throwable);
                        })
                    ;
                }, function (\Throwable $throwable): void {
                    $this->markError($throwable);
                })
            ;
        } catch (\Throwable $throwable) {
            $this->markError($throwable);
        }
    }

    private function loadKeysUsingBlockingIo(string $privateKeyPath, string $publicKeyPath): void
    {
        $privateKey = file_get_contents($privateKeyPath);
        $publicKey = file_get_contents($publicKeyPath);

        if (! is_string($privateKey) || '' === $privateKey) {
            throw new \RuntimeException("Failed to open {$privateKeyPath}");
        }

        if (! is_string($publicKey) || '' === $publicKey) {
            throw new \RuntimeException("Failed to open {$publicKeyPath}");
        }

        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->markReady();
    }

    private function writeKeysUsingBlockingIo(string $privateKeyPath, string $publicKeyPath, string $baseDir): void
    {
        $wrotePrivateKey = file_put_contents($privateKeyPath, $this->privateKey);
        $wrotePublicKey = file_put_contents($publicKeyPath, $this->publicKey);

        chmod($privateKeyPath, 0600);
        chmod($publicKeyPath, 0644);

        if (false === $wrotePrivateKey || false === $wrotePublicKey) {
            throw new \RuntimeException('Failed to write server\'s SSH host keypair in ' . $baseDir);
        }

        $this->markReady();
    }

    private function getLoop(): LoopInterface
    {
        return $this->loop ?? Loop::get();
    }

    private function shouldUseBlockingFileIo(): bool
    {
        // libuv-backed loops do not support polling regular files as streams.
        return $this->getLoop() instanceof ExtUvLoop;
    }

    private function markReady(): void
    {
        $this->ready = true;
        $this->emit('ready');
    }

    private function markError(\Throwable $throwable): void
    {
        $this->loadError = $throwable;
        $this->emit('error', [$throwable]);
    }

    private function assertReady(): void
    {
        if ($this->ready) {
            return;
        }

        if ($this->loadError instanceof \Throwable) {
            throw new \RuntimeException('Server host key failed to initialize', 0, $this->loadError);
        }

        throw new \RuntimeException('Server host key is not ready');
    }

    // Build OpenSSH RSA public key (type + exponent + modulus)
    private function sshEncodeBuffer(string $data): string
    {
        return pack('N', strlen($data)) . $data;
    }
}
