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

use function React\Promise\Stream\buffer;

use React\Stream\ReadableResourceStream;
use React\Stream\WritableResourceStream;

/**
 * Manages the server's host key. If this key changes, you'll see SSH connection errors due to 'known_hosts'.
 */
final class ServerHostKey implements EventEmitterInterface
{
    use EventEmitterTrait;

    private string $privateKey;
    private string $publicKey;

    public function __construct(
        private string $hostKeyAlgorithm = 'ed25519',
        private ?string $name = 'ssh',
        private ?string $baseDir = null
    ) {
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

        $privateKeyPath = $baseDir . '/ssh_host_' . $this->hostKeyAlgorithm . '_key';
        $publicKeyPath = $baseDir . '/ssh_host_' . $this->hostKeyAlgorithm . '_key.pub';

        if (file_exists($privateKeyPath) && file_exists($publicKeyPath)) {
            $privateKeyResource = fopen($privateKeyPath, 'r') ?: throw new \RuntimeException("Failed to open {$privateKeyPath}");
            buffer(new ReadableResourceStream($privateKeyResource))
                ->then(function (mixed $contents) use ($publicKeyPath): void {
                    $this->privateKey = $contents;

                    $publicKeyResource = fopen($publicKeyPath, 'r') ?: throw new \RuntimeException("Failed to open {$publicKeyPath}");
                    buffer(new ReadableResourceStream($publicKeyResource))
                        ->then(function (mixed $contents): void {
                            $this->publicKey = $contents;
                        })
                    ;
                })
            ;
        } else {
            // Generate new key pair
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

                    // Extract private key (PEM format)
                    openssl_pkey_export($res, $privateKeyPem);

                    if (! is_string($privateKeyPem)) {
                        throw new \UnexpectedValueException('RSA private key has unexpected format');
                    }

                    // Extract public key (OpenSSH-compatible format requires manual assembly)
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

            // Save key pair
            $wrotePrivateKey = $this->writeFileStream(
                fopen($privateKeyPath, 'w') ?: throw new \RuntimeException('Failure opening ' . $privateKeyPath . ' for writing'),
                $this->privateKey
            );
            $wrotePublicKey = $this->writeFileStream(
                fopen($publicKeyPath, 'w') ?: throw new \RuntimeException('Failure opening ' . $publicKeyPath . ' for writing'),
                $this->publicKey
            );
            chmod($privateKeyPath, 0600);
            chmod($publicKeyPath, 0644);

            if (false === $wrotePrivateKey || false === $wrotePublicKey) {
                throw new \RuntimeException('Failed to write server\'s SSH host keypair in ' . $baseDir);
            }
        }
    }

    public function getHostKeyAlgorithm(): string
    {
        return $this->hostKeyAlgorithm;
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getOpensslPrivateKey(): \OpenSSLAsymmetricKey
    {
        return openssl_get_privatekey($this->privateKey) ?: throw new \RuntimeException('Failure reading private key');
    }

    public function getOpensslPublicKey(): \OpenSSLAsymmetricKey
    {
        return openssl_get_publickey($this->publicKey) ?: throw new \RuntimeException('Failure reading public key');
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
     * Write file stream.
     *
     * @param resource $stream
     * @param mixed    $data
     */
    private function writeFileStream($stream, mixed $data): bool // @pest-ignore-type
    {
        $writableStream = new WritableResourceStream($stream);
        $result = $writableStream->write($data);
        $writableStream->end();

        return $result;
    }

    // Build OpenSSH RSA public key (type + exponent + modulus)
    private function sshEncodeBuffer(string $data): string
    {
        return pack('N', strlen($data)) . $data;
    }
}
