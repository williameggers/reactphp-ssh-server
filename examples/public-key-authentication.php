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

use phpseclib3\Crypt\PublicKeyLoader;
use React\Promise\Deferred;
use WilliamEggers\React\SSH\Channel;
use WilliamEggers\React\SSH\Connection;
use WilliamEggers\React\SSH\Server;

$authorizedPublicKeys = [
    'test-user' => [
        // List of authorized public keys for this user, in standard OpenSSH format.
        // These are used to validate that the authenticated public key matches a known trusted key.
        //
        // You may store and retrieve these keys using any preferred mechanism
        // (e.g., flat files, database, configuration service, etc.).
        //
        // Key comments are optional and can help with identification.
        //
        // Example formats:
        //   ssh-rsa AAAAB3... comment
        //   ssh-ed25519 AAAAC3... comment
        //
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCXDhIbGLvBqLiVR+... authkey-rsa',
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPo5m2Az1E0PA9jn1bOLd3D... authkey-ed25519',
        // Add additional keys per user as needed.
    ],
];

$server = (new Server('127.0.0.1:22'))
    ->enableAuthentication()
;

$server->on('connection', function (Connection $connection) use ($authorizedPublicKeys) {
    $connection->on('authenticate', function (string $username, string $method, array $credentials, Deferred $authenticated) use ($authorizedPublicKeys) {
        /**
         * By this point, the supplied public key has already been verified via its signature
         * during the USERAUTH_REQUEST exchange by the server.
         *
         * Explanation from RFC 4252, Section 7:
         *
         *   "This method works by sending a signature created with a private key of the user.
         *    The server MUST check that the key is a valid authenticator for the user,
         *    and MUST check that the signature is valid."
         *
         * Therefore, this phase is solely concerned with authorization—verifying that the
         * already validated public key matches one of the authorized keys for the given user.
         */
        $isAuthenticated = false;

        if (
            'publickey' === $method && is_string($credentials[0] ?? null)
        ) {
            $publicKeyString = $credentials[0];

            try {
                /**
                 * Create a public key object from the public key string, then extract its fingerprint.
                 *
                 * @var string $publicKeyFingerprint
                 */
                $publicKeyFingerprint = PublicKeyLoader::loadPublicKey($publicKeyString)->getFingerprint('sha256');

                /**
                 * Precompute fingerprints for each trusted key for comparison purposes.
                 *
                 * @var array<string> $authorizedFingerprints
                 */
                $authorizedFingerprints = array_map(
                    fn ($keyString) => PublicKeyLoader::loadPublicKey($keyString)->getFingerprint('sha256'),
                    $authorizedPublicKeys[$username] ?? []
                );

                foreach ($authorizedFingerprints ?? [] as $authorizedFingerprint) {
                    if (hash_equals($authorizedFingerprint, $publicKeyFingerprint)) {
                        $isAuthenticated = true;

                        break;
                    }
                }
            } catch (Throwable $e) {
                // Invalid key format — log or ignore as needed
            }
        }

        $authenticated->resolve($isAuthenticated);
    });

    $connection->on('channel.open', function (Channel $channel) {
        $channel->on('shell-request', function (Deferred $started) use ($channel) {
            $channel->end('Authenticated as ' . $channel->getConnection()->getUsername() . " via public key\r\n");
            $started->resolve(true);
        });
    });
});
