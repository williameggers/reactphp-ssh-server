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

use phpseclib3\Crypt\DH;
use Psr\Log\LoggerInterface;
use WilliamEggers\React\SSH\Crypto\MlKem768OpenSsl;
use WilliamEggers\React\SSH\Enums\MessageType;
use WilliamEggers\React\SSH\Loggers\NullLogger;

final class Kex
{
    /**
     * The classical Curve25519 key exchange method.
     */
    public const KEX_CURVE25519_SHA256 = 'curve25519-sha256';

    /**
     * The post-quantum hybrid key exchange method: ML-KEM-768 combined with Curve25519.
     */
    public const KEX_MLKEM768X25519_SHA256 = 'mlkem768x25519-sha256';

    /**
     * Byte length of a Curve25519 key exchange public key.
     */
    private const CURVE25519_PUBLIC_KEY_BYTES = 32;

    private ?string $sessionId = null;
    private string $exchangeHash;
    private string $sharedSecret;

    /**
     * Whether the shared secret must be encoded as an SSH string rather than an mpint.
     *
     * Classical algorithms agree on an integer, which SSH encodes as an mpint. The hybrid
     * exchange hashes its two secrets together, producing a fixed-width opaque value that
     * is encoded as a plain string.
     */
    private bool $sharedSecretIsString = false;

    private readonly LoggerInterface $logger;

    public function __construct(
        public Packet $packet,
        public KexNegotiator $kexNegotiator,
        public ServerHostKey $serverHostKey,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Returns the exchange hash (H) generated during the key exchange process.
     *
     * This hash is computed from key exchange parameters and is used for
     * verifying host keys, generating session identifiers, and deriving keys.
     *
     * @return string the exchange hash as a binary string
     */
    public function getExchangeHash(): string
    {
        return $this->exchangeHash;
    }

    /**
     * Returns the shared secret (K) generated during the key exchange process.
     *
     * This value is the result of the Diffie-Hellman or elliptic-curve key
     * agreement algorithm and is used in conjunction with the exchange hash to
     * derive encryption and MAC keys. The hybrid mlkem768x25519-sha256 exchange
     * instead returns the hash of its ML-KEM and Curve25519 secrets.
     *
     * Callers deriving session keys should use encodedSharedSecret(), which applies the
     * encoding the negotiated algorithm requires.
     *
     * @return string the shared secret as a binary string
     */
    public function getSharedSecret(): string
    {
        return $this->sharedSecret;
    }

    /**
     * Returns the session identifier (session ID) used for the SSH connection.
     *
     * The session ID is typically the exchange hash (H) from the first key exchange
     * and remains constant for the lifetime of the connection. It is used in key
     * derivation and for verifying host keys during rekeying.
     *
     * @return null|string the session ID as a binary string, or null if not yet established
     */
    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    /**
     * Sets the session ID for the SSH connection.
     *
     * The session ID is derived from the initial key exchange (typically the first exchange hash)
     * and is used in subsequent key derivation and authentication steps. This method enforces
     * immutability—once set, the session ID cannot be changed for the duration of the connection.
     *
     * @param string $sessionId the session ID as a binary string
     *
     * @throws \RuntimeException if the session ID has already been set
     */
    public function setSessionId(string $sessionId): self
    {
        if (! is_null($this->sessionId)) {
            throw new \RuntimeException('Session Id already set');
        }

        $this->sessionId = $sessionId;

        return $this;
    }

    /**
     * Diffie Hellman key exchange response.
     */
    public function response(): string
    {
        $kexAlgorithm = $this->kexNegotiator->getNegotiatedAlgorithm('kex');

        // The hybrid post-quantum exchange has a different client payload layout and encodes
        // the shared secret differently, so it is handled on its own path.
        if (self::KEX_MLKEM768X25519_SHA256 === $kexAlgorithm) {
            return $this->mlKem768X25519Response();
        }

        // Extract client's public key (32 bytes after 4-byte length)
        $clientPublicKeyLength = (unpack('N', substr($this->packet->message, 0, 4)) ?: [])[1] ?? null;
        if (is_null($clientPublicKeyLength)) {
            throw new \RuntimeException('Failure resolving client public key length');
        }
        if (! is_int($clientPublicKeyLength) && ! is_float($clientPublicKeyLength)) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }
        $clientPublicKey = substr($this->packet->message, 4, (int) $clientPublicKeyLength);

        switch ($kexAlgorithm) {
            case 'curve25519-sha256':
            case 'curve25519-sha256@libssh.org':
                // Generate our Curve25519 keypair for key exchange
                $curveKeyPair = sodium_crypto_box_keypair();
                $curve25519Private = sodium_crypto_box_secretkey($curveKeyPair);
                $curve25519Public = sodium_crypto_box_publickey($curveKeyPair);
                $ephemeralPublic = $curve25519Public;

                break;

            case 'diffie-hellman-group14-sha256':
                $dhParameters = DH::createParameters($kexAlgorithm);
                $dhPrivate = DH::createKey($dhParameters);
                $dhPublic = $dhPrivate->getPublicKey();
                $ephemeralPublic = $dhPublic->toBigInteger()->toBytes(true);

                break;

            default:
                throw new \RuntimeException('Unhandled KEX algorithm: ' . $kexAlgorithm);
        }

        // Use the persistent host key instead of generating a new one
        $hostKeyBlob = $this->hostKeyBlob();

        // Compute shared secret
        switch ($kexAlgorithm) {
            case 'curve25519-sha256':
            case 'curve25519-sha256@libssh.org':
                if (! isset($curve25519Private)) {
                    throw new \RuntimeException('Ephemeral private uninitialized');
                }

                $this->sharedSecret = sodium_crypto_scalarmult($curve25519Private, $clientPublicKey);

                break;

            case 'diffie-hellman-group14-sha256':
                if (! isset($dhPrivate)) {
                    throw new \RuntimeException('Ephemeral private uninitialized');
                }

                $sharedSecret = DH::computeSecret($dhPrivate, $clientPublicKey);
                if (! is_string($sharedSecret)) {
                    throw new \RuntimeException('Unhandled return type for shared secret');
                }

                $this->sharedSecret = $sharedSecret;

                break;
        }

        // Create exchange hash
        $exchangeHash = hash('sha256', implode('', [
            $this->packString($this->kexNegotiator->clientVersion),
            $this->packString($this->kexNegotiator->serverVersion),
            $this->packString((string) $this->kexNegotiator->clientKexInit), // Client's KEXINIT
            $this->packString((string) $this->kexNegotiator->serverKexInit), // Our KEXINIT
            $this->packString($hostKeyBlob),                                 // Host key blob
            $this->packString($clientPublicKey),                             // Client's ephemeral public key
            $this->packString($ephemeralPublic),                             // Our ephemeral public key
            $this->packMpint($this->sharedSecret),                           // Shared secret
        ]), true);

        // Store session ID if this is first key exchange
        if (is_null($this->sessionId)) {
            $this->sessionId = $exchangeHash;
        }

        $signatureBlob = $this->signExchangeHash($exchangeHash);

        $this->logger->debug('Key exchange details:' . json_encode([
            'host_key_blob_len' => strlen($hostKeyBlob),
            'host_key_public' => $this->serverHostKey->getHostKeyAlgorithm(),
            'signature_blob_len' => strlen($signatureBlob),
            'exchange_hash' => bin2hex($exchangeHash),
        ]));

        // Construct KEX_ECDH_REPLY
        $kexReplyPayload
            = MessageType::chr(MessageType::KEXDH_REPLY)
            . $this->packString($hostKeyBlob)       // Host key blob (includes identifier)
            . $this->packString($ephemeralPublic)   // Server's ephemeral public key
            . $this->packString($signatureBlob);    // Signature blob (includes identifier)

        $this->exchangeHash = $exchangeHash;

        return $kexReplyPayload;
    }

    /**
     * Returns the shared secret (K) in the wire encoding the negotiated algorithm requires.
     *
     * Classical algorithms agree on a large integer, which SSH transmits and hashes as an
     * mpint. The hybrid mlkem768x25519-sha256 exchange hashes its two component secrets into
     * a fixed-width opaque value, which is encoded as a plain length-prefixed string instead.
     *
     * Key derivation must use this method rather than packing getSharedSecret() directly, or
     * the derived session keys will not match the client's.
     *
     * @return string the encoded shared secret
     */
    public function encodedSharedSecret(): string
    {
        return $this->sharedSecretIsString
            ? $this->packString($this->sharedSecret)
            : $this->packMpint($this->sharedSecret);
    }

    /**
     * Post-quantum hybrid key exchange response for mlkem768x25519-sha256.
     *
     * The client sends one blob containing its ML-KEM-768 encapsulation key followed by its
     * Curve25519 public key. The server encapsulates a shared secret to the ML-KEM key, runs
     * the classical Curve25519 agreement, and hashes both secrets together, so the session
     * keys stay protected even if one of the two primitives is later broken.
     *
     * @throws \UnexpectedValueException if the client payload is not exactly one hybrid blob
     * @throws \RuntimeException         if libcrypto cannot encapsulate to the client's ML-KEM key
     */
    private function mlKem768X25519Response(): string
    {
        $offset = 0;

        // The client's contribution is a single string: ML-KEM-768 public key, then Curve25519 public key.
        [$clientBlob] = $this->packet->extractString($this->packet->message, $offset);

        $expectedClientBlobLength = MlKem768OpenSsl::PUBLIC_KEY_BYTES + self::CURVE25519_PUBLIC_KEY_BYTES;
        if (strlen($clientBlob) !== $expectedClientBlobLength) {
            throw new \UnexpectedValueException(
                'Invalid mlkem768x25519-sha256 client key exchange payload: expected '
                . $expectedClientBlobLength . ' bytes, got ' . strlen($clientBlob),
            );
        }

        $clientMlKemPublicKey = substr($clientBlob, 0, MlKem768OpenSsl::PUBLIC_KEY_BYTES);
        $clientCurve25519PublicKey = substr($clientBlob, MlKem768OpenSsl::PUBLIC_KEY_BYTES, self::CURVE25519_PUBLIC_KEY_BYTES);

        $encapsulation = MlKem768OpenSsl::create()->encapsulate($clientMlKemPublicKey);

        $curveKeyPair = sodium_crypto_box_keypair();
        $curve25519Private = sodium_crypto_box_secretkey($curveKeyPair);
        $curve25519Public = sodium_crypto_box_publickey($curveKeyPair);
        $curve25519SharedSecret = sodium_crypto_scalarmult($curve25519Private, $clientCurve25519PublicKey);

        // The server's reply blob mirrors the client's: ML-KEM ciphertext, then Curve25519 public key.
        $serverBlob = $encapsulation['ciphertext'] . $curve25519Public;

        $this->sharedSecret = hash('sha256', $encapsulation['sharedSecret'] . $curve25519SharedSecret, true);
        $this->sharedSecretIsString = true;

        $hostKeyBlob = $this->hostKeyBlob();

        $exchangeHash = hash('sha256', implode('', [
            $this->packString($this->kexNegotiator->clientVersion),
            $this->packString($this->kexNegotiator->serverVersion),
            $this->packString((string) $this->kexNegotiator->clientKexInit), // Client's KEXINIT
            $this->packString((string) $this->kexNegotiator->serverKexInit), // Our KEXINIT
            $this->packString($hostKeyBlob),                                 // Host key blob
            $this->packString($clientBlob),                                  // Client's hybrid key blob
            $this->packString($serverBlob),                                  // Our hybrid key blob
            $this->packString($this->sharedSecret),                          // Shared secret, as a string
        ]), true);

        // Store session ID if this is first key exchange
        if (is_null($this->sessionId)) {
            $this->sessionId = $exchangeHash;
        }

        $signatureBlob = $this->signExchangeHash($exchangeHash);

        $this->logger->debug('Hybrid key exchange details:' . json_encode([
            'algorithm' => self::KEX_MLKEM768X25519_SHA256,
            'host_key_blob_len' => strlen($hostKeyBlob),
            'client_blob_len' => strlen($clientBlob),
            'server_blob_len' => strlen($serverBlob),
            'signature_blob_len' => strlen($signatureBlob),
            'exchange_hash' => bin2hex($exchangeHash),
        ]));

        // Construct KEX_ECDH_REPLY
        $kexReplyPayload
            = MessageType::chr(MessageType::KEXDH_REPLY)
            . $this->packString($hostKeyBlob)       // Host key blob (includes identifier)
            . $this->packString($serverBlob)        // Server's hybrid ephemeral key material
            . $this->packString($signatureBlob);    // Signature blob (includes identifier)

        $this->exchangeHash = $exchangeHash;

        return $kexReplyPayload;
    }

    /**
     * Builds the host key blob advertised in the key exchange reply.
     *
     * This is the blob the client verifies against its known_hosts entry. Its layout depends
     * on the key type: Ed25519 carries one raw public key, while RSA carries the exponent and
     * modulus as mpints.
     *
     * @return string the encoded host key blob
     *
     * @throws \RuntimeException if the host key algorithm is unsupported
     */
    private function hostKeyBlob(): string
    {
        switch ($this->serverHostKey->getHostKeyAlgorithm()) {
            case 'ed25519':
                $ed25519Public = $this->serverHostKey->getPublicKey();
                if (empty($ed25519Public)) {
                    throw new \RuntimeException('Invalid server public key');
                }

                // Format the host key blob
                return $this->packString('ssh-ed25519') . $this->packString($ed25519Public);

            case 'rsa':
                $keyDetails = openssl_pkey_get_details(
                    $this->serverHostKey->getOpensslPublicKey()
                ) ?: throw new \RuntimeException('Failure reading RSA public key');

                /**
                 * @var array $rsaPublicKey
                 */
                $rsaPublicKey = $keyDetails['rsa'];
                $n = $rsaPublicKey['n'];
                $e = $rsaPublicKey['e'];

                if (! is_string($e) || ! is_string($n)) {
                    throw new \UnexpectedValueException('RSA key components must be strings');
                }

                return $this->packString('ssh-rsa') . $this->packMpint($e) . $this->packMpint($n);

            default:
                throw new \RuntimeException('Unhandled server host key algorithm: ' . $this->serverHostKey->getHostKeyAlgorithm());
        }
    }

    /**
     * Signs a key exchange hash with the negotiated server host key.
     *
     * @param string $exchangeHash the exchange hash (H) to sign
     *
     * @return string the signature blob: the signature algorithm name followed by the raw signature
     *
     * @throws \RuntimeException if the negotiated host key algorithm is unsupported
     */
    private function signExchangeHash(string $exchangeHash): string
    {
        $serverHostKeyAlgorithm = $this->kexNegotiator->negotiateAlgorithms()['hostkey'];

        switch ($serverHostKeyAlgorithm) {
            case 'ssh-ed25519':
                $ed25519Private = $this->serverHostKey->getPrivateKey();
                if (empty($ed25519Private)) {
                    throw new \RuntimeException('Invalid server private key');
                }

                $signature = sodium_crypto_sign_detached($exchangeHash, $ed25519Private);

                return $this->packString('ssh-ed25519') . $this->packString($signature);

            case 'rsa-sha2-256':
            case 'rsa-sha2-512':
                $privateKey = $this->serverHostKey->getOpensslPrivateKey(); // An OpenSSL key resource or object
                if (! openssl_sign($exchangeHash, $signature, $privateKey, match ($serverHostKeyAlgorithm) {
                    'rsa-sha2-256' => OPENSSL_ALGO_SHA256,
                    'rsa-sha2-512' => OPENSSL_ALGO_SHA512,
                })) {
                    throw new \RuntimeException('Signature generation failed');
                }
                if (! is_string($signature)) {
                    throw new \RuntimeException('Invalid signature type');
                }

                // SSH signature format: string "rsa-sha2-256" || string <raw signature>
                return $this->packString($serverHostKeyAlgorithm) . $this->packString($signature);

            default:
                throw new \RuntimeException('Unhandled server host key algorithm: ' . $serverHostKeyAlgorithm);
        }
    }

    /**
     * Packs a string for transmission according to the SSH binary protocol format.
     * The format is: 4-byte big-endian length prefix followed by the raw string bytes.
     *
     * @param string $str the string to pack
     *
     * @return string the packed string
     */
    private function packString(string $str): string
    {
        return pack('N', strlen($str)) . $str;
    }

    /**
     * Packs a multiple-precision integer (mpint) for SSH use.
     * This format is used for transmitting big integers like public keys or DH parameters.
     *
     * Leading zero bytes are trimmed unless the most significant bit (MSB) of the first byte
     * is set, in which case a single zero byte is prepended to indicate that the integer is positive.
     *
     * The final format is: 4-byte big-endian length prefix followed by the adjusted binary integer.
     *
     * @param string $bignum binary string representing the big integer
     *
     * @return string the packed mpint value
     */
    private function packMpint(string $bignum): string
    {
        // Remove ALL leading zeros first
        $bignum = ltrim($bignum, "\0");

        // Add single zero byte only if MSB is set
        if (strlen($bignum) > 0 && (ord($bignum[0]) & 0x80)) {
            $bignum = "\0" . $bignum;
        }

        // Pack length and value
        return pack('N', strlen($bignum)) . $bignum;
    }
}
