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

namespace WilliamEggers\React\SSH\Crypto;

use FFI\CData;

/**
 * ML-KEM-768 encapsulation backend backed by OpenSSL's libcrypto over FFI.
 *
 * ML-KEM-768 is the key encapsulation mechanism standardised in FIPS 203, which OpenSSL
 * exposes as the "ML-KEM-768" algorithm from version 3.5 onwards. PHP ships no ML-KEM
 * binding, so the server's one-sided half of the hybrid key exchange (encapsulating a
 * shared secret to the client's public key) is done by calling the EVP interface directly.
 *
 * Support is entirely optional and this class must never be the reason a connection fails:
 * when ext-ffi is unavailable, libcrypto cannot be loaded, or the loaded libcrypto predates
 * ML-KEM, isAvailable() reports false and the server simply does not advertise the hybrid
 * key exchange method.
 */
final class MlKem768OpenSsl
{
    /**
     * Byte length of an ML-KEM-768 public key (the encapsulation key the client sends).
     */
    public const PUBLIC_KEY_BYTES = 1184;

    /**
     * Byte length of an ML-KEM-768 ciphertext (the encapsulated key the server returns).
     */
    public const CIPHERTEXT_BYTES = 1088;

    /**
     * Byte length of the shared secret produced by encapsulation.
     */
    public const SHARED_SECRET_BYTES = 32;

    private const ALGORITHM = 'ML-KEM-768';

    /**
     * Memoised availability probe so the FFI handshake runs at most once per process.
     */
    private static ?bool $available = null;

    private \FFI $ffi;

    private function __construct()
    {
        if (! extension_loaded('ffi')) {
            throw new \RuntimeException('FFI extension not loaded.');
        }

        $this->ffi = \FFI::cdef('
            typedef struct evp_pkey_st EVP_PKEY;
            typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
            typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

            EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name, const char *propquery);
            EVP_PKEY *EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx, const char *keytype, const char *propq, const unsigned char *key, size_t keylen);
            EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey, const char *propquery);

            int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const void *params);
            int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *wrappedkey, size_t *wrappedkeylen, unsigned char *genkey, size_t *genkeylen);

            void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
            void EVP_PKEY_free(EVP_PKEY *pkey);

            unsigned long ERR_get_error(void);
            char *ERR_error_string(unsigned long e, char *buf);
        ', $this->libcrypto());
    }

    /**
     * Reports whether ML-KEM-768 encapsulation can actually be performed here.
     *
     * Never throws: a missing FFI extension, an unloadable libcrypto, or an OpenSSL
     * without ML-KEM support all result in false.
     */
    public static function isAvailable(): bool
    {
        if (null !== self::$available) {
            return self::$available;
        }

        try {
            self::$available = (new self())->supportsAlgorithm();
        } catch (\Throwable) {
            self::$available = false;
        }

        return self::$available;
    }

    /**
     * Creates a backend, failing loudly if this host cannot provide ML-KEM-768.
     *
     * Callers that negotiated the hybrid algorithm should treat a failure here as a key
     * exchange failure rather than silently downgrading to a classical algorithm.
     */
    public static function create(): self
    {
        $backend = new self();
        if (! $backend->supportsAlgorithm()) {
            throw new \RuntimeException('OpenSSL does not provide ML-KEM-768.');
        }

        return $backend;
    }

    /**
     * Encapsulates a fresh shared secret to the client's ML-KEM-768 public key.
     *
     * Encapsulation is the sender-side half of a key encapsulation mechanism: it needs no
     * secret key of our own, only the recipient's public key, which is exactly what the
     * server needs during a hybrid key exchange.
     *
     * @param string $publicKey the raw, unpacked 1184-byte client encapsulation key
     *
     * @return array{ciphertext: string, sharedSecret: string} the ciphertext to send back
     *                                                         and the shared secret to mix into K
     *
     * @throws \RuntimeException if the key length is wrong or libcrypto rejects the operation
     */
    public function encapsulate(string $publicKey): array
    {
        if (self::PUBLIC_KEY_BYTES !== strlen($publicKey)) {
            throw new \RuntimeException('Invalid ML-KEM-768 public key length.');
        }

        $publicKeyBuffer = $this->allocate('unsigned char[' . self::PUBLIC_KEY_BYTES . ']');
        \FFI::memcpy($publicKeyBuffer, $publicKey, self::PUBLIC_KEY_BYTES);

        $publicKeyHandle = $this->ffi->EVP_PKEY_new_raw_public_key_ex(
            null,
            self::ALGORITHM,
            null,
            $publicKeyBuffer,
            self::PUBLIC_KEY_BYTES,
        );

        if (null === $publicKeyHandle) {
            throw new \RuntimeException('Could not import ML-KEM-768 public key: ' . $this->lastError());
        }

        $context = null;

        try {
            $context = $this->ffi->EVP_PKEY_CTX_new_from_pkey(null, $publicKeyHandle, null);
            if (null === $context) {
                throw new \RuntimeException('Could not create ML-KEM-768 context: ' . $this->lastError());
            }

            if (1 !== $this->ffi->EVP_PKEY_encapsulate_init($context, null)) {
                throw new \RuntimeException('Could not initialize ML-KEM-768 encapsulation: ' . $this->lastError());
            }

            // Ask libcrypto for the output sizes before allocating, so a libcrypto that
            // reports different dimensions is rejected rather than overflowing our buffers.
            $ciphertextLength = $this->allocate('size_t[1]');
            $sharedSecretLength = $this->allocate('size_t[1]');
            if (1 !== $this->ffi->EVP_PKEY_encapsulate($context, null, $ciphertextLength, null, $sharedSecretLength)) {
                throw new \RuntimeException('Could not size ML-KEM-768 encapsulation output: ' . $this->lastError());
            }

            if (self::CIPHERTEXT_BYTES !== $ciphertextLength[0] || self::SHARED_SECRET_BYTES !== $sharedSecretLength[0]) {
                throw new \RuntimeException('Unexpected ML-KEM-768 encapsulation output length.');
            }

            $ciphertext = $this->allocate('unsigned char[' . self::CIPHERTEXT_BYTES . ']');
            $sharedSecret = $this->allocate('unsigned char[' . self::SHARED_SECRET_BYTES . ']');

            if (1 !== $this->ffi->EVP_PKEY_encapsulate($context, $ciphertext, $ciphertextLength, $sharedSecret, $sharedSecretLength)) {
                throw new \RuntimeException('Could not encapsulate ML-KEM-768 shared secret: ' . $this->lastError());
            }

            return [
                'ciphertext' => \FFI::string($ciphertext, self::CIPHERTEXT_BYTES),
                'sharedSecret' => \FFI::string($sharedSecret, self::SHARED_SECRET_BYTES),
            ];
        } finally {
            // EVP objects are reference-counted C allocations, so they must be released on
            // every path including the exceptions thrown above.
            if (null !== $context) {
                $this->ffi->EVP_PKEY_CTX_free($context);
            }

            $this->ffi->EVP_PKEY_free($publicKeyHandle);
        }
    }

    /**
     * Checks whether the loaded libcrypto implements the ML-KEM-768 algorithm name.
     *
     * A context can be created for any algorithm the provider database knows about, which
     * makes this the cheapest reliable capability probe without touching key material.
     */
    private function supportsAlgorithm(): bool
    {
        $context = $this->ffi->EVP_PKEY_CTX_new_from_name(null, self::ALGORITHM, null);
        if (null === $context) {
            return false;
        }

        $this->ffi->EVP_PKEY_CTX_free($context);

        return true;
    }

    /**
     * Renders the most recent OpenSSL error for inclusion in an exception message.
     */
    private function lastError(): string
    {
        $error = $this->ffi->ERR_get_error();
        if (0 === $error) {
            return 'no OpenSSL error available';
        }

        // ERR_error_string hands back a pointer into OpenSSL's own buffer, so it has to be
        // copied out of C memory before it can be used as a PHP string.
        $message = $this->ffi->ERR_error_string($error, null);
        if (! $message instanceof CData) {
            return 'no OpenSSL error string available';
        }

        return \FFI::string($message);
    }

    /**
     * Allocates a raw buffer in the FFI scope.
     *
     * @throws \RuntimeException if libcrypto cannot provide the buffer
     */
    private function allocate(string $cType): CData
    {
        $buffer = $this->ffi->new($cType);
        if (! $buffer instanceof CData) {
            throw new \RuntimeException('Could not allocate FFI buffer: ' . $cType);
        }

        return $buffer;
    }

    /**
     * Resolves the libcrypto shared object to bind against.
     *
     * PHP's openssl extension may be compiled against a different libcrypto than the one
     * FFI would pick up by default, so REACT_SSH_LIBCRYPTO lets an operator point at the
     * exact shared object that provides ML-KEM-768.
     */
    private function libcrypto(): string
    {
        $configured = getenv('REACT_SSH_LIBCRYPTO');
        if (is_string($configured) && '' !== $configured) {
            return $configured;
        }

        $candidates = PHP_OS === 'Darwin'
            ? [
                '/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib',
                '/usr/local/opt/openssl@3/lib/libcrypto.dylib',
                'libcrypto.dylib',
            ]
            : [
                'libcrypto.so.3',
                'libcrypto.so',
            ];

        foreach ($candidates as $candidate) {
            try {
                // A throwaway cdef confirms the library exists and is loadable before we
                // commit to it as the backend for the real declarations.
                \FFI::cdef('unsigned long OpenSSL_version_num(void);', $candidate);

                return $candidate;
            } catch (\Throwable) {
                continue;
            }
        }

        throw new \RuntimeException('Could not load libcrypto.');
    }
}
