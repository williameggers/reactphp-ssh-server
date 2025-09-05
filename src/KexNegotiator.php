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

use WilliamEggers\React\SSH\Enums\MessageType;

final class KexNegotiator
{
    public ?string $clientKexInit = null;

    public ?string $serverKexInit = null;

    /**
     * Negotiated SSH algorithms determined from client and server preferences.
     *
     * @var ?array{kex: string, hostkey: string, encryption_ctos: string, encryption_stoc: string, mac_ctos: string, mac_stoc: string, compression_ctos: string, compression_stoc: string}
     */
    private ?array $negotiatedAlgorithms = null;

    private array $acceptedUserKeyAlgorithms = [
        'ssh-ed25519',
        'rsa-sha2-256',
        'rsa-sha2-512',
    ];

    private array $kexAlgorithms = [
        'curve25519-sha256',                 // Most modern and recommended
        'curve25519-sha256@libssh.org',      // Same as above but with older OpenSSH compatibility tag
        'diffie-hellman-group14-sha256',     // Legacy-safe fallback with stronger hash
        // 'ecdh-sha2-nistp256',             // Widely supported backup; not implemented yet
    ];

    private array $serverHostKeyAlgorithms = [
        'ssh-ed25519',                       // Modern, secure, and efficient
        'rsa-sha2-256',                      // RSA using SHA-256; widely supported and more secure than legacy ssh-rsa
        'rsa-sha2-512',                      // RSA with stronger SHA-512 hashing; included for compatibility and future-proofing
        // 'ssh-rsa',                        // Deprecated and insecure; removed due to SHA-1 vulnerabilities
    ];

    private array $encryptionAlgorithms = [
        // 'chacha20-poly1305@openssh.com',  // Modern, high-performance cipher with built-in authentication; not implemented yet
        'aes256-gcm@openssh.com',            // Strong AES cipher with 256-bit key in GCM mode (authenticated encryption)
        'aes128-gcm@openssh.com',            // AES with 128-bit key in GCM mode (authenticated encryption, faster than 256-bit)
        'aes256-ctr',                        // AES-256 in CTR mode; requires separate MAC; widely supported
        'aes192-ctr',                        // AES-192 in CTR mode; requires separate MAC; widely supported
        'aes128-ctr',                        // AES-128 in CTR mode; requires separate MAC; widely supported
    ];

    private array $macAlgorithms = [
        // 'hmac-sha2-512-etm@openssh.com',  // Encrypt-then-MAC with SHA-512; modern and secure; not implemented yet
        // 'hmac-sha2-256-etm@openssh.com',  // Encrypt-then-MAC with SHA-256; modern and widely supported; not implemented yet
        'hmac-sha2-512',                     // Standard MAC using SHA-512; strong but slightly less preferred than ETM
        'hmac-sha2-256',                     // Standard MAC using SHA-256; good compatibility and security
        'hmac-sha1',                         // Legacy MAC for compatibility with older clients; SHA-1 is considered weak
    ];

    private array $compressionAlgorithms = [
        'none',
    ];

    public function __construct(
        public readonly string $clientVersion,
        public readonly string $serverVersion,
        public ?Packet $packet = null
    ) {
        if (! is_null($packet)) {
            $this->setClientKexInit($packet);
        }
    }

    /**
     * Returns the list of public key algorithms accepted for user authentication.
     *
     * These are the algorithms the server will accept when the client attempts
     * to authenticate using the 'publickey' method.
     *
     * @return array List of accepted user key algorithm names (e.g., ['ssh-ed25519', 'rsa-sha2-256']).
     */
    public function getAcceptedUserKeyAlgorithms(): array
    {
        return $this->acceptedUserKeyAlgorithms;
    }

    public function setClientKexInit(Packet $packet): void
    {
        $this->packet = $packet;
        if (! is_null($this->packet)) {
            $this->clientKexInit = chr($this->packet->type->value) . $this->packet->message;
        }
    }

    public function response(): string
    {
        // Build our algorithms lists
        $kexAlgorithms = implode(',', $this->kexAlgorithms);
        $serverHostKeyAlgorithms = implode(',', $this->serverHostKeyAlgorithms);
        $encryptionAlgorithmsCS = implode(',', $this->encryptionAlgorithms);
        $encryptionAlgorithmsSC = implode(',', $this->encryptionAlgorithms);
        $macAlgorithmsCS = implode(',', $this->macAlgorithms);
        $macAlgorithmsSC = implode(',', $this->macAlgorithms);
        $compressionAlgorithmsCS = implode(',', $this->compressionAlgorithms);
        $compressionAlgorithmsSC = implode(',', $this->compressionAlgorithms);
        $languagesCS = '';
        $languagesSC = '';

        // Construct KEXINIT payload
        $kexinitPayload
            = chr(MessageType::KEXINIT->value)
            . random_bytes(16) // Cookie
            . $this->packString($kexAlgorithms)
            . $this->packString($serverHostKeyAlgorithms)
            . $this->packString($encryptionAlgorithmsCS)
            . $this->packString($encryptionAlgorithmsSC)
            . $this->packString($macAlgorithmsCS)
            . $this->packString($macAlgorithmsSC)
            . $this->packString($compressionAlgorithmsCS)
            . $this->packString($compressionAlgorithmsSC)
            . $this->packString($languagesCS)
            . $this->packString($languagesSC)
            . "\0" // first_kex_packet_follows
            . pack('N', 0); // reserved

        $this->serverKexInit = $kexinitPayload;

        return $kexinitPayload;
    }

    /**
     * Negotiates SSH algorithms between client and server preferences.
     *
     * Parses $this->clientKexInit and selects agreed algorithms according to
     * the SSH protocol (RFC 4253 §7.1), respecting the client's order of preference.
     *
     * @return array{
     *     kex: string,
     *     hostkey: string,
     *     encryption_ctos: string,
     *     encryption_stoc: string,
     *     mac_ctos: string,
     *     mac_stoc: string,
     *     compression_ctos: string,
     *     compression_stoc: string
     * }
     *
     * @throws \RuntimeException if no common algorithm can be agreed upon
     */
    public function negotiateAlgorithms(): array
    {
        $clientPacket = substr((string) $this->clientKexInit, 1); // skip message type byte (SSH_MSG_KEXINIT = 20)
        $offset = 16; // skip 16-byte cookie

        // SSH KEXINIT contains 10 name-list fields; we'll extract them in order:
        $fields = [];
        for ($i = 0; $i < 10; ++$i) {
            $length = (unpack('N', substr($clientPacket, $offset, 4)) ?: [])[1] ?? null;
            if (is_null($length)) {
                throw new \RuntimeException('Failure unpacking KEXINIT data');
            }
            if (! is_int($length)) {
                throw new \UnexpectedValueException('Expected int-castable value at offset 1');
            }
            $offset += 4;
            $list = substr($clientPacket, $offset, $length);
            $fields[] = explode(',', $list);
            $offset += $length;
        }

        [
            $clientKexAlgs,
            $clientHostKeyAlgs,
            $clientEncCtoS,
            $clientEncStoC,
            $clientMacCtoS,
            $clientMacStoC,
            $clientCompCtoS,
            $clientCompStoC,
            $langCtoS,
            $langStoC,
        ] = $fields;

        // The server must follow the client's preference order when selecting.
        $select = function (array $clientList, array $serverList, string $label): string {
            foreach ($clientList as $alg) {
                if (in_array($alg, $serverList, true)) {
                    return $alg; // @phpstan-ignore-line
                }
            }

            throw new \RuntimeException("No common algorithm found for {$label}. Client supported values: " . implode(',', $clientList));
        };

        $this->negotiatedAlgorithms = [
            'kex' => $select($clientKexAlgs, $this->kexAlgorithms, 'kex'),
            'hostkey' => $select($clientHostKeyAlgs, $this->serverHostKeyAlgorithms, 'hostkey'),
            'encryption_ctos' => $select($clientEncCtoS, $this->encryptionAlgorithms, 'encryption_ctos'),
            'encryption_stoc' => $select($clientEncStoC, $this->encryptionAlgorithms, 'encryption_stoc'),
            'mac_ctos' => $select($clientMacCtoS, $this->macAlgorithms, 'mac_ctos'),
            'mac_stoc' => $select($clientMacStoC, $this->macAlgorithms, 'mac_stoc'),
            'compression_ctos' => $select($clientCompCtoS, $this->compressionAlgorithms, 'compression_ctos'),
            'compression_stoc' => $select($clientCompStoC, $this->compressionAlgorithms, 'compression_stoc'),
        ];

        return $this->negotiatedAlgorithms;
    }

    /**
     * Retrieves the negotiated algorithm for a given algorithm type.
     *
     * This returns the specific algorithm that was agreed upon during key exchange
     * for the given category, such as 'kex', 'encryption_ctos', 'mac_ctos', etc.
     *
     * @param string $algorithmType The type/category of algorithm (e.g., 'kex', 'encryption_ctos').
     *
     * @return null|string the negotiated algorithm name, or null if none was negotiated for this type
     */
    public function getNegotiatedAlgorithm(string $algorithmType): ?string
    {
        return $this->negotiatedAlgorithms[$algorithmType] ?? null;
    }

    /**
     * Returns all algorithms that were successfully negotiated during key exchange.
     *
     * This includes the full set of negotiated algorithms, such as key exchange (kex),
     * host key, encryption (both directions), and MAC algorithms.
     *
     * @return null|array<string, string> an associative array of negotiated algorithm types and their values,
     *                                    or null if negotiation has not yet completed
     */
    public function getNegotiatedAlgorithms(): ?array
    {
        return $this->negotiatedAlgorithms;
    }

    private function packString(string $str): string
    {
        return pack('N', strlen($str)) . $str;
    }
}
