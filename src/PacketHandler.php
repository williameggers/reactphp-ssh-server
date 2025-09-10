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

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Hash;
use React\Socket\ConnectionInterface;
use WilliamEggers\React\SSH\Concerns\WritesLogs;
use WilliamEggers\React\SSH\Enums\MessageType;

/**
 * The PacketHandler is responsible for parsing raw input data into complete SSH packets.
 * It encapsulates all encryption, decryption, and MAC validation logic for the duration
 * of the connection, allowing the Connection class to remain focused on higher-level
 * application protocol handling.
 */
final class PacketHandler
{
    use WritesLogs;

    // Whether a rekey is currently in progress for this connection
    private bool $rekeyInProgress = false;

    // Whether the connection has completed its initial key exchange
    private bool $hasCompletedInitialKeyExchange = false;

    // Whether encryption is currently active for this connection
    private bool $encryptionActive = false;

    // Sequence number for Server->Client packets
    private int $packetSeq_StoC = 0;

    // Sequence number for Client->Server packets
    private int $packetSeq_CtoS = 0;

    // Negotiated encryption method Client->Server
    private string $encryptionMethod_CtoS;

    // Initialization Vector (salt) for Client->Server encryption
    private string $encryptIV_CtoS;

    // AES-256 encryption key for Client->Server messages
    private string $encryptKey_CtoS;

    // Negotiated MAC method Client->Server
    private string $macMethod_CtoS;

    // MAC key for Client->Server messages
    private ?string $macKey_CtoS = null;

    // Negotiated encryption method Server->Client
    private string $encryptionMethod_StoC;

    // Initialization Vector (salt) for Server->Client encryption
    private string $encryptIV_StoC;

    // Encryption key for Server->Client messages
    private string $encryptKey_StoC;

    // Negotiated MAC method Server->Client
    private string $macMethod_StoC;

    // MAC key for Server->Client messages
    private ?string $macKey_StoC = null;

    // Key exchange instance
    private Kex $kex;

    // Key exchange instance (re-key)
    private ?Kex $rekeyKex = null;

    // AES instance for encryption
    private ?AES $encryptor = null;

    // AES instance for decryption
    private ?AES $decryptor = null;

    // Hash instanse StoC
    private ?Hash $hash_StoC = null;

    // Hash instanse CtoS
    private ?Hash $hash_CtoS = null;

    /**
     * @var null|array<null|string>
     */
    private ?array $pendingKeys = null;

    public function __construct(
        public ConnectionInterface $connection
    ) {
        if (! sodium_crypto_aead_aes256gcm_is_available() && ! in_array('aes-256-gcm', openssl_get_cipher_methods())) {
            throw new \RuntimeException('AES-256-GCM not available');
        }
    }

    public function setKex(Kex $kex): self
    {
        $this->kex = $kex;

        return $this;
    }

    /**
     * Check if encryption is currently active for the connection.
     *
     * Returns true once the initial key exchange has completed and
     * packets are being encrypted and authenticated.
     */
    public function isEncryptionActive(): bool
    {
        return $this->encryptionActive;
    }

    /**
     * Check if a rekey operation is currently in progress.
     *
     * During rekeying, packet processing may be temporarily affected.
     */
    public function hasRekeyInProgress(): bool
    {
        return $this->rekeyInProgress;
    }

    /**
     * Toggle the rekey-in-progress state.
     *
     * Used to mark the start or end of a rekeying phase.
     */
    public function toggleRekeyInProgress(): self
    {
        $this->rekeyInProgress = ! $this->rekeyInProgress;

        return $this;
    }

    /**
     * Check if the initial key exchange has completed.
     *
     * This determines whether the connection has fully transitioned
     * from plaintext to encrypted communication.
     */
    public function hasCompletedInitialKeyExchange(): bool
    {
        return $this->hasCompletedInitialKeyExchange;
    }

    /**
     * Sets the negotiated encryption algorithms for both directions of communication.
     *
     * This method stores the client-to-server (CtoS) and server-to-client (StoC)
     * encryption algorithms as determined during key exchange. These values are later
     * used to initialize the appropriate cipher instances.
     *
     * @param string $encryptionMethod_CtoS the encryption algorithm for incoming packets from the client
     * @param string $encryptionMethod_StoC the encryption algorithm for outgoing packets to the client
     */
    public function setEncryptionMethods(string $encryptionMethod_CtoS, string $encryptionMethod_StoC): self
    {
        $this->encryptionMethod_CtoS = $encryptionMethod_CtoS;
        $this->encryptionMethod_StoC = $encryptionMethod_StoC;

        return $this;
    }

    /**
     * Sets the negotiated MAC algorithms for both directions of communication.
     *
     * This method stores the client-to-server (CtoS) and server-to-client (StoC)
     * message authentication algorithms as determined during key exchange. These values
     * are used to validate or generate HMACs for each packet when using non-AEAD ciphers.
     *
     * @param string $macMethod_CtoS the MAC algorithm for incoming packets from the client
     * @param string $macMethod_StoC the MAC algorithm for outgoing packets to the client
     */
    public function setMacMethods(string $macMethod_CtoS, string $macMethod_StoC): self
    {
        $this->macMethod_CtoS = $macMethod_CtoS;
        $this->macMethod_StoC = $macMethod_StoC;

        return $this;
    }

    /**
     * Derives the necessary encryption, MAC, and IV keys for the connection.
     *
     * This method is called after a key exchange has completed (either initially
     * or during a rekeying procedure). It uses the shared secret and exchange
     * hash to derive keys for both directions (C-to-S and S-to-C) according to the
     * negotiated key exchange algorithm.
     *
     * If a specific Kex instance is passed in, it will be used for key derivation;
     * otherwise, the most recently negotiated Kex will be used.
     *
     * @param null|Kex $kexToUse optional key exchange context to use for derivation
     */
    public function deriveKeys(?Kex $kexToUse = null): void
    {
        // Use provided Kex or fall back to the instance property
        $kex = $kexToUse ?? $this->kex;

        // Store the rekeying Kex if needed
        if ($this->hasRekeyInProgress()) {
            $this->rekeyKex = $kex;
        }

        // Pack shared secret as MPInt (confirm no extra leading zeros)
        $K = $this->packMpint($kex->getSharedSecret());
        $H = $kex->getExchangeHash();

        $kdf_mac = static function (string $letter, int $needed_length) use ($K, $H, $kex): string {
            $output = '';
            $input = $K . $H . $letter . $kex->getSessionId();
            $output = hash('sha256', $input, true);
            while (strlen($output) < $needed_length) {
                $input = $K . $H . $output;
                $output .= hash('sha256', $input, true);
            }

            return substr($output, 0, $needed_length);
        };

        // Modified KDF to support extended hashing if needed
        $kdf = static function (string $letter, int $needed_length) use ($K, $H, $kex): string {
            $output = '';
            $prev_block = '';

            while (strlen($output) < $needed_length) {
                $input = $K . $H . ($prev_block ?: $letter) . $kex->getSessionId();
                $hash = hash('sha256', $input, true);
                $output .= $hash;
                $prev_block = $hash;
            }

            return substr($output, 0, $needed_length);
        };

        if (! $this->hasRekeyInProgress()) {
            // Initialize hash instances
            [$this->hash_StoC, $StoC_macKeyLengthInBytes] = $this->macAlgorithmToHashInstance($this->macMethod_StoC);
            [$this->hash_CtoS, $CtoS_macKeyLengthInBytes] = $this->macAlgorithmToHashInstance($this->macMethod_CtoS);
        } else {
            [, $StoC_macKeyLengthInBytes] = $this->macAlgorithmToHashInstance($this->macMethod_StoC);
            [, $CtoS_macKeyLengthInBytes] = $this->macAlgorithmToHashInstance($this->macMethod_CtoS);
        }

        switch ($this->encryptionMethod_CtoS) {
            case 'aes128-gcm@openssh.com':
                // For aes256-gcm@openssh.com:
                // - We need 16-byte keys for AES-128
                // - We need 12-byte IVs for GCM
                $encryptIV_CtoS = $kdf('A', 12);    // Only take 12 bytes for GCM IV
                $encryptKey_CtoS = $kdf('C', 16);   // 16 bytes for AES-128 key
                $macKey_CtoS = null;

                break;

            case 'aes256-gcm@openssh.com':
                // For aes256-gcm@openssh.com:
                // - We need 32-byte keys for AES-256
                // - We need 12-byte IVs for GCM
                $encryptIV_CtoS = $kdf('A', 12);    // Only take 12 bytes for GCM IV
                $encryptKey_CtoS = $kdf('C', 32);   // 32 bytes for AES-256 key
                $macKey_CtoS = null;

                break;

            case 'aes128-ctr':
            case 'aes192-ctr':
            case 'aes256-ctr':
                // For AES-CTR
                // - We need 16-byte keys for AES-128
                // - We need 24-byte keys for AES-192
                // - We need 32-byte keys for AES-256
                $encryptIV_CtoS = $kdf('A', 16);     // 16 bytes for CTR IV
                $encryptKey_CtoS = $kdf('C', match ($this->encryptionMethod_CtoS) {
                    'aes128-ctr' => 16,
                    'aes192-ctr' => 24,
                    'aes256-ctr' => 32,
                    default => 0
                });                                  // CTR Key
                $macKey_CtoS = $kdf_mac(
                    'E',
                    $CtoS_macKeyLengthInBytes
                );
                if (! $this->rekeyInProgress) {
                    // MAC Key
                    $this->hash_CtoS?->setKey($macKey_CtoS);
                }

                break;

            default:
                throw new \RuntimeException('Unhandled encryption method CtoS');
        }

        switch ($this->encryptionMethod_StoC) {
            case 'aes128-gcm@openssh.com':
                // For aes256-gcm@openssh.com:
                // - We need 16-byte keys for AES-128
                // - We need 12-byte IVs for GCM
                $encryptIV_StoC = $kdf('B', 12);     // Only take 12 bytes for GCM IV
                $encryptKey_StoC = $kdf('D', 16);    // 16 bytes for AES-256 key
                $macKey_StoC = null;

                break;

            case 'aes256-gcm@openssh.com':
                // For aes256-gcm@openssh.com:
                // - We need 32-byte keys for AES-256
                // - We need 12-byte IVs for GCM
                $encryptIV_StoC = $kdf('B', 12);     // Only take 12 bytes for GCM IV
                $encryptKey_StoC = $kdf('D', 32);    // 32 bytes for AES-256 key
                $macKey_StoC = null;

                break;

            case 'aes128-ctr':
            case 'aes192-ctr':
            case 'aes256-ctr':
                // For AES-CTR
                // - We need 16-byte keys for AES-128
                // - We need 24-byte keys for AES-192
                // - We need 32-byte keys for AES-256
                $encryptIV_StoC = $kdf('B', 16);     // 16 bytes for CTR IV
                $encryptKey_StoC = $kdf('D', match ($this->encryptionMethod_StoC) {
                    'aes128-ctr' => 16,
                    'aes192-ctr' => 24,
                    'aes256-ctr' => 32,
                    default => 0
                });                                  // CTR Key
                $macKey_StoC = $kdf_mac(
                    'F',
                    $StoC_macKeyLengthInBytes
                );                                   // MAC Key
                if (! $this->rekeyInProgress) {
                    $this->hash_StoC?->setKey($macKey_StoC);
                }

                break;

            default:
                throw new \RuntimeException('Unhandled encryption method CtoS');
        }

        // Store derived keys in appropriate container
        if ($this->rekeyInProgress) {
            $this->pendingKeys = [
                'encryptIV_CtoS' => $encryptIV_CtoS,
                'encryptKey_CtoS' => $encryptKey_CtoS,
                'macKey_CtoS' => $macKey_CtoS,
                'encryptIV_StoC' => $encryptIV_StoC,
                'encryptKey_StoC' => $encryptKey_StoC,
                'macKey_StoC' => $macKey_StoC,
            ];
        } else {
            $this->encryptIV_CtoS = $encryptIV_CtoS;
            $this->encryptKey_CtoS = $encryptKey_CtoS;
            $this->macKey_CtoS = $macKey_CtoS;

            $this->encryptIV_StoC = $encryptIV_StoC;
            $this->encryptKey_StoC = $encryptKey_StoC;
            $this->macKey_StoC = $macKey_StoC;

            // Initialize AES instances with the new keys
            switch ($this->encryptionMethod_StoC) {
                case 'aes256-gcm@openssh.com':
                case 'aes128-gcm@openssh.com':
                    $this->encryptor = new AES('gcm');
                    $this->encryptor->setKey($this->encryptKey_StoC);

                    // Reset sequence number for GCM mode.
                    // In AES-GCM, the packet sequence number is used as part of the IV and AAD
                    // for decryption. It must start at 0 immediately after the NEWKEYS exchange,
                    // and increment with each decrypted packet to ensure correct authentication.
                    $this->packetSeq_StoC = 0;

                    break;

                case 'aes256-ctr':
                case 'aes192-ctr':
                case 'aes128-ctr':
                    $this->encryptor = new AES('ctr');
                    $this->encryptor->setKey($this->encryptKey_StoC);
                    $this->encryptor->setIV($this->encryptIV_StoC);
                    $this->encryptor->disablePadding();
                    $this->encryptor->enableContinuousBuffer();

                    break;
            }

            switch ($this->encryptionMethod_CtoS) {
                case 'aes256-gcm@openssh.com':
                case 'aes128-gcm@openssh.com':
                    $this->decryptor = new AES('gcm');
                    $this->decryptor->setKey($this->encryptKey_CtoS);

                    // Reset sequence number for GCM mode.
                    // In AES-GCM, the packet sequence number is used as part of the IV and AAD
                    // for decryption. It must start at 0 immediately after the NEWKEYS exchange,
                    // and increment with each decrypted packet to ensure correct authentication.
                    $this->packetSeq_CtoS = 0;

                    break;

                case 'aes256-ctr':
                case 'aes192-ctr':
                case 'aes128-ctr':
                    $this->decryptor = new AES('ctr');
                    $this->decryptor->setKey($this->encryptKey_CtoS);
                    $this->decryptor->setIV($this->encryptIV_CtoS);
                    $this->decryptor->disablePadding();
                    $this->decryptor->enableContinuousBuffer();

                    break;
            }
        }

        // Enable encryption and mark initial key exchange as complete
        $this->encryptionActive = true;
        $this->hasCompletedInitialKeyExchange = true;
    }

    public function constructPacket(string $payload): false|string
    {
        if ($this->encryptionActive) {
            switch ($this->encryptionMethod_StoC) {
                case 'aes256-gcm@openssh.com':
                case 'aes128-gcm@openssh.com':
                    return $this->constructEncryptedPacketAESGCM($payload);

                case 'aes256-ctr':
                case 'aes192-ctr':
                case 'aes128-ctr':
                    return $this->constructEncryptedPacketAESCTR($payload);
            }
        }

        $packetLen = strlen($payload);
        // Calculate padding to make total length a multiple of 8
        // Total length = packetLen + paddingLen + 5 (4 for length + 1 for padding length)
        $paddingLen = 8 - (($packetLen + 5) % 8);
        if ($paddingLen < 4) {
            $paddingLen += 8;
        }

        ++$this->packetSeq_StoC;

        return pack('N', $packetLen + $paddingLen + 1)
            . chr($paddingLen)
            . $payload
            . random_bytes($paddingLen);
    }

    /**
     * Parses a complete SSH packet from the raw input buffer.
     *
     * This method handles both encrypted and unencrypted SSH packet formats.
     * If encryption is active, it selects the appropriate decryption routine
     * based on the negotiated C-to-S cipher method, such as AES-GCM or AES-CTR.
     * Each encrypted mode has specific handling for packet structure and MAC/tag validation.
     *
     * For unencrypted packets, it reads the packet length and attempts to construct
     * a Packet instance directly from the input buffer.
     *
     * If the input data does not yet contain a full packet (e.g., due to partial reads),
     * it returns [null, 0] to indicate that more data is needed.
     *
     * @param string $data Raw input buffer data
     *
     * @return array{0: ?Packet, 1: int} A tuple containing the parsed Packet (or null if incomplete/failed)
     *                                   and the number of bytes consumed from the input buffer
     *
     * @throws \RuntimeException|\UnexpectedValueException on structural errors
     */
    public function fromData(string $data): array
    {
        // If encryption is active, parse an encrypted packet.
        if ($this->encryptionActive) {
            switch ($this->encryptionMethod_CtoS) {
                case 'aes128-gcm@openssh.com':
                case 'aes256-gcm@openssh.com':
                    $packetLength = null;
                    $packet = $this->handleEncryptedPacketAESGCM($data);
                    $macLength = 16;

                    break;

                case 'aes128-ctr':
                case 'aes192-ctr':
                case 'aes256-ctr':
                    $packetLength = 0;
                    $packet = $this->handleEncryptedPacketAESCTR($data, $packetLength);
                    $macLength = $this->hash_CtoS?->getLengthInBytes();

                    break;

                default:
                    throw new \RuntimeException('Unhandled encryption method: ' . $this->encryptionMethod_CtoS);
            }

            if (false === $packet) {
                // Suggests a decryption or parse error
                // Return [null, 0] to indicate failure
                return [null, 0];
            }

            // If handleEncryptedPacket succeeded, we know how many bytes we used:
            //   4 bytes for length + $packetLength bytes of ciphertext + 16 bytes for GCM tag.
            if (strlen($data) < 4) {
                return [null, 0];
            }
            if (is_null($packetLength)) {
                $packetLength = (unpack('N', substr($data, 0, 4)) ?: [])[1] ?? null;
                if (! is_int($packetLength)) {
                    throw new \UnexpectedValueException('Expected int-castable value at offset 1');
                }
            }
            $bytesUsed = 4 + $packetLength + $macLength;

            return [$packet, $bytesUsed];
        }

        // If encryption isn't active, parse an unencrypted SSH packet.
        // Unencrypted logic typically has: 4 bytes for length + that many payload/padding bytes.
        if (strlen($data) < 4) {
            // Not enough data to even read the packet length
            return [null, 0];
        }

        $packetLength = (unpack('N', substr($data, 0, 4)) ?: [])[1] ?? null;
        if (! is_int($packetLength)) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }
        if (strlen($data) < 4 + $packetLength) {
            // Incomplete
            return [null, 0];
        }

        $packet = Packet::fromData($data);

        $bytesUsed = 4 + $packetLength;
        ++$this->packetSeq_CtoS;

        return [$packet, $bytesUsed];
    }

    public function packString(string $str): string
    {
        return pack('N', strlen($str)) . $str;
    }

    public function packValue(MessageType $type, mixed $value): string
    {
        return $this->packValues($type, [$value]);
    }

    public function packValues(MessageType $type, array $values = []): string
    {
        $packed = MessageType::chr($type);
        foreach ($values as $value) {
            $type = strtolower(gettype($value));
            $packMethod = 'pack' . ucfirst($type);

            if (method_exists($this, $packMethod)) {
                $packed .= $this->{$packMethod}($value); // @phpstan-ignore-line
            } else {
                $this->error("No pack method for type: {$type}");
            }
        }

        return $packed;
    }

    public function switchToNewKeys(): void
    {
        $this->info('Switching to new keys');

        if (! $this->rekeyInProgress || ! $this->pendingKeys) {
            $this->error('switchToNewKeys called but no pending keys available');

            return;
        }

        // Apply pending keys
        $this->encryptIV_CtoS = $this->pendingKeys['encryptIV_CtoS'] ?? throw new \RuntimeException('Invalid encryptIV_CtoS');
        $this->encryptKey_CtoS = $this->pendingKeys['encryptKey_CtoS'] ?? throw new \RuntimeException('Invalid encryptKey_CtoS');
        $this->macKey_CtoS = $this->pendingKeys['macKey_CtoS'];
        $this->encryptIV_StoC = $this->pendingKeys['encryptIV_StoC'] ?? throw new \RuntimeException('Invalid encryptIV_StoC');
        $this->encryptKey_StoC = $this->pendingKeys['encryptKey_StoC'] ?? throw new \RuntimeException('Invalid encryptKey_StoC');
        $this->macKey_StoC = $this->pendingKeys['macKey_StoC'];

        // Re-initialize hash instances
        [$this->hash_StoC] = $this->macAlgorithmToHashInstance($this->macMethod_StoC);
        [$this->hash_CtoS] = $this->macAlgorithmToHashInstance($this->macMethod_CtoS);

        // Create new encryptor/decryptor instances
        switch ($this->encryptionMethod_StoC) {
            case 'aes256-gcm@openssh.com':
            case 'aes128-gcm@openssh.com':
                $this->encryptor = new AES('gcm');
                $this->encryptor->setKey($this->encryptKey_StoC);

                break;

            case 'aes128-ctr':
            case 'aes192-ctr':
            case 'aes256-ctr':
                $this->encryptor = new AES('ctr');
                $this->encryptor->setKey($this->encryptKey_StoC);
                $this->encryptor->setIV($this->encryptIV_StoC);
                $this->encryptor->disablePadding();
                $this->encryptor->enableContinuousBuffer();
                $this->hash_StoC->setKey($this->macKey_StoC ?? throw new \RuntimeException('Invalid MAC key'));

                break;
        }

        switch ($this->encryptionMethod_CtoS) {
            case 'aes256-gcm@openssh.com':
            case 'aes128-gcm@openssh.com':
                $this->decryptor = new AES('gcm');
                $this->decryptor->setKey($this->encryptKey_CtoS);

                break;

            case 'aes128-ctr':
            case 'aes192-ctr':
            case 'aes256-ctr':
                $this->decryptor = new AES('ctr');
                $this->decryptor->setKey($this->encryptKey_CtoS);
                $this->decryptor->setIV($this->encryptIV_CtoS);
                $this->decryptor->disablePadding();
                $this->decryptor->enableContinuousBuffer();
                $this->hash_CtoS->setKey($this->macKey_CtoS ?? throw new \RuntimeException('Invalid MAC key'));

                break;
        }

        // Apply the new Kex object but ensure it keeps the original session ID
        if ($this->rekeyKex) {
            // Double-check that the session ID is properly preserved
            if (is_null($this->rekeyKex->getSessionId())) {
                $this->rekeyKex->setSessionId($this->kex->getSessionId() ?? throw new \RuntimeException('Session Id not set'));
            }
            $this->kex = $this->rekeyKex;
            $this->rekeyKex = null;
        }

        // Reset sequence numbers as per RFC 4253, Section 7.4
        if (in_array($this->encryptionMethod_CtoS, ['aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'])) {
            $this->packetSeq_CtoS = 0;
        }
        if (in_array($this->encryptionMethod_StoC, ['aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'])) {
            $this->packetSeq_StoC = 0;
        }

        // Reset state
        $this->pendingKeys = null;
        $this->rekeyInProgress = false;
    }

    private function extractString(string $data, int &$offset): array
    {
        $length = (unpack('N', substr($data, $offset, 4)) ?: [])[1] ?? null;
        if (! is_int($length)) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }

        $string = substr($data, $offset + 4, $length);
        $offset += 4 + $length;

        return [$string, $offset];
    }

    private function packInteger(int $uint): string
    {
        return pack('N', $uint);
    }

    private function packBool(bool $bool): string
    {
        return $bool ? chr(1) : chr(0);
    }

    private function packBoolean(bool $bool): string
    {
        return $this->packBool($bool);
    }

    private function packNull(mixed $value): string
    {
        return '';
    }

    private function getDecryptor(): ?AES
    {
        return $this->decryptor;
    }

    /**
     * Constructs and encrypts an SSH packet using AES in CTR mode.
     *
     * This method handles padding, packet length encoding, HMAC computation, and encryption
     * for AES-CTR mode. Unlike GCM, CTR mode requires separate authentication via HMAC,
     * and the packet length field is included in the encrypted payload.
     *
     * @param string $payload the SSH message payload to be sent
     *
     * @return false|string the fully encrypted packet (ciphertext + MAC), or false on error
     */
    private function constructEncryptedPacketAESCTR(string $payload): false|string
    {
        // The block size for AES is 16 bytes
        $blockSize = 16;
        $payloadLength = strlen($payload);

        // Calculate minimum padding needed
        $paddingLength = $blockSize - ((1 + $payloadLength + 4) % $blockSize);
        if ($paddingLength < 4) {
            $paddingLength += $blockSize;
        }

        // Verify our calculation - total length should be multiple of blockSize
        $packetLength = 1 + $payloadLength + 4 + $paddingLength;
        if (0 !== $packetLength % $blockSize) {
            $this->error("Invalid padding calculation: {$packetLength} is not a multiple of {$blockSize}");

            return false;
        }

        // Pack the length and create packet
        $packetLengthBytes = pack('N', $packetLength - 4);
        $padding = random_bytes($paddingLength);
        $packet = chr($paddingLength) . $payload . $padding;

        // Encrypt the full packet (length + rest)
        $plaintextPacket = $packetLengthBytes . $packet;
        $payloadCipher = $this->encryptor?->encrypt($packetLengthBytes . $packet);

        // Setup HMAC
        // [$hmac, $keyLength] = $this->macAlgorithmToHashInstance($this->macMethod_StoC);
        // $hmac->setKey($this->macKey_StoC ?? throw new \RuntimeException('Invalid MAC key'));
        $macValue = pack('Na*', $this->packetSeq_StoC, substr($plaintextPacket, 0, $packetLength)); // MAC input includes sequence number
        $mac = $this->hash_StoC?->hash($macValue) ?? throw new \RuntimeException('Hash instance not initialized');

        ++$this->packetSeq_StoC;

        // Send packet: ciphertext + mac
        return $payloadCipher . substr($mac, 0, $this->hash_StoC->getLengthInBytes());
    }

    /**
     * Constructs and encrypts an SSH packet using AES in GCM mode.
     *
     * In AES-GCM mode, both encryption and authentication are handled together,
     * so no separate HMAC is needed. The packet length is not encrypted and must
     * be prepended separately. The method returns the concatenated length field,
     * ciphertext, and authentication tag.
     *
     * @param string $payload the SSH message payload to be sent
     *
     * @return false|string the fully encrypted and authenticated packet, or false on error
     */
    private function constructEncryptedPacketAESGCM(string $payload): false|string
    {
        // The block size for AES is 16 bytes
        $blockSize = 16;

        // Calculate minimum padding needed
        $paddingLength = $blockSize - ((1 + strlen($payload)) % $blockSize);
        if ($paddingLength < 4) {
            $paddingLength += $blockSize;
        }

        // Verify our calculation - total length should be multiple of blockSize
        $packetLength = 1 + strlen($payload) + $paddingLength;
        if (0 !== $packetLength % $blockSize) {
            $this->error("Invalid padding calculation: {$packetLength} is not a multiple of {$blockSize}");

            return false;
        }

        // Pack the length and create packet
        $lengthBytes = pack('N', $packetLength);
        $padding = random_bytes($paddingLength);
        $packet = chr($paddingLength) . $payload . $padding;

        // Set the nonce for this packet
        $nonce = $this->getNonce($this->encryptIV_StoC, $this->packetSeq_StoC);
        $this->encryptor?->setNonce($nonce);

        // Set AAD before encryption
        $this->encryptor?->setAAD($lengthBytes);

        // Encrypt
        $ciphertext = $this->encryptor?->encrypt($packet);
        $tag = $this->encryptor?->getTag();

        ++$this->packetSeq_StoC;

        // Send packet: length + ciphertext + tag
        return $lengthBytes . $ciphertext . $tag;
    }

    private function getNonce(string $baseIV, int $sequenceNumber): string
    {
        // Start with the complete IV (12 bytes)
        $nonce = $baseIV;

        // Treat last 4 bytes as counter, increment by sequence number
        $counter = (unpack('N', substr($baseIV, 8, 4)) ?: [])[1] ?? null;
        if (! is_int($counter)) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }
        $counter = ($counter + $sequenceNumber) & 0xFFFFFFFF;

        // Replace last 4 bytes with incremented counter
        $nonce[8] = chr(($counter >> 24) & 0xFF);
        $nonce[9] = chr(($counter >> 16) & 0xFF);
        $nonce[10] = chr(($counter >> 8) & 0xFF);
        $nonce[11] = chr($counter & 0xFF);

        return $nonce;
    }

    /**
     * Decrypts and parses an SSH packet encrypted using AES in CTR mode.
     *
     * This method handles the specific requirements of AES-CTR, where the entire
     * packet including the length field is encrypted. It decrypts the input data,
     * extracts the packet length, validates padding, and returns the resulting Packet
     * instance. The packet length is passed by reference so the caller can determine
     * how many bytes were consumed from the buffer.
     *
     * @param string $data          The raw encrypted data from the input buffer
     * @param int    &$packetLength Reference to capture the decrypted packet length
     *
     * @return false|Packet The parsed Packet on success, or false on failure
     */
    private function handleEncryptedPacketAESCTR(string $data, int &$packetLength): false|Packet
    {
        // Decrypt AES-CTR
        try {
            $resolvedPacketLength = false;
            $blockLength = $this->decryptor?->getBlockLengthInBytes() ?? throw new \RuntimeException('Decryptor not initialized');
            $finalBlock = (int) strlen($data) / $blockLength;
            $currentBlock = 0;
            $plaintext = '';
            do {
                $plaintext .= $this->decryptor->decrypt(substr($data, $currentBlock * $blockLength, $blockLength));
                if (! $resolvedPacketLength) {
                    ++$currentBlock;
                    $plaintext .= $this->decryptor->decrypt(substr($data, $currentBlock * $blockLength, $blockLength));

                    $tmpPacketLength = (unpack('N', substr($plaintext, 0, 4)) ?: [])[1] ?? null;
                    if (! is_int($tmpPacketLength)) {
                        throw new \RuntimeException('Failure obtaining packet length');
                    }
                    $packetLength = $tmpPacketLength;

                    $finalBlock = (($packetLength + 4) / $blockLength) - $currentBlock;
                    $resolvedPacketLength = true;
                }

                ++$currentBlock;
            } while ($currentBlock <= $finalBlock);

            $maxPacketSize = 1024 * 1024;
            if ($packetLength > $maxPacketSize) {
                throw new \RuntimeException("Protocol error: packet too large ({$packetLength} > {$maxPacketSize}), bad packet received");
            }

            $payload = substr($plaintext, 0, 4 + $packetLength);
            $mac = substr($data, 4 + $packetLength, $this->hash_CtoS?->getLengthInBytes());

            $macData = $this->packInteger($this->packetSeq_CtoS) . $payload;
            $calculatedMac = $this->hash_CtoS?->hash($macData) ?? throw new \RuntimeException('Failure generating hash');

            // Validate HMAC
            if (! hash_equals($calculatedMac, $mac)) {
                throw new \RuntimeException('Invalid HMAC');
            }
        } catch (\Exception $e) {
            $this->error(sprintf(
                'Decryption failed for packet seq %d\nError: %s',
                $this->packetSeq_CtoS,
                $e->getMessage()
            ));

            return false;
        }

        if (empty($plaintext)) {
            return false;
        }

        ++$this->packetSeq_CtoS;

        $paddingLength = ord($plaintext[4]);

        return new Packet(substr($plaintext, 5, -$paddingLength));
    }

    /**
     * Decrypts and parses an SSH packet encrypted using AES in GCM mode.
     *
     * AES-GCM provides both encryption and authentication, so this method handles
     * decryption and automatic MAC (auth tag) validation. Unlike CTR mode, the
     * packet length can be determined without decryption. This method extracts the
     * complete packet, verifies integrity via GCM authentication, and returns the
     * resulting Packet instance on success.
     *
     * @param string $data the raw encrypted data including GCM authentication tag
     *
     * @return false|Packet the parsed Packet on success, or false if authentication fails
     *                      or the packet is malformed
     */
    private function handleEncryptedPacketAESGCM(string $data): false|Packet
    {
        // Get the length of the packet from the first 4 bytes
        $lengthBytes = substr($data, 0, 4);
        if (4 !== strlen($lengthBytes)) {
            $this->error('Failed to read length: got ' . (strlen($lengthBytes) ?: 0) . ' bytes');

            return false;
        }

        $packetLength = (unpack('N', $lengthBytes) ?: null)[1] ?? null;
        if (is_null($packetLength)) {
            $this->error('Failed to read length');

            return false;
        }
        if (! is_int($packetLength) && ! is_float($packetLength) && ! is_string($packetLength)) {
            throw new \UnexpectedValueException('Expected int-castable value at offset 1');
        }
        $packetLength = (int) $packetLength;
        $cipherAndTag = substr($data, 4, $packetLength + 16);
        if (strlen($cipherAndTag) !== $packetLength + 16) {
            $this->error(sprintf(
                'Failed to read complete ciphertext+tag: expected %d bytes, got %d',
                $packetLength + 16,
                strlen($cipherAndTag)
            ));

            return false;
        }

        $ciphertext = substr($cipherAndTag, 0, $packetLength);
        $tag = substr($cipherAndTag, $packetLength);

        // Set the nonce for this packet
        $nonce = $this->getNonce($this->encryptIV_CtoS, $this->packetSeq_CtoS);

        $this->decryptor?->setNonce($nonce);

        // Set AAD before decryption
        $this->decryptor?->setAAD($lengthBytes);
        $this->decryptor?->setTag($tag);

        // Decrypt
        try {
            $plaintext = $this->decryptor?->decrypt($ciphertext);
        } catch (\Exception $e) {
            $this->error(sprintf(
                'Decryption failed for packet seq %d\nError: %s',
                $this->packetSeq_CtoS,
                $e->getMessage()
            ));

            return false;
        }

        if (null === $plaintext) {
            return false;
        }

        ++$this->packetSeq_CtoS;

        $paddingLength = ord($plaintext[0]);

        return new Packet(substr($plaintext, 1, strlen($plaintext) - $paddingLength - 1));
    }

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

    /**
     * Maps an encryption algorithm name to an instance of a subclass of
     * \phpseclib3\Crypt\Hash.
     *
     * @param string $algorithm Name of the encryption algorithm
     *
     * @return array{Hash, int}
     */
    private function macAlgorithmToHashInstance(string $algorithm): array
    {
        return match ($algorithm) {
            'umac-64@openssh.com', 'umac-64-etm@openssh.com' => [new Hash('umac-64'), 16],
            'umac-128@openssh.com', 'umac-128-etm@openssh.com' => [new Hash('umac-128'), 16],
            'hmac-sha2-512', 'hmac-sha2-512-etm@openssh.com' => [new Hash('sha512'), 64],
            'hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com' => [new Hash('sha256'), 32],
            'hmac-sha1', 'hmac-sha1-etm@openssh.com' => [new Hash('sha1'), 20],
            'hmac-sha1-96' => [new Hash('sha1-96'), 20],
            'hmac-md5' => [new Hash('md5'), 16],
            'hmac-md5-96' => [new Hash('md5-96'), 16],
            default => throw new \RuntimeException('Unhandled hash algorithm'),
        };
    }
}
