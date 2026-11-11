<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-totp-core (bin/lh-totp)
// Module:        Logihertz\TotpCore\BackupCodeManager
// Role:          CSPRNG Single-Use Backup Recovery Code Generator & PBKDF2 Verifier
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\TotpCore;

use InvalidArgumentException;

/**
 * Manages cryptographically random single-use backup recovery codes with
 * PBKDF2-HMAC-SHA256 storage-at-rest hashing and consumption tracking.
 */
class BackupCodeManager
{
    /** Unambiguous 32-character alphanumeric alphabet (excluding 0, O, 1, I) */
    public const CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    public const PBKDF2_ITERATIONS = 100000;

    /**
     * Generate cryptographically random single-use backup recovery codes.
     *
     * @param int $count Number of backup codes to generate (default 8).
     * @param int $groups Number of dash-separated groups (default 4).
     * @param int $groupLength Characters per group (default 4 -> 16 chars = 80 bits).
     * @return array<int, array{code: string, hash: string, salt: string, spent: bool}>
     * @throws InvalidArgumentException
     */
    public function generateCodes(int $count = 8, int $groups = 4, int $groupLength = 4): array
    {
        if ($count < 1 || $count > 50) {
            throw new InvalidArgumentException("Backup code count must be between 1 and 50; requested {$count}.");
        }

        $alphabet = self::CODE_ALPHABET;
        $alphabetLen = strlen($alphabet);
        $totalChars = $groups * $groupLength;

        $results = [];

        for ($i = 0; $i < $count; $i++) {
            $rawChars = '';
            for ($c = 0; $c < $totalChars; $c++) {
                $rawChars .= $alphabet[random_int(0, $alphabetLen - 1)];
            }

            // Split into groups separated by hyphens (e.g., ABCD-EFGH-JKLM-NPQR)
            $chunks = str_split($rawChars, $groupLength);
            $formattedCode = implode('-', $chunks);

            // Hash code with PBKDF2-HMAC-SHA256 for secure storage at rest
            $salt = bin2hex(random_bytes(16));
            $hash = $this->hashCode($rawChars, $salt);

            $results[] = [
                'code' => $formattedCode,
                'hash' => $hash,
                'salt' => $salt,
                'spent' => false,
            ];
        }

        return $results;
    }

    /**
     * Verify and consume a single-use backup code against stored hashed records.
     *
     * @param string $inputCode User-provided recovery code.
     * @param array<int, array{code?: string, hash: string, salt: string, spent: bool, spent_at?: int}> &$storedRecords
     * @return bool True if valid and newly consumed; false if invalid or already spent.
     */
    public function verifyAndConsume(string $inputCode, array &$storedRecords): bool
    {
        $normalized = $this->normalizeCode($inputCode);
        if ($normalized === '') {
            return false;
        }

        $matchedIndex = null;

        // Traverse all stored records in constant time
        foreach ($storedRecords as $idx => $record) {
            if ($record['spent']) {
                continue;
            }

            $computedHash = $this->hashCode($normalized, $record['salt']);
            if (hash_equals($record['hash'], $computedHash) && $matchedIndex === null) {
                $matchedIndex = $idx;
            }
        }

        if ($matchedIndex !== null) {
            $storedRecords[$matchedIndex]['spent'] = true;
            $storedRecords[$matchedIndex]['spent_at'] = time();
            return true;
        }

        return false;
    }

    /**
     * Normalize a backup code by stripping hyphens/whitespace and converting to uppercase.
     *
     * @param string $code Raw input code.
     * @return string Clean alphanumeric string.
     */
    public function normalizeCode(string $code): string
    {
        return strtoupper(preg_replace('/[^a-zA-Z0-9]/', '', $code) ?? '');
    }

    /**
     * Compute PBKDF2-HMAC-SHA256 hash for a normalized recovery code.
     *
     * @param string $normalizedCode Normalized alphanumeric code.
     * @param string $salt Cryptographic salt.
     * @return string Hex-encoded hash.
     */
    public function hashCode(string $normalizedCode, string $salt): string
    {
        return hash_pbkdf2('sha256', $normalizedCode, $salt, self::PBKDF2_ITERATIONS);
    }

    /**
     * Calculate effective bit entropy of a recovery code based on alphabet size.
     *
     * @param string $code Formatted or unformatted recovery code.
     * @return int Entropy in bits.
     */
    public function calculateEntropyBits(string $code): int
    {
        $normalized = $this->normalizeCode($code);
        // Alphabet has 32 symbols -> 5 bits per character
        return strlen($normalized) * 5;
    }
}
