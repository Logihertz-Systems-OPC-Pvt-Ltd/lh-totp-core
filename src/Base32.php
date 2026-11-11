<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-totp-core (bin/lh-mail / bin/lh-totp)
// Module:        Logihertz\TotpCore\Base32
// Role:          RFC 4648 Base32 Encoder, Decoder & Entropy Analyzer
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\TotpCore;

use InvalidArgumentException;

/**
 * Implements strict RFC 4648 Base32 encoding, decoding, CSPRNG secret generation,
 * and Shannon entropy evaluation.
 */
class Base32
{
    public const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Encode binary data into RFC 4648 Base32 string.
     *
     * @param string $binaryData Raw binary data.
     * @param bool $pad Whether to append '=' padding characters.
     * @return string Encoded Base32 string.
     */
    public static function encode(string $binaryData, bool $pad = false): string
    {
        if ($binaryData === '') {
            return '';
        }

        $alphabet = self::ALPHABET;
        $output = '';
        $buffer = 0;
        $bufferLength = 0;
        $len = strlen($binaryData);

        for ($i = 0; $i < $len; $i++) {
            $buffer = ($buffer << 8) | ord($binaryData[$i]);
            $bufferLength += 8;

            while ($bufferLength >= 5) {
                $bufferLength -= 5;
                $index = ($buffer >> $bufferLength) & 0x1F;
                $output .= $alphabet[$index];
            }
        }

        if ($bufferLength > 0) {
            $index = ($buffer << (5 - $bufferLength)) & 0x1F;
            $output .= $alphabet[$index];
        }

        if ($pad) {
            $remainder = strlen($output) % 8;
            if ($remainder !== 0) {
                $output .= str_repeat('=', 8 - $remainder);
            }
        }

        return $output;
    }

    /**
     * Decode RFC 4648 Base32 string into binary bytes.
     *
     * @param string $base32 Base32 formatted string.
     * @return string Decoded raw binary data.
     * @throws InvalidArgumentException
     */
    public static function decode(string $base32): string
    {
        $clean = strtoupper(rtrim(str_replace([' ', "\t", "\r", "\n"], '', $base32), '='));
        if ($clean === '') {
            return '';
        }

        $alphabet = self::ALPHABET;
        $output = '';
        $buffer = 0;
        $bufferLength = 0;
        $len = strlen($clean);

        for ($i = 0; $i < $len; $i++) {
            $char = $clean[$i];
            $val = strpos($alphabet, $char);
            if ($val === false) {
                throw new InvalidArgumentException("Invalid RFC 4648 Base32 character encountered: '{$char}'.");
            }

            $buffer = ($buffer << 5) | $val;
            $bufferLength += 5;

            if ($bufferLength >= 8) {
                $bufferLength -= 8;
                $output .= chr(($buffer >> $bufferLength) & 0xFF);
            }
        }

        return $output;
    }

    /**
     * Generate a cryptographically secure Base32 shared secret.
     *
     * @param int $byteLength Number of random bytes (minimum 16 bytes = 128 bits, default 32 = 256 bits).
     * @return string Unpadded Base32 encoded secret.
     * @throws InvalidArgumentException
     */
    public static function generateSecret(int $byteLength = 32): string
    {
        if ($byteLength < 16) {
            throw new InvalidArgumentException("Shared secret must be at least 16 bytes (128 bits) per RFC 4226 Section 4; requested {$byteLength} bytes.");
        }

        $bytes = random_bytes($byteLength);
        return self::encode($bytes, false);
    }

    /**
     * Calculate effective bit length of a Base32 shared secret.
     *
     * @param string $base32Secret The Base32 secret string.
     * @return int Bit length (e.g., 128, 160, 256, 512).
     */
    public static function calculateBitEntropy(string $base32Secret): int
    {
        try {
            $bytes = self::decode($base32Secret);
            return strlen($bytes) * 8;
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Compute Shannon entropy in bits per byte for a given byte string.
     *
     * @param string $rawBytes Binary data string.
     * @return float Shannon entropy H(X) in bits per byte (0.0 to 8.0).
     */
    public static function calculateShannonEntropy(string $rawBytes): float
    {
        $len = strlen($rawBytes);
        if ($len === 0) {
            return 0.0;
        }

        $frequencies = array_fill(0, 256, 0);
        for ($i = 0; $i < $len; $i++) {
            $frequencies[ord($rawBytes[$i])]++;
        }

        $entropy = 0.0;
        foreach ($frequencies as $count) {
            if ($count > 0) {
                $p = $count / $len;
                $entropy -= $p * log($p, 2);
            }
        }

        return round($entropy, 4);
    }
}
