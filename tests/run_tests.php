<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-totp-core (bin/lh-totp)
// Module:        tests/run_tests.php
// Role:          Zero-Dependency Deterministic Test Suite
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

require_once __DIR__ . '/../src/Autoloader.php';

use Logihertz\TotpCore\Autoloader;
use Logihertz\TotpCore\Base32;
use Logihertz\TotpCore\HotpEngine;
use Logihertz\TotpCore\TotpEngine;
use Logihertz\TotpCore\BackupCodeManager;
use Logihertz\TotpCore\TotpAuditor;
use Logihertz\TotpCore\Exporters;
use Logihertz\TotpCore\CliApplication;

Autoloader::register();

class TestRunner
{
    private int $totalAssertions = 0;
    private int $passedAssertions = 0;
    /** @var array<string> */
    private array $failures = [];

    public function assert(bool $condition, string $description): void
    {
        $this->totalAssertions++;
        if ($condition) {
            $this->passedAssertions++;
            echo "  \033[32m✓\033[0m {$description}\n";
        } else {
            $this->failures[] = $description;
            echo "  \033[31m✗ FAIL:\033[0m {$description}\n";
        }
    }

    public function summary(): int
    {
        echo "\n" . str_repeat('=', 80) . "\n";
        if (empty($this->failures)) {
            echo sprintf(
                "\033[32;1mTEST SUITE PASSED:\033[0m %d/%d assertions passing (100%% success rate)\n",
                $this->passedAssertions,
                $this->totalAssertions
            );
            echo str_repeat('=', 80) . "\n\n";
            return 0;
        }

        echo sprintf(
            "\033[31;1mTEST SUITE FAILED:\033[0m %d/%d assertions failed:\n",
            count($this->failures),
            $this->totalAssertions
        );
        foreach ($this->failures as $f) {
            echo " - {$f}\n";
        }
        echo str_repeat('=', 80) . "\n\n";
        return 1;
    }
}

$t = new TestRunner();

echo "\n================================================================================\n";
echo "  lh-totp-core: Zero-Dependency Verification Test Suite\n";
echo "================================================================================\n\n";

// -----------------------------------------------------------------------------
// Group 1: Autoloader Verification
// -----------------------------------------------------------------------------
echo "[Group 1: Autoloader Verification]\n";
$t->assert(class_exists(Base32::class), 'Autoloader resolves Base32 class');
$t->assert(!Autoloader::loadClass('Vendor\\ForeignClass'), 'Autoloader ignores foreign namespace');
$t->assert(!Autoloader::loadClass('Logihertz\\TotpCore\\NonexistentClassXYZ'), 'Autoloader handles missing class gracefully');

// -----------------------------------------------------------------------------
// Group 2: RFC 4648 Base32 Encoding, Decoding & Entropy
// -----------------------------------------------------------------------------
echo "\n[Group 2: RFC 4648 Base32 Encoding, Decoding & Entropy]\n";

$b32Raw = "12345678901234567890";
$b32Encoded = Base32::encode($b32Raw, false);
$t->assert($b32Encoded === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'RFC 4648 test vector encodes to exact Base32');

$b32Decoded = Base32::decode($b32Encoded);
$t->assert($b32Decoded === $b32Raw, 'RFC 4648 Base32 decodes cleanly back to original binary string');

$b32Padded = Base32::encode("foo", true);
$t->assert($b32Padded === 'MZXW6===', 'Base32 encode with padding produces valid padded string');

$b32PaddedDecoded = Base32::decode($b32Padded);
$t->assert($b32PaddedDecoded === 'foo', 'Base32 decode strips and parses padded string correctly');

$emptyEnc = Base32::encode('', false);
$t->assert($emptyEnc === '', 'Empty binary string encodes to empty string');
$emptyDec = Base32::decode('');
$t->assert($emptyDec === '', 'Empty Base32 decodes to empty string');

$secret256 = Base32::generateSecret(32);
$t->assert(strlen($secret256) > 0, 'CSPRNG shared secret generated successfully');
$entropyBits256 = Base32::calculateBitEntropy($secret256);
$t->assert($entropyBits256 === 256, '256-bit generated secret calculates to exactly 256 bits of entropy');

$shannon = Base32::calculateShannonEntropy(random_bytes(64));
$t->assert($shannon >= 3.5, 'CSPRNG random seed achieves high Shannon entropy (>= 3.5 bits/byte)');

$invalidB32Caught = false;
try {
    Base32::decode('INVALID_89!');
} catch (\InvalidArgumentException) {
    $invalidB32Caught = true;
}
$t->assert($invalidB32Caught, 'Base32 decode rejects invalid characters (non A-Z, 2-7)');

// -----------------------------------------------------------------------------
// Group 3: RFC 4226 Appendix D Official HOTP Test Vectors
// -----------------------------------------------------------------------------
echo "\n[Group 3: RFC 4226 Appendix D Official HOTP Test Vectors]\n";

$hotp = new HotpEngine();
$rfc4226Key = "12345678901234567890"; // 20-byte key
$expectedHotp = [
    0 => '755224',
    1 => '287082',
    2 => '359152',
    3 => '969429',
    4 => '338314',
    5 => '254676',
    6 => '287922',
    7 => '162583',
    8 => '399871',
    9 => '520489',
];

foreach ($expectedHotp as $counter => $expectedOtp) {
    $calculated = $hotp->generateFromRawKey($rfc4226Key, $counter, 6, 'sha1');
    $t->assert($calculated === $expectedOtp, "RFC 4226 HOTP vector counter={$counter} matches {$expectedOtp}");
}

// -----------------------------------------------------------------------------
// Group 4: RFC 6238 Appendix B Official TOTP Test Vectors (8-Digit)
// -----------------------------------------------------------------------------
echo "\n[Group 4: RFC 6238 Appendix B Official TOTP Test Vectors (8-Digit)]\n";

$totp = new TotpEngine($hotp);

$seedSha1 = "12345678901234567890"; // 20 bytes
$seedSha256 = "12345678901234567890123456789012"; // 32 bytes
$seedSha512 = "1234567890123456789012345678901234567890123456789012345678901234"; // 64 bytes

$rfc6238Vectors = [
    59 => [
        'sha1' => '94287082',
        'sha256' => '46119246',
        'sha512' => '90693936',
    ],
    1111111109 => [
        'sha1' => '07081804',
        'sha256' => '68084774',
        'sha512' => '25091201',
    ],
    1111111111 => [
        'sha1' => '14050471',
        'sha256' => '67062674',
        'sha512' => '99943326',
    ],
    1234567890 => [
        'sha1' => '89005924',
        'sha256' => '91819424',
        'sha512' => '93441116',
    ],
    2000000000 => [
        'sha1' => '69279037',
        'sha256' => '90698825',
        'sha512' => '38618901',
    ],
    20000000000 => [
        'sha1' => '65353130',
        'sha256' => '77737706',
        'sha512' => '47863826',
    ],
];

foreach ($rfc6238Vectors as $ts => $expectedCodes) {
    // SHA1 test
    $cSha1 = $totp->generateFromRawKey($seedSha1, $ts, 30, 8, 'sha1');
    $t->assert($cSha1 === $expectedCodes['sha1'], "RFC 6238 TOTP SHA1 at t={$ts} matches {$expectedCodes['sha1']}");

    // SHA256 test
    $cSha256 = $totp->generateFromRawKey($seedSha256, $ts, 30, 8, 'sha256');
    $t->assert($cSha256 === $expectedCodes['sha256'], "RFC 6238 TOTP SHA256 at t={$ts} matches {$expectedCodes['sha256']}");

    // SHA512 test
    $cSha512 = $totp->generateFromRawKey($seedSha512, $ts, 30, 8, 'sha512');
    $t->assert($cSha512 === $expectedCodes['sha512'], "RFC 6238 TOTP SHA512 at t={$ts} matches {$expectedCodes['sha512']}");
}

// -----------------------------------------------------------------------------
// Group 5: Dynamic Truncation & Digit Length Formats (6, 7, 8 Digits)
// -----------------------------------------------------------------------------
echo "\n[Group 5: Dynamic Truncation & Digit Length Formats]\n";

$d6 = $hotp->generateFromRawKey($rfc4226Key, 1, 6, 'sha1');
$t->assert(strlen($d6) === 6 && $d6 === '287082', 'Dynamic truncation formats 6-digit code');

$d7 = $hotp->generateFromRawKey($rfc4226Key, 1, 7, 'sha1');
$t->assert(strlen($d7) === 7, 'Dynamic truncation formats 7-digit code');

$d8 = $hotp->generateFromRawKey($rfc4226Key, 1, 8, 'sha1');
$t->assert(strlen($d8) === 8, 'Dynamic truncation formats 8-digit code');

$dInvalidUnder = false;
try {
    $hotp->generateFromRawKey($rfc4226Key, 1, 5, 'sha1');
} catch (\InvalidArgumentException) {
    $dInvalidUnder = true;
}
$t->assert($dInvalidUnder, 'HOTP rejects digits < 6');

$dInvalidOver = false;
try {
    $hotp->generateFromRawKey($rfc4226Key, 1, 9, 'sha1');
} catch (\InvalidArgumentException) {
    $dInvalidOver = true;
}
$t->assert($dInvalidOver, 'HOTP rejects digits > 8');

$dNegativeCounter = false;
try {
    $hotp->generateFromRawKey($rfc4226Key, -1, 6, 'sha1');
} catch (\InvalidArgumentException) {
    $dNegativeCounter = true;
}
$t->assert($dNegativeCounter, 'HOTP rejects negative counter values');

// -----------------------------------------------------------------------------
// Group 6: Constant-Time Verification & Look-Ahead Windows
// -----------------------------------------------------------------------------
echo "\n[Group 6: Constant-Time Verification & Look-Ahead Windows]\n";

$b32Key = Base32::encode($rfc4226Key, false);

// Exact match at counter 0
$v0 = $hotp->verify($b32Key, '755224', 0, lookAheadWindow: 2, digits: 6, algo: 'sha1');
$t->assert($v0['valid'] === true && $v0['matched_counter'] === 0 && $v0['next_counter'] === 1, 'HOTP verify succeeds on exact counter match');

// Look-ahead match at counter 2 when current is 0 and window is 2
$v2 = $hotp->verify($b32Key, '359152', 0, lookAheadWindow: 2, digits: 6, algo: 'sha1');
$t->assert($v2['valid'] === true && $v2['matched_counter'] === 2 && $v2['next_counter'] === 3, 'HOTP verify succeeds within forward look-ahead window (+2 steps)');

// Beyond look-ahead window (code for counter 3 with window 2)
$v3Fail = $hotp->verify($b32Key, '969429', 0, lookAheadWindow: 2, digits: 6, algo: 'sha1');
$t->assert($v3Fail['valid'] === false && $v3Fail['matched_counter'] === null, 'HOTP verify rejects codes beyond look-ahead window');

// Invalid OTP string
$vInvalid = $hotp->verify($b32Key, '000000', 0, lookAheadWindow: 5, digits: 6, algo: 'sha1');
$t->assert($vInvalid['valid'] === false, 'HOTP verify rejects invalid OTP');

// Whitespace handling in OTP
$vTrim = $hotp->verify($b32Key, '  755224  ', 0, lookAheadWindow: 0, digits: 6, algo: 'sha1');
$t->assert($vTrim['valid'] === true, 'HOTP verify cleans leading and trailing whitespace from input OTP');

// Hash equals constant time behavior (non-empty raw key)
$t->assert(hash_equals('755224', '755224'), 'hash_equals validates matching string');
$t->assert(!hash_equals('755224', '755225'), 'hash_equals rejects differing string');
$t->assert(!hash_equals('755224', '75522'), 'hash_equals rejects differing length');

// -----------------------------------------------------------------------------
// Group 7: Time Drift Tolerance Window & Replay Protection Cache
// -----------------------------------------------------------------------------
echo "\n[Group 7: Time Drift Tolerance Window & Replay Protection Cache]\n";

TotpEngine::clearReplayCache();
$testSecret = Base32::encode(random_bytes(32), false);
$now = 1700000000;

// Current token
$currentToken = $totp->generate($testSecret, $now, period: 30, digits: 6, algo: 'sha256');

// First verification: should succeed (drift 0)
$res1 = $totp->verify($testSecret, $currentToken, timestamp: $now, window: 1, period: 30, digits: 6, algo: 'sha256');
$t->assert($res1['valid'] === true && $res1['drift_steps'] === 0, 'TOTP verify succeeds on exact current step (drift: 0)');

// Immediate replay: should fail due to replay protection cache
$resReplay = $totp->verify($testSecret, $currentToken, timestamp: $now, window: 1, period: 30, digits: 6, algo: 'sha256');
$t->assert($resReplay['valid'] === false && $resReplay['replayed'] === true, 'TOTP replay protection successfully blocks reuse of verified token');

// Drift +1 step (token generated for 30 seconds ahead)
$futureToken = $totp->generate($testSecret, $now + 30, period: 30, digits: 6, algo: 'sha256');
$resFuture = $totp->verify($testSecret, $futureToken, timestamp: $now, window: 1, period: 30, digits: 6, algo: 'sha256');
$t->assert($resFuture['valid'] === true && $resFuture['drift_steps'] === 1, 'TOTP verify accepts +1 forward clock drift step');

// Drift -1 step (token generated for 30 seconds behind)
$pastToken = $totp->generate($testSecret, $now - 30, period: 30, digits: 6, algo: 'sha256');
$resPast = $totp->verify($testSecret, $pastToken, timestamp: $now, window: 1, period: 30, digits: 6, algo: 'sha256');
$t->assert($resPast['valid'] === true && $resPast['drift_steps'] === -1, 'TOTP verify accepts -1 backward clock drift step');

// Drift beyond window (+2 steps with window 1)
$tooFarFuture = $totp->generate($testSecret, $now + 60, period: 30, digits: 6, algo: 'sha256');
$resTooFar = $totp->verify($testSecret, $tooFarFuture, timestamp: $now, window: 1, period: 30, digits: 6, algo: 'sha256');
$t->assert($resTooFar['valid'] === false, 'TOTP verify rejects tokens generated outside clock drift window (+2 with w=1)');

// Provisioning URI generation
$uri = $totp->buildProvisioningUri('Logihertz Systems', 'ops@logihertz.com', $testSecret, 'SHA256', 6, 30);
$t->assert(str_starts_with($uri, 'otpauth://totp/'), 'Provisioning URI uses otpauth://totp/ scheme');
$t->assert(str_contains($uri, 'issuer=Logihertz+Systems') || str_contains($uri, 'issuer=Logihertz%20Systems'), 'Provisioning URI includes issuer parameter');
$t->assert(str_contains($uri, 'secret=' . $testSecret), 'Provisioning URI includes shared secret parameter');
$t->assert(str_contains($uri, 'algorithm=SHA256'), 'Provisioning URI includes algorithm parameter');

$card = $totp->renderEnrollmentCard($uri, $testSecret);
$t->assert(str_contains($card, 'MFA ENROLLMENT PROVISIONING CARD'), 'Enrollment card renders terminal box');

// -----------------------------------------------------------------------------
// Group 8: Backup Recovery Code Generation, Entropy & PBKDF2 Verification
// -----------------------------------------------------------------------------
echo "\n[Group 8: Backup Recovery Code Generation, Entropy & PBKDF2 Verification]\n";

$backupMgr = new BackupCodeManager();
$codes = $backupMgr->generateCodes(8);
$t->assert(count($codes) === 8, 'Generates requested count of 8 backup codes');

$sampleCode = $codes[0]['code'];
$t->assert(preg_match('/^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$/', $sampleCode) === 1, 'Backup code formatted with 4 groups of 4 unambiguous characters');

$entropy = $backupMgr->calculateEntropyBits($sampleCode);
$t->assert($entropy === 80, 'Backup code provides 80 bits of cryptographic entropy (>= 64 bits)');

$salt = $codes[0]['salt'];
$expectedHash = $codes[0]['hash'];
$computedHash = $backupMgr->hashCode($backupMgr->normalizeCode($sampleCode), $salt);
$t->assert(hash_equals($expectedHash, $computedHash), 'PBKDF2 hash matches stored hash for valid backup code');

// Test verification and single-use consumption
$consumeOk = $backupMgr->verifyAndConsume($sampleCode, $codes);
$t->assert($consumeOk === true, 'Valid backup code is successfully verified and consumed');
$t->assert($codes[0]['spent'] === true, 'Consumed backup code is marked spent=true');

// Re-consumption of spent code must fail
$reconsumeOk = $backupMgr->verifyAndConsume($sampleCode, $codes);
$t->assert($reconsumeOk === false, 'Spent backup code cannot be consumed a second time');

// Invalid recovery code must fail
$invalidConsume = $backupMgr->verifyAndConsume('XXXX-YYYY-ZZZZ-WWWW', $codes);
$t->assert($invalidConsume === false, 'Nonexistent recovery code is rejected');

// -----------------------------------------------------------------------------
// Group 9: 10-Rule MFA Posture Auditor & S_posture Math
// -----------------------------------------------------------------------------
echo "\n[Group 9: 10-Rule MFA Posture Auditor & S_posture Math]\n";

$auditor = new TotpAuditor();

// 1. Hardened policy test
$hardenedResult = $auditor->auditFile(__DIR__ . '/../fixtures/hardened_mfa_policy.json');
$t->assert($hardenedResult->summary['total_findings'] === 0, 'Hardened MFA policy produces 0 security findings');
$t->assert($hardenedResult->postureScore === 100, 'Hardened MFA policy achieves perfect posture score 100');

// 2. Vulnerable policy test
$vulnResult = $auditor->auditFile(__DIR__ . '/../fixtures/vulnerable_mfa_policy.json');
$t->assert($vulnResult->summary['total_findings'] === 10, 'Vulnerable policy triggers all 10 security rules');
$t->assert($vulnResult->postureScore === 0, 'Vulnerable policy receives minimum posture score 0');
$t->assert($vulnResult->summary['critical'] === 3, 'Vulnerable policy categorizes 3 CRITICAL findings');
$t->assert($vulnResult->summary['high'] === 4, 'Vulnerable policy categorizes 4 HIGH findings');
$t->assert($vulnResult->summary['medium'] === 2, 'Vulnerable policy categorizes 2 MEDIUM findings');
$t->assert($vulnResult->summary['low'] === 1, 'Vulnerable policy categorizes 1 LOW finding');

$vulnRuleIds = array_column(array_map(fn($f) => $f->toArray(), $vulnResult->findings), 'rule_id');
$t->assert(in_array('LH-TOTP-001', $vulnRuleIds, true), 'Triggers LH-TOTP-001 (Weak secret bits/entropy)');
$t->assert(in_array('LH-TOTP-002', $vulnRuleIds, true), 'Triggers LH-TOTP-002 (Replay protection disabled)');
$t->assert(in_array('LH-TOTP-003', $vulnRuleIds, true), 'Triggers LH-TOTP-003 (Excessive drift window)');
$t->assert(in_array('LH-TOTP-004', $vulnRuleIds, true), 'Triggers LH-TOTP-004 (Missing/weak lockout)');
$t->assert(in_array('LH-TOTP-005', $vulnRuleIds, true), 'Triggers LH-TOTP-005 (Excessive period / short digits)');
$t->assert(in_array('LH-TOTP-006', $vulnRuleIds, true), 'Triggers LH-TOTP-006 (Deprecated SHA1 algorithm)');
$t->assert(in_array('LH-TOTP-007', $vulnRuleIds, true), 'Triggers LH-TOTP-007 (Plaintext secret/unhashed codes)');
$t->assert(in_array('LH-TOTP-008', $vulnRuleIds, true), 'Triggers LH-TOTP-008 (Non-constant-time check)');
$t->assert(in_array('LH-TOTP-009', $vulnRuleIds, true), 'Triggers LH-TOTP-009 (Insecure provisioning hygiene)');
$t->assert(in_array('LH-TOTP-010', $vulnRuleIds, true), 'Triggers LH-TOTP-010 (Excessive backup codes / low bits)');

// 3. Isolated mathematical deduction test
$partialPolicy = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/hardened_mfa_policy.json'), true);
$partialPolicy['secret_bits'] = 64; // LH-TOTP-001 (CRITICAL: 25)
$partialPolicy['window_steps'] = 4; // LH-TOTP-003 (HIGH: 10)
$partialResult = $auditor->auditPolicy($partialPolicy);
$t->assert($partialResult->summary['critical'] === 1 && $partialResult->summary['high'] === 1, 'Isolated policy yields 1 CRITICAL and 1 HIGH finding');
$t->assert($partialResult->postureScore === 65, 'Exact posture math: 100 - (25*1 + 10*1) = 65');

// -----------------------------------------------------------------------------
// Group 10: Exporters Validation (Table, JSON, SARIF v2.1.0)
// -----------------------------------------------------------------------------
echo "\n[Group 10: Exporters Validation (Table, JSON, SARIF v2.1.0)]\n";

$tableOut = Exporters::renderTable($vulnResult);
$t->assert(str_contains($tableOut, 'LH-TOTP-001'), 'Table exporter displays rule ID');
$t->assert(str_contains($tableOut, 'Posture:'), 'Table exporter displays posture score banner');

$jsonOut = Exporters::exportJson($vulnResult);
$decodedJson = json_decode($jsonOut, true);
$t->assert(is_array($decodedJson) && isset($decodedJson['posture_score']), 'JSON exporter outputs valid JSON with posture_score');
$t->assert($decodedJson['summary']['total_findings'] === 10, 'JSON exporter retains accurate summary totals');

$sarifOut = Exporters::exportSarif($vulnResult);
$decodedSarif = json_decode($sarifOut, true);
$t->assert(is_array($decodedSarif) && ($decodedSarif['version'] ?? '') === '2.1.0', 'SARIF exporter outputs OASIS SARIF v2.1.0 schema');
$t->assert(count($decodedSarif['runs'][0]['tool']['driver']['rules']) === 10, 'SARIF exporter defines all 10 core detection rules');
$t->assert(count($decodedSarif['runs'][0]['results']) === 10, 'SARIF exporter maps all detected findings into results');

// -----------------------------------------------------------------------------
// Group 11: CLI Application & Subprocess Exit Codes
// -----------------------------------------------------------------------------
echo "\n[Group 11: CLI Application & Subprocess Exit Codes]\n";

$binPath = escapeshellarg(__DIR__ . '/../bin/lh-totp');

// 1. --help exit code 0
exec("php {$binPath} --help 2>&1", $helpOut, $helpCode);
$t->assert($helpCode === 0, 'CLI --help exits with code 0');

// 2. --version exit code 0
exec("php {$binPath} --version 2>&1", $verOut, $verCode);
$t->assert($verCode === 0, 'CLI --version exits with code 0');

// 3. scan hardened policy exit code 0
$hardenedPath = escapeshellarg(__DIR__ . '/../fixtures/hardened_mfa_policy.json');
exec("php {$binPath} scan {$hardenedPath} 2>&1", $scanHardenedOut, $scanHardenedCode);
$t->assert($scanHardenedCode === 0, 'CLI scan on hardened policy exits with code 0');

// 4. scan vulnerable policy exit code 1
$vulnPath = escapeshellarg(__DIR__ . '/../fixtures/vulnerable_mfa_policy.json');
exec("php {$binPath} scan {$vulnPath} 2>&1", $scanVulnOut, $scanVulnCode);
$t->assert($scanVulnCode === 1, 'CLI scan on policy-violating configuration exits with code 1');

// 5. scan nonexistent file exit code 2
exec("php {$binPath} scan /nonexistent/file.json 2>&1", $scanErrOut, $scanErrCode);
$t->assert($scanErrCode === 2, 'CLI scan on invalid or missing file exits with code 2');

// 6. generate command exit code 0
exec("php {$binPath} generate --secret {$b32Key} 2>&1", $genOut, $genCode);
$t->assert($genCode === 0, 'CLI generate command exits with code 0');
$t->assert(str_contains(implode("\n", $genOut), 'Current Code:'), 'CLI generate outputs valid one-time password');

// 7. provision command exit code 0
exec("php {$binPath} provision --issuer \"Logihertz Systems\" --account \"ops@logihertz.com\" --secret {$b32Key} 2>&1", $provOut, $provCode);
$t->assert($provCode === 0, 'CLI provision command exits with code 0');
$t->assert(str_contains(implode("\n", $provOut), 'otpauth://totp/'), 'CLI provision outputs valid otpauth:// URI');

// 8. backup-codes command exit code 0
exec("php {$binPath} backup-codes --count 8 2>&1", $bcOut, $bcCode);
$t->assert($bcCode === 0, 'CLI backup-codes command exits with code 0');

exit($t->summary());
