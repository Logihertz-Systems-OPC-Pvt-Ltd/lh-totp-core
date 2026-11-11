<?php

declare(strict_types=1);

// ==============================================================================
// Product:       lh-totp-core (bin/lh-totp)
// Module:        Logihertz\TotpCore\CliApplication
// Role:          CLI Execution Controller & Argument Router
// Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
// Creator:       Sameer Tawade (Creator, Founder, Director & Sole Developer)
// Contact:       ops@logihertz.com | https://logihertz.com/
// License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
// ==============================================================================

namespace Logihertz\TotpCore;

use Throwable;

/**
 * Command-line interface router and controller for bin/lh-totp.
 */
class CliApplication
{
    public const EXIT_OK = 0;
    public const EXIT_POLICY_VIOLATION = 1;
    public const EXIT_USAGE_ERROR = 2;

    /**
     * Run the application with command line arguments.
     *
     * @param array<int, string> $argv Command line arguments.
     * @return int Exit code (0, 1, or 2).
     */
    public function run(array $argv): int
    {
        array_shift($argv); // Remove script name

        if (empty($argv) || in_array('--help', $argv, true) || in_array('-h', $argv, true)) {
            $this->printHelp();
            return empty($argv) ? self::EXIT_USAGE_ERROR : self::EXIT_OK;
        }

        if (in_array('--version', $argv, true) || in_array('-v', $argv, true)) {
            $this->printVersion();
            return self::EXIT_OK;
        }

        $command = array_shift($argv);

        return match ($command) {
            'scan' => $this->handleScan($argv),
            'generate' => $this->handleGenerate($argv),
            'verify' => $this->handleVerify($argv),
            'provision' => $this->handleProvision($argv),
            'backup-codes' => $this->handleBackupCodes($argv),
            default => $this->handleUnknownCommand($command),
        };
    }

    /**
     * Handle the `scan` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleScan(array $args): int
    {
        if (empty($args)) {
            fwrite(STDERR, "Error: Missing target policy path for 'scan' command.\n");
            fwrite(STDERR, "Usage: lh-totp scan <path-to-policy.json> [--format table|json|sarif] [--output <path>]\n");
            return self::EXIT_USAGE_ERROR;
        }

        $targetPath = '';
        $format = 'table';
        $outputPath = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--format' || $arg === '-f') {
                $format = strtolower($args[++$i] ?? 'table');
            } elseif (str_starts_with($arg, '--format=')) {
                $format = strtolower(substr($arg, 9));
            } elseif ($arg === '--output' || $arg === '-o') {
                $outputPath = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--output=')) {
                $outputPath = substr($arg, 9);
            } elseif (!str_starts_with($arg, '-') && $targetPath === '') {
                $targetPath = $arg;
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($targetPath === '') {
            fwrite(STDERR, "Error: Missing target policy file path.\n");
            return self::EXIT_USAGE_ERROR;
        }

        if (!in_array($format, ['table', 'json', 'sarif'], true)) {
            fwrite(STDERR, "Error: Invalid output format '{$format}'. Allowed: table, json, sarif.\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            $auditor = new TotpAuditor();
            $result = $auditor->auditFile($targetPath);

            $rendered = match ($format) {
                'json' => Exporters::exportJson($result),
                'sarif' => Exporters::exportSarif($result),
                default => Exporters::renderTable($result),
            };

            if ($outputPath !== null) {
                if (file_put_contents($outputPath, $rendered) === false) {
                    fwrite(STDERR, "Error: Unable to write report to '{$outputPath}'.\n");
                    return self::EXIT_USAGE_ERROR;
                }
                echo "Report successfully written to {$outputPath}\n";
            } else {
                echo $rendered;
            }

            return $result->summary['total_findings'] > 0 ? self::EXIT_POLICY_VIOLATION : self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Audit Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `generate` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleGenerate(array $args): int
    {
        $secret = null;
        $algo = 'SHA256';
        $digits = 6;
        $period = 30;
        $time = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--secret' || $arg === '-s') {
                $secret = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--secret=')) {
                $secret = substr($arg, 9);
            } elseif ($arg === '--algo' || $arg === '-a') {
                $algo = strtoupper($args[++$i] ?? 'SHA256');
            } elseif (str_starts_with($arg, '--algo=')) {
                $algo = strtoupper(substr($arg, 7));
            } elseif ($arg === '--digits' || $arg === '-d') {
                $digits = (int) ($args[++$i] ?? 6);
            } elseif (str_starts_with($arg, '--digits=')) {
                $digits = (int) substr($arg, 9);
            } elseif ($arg === '--period' || $arg === '-p') {
                $period = (int) ($args[++$i] ?? 30);
            } elseif (str_starts_with($arg, '--period=')) {
                $period = (int) substr($arg, 9);
            } elseif ($arg === '--time' || $arg === '-t') {
                $time = (int) ($args[++$i] ?? time());
            } elseif (str_starts_with($arg, '--time=')) {
                $time = (int) substr($arg, 7);
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        try {
            $generatedNewSecret = false;
            if ($secret === null || trim($secret) === '') {
                $secret = Base32::generateSecret(32);
                $generatedNewSecret = true;
            }

            $totp = new TotpEngine();
            $code = $totp->generate($secret, $time, $period, $digits, $algo);

            if ($generatedNewSecret) {
                echo "Generated New Secret: {$secret}\n";
            }
            echo "Current Code:         {$code}\n";
            echo "Algorithm:            {$algo}\n";
            echo "Period:               {$period}s\n";
            echo "Digits:               {$digits}\n";
            return self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Generation Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `verify` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleVerify(array $args): int
    {
        $secret = null;
        $code = null;
        $algo = 'SHA256';
        $window = 1;
        $period = 30;
        $time = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--secret' || $arg === '-s') {
                $secret = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--secret=')) {
                $secret = substr($arg, 9);
            } elseif ($arg === '--code' || $arg === '-c') {
                $code = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--code=')) {
                $code = substr($arg, 7);
            } elseif ($arg === '--algo' || $arg === '-a') {
                $algo = strtoupper($args[++$i] ?? 'SHA256');
            } elseif (str_starts_with($arg, '--algo=')) {
                $algo = strtoupper(substr($arg, 7));
            } elseif ($arg === '--window' || $arg === '-w') {
                $window = (int) ($args[++$i] ?? 1);
            } elseif (str_starts_with($arg, '--window=')) {
                $window = (int) substr($arg, 9);
            } elseif ($arg === '--period' || $arg === '-p') {
                $period = (int) ($args[++$i] ?? 30);
            } elseif (str_starts_with($arg, '--period=')) {
                $period = (int) substr($arg, 9);
            } elseif ($arg === '--time' || $arg === '-t') {
                $time = (int) ($args[++$i] ?? time());
            } elseif (str_starts_with($arg, '--time=')) {
                $time = (int) substr($arg, 7);
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($secret === null || $code === null) {
            fwrite(STDERR, "Error: Both --secret and --code are mandatory for verification.\n");
            fwrite(STDERR, "Usage: lh-totp verify --secret <base32> --code <otp> [options]\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            $totp = new TotpEngine();
            $result = $totp->verify(
                base32Secret: $secret,
                otp: $code,
                timestamp: $time,
                window: $window,
                period: $period,
                digits: strlen(trim($code)),
                algo: $algo,
                enforceReplayProtection: true
            );

            if ($result['valid']) {
                $drift = $result['drift_steps'] ?? 0;
                $driftSign = $drift >= 0 ? "+{$drift}" : (string) $drift;
                echo "✓ OTP Verification Succeeded [Drift: {$driftSign} step(s)]\n";
                return self::EXIT_OK;
            }

            if ($result['replayed']) {
                fwrite(STDERR, "✗ Verification Failed: Token has already been used and cannot be replayed.\n");
                return self::EXIT_POLICY_VIOLATION;
            }

            fwrite(STDERR, "✗ Verification Failed: Invalid or expired one-time password.\n");
            return self::EXIT_POLICY_VIOLATION;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Verification Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `provision` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleProvision(array $args): int
    {
        $issuer = 'Logihertz Systems';
        $account = '';
        $secret = null;
        $algo = 'SHA256';
        $digits = 6;
        $period = 30;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--issuer' || $arg === '-i') {
                $issuer = $args[++$i] ?? 'Logihertz Systems';
            } elseif (str_starts_with($arg, '--issuer=')) {
                $issuer = substr($arg, 9);
            } elseif ($arg === '--account' || $arg === '-u') {
                $account = $args[++$i] ?? '';
            } elseif (str_starts_with($arg, '--account=')) {
                $account = substr($arg, 10);
            } elseif ($arg === '--secret' || $arg === '-s') {
                $secret = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--secret=')) {
                $secret = substr($arg, 9);
            } elseif ($arg === '--algo' || $arg === '-a') {
                $algo = strtoupper($args[++$i] ?? 'SHA256');
            } elseif (str_starts_with($arg, '--algo=')) {
                $algo = strtoupper(substr($arg, 7));
            } elseif ($arg === '--digits' || $arg === '-d') {
                $digits = (int) ($args[++$i] ?? 6);
            } elseif (str_starts_with($arg, '--digits=')) {
                $digits = (int) substr($arg, 9);
            } elseif ($arg === '--period' || $arg === '-p') {
                $period = (int) ($args[++$i] ?? 30);
            } elseif (str_starts_with($arg, '--period=')) {
                $period = (int) substr($arg, 9);
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($account === '') {
            fwrite(STDERR, "Error: --account is mandatory for enrollment provisioning.\n");
            fwrite(STDERR, "Usage: lh-totp provision --account user@example.com [--issuer \"My App\"] [options]\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            if ($secret === null || trim($secret) === '') {
                $secret = Base32::generateSecret(32);
            }

            $totp = new TotpEngine();
            $uri = $totp->buildProvisioningUri($issuer, $account, $secret, $algo, $digits, $period);

            echo $totp->renderEnrollmentCard($uri, $secret);
            echo "Provisioning URI: {$uri}\n";
            return self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Provisioning Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `backup-codes` subcommand.
     *
     * @param array<int, string> $args Remaining arguments.
     * @return int Exit code.
     */
    private function handleBackupCodes(array $args): int
    {
        $count = 8;
        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--count' || $arg === '-n') {
                $count = (int) ($args[++$i] ?? 8);
            } elseif (str_starts_with($arg, '--count=')) {
                $count = (int) substr($arg, 8);
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        try {
            $mgr = new BackupCodeManager();
            $codes = $mgr->generateCodes($count);

            echo "┌────────────────────────────────────────────────────────────┐\n";
            echo "│            EMERGENCY BACKUP RECOVERY CODES                 │\n";
            echo "├────────────────────────────────────────────────────────────┤\n";
            echo "│ Store these single-use recovery codes in a secure vault.   │\n";
            echo "│ Each recovery code provides 80 bits of cryptographic       │\n";
            echo "│ entropy and becomes permanently invalid upon consumption.  │\n";
            echo "├────────────────────────────────────────────────────────────┤\n";

            foreach ($codes as $idx => $record) {
                printf("│ [%02d] %-20s  (PBKDF2-SHA256 hashed at rest) │\n", $idx + 1, $record['code']);
            }

            echo "└────────────────────────────────────────────────────────────┘\n";
            return self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, 'Backup Code Error: ' . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Print help information.
     */
    public function printHelp(): void
    {
        echo <<<HELP
lh-totp: Enterprise Zero-Dependency RFC 6238 TOTP & RFC 4226 HOTP Engine
Version: 0.1.0 | Logihertz Systems (OPC) Private Limited

USAGE:
  lh-totp scan <path-to-policy.json> [options]
  lh-totp generate [--secret <base32>] [options]
  lh-totp verify --secret <base32> --code <otp> [options]
  lh-totp provision --account <user@example.com> [--issuer <name>] [options]
  lh-totp backup-codes [--count 8]
  lh-totp --version
  lh-totp --help

COMMANDS:
  scan          Audit MFA policy configuration against rules LH-TOTP-001..010
  generate      Generate an RFC 6238 TOTP code (creates CSPRNG secret if omitted)
  verify        Verify user-submitted OTP with constant-time equality & replay guard
  provision     Build otpauth:// URI and terminal enrollment card
  backup-codes  Generate cryptographically random PBKDF2-hashed recovery codes

SCAN OPTIONS:
  --format, -f <table|json|sarif>   Report output format (default: table)
  --output, -o <path>               Optional destination file path for report

GENERATE / VERIFY OPTIONS:
  --secret, -s <base32>             Shared secret in RFC 4648 Base32 format
  --code, -c <otp>                  User OTP code to verify (required for verify)
  --algo, -a <SHA1|SHA256|SHA512>   HMAC digest algorithm (default: SHA256)
  --digits, -d <6|7|8>              Output code length (default: 6)
  --period, -p <seconds>            Time step period (default: 30)
  --window, -w <steps>              Clock drift tolerance window (default: 1 step)
  --time, -t <unix_ts>              Reference Unix timestamp (default: current time)

PROVISION OPTIONS:
  --account, -u <email>             Account username or email (required)
  --issuer, -i <name>               Service or organization name (default: Logihertz Systems)

EXIT CODES:
  0   Audit clean / OTP verified / Command succeeded
  1   Policy violation / Invalid OTP / Replay blocked
  2   CLI usage error, invalid options, or unreadable target

HELP;
    }

    /**
     * Print version details.
     */
    public function printVersion(): void
    {
        echo sprintf(
            "%s v%s (PHP %s, ext-hash, ext-json, ext-spl)\n%s\nCreator & Sole Developer: Sameer Tawade <ops@logihertz.com>\n",
            Exporters::TOOL_NAME,
            Exporters::TOOL_VERSION,
            PHP_VERSION,
            Exporters::ORGANIZATION
        );
    }

    /**
     * Handle unrecognized command.
     */
    private function handleUnknownCommand(string $command): int
    {
        fwrite(STDERR, "Error: Unknown command '{$command}'.\n");
        fwrite(STDERR, "Run 'lh-totp --help' for available commands.\n");
        return self::EXIT_USAGE_ERROR;
    }
}
