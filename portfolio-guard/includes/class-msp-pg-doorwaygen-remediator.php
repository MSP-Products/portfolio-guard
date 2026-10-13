<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Remediation for PG-DoorwayContentGenerator detections produced by
 * MSP_PG_DoorwayGen_Scanner::scan(). Single artifact type, a standalone
 * attacker-created loose file at web root -- always eligible for the real
 * evidence-then-quarantine-then-remove sequence once detected (detection
 * itself already requires a hash or structural content hit; there is no
 * weaker, name-only match for this family to guard against).
 */
class MSP_PG_DoorwayGen_Remediator
{
    public static function remediate($analysis, $siteMeta, $scanDir, $dryRun)
    {
        $livePath = $analysis['plugin_dir'];
        $actions  = array('CONFIRMED_MALWARE_IDENTIFIED');
        $errors   = array();
        $warnings = array();

        $evidenceMode = MSP_PG_Config::evidence_retention_mode();
        $artifactDir  = MSP_PG_Utils::join_paths($scanDir, 'artifacts', self::artifact_key($analysis));
        $quarantineDir = MSP_PG_Utils::join_paths($artifactDir, 'quarantine', basename($livePath));
        $zipPath      = MSP_PG_Utils::join_paths($artifactDir, 'artifact.zip');
        $manifestPath = MSP_PG_Utils::join_paths($artifactDir, 'evidence.json');
        $reportPath   = MSP_PG_Utils::join_paths($artifactDir, 'report.json');
        $markdownPath = MSP_PG_Utils::join_paths($artifactDir, 'report.md');
        $textPath     = MSP_PG_Utils::join_paths($artifactDir, 'report.txt');

        if ($dryRun) {
            $actions[] = 'DRY_RUN_ENABLED';
            $actions[] = 'WOULD_EVIDENCE_MANIFEST_CREATE';
            if ($evidenceMode === 'compressed_archive') {
                $actions[] = 'WOULD_EVIDENCE_ARCHIVE_CREATE';
            } elseif ($evidenceMode === 'full_artifact_retention') {
                $actions[] = 'WOULD_FULL_ARTIFACT_RETAIN';
            }
            $actions[] = 'WOULD_LIVE_ARTIFACT_REMOVE';

            return self::to_detection_record($analysis, $artifactDir, $manifestPath, '', '', $actions, $errors, $warnings, false, true, false);
        }

        MSP_PG_Utils::ensure_directory($artifactDir);

        $totalBytes  = is_file($livePath) ? (int) @filesize($livePath) : 0;
        $fingerprint = strtoupper(hash('sha256', wp_json_encode(array(
            'path'   => basename($livePath),
            'size'   => $totalBytes,
            'sha256' => MSP_PG_Utils::hash_file_safe($livePath),
        ))));

        $manifest = array(
            'family'                       => $analysis['family'],
            'classification'               => 'Confirmed Malware',
            'tier'                         => 'TIER1',
            'confidence'                   => $analysis['confidence'],
            'source'                       => $analysis['detection_source'],
            'action'                       => 'Pending Remediation',
            'detected_at'                  => gmdate('c'),
            'plugin_slug'                  => $analysis['plugin_slug'],
            'artifact_type'                => $analysis['artifact_type'],
            'file_count'                   => 1,
            'directory_count'              => 0,
            'total_bytes'                  => $totalBytes,
            'sha256_directory_fingerprint' => $fingerprint,
            'evidence_retention_mode'      => $evidenceMode,
            'variant_fingerprint'          => $analysis['variant_hash'],
            'dry_run'                      => false,
            'site_url'                     => $siteMeta['site_url'],
            'wordpress_version'            => $siteMeta['wordpress_version'],
            'php_version'                  => $siteMeta['php_version'],
            'exact_match_types'            => $analysis['exact_match_types'],
            'matched_indicators'           => $analysis['matched_indicators'],
            'payload_hashes'               => $analysis['payload_hashes'],
            'signature_version'            => MSP_PG_Config::signature_version(),
            'score'                        => $analysis['score'],
            'reasons'                      => $analysis['reasons'],
        );

        $evidenceArchiveCreated = false;
        if ($evidenceMode === 'compressed_archive' || $evidenceMode === 'full_artifact_retention') {
            $evidenceArchiveCreated = self::zip_single_file($livePath, $zipPath);
            $actions[] = $evidenceArchiveCreated ? 'EVIDENCE_ARCHIVE_CREATED' : 'EVIDENCE_ARCHIVE_FAILED';
        }

        $manifestOk = MSP_PG_Utils::write_json($manifestPath, $manifest);
        if ($manifestOk) {
            $actions[] = 'EVIDENCE_MANIFEST_CREATED';
        }

        $zipOk = ($evidenceMode === 'compressed_archive' || $evidenceMode === 'full_artifact_retention')
            ? ($evidenceArchiveCreated && is_readable($zipPath))
            : true;
        $preservationVerified = $manifestOk && is_readable($manifestPath) && $zipOk;

        if ($preservationVerified) {
            $actions[] = 'BUNDLE_VERIFIED';
        } else {
            $errors[] = 'Preservation verification failed; live artifact retained.';
        }

        if ($preservationVerified && MSP_PG_Config::doorway_content_gen_delete_enabled()) {
            if ($evidenceMode === 'full_artifact_retention') {
                $moved = MSP_PG_Utils::ensure_directory(dirname($quarantineDir)) && @rename($livePath, $quarantineDir);
                if ($moved) {
                    $actions[] = 'QUARANTINE_COMPLETED';
                    $actions[] = 'LIVE_ARTIFACT_REMOVED';
                } else {
                    $errors[] = 'Failed to move artifact into persistent quarantine after verified preservation.';
                }
            } else {
                $removed = @unlink($livePath);
                if ($removed) {
                    $actions[] = 'LIVE_ARTIFACT_REMOVED';
                } else {
                    $errors[] = 'Failed to remove live artifact after verified evidence preservation.';
                }
            }
        }

        $artifactReport = array(
            'plugin_slug'            => $analysis['plugin_slug'],
            'artifact_type'          => $analysis['artifact_type'],
            'live_path'              => $analysis['plugin_dir'],
            'artifact_dir'           => $artifactDir,
            'evidence_manifest_path' => $manifestPath,
            'tier'                   => $analysis['tier'],
            'score'                 => $analysis['score'],
            'confidence'             => $analysis['confidence'],
            'source'                 => $analysis['detection_source'],
            'reason_labels'          => array_values(array_map(function ($r) { return $r['label']; }, $analysis['reasons'])),
            'actions'                => $actions,
            'action_descriptions'    => MSP_PG_Utils::describe_actions($actions),
            'exact_match_types'      => $analysis['exact_match_types'],
            'matched_indicators'     => $analysis['matched_indicators'],
            'errors'                 => $errors,
            'warnings'               => $warnings,
            'protected_plugin'       => false,
            'variant_hash'           => $analysis['variant_hash'],
            'behavior_profiles'      => array(),
            'preservation_verified'  => $preservationVerified,
            'file_count'             => 1,
            'directory_count'        => 0,
            'total_bytes'            => $totalBytes,
            'sha256_directory_fingerprint' => $fingerprint,
        );

        MSP_PG_Utils::write_json($reportPath, $artifactReport);
        MSP_PG_Utils::write_text($markdownPath, self::artifact_markdown($artifactReport));
        MSP_PG_Utils::write_text($textPath, self::artifact_markdown($artifactReport));

        return self::to_detection_record(
            $analysis,
            $artifactDir,
            $manifestPath,
            in_array('QUARANTINE_COMPLETED', $actions, true) ? $quarantineDir : '',
            ($evidenceMode === 'compressed_archive' || $evidenceMode === 'full_artifact_retention') ? $zipPath : '',
            $actions,
            $errors,
            $warnings,
            $preservationVerified,
            true,
            in_array('LIVE_ARTIFACT_REMOVED', $actions, true) || in_array('QUARANTINE_COMPLETED', $actions, true)
        );
    }

    private static function artifact_key($analysis)
    {
        return preg_replace('/[^A-Za-z0-9_-]+/', '_', $analysis['plugin_slug']);
    }

    private static function zip_single_file($file, $zipPath)
    {
        if (!class_exists('ZipArchive')) {
            return false;
        }
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            return false;
        }
        $zip->addFile($file, basename($file));
        $zip->close();

        return file_exists($zipPath) && filesize($zipPath) > 0;
    }

    private static function artifact_markdown($artifactReport)
    {
        $lines = array(
            '# PG-DoorwayContentGenerator Artifact Report',
            '',
            '- Artifact: `' . $artifactReport['plugin_slug'] . '`',
            '- Live path: `' . $artifactReport['live_path'] . '`',
            '- Tier: `' . $artifactReport['tier'] . '`',
            '- Confidence: `' . $artifactReport['confidence'] . '`',
            '- Score: `' . $artifactReport['score'] . '`',
            '- Reasons: `' . implode(', ', $artifactReport['reason_labels']) . '`',
            '- Actions: `' . implode(', ', $artifactReport['actions']) . '`',
            '- Preservation verified: `' . ($artifactReport['preservation_verified'] ? 'yes' : 'no') . '`',
        );

        if (!empty($artifactReport['errors'])) {
            $lines[] = '';
            $lines[] = '## Errors';
            foreach ($artifactReport['errors'] as $e) {
                $lines[] = '- ' . $e;
            }
        }

        return implode("\n", $lines) . "\n";
    }

    private static function to_detection_record($analysis, $artifactDir, $manifestPath, $quarantinePath, $zipPath, $actions, $errors, $warnings, $preservationVerified, $bundleEligible, $fullyRemediated)
    {
        return array(
            'plugin_slug'             => $analysis['plugin_slug'],
            'live_path'               => $analysis['plugin_dir'],
            'artifact_dir'            => $artifactDir,
            'quarantine_path'         => $quarantinePath,
            'snapshot_path'           => '',
            'zip_path'                => $zipPath,
            'evidence_manifest_path'  => $manifestPath,
            'tier'                    => $analysis['tier'],
            'family'                  => $analysis['family'],
            'score'                   => $analysis['score'],
            'confidence'              => $analysis['confidence'],
            'source'                  => $analysis['detection_source'],
            'reason_labels'           => array_values(array_map(function ($r) { return $r['label']; }, $analysis['reasons'])),
            'exact_match_types'       => $analysis['exact_match_types'],
            'variant_hash'            => $analysis['variant_hash'],
            'payload_hashes'          => $analysis['payload_hashes'],
            'domains'                 => array(),
            'routes'                  => array(),
            'backdoor_indicators'     => array(),
            'structural_indicators'   => array(),
            'matched_indicators'      => $analysis['matched_indicators'],
            'actions'                 => $actions,
            'action_descriptions'     => MSP_PG_Utils::describe_actions($actions),
            'errors'                  => $errors,
            'warnings'                => $warnings,
            'protected_plugin'        => false,
            'preservation_verified'   => $preservationVerified,
            'bundle_eligible'         => $bundleEligible,
            'evidence_retention_mode' => MSP_PG_Config::evidence_retention_mode(),
            'behavior_profiles'       => array(),
            'fully_remediated'        => $fullyRemediated,
        );
    }
}
