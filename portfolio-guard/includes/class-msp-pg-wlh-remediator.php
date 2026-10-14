<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Remediation for PG-WPLinkHelper detections produced by
 * MSP_PG_WLH_Scanner::scan().
 *
 * Both artifact types here (mu-plugin file, backup directory) are
 * standalone, wholly attacker-created filesystem objects -- never a
 * modification of a legitimate file -- so both are eligible for the same
 * real evidence-then-quarantine-then-remove sequence the other remediators
 * use, reusing the same MSP_PG_Utils primitives.
 *
 * Per this family's explicit remediation rule, re-validated independently
 * here rather than trusted from the scanner's classification: a backup
 * directory's NAME match is never sufficient on its own to authorize
 * deletion. MSP_PG_WLH_Scanner already never reports a backup-directory
 * detection without a corroborating content-level hit (see
 * build_backup_directory_analysis()), but this remediator re-checks that
 * invariant explicitly before allowing removal, rather than trusting that
 * invariant to hold without verification.
 */
class MSP_PG_WLH_Remediator
{
    public static function remediate($analysis, $siteMeta, $scanDir, $dryRun)
    {
        $isDirectory = $analysis['artifact_type'] === MSP_PG_WLH_Scanner::ARTIFACT_BACKUP_DIRECTORY;
        $livePath    = $analysis['plugin_dir'];
        $actions     = array('CONFIRMED_MALWARE_IDENTIFIED');
        $errors      = array();
        $warnings    = array();

        // Independent re-validation: at least one content-level signature
        // (not merely the corroborating directory-name match) must be
        // present. backup_dir_name/known_domain alone (with no hash/IOC/
        // vault hit) is deliberately NOT treated as sufficient here even
        // though the scanner structurally guarantees more than that today --
        // this remediator does not trust that guarantee blindly.
        // Deliberately no ">= N corroborating signatures" fallback here
        // (unlike the plugin loop's/other families' canDeleteOriginal gate):
        // per this family's explicit remediation rule, only an
        // independently-validated high-confidence content signature or an
        // exact known hash authorizes removal -- known_domain and
        // backup_dir_name are corroborating-only and must never combine to
        // reach a deletion decision on their own, however many of them fire.
        $highConfidenceTypes = array('known_payload_hash', 'ioc_string', 'vault_derivation');
        $canDeleteOriginal = !empty(array_intersect($highConfidenceTypes, $analysis['exact_match_types']));

        $evidenceMode  = MSP_PG_Config::evidence_retention_mode();
        $artifactDir   = MSP_PG_Utils::join_paths($scanDir, 'artifacts', self::artifact_key($analysis));
        $quarantineDir = MSP_PG_Utils::join_paths($artifactDir, 'quarantine', basename($livePath));
        $snapshotDir   = MSP_PG_Utils::join_paths($artifactDir, 'snapshot', basename($livePath));
        $zipPath       = MSP_PG_Utils::join_paths($artifactDir, 'artifact.zip');
        $manifestPath  = MSP_PG_Utils::join_paths($artifactDir, 'evidence.json');
        $reportPath    = MSP_PG_Utils::join_paths($artifactDir, 'report.json');
        $markdownPath  = MSP_PG_Utils::join_paths($artifactDir, 'report.md');
        $textPath      = MSP_PG_Utils::join_paths($artifactDir, 'report.txt');

        if (!$canDeleteOriginal) {
            $actions[] = 'REMOVAL_WITHHELD_INSUFFICIENT_CONFIDENCE';
            $warnings[] = 'Directory-name match alone is never sufficient to authorize removal of this family\'s backup directory; no independently-validated content signature was present.';
        }

        if ($dryRun) {
            $actions[] = 'DRY_RUN_ENABLED';
            $actions[] = 'WOULD_EVIDENCE_MANIFEST_CREATE';
            if ($canDeleteOriginal) {
                if ($evidenceMode === 'compressed_archive') {
                    $actions[] = 'WOULD_EVIDENCE_ARCHIVE_CREATE';
                } elseif ($evidenceMode === 'full_artifact_retention') {
                    $actions[] = 'WOULD_FULL_ARTIFACT_RETAIN';
                }
                if (MSP_PG_Config::wp_link_helper_delete_enabled()) {
                    $actions[] = 'WOULD_LIVE_ARTIFACT_REMOVE';
                }
            }

            return self::to_detection_record($analysis, $artifactDir, $manifestPath, '', '', $actions, $errors, $warnings, false, true, false);
        }

        MSP_PG_Utils::ensure_directory($artifactDir);

        if ($isDirectory) {
            $counts      = MSP_PG_Utils::directory_counts($livePath);
            $fileCount   = (int) $counts['file_count'];
            $dirCount    = (int) $counts['directory_count'];
            $totalBytes  = (int) MSP_PG_Utils::directory_size($livePath);
            $fingerprint = MSP_PG_Utils::directory_fingerprint($livePath);
        } else {
            $fileCount   = 1;
            $dirCount    = 0;
            $totalBytes  = is_file($livePath) ? (int) @filesize($livePath) : 0;
            $fingerprint = strtoupper(hash('sha256', wp_json_encode(array(
                'path'   => basename($livePath),
                'size'   => $totalBytes,
                'sha256' => MSP_PG_Utils::hash_file_safe($livePath),
            ))));
        }

        $hashes = ($evidenceMode === 'full_artifact_retention' && $isDirectory) ? MSP_PG_Utils::hash_directory($livePath) : array();

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
            'file_count'                   => $fileCount,
            'directory_count'              => $dirCount,
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
            'hashes'                       => $hashes,
            'domains'                      => $analysis['domains'],
            'structural_indicators'        => $analysis['structural_indicators'],
            'signature_version'            => MSP_PG_Config::signature_version(),
            'score'                        => $analysis['score'],
            'reasons'                      => $analysis['reasons'],
        );

        $evidenceArchiveCreated = false;
        if ($evidenceMode === 'compressed_archive') {
            $evidenceArchiveCreated = $isDirectory
                ? MSP_PG_Utils::zip_directory($livePath, $zipPath)
                : self::zip_single_file($livePath, $zipPath);
            $actions[] = $evidenceArchiveCreated ? 'EVIDENCE_ARCHIVE_CREATED' : 'EVIDENCE_ARCHIVE_FAILED';
        } elseif ($evidenceMode === 'full_artifact_retention') {
            $copied = $isDirectory
                ? MSP_PG_Utils::copy_directory($livePath, $snapshotDir)
                : (MSP_PG_Utils::ensure_directory(dirname($snapshotDir)) && @copy($livePath, $snapshotDir));
            if ($copied) {
                $actions[] = 'FULL_ARTIFACT_SNAPSHOT_CREATED';
                $evidenceArchiveCreated = MSP_PG_Utils::zip_directory($artifactDir, $zipPath);
            } else {
                $errors[] = 'Failed to create evidence snapshot.';
            }
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

        if ($preservationVerified && $canDeleteOriginal && MSP_PG_Config::wp_link_helper_delete_enabled()) {
            if ($evidenceMode === 'full_artifact_retention') {
                $moved = $isDirectory
                    ? MSP_PG_Utils::move_directory($livePath, $quarantineDir)
                    : (MSP_PG_Utils::ensure_directory(dirname($quarantineDir)) && @rename($livePath, $quarantineDir));
                if ($moved) {
                    $actions[] = 'QUARANTINE_COMPLETED';
                    $actions[] = 'LIVE_ARTIFACT_REMOVED';
                } else {
                    $errors[] = 'Failed to move artifact into persistent quarantine after verified preservation.';
                }
            } else {
                $removed = $isDirectory ? self::delete_directory($livePath) : @unlink($livePath);
                if ($removed) {
                    $actions[] = 'LIVE_ARTIFACT_REMOVED';
                } else {
                    $errors[] = 'Failed to remove live artifact after verified evidence preservation.';
                }
            }
        } elseif ($preservationVerified && $canDeleteOriginal && !MSP_PG_Config::wp_link_helper_delete_enabled()) {
            // Evidence was verified and confidence was sufficient -- the
            // artifact was eligible for removal, but this family's delete
            // flag is configured off. Recorded explicitly so an operator
            // can tell a deliberate configuration choice (e.g. a canary
            // deployment) apart from an unexplained gap -- see
            // MSP_PG_SC_Remediator's identical fix for the full rationale.
            $actions[] = 'REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION';
        }

        // Correct the manifest's outcome fields to the actual result -- see
        // MSP_PG_SC_Remediator's identical fix for the full rationale.
        if (in_array('LIVE_ARTIFACT_REMOVED', $actions, true) && in_array('QUARANTINE_COMPLETED', $actions, true)) {
            $manifest['action'] = 'Quarantined';
            $manifest['remediation_status'] = 'Quarantined';
        } elseif (in_array('LIVE_ARTIFACT_REMOVED', $actions, true)) {
            $manifest['action'] = 'Removed';
            $manifest['remediation_status'] = 'Removed';
        } else {
            $manifest['action'] = 'Preserved Evidence';
            $manifest['remediation_status'] = 'Evidence Preserved — Removal Withheld';
        }
        MSP_PG_Utils::write_json($manifestPath, $manifest);

        $artifactReport = self::artifact_report($analysis, $artifactDir, $manifestPath, $actions, $errors, $warnings, $preservationVerified);
        $artifactReport['file_count'] = $fileCount;
        $artifactReport['directory_count'] = $dirCount;
        $artifactReport['total_bytes'] = $totalBytes;
        $artifactReport['sha256_directory_fingerprint'] = $fingerprint;

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

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

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

    /**
     * Symlink-safe recursive delete -- see MSP_PG_SC_Remediator::delete_directory()
     * for the full rationale. RecursiveDirectoryIterator follows symlinked
     * subdirectories during traversal by default; walked manually here so a
     * planted symlink is unlinked as a leaf and never entered.
     */
    private static function delete_directory($dir)
    {
        if (is_link($dir)) {
            return @unlink($dir);
        }
        if (!is_dir($dir)) {
            return false;
        }

        foreach (@scandir($dir) ?: array() as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = MSP_PG_Utils::join_paths($dir, $entry);
            if (is_link($path)) {
                @unlink($path);
            } elseif (is_dir($path)) {
                self::delete_directory($path);
            } else {
                @unlink($path);
            }
        }
        return @rmdir($dir);
    }

    private static function artifact_report($analysis, $artifactDir, $manifestPath, $actions, $errors, $warnings, $preservationVerified)
    {
        return array(
            'plugin_slug'            => $analysis['plugin_slug'],
            'artifact_type'          => $analysis['artifact_type'],
            'live_path'              => $analysis['plugin_dir'],
            'artifact_dir'           => $artifactDir,
            'evidence_manifest_path' => $manifestPath,
            'tier'                   => $analysis['tier'],
            'score'                  => $analysis['score'],
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
        );
    }

    private static function artifact_markdown($artifactReport)
    {
        $lines = array(
            '# PG-WPLinkHelper Artifact Report',
            '',
            '- Artifact: `' . $artifactReport['plugin_slug'] . '`',
            '- Artifact type: `' . $artifactReport['artifact_type'] . '`',
            '- Live path: `' . $artifactReport['live_path'] . '`',
            '- Tier: `' . $artifactReport['tier'] . '`',
            '- Confidence: `' . $artifactReport['confidence'] . '`',
            '- Score: `' . $artifactReport['score'] . '`',
            '- Reasons: `' . implode(', ', $artifactReport['reason_labels']) . '`',
            '- Actions: `' . implode(', ', $artifactReport['actions']) . '`',
            '- Preservation verified: `' . ($artifactReport['preservation_verified'] ? 'yes' : 'no') . '`',
        );

        if (!empty($artifactReport['warnings'])) {
            $lines[] = '';
            $lines[] = '## Warnings';
            foreach ($artifactReport['warnings'] as $w) {
                $lines[] = '- ' . $w;
            }
        }
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
            'domains'                 => $analysis['domains'],
            'routes'                  => array(),
            'backdoor_indicators'     => array(),
            'structural_indicators'   => $analysis['structural_indicators'],
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
