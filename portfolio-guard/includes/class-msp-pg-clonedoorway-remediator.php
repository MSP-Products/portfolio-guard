<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Remediation for PG-ClonedDoorway detections produced by
 * MSP_PG_ClonedDoorway_Scanner::scan().
 *
 * MSP_PG_Remediator::remediate_detection() (the existing plugin-family
 * remediator) is untouched by this file. This class returns detection
 * records in the exact same shape it does, so MSP_PG_Remediator::run_scan()
 * can append them to the same $detections[] array and every existing report
 * renderer (MSP_PG_Utils::markdown_report/plain_text_report/html_report)
 * works on them unmodified.
 *
 * One deliberate behavioral difference from the plugin remediator: artifacts
 * of type ARTIFACT_MODIFIED_CORE_FILE (a legitimate WordPress file that was
 * altered in place, e.g. the web-root index.php) are ALWAYS report-only.
 * Portfolio Guard does not move, delete, or overwrite that file under any
 * configuration -- evidence is preserved via a *copy*, and the operator is
 * given an explicit restoration instruction instead. This is a hard
 * requirement, not a tunable: removing a site's front controller or silently
 * "restoring" WordPress core from an assumed-clean copy is out of scope and
 * was explicitly excluded from this feature.
 */
class MSP_PG_ClonedDoorway_Remediator
{
    public static function remediate($analysis, $siteMeta, $scanDir, $dryRun)
    {
        if ($analysis['artifact_type'] === MSP_PG_ClonedDoorway_Scanner::ARTIFACT_MODIFIED_CORE_FILE) {
            return self::remediate_modified_core_file($analysis, $siteMeta, $scanDir, $dryRun);
        }

        return self::remediate_attacker_created_artifact($analysis, $siteMeta, $scanDir, $dryRun);
    }

    // -------------------------------------------------------------------------
    // Legitimate file that was modified in place -- report-only, always.
    // -------------------------------------------------------------------------

    private static function remediate_modified_core_file($analysis, $siteMeta, $scanDir, $dryRun)
    {
        $actions = array('CONFIRMED_MALWARE_IDENTIFIED', 'REPORT_ONLY_MODIFIED_CORE_FILE');
        $errors  = array();
        $warnings = array(
            'This is a legitimate WordPress file that has been altered, not an attacker-created file. '
            . 'Portfolio Guard does not modify or remove it automatically.',
        );

        $artifactDir   = MSP_PG_Utils::join_paths($scanDir, 'artifacts', self::artifact_key($analysis));
        $manifestPath  = MSP_PG_Utils::join_paths($artifactDir, 'evidence.json');
        $reportPath    = MSP_PG_Utils::join_paths($artifactDir, 'report.json');
        $markdownPath  = MSP_PG_Utils::join_paths($artifactDir, 'report.md');
        $textPath      = MSP_PG_Utils::join_paths($artifactDir, 'report.txt');
        $evidenceCopyPath = MSP_PG_Utils::join_paths($artifactDir, 'quarantine', basename($analysis['plugin_dir']));

        $operatorAction = sprintf(
            'Restore %s from a clean WordPress core distribution matching this site\'s installed version '
            . '(%s). Do not simply delete this file -- it is required for WordPress to serve any request. '
            . 'After restoring, rotate wp-config.php secret keys/salts and any credentials that may have been '
            . 'exposed while the modified file was live.',
            $analysis['plugin_dir'],
            $siteMeta['wordpress_version']
        );
        $actions[] = 'OPERATOR_ACTION_REQUIRED';

        $preservationVerified = false;
        $evidenceCopied = false;

        if ($dryRun) {
            $actions[] = 'DRY_RUN_ENABLED';
            $actions[] = 'WOULD_EVIDENCE_MANIFEST_CREATE';
        } else {
            MSP_PG_Utils::ensure_directory($artifactDir);
            MSP_PG_Utils::ensure_directory(dirname($evidenceCopyPath));
            $evidenceCopied = @copy($analysis['plugin_dir'], $evidenceCopyPath);
            if ($evidenceCopied) {
                $actions[] = 'MODIFIED_FILE_EVIDENCE_COPIED';
            } else {
                $errors[] = 'Failed to copy modified core file into evidence storage; live file was not touched.';
            }
        }

        $manifest = array(
            'family'                  => $analysis['family'],
            'classification'          => 'Confirmed Malware',
            'tier'                    => 'TIER1',
            'confidence'              => $analysis['confidence'],
            'source'                  => $analysis['detection_source'],
            'action'                  => 'Reported — Manual Restoration Required',
            'detected_at'             => gmdate('c'),
            'plugin_slug'             => $analysis['plugin_slug'],
            'live_path'               => $analysis['plugin_dir'],
            'operator_action_required' => $operatorAction,
            'evidence_copy_path'      => $evidenceCopied ? $evidenceCopyPath : '',
            'sha256'                  => MSP_PG_Utils::hash_file_safe($analysis['plugin_dir']),
            'dry_run'                 => $dryRun,
            'site_url'                => $siteMeta['site_url'],
            'wordpress_version'       => $siteMeta['wordpress_version'],
            'php_version'             => $siteMeta['php_version'],
            'score'                   => $analysis['score'],
            'reasons'                 => $analysis['reasons'],
            'exact_match_types'       => $analysis['exact_match_types'],
            'matched_indicators'      => $analysis['matched_indicators'],
            'signature_version'       => MSP_PG_Config::signature_version(),
        );

        if (!$dryRun) {
            $manifestOk = MSP_PG_Utils::write_json($manifestPath, $manifest);
            $preservationVerified = $manifestOk && $evidenceCopied && is_readable($manifestPath) && is_readable($evidenceCopyPath);
            if ($preservationVerified) {
                $actions[] = 'EVIDENCE_MANIFEST_CREATED';
                $actions[] = 'BUNDLE_VERIFIED';
            } else {
                $errors[] = 'Evidence preservation for modified core file could not be fully verified.';
            }
        }

        $artifactReport = self::artifact_report($analysis, $artifactDir, $manifestPath, $actions, $errors, $warnings, $preservationVerified);
        $artifactReport['operator_action_required'] = $operatorAction;

        if (!$dryRun) {
            MSP_PG_Utils::write_json($reportPath, $artifactReport);
            MSP_PG_Utils::write_text($markdownPath, self::artifact_markdown($artifactReport, $manifest, $operatorAction));
            MSP_PG_Utils::write_text($textPath, self::artifact_markdown($artifactReport, $manifest, $operatorAction));
        }

        return self::to_detection_record($analysis, $artifactDir, $manifestPath, '', '', $actions, $errors, $warnings, $preservationVerified, true);
    }

    // -------------------------------------------------------------------------
    // Attacker-created artifacts (clone directories, loose loader files) --
    // full evidence-then-quarantine flow, mirroring MSP_PG_Remediator's tier1
    // sequencing for the existing plugin family (preserve first, verify, then
    // remove the live artifact).
    // -------------------------------------------------------------------------

    private static function remediate_attacker_created_artifact($analysis, $siteMeta, $scanDir, $dryRun)
    {
        $isDirectory = $analysis['artifact_type'] === MSP_PG_ClonedDoorway_Scanner::ARTIFACT_CLONE_DIRECTORY;
        $livePath    = $analysis['plugin_dir'];
        $actions     = array('CONFIRMED_MALWARE_IDENTIFIED');
        $errors      = array();
        $warnings    = array();

        $evidenceMode = MSP_PG_Config::evidence_retention_mode();
        $artifactDir  = MSP_PG_Utils::join_paths($scanDir, 'artifacts', self::artifact_key($analysis));
        $quarantineDir = MSP_PG_Utils::join_paths($artifactDir, 'quarantine', basename($livePath));
        $snapshotDir   = MSP_PG_Utils::join_paths($artifactDir, 'snapshot', basename($livePath));
        $zipPath       = MSP_PG_Utils::join_paths($artifactDir, 'artifact.zip');
        $manifestPath  = MSP_PG_Utils::join_paths($artifactDir, 'evidence.json');
        $reportPath    = MSP_PG_Utils::join_paths($artifactDir, 'report.json');
        $markdownPath  = MSP_PG_Utils::join_paths($artifactDir, 'report.md');
        $textPath      = MSP_PG_Utils::join_paths($artifactDir, 'report.txt');

        if ($dryRun) {
            $actions[] = 'DRY_RUN_ENABLED';
            $actions[] = 'WOULD_EVIDENCE_MANIFEST_CREATE';
            if ($evidenceMode === 'compressed_archive') {
                $actions[] = 'WOULD_EVIDENCE_ARCHIVE_CREATE';
            } elseif ($evidenceMode === 'full_artifact_retention') {
                $actions[] = 'WOULD_FULL_ARTIFACT_RETAIN';
            }
            $actions[] = 'WOULD_LIVE_ARTIFACT_REMOVE';

            $artifactReport = self::artifact_report($analysis, $artifactDir, $manifestPath, $actions, $errors, $warnings, false);

            return self::to_detection_record($analysis, $artifactDir, $manifestPath, '', '', $actions, $errors, $warnings, false, true);
        }

        MSP_PG_Utils::ensure_directory($artifactDir);

        if ($isDirectory) {
            $fileCount  = (int) MSP_PG_Utils::directory_counts($livePath)['file_count'];
            $dirCount   = (int) MSP_PG_Utils::directory_counts($livePath)['directory_count'];
            $totalBytes = (int) MSP_PG_Utils::directory_size($livePath);
            $fingerprint = MSP_PG_Utils::directory_fingerprint($livePath);
        } else {
            $fileCount   = 1;
            $dirCount    = 0;
            $totalBytes  = (int) filesize($livePath);
            $fingerprint = self::single_file_fingerprint($livePath);
        }

        $hashes = $evidenceMode === 'full_artifact_retention' && $isDirectory
            ? MSP_PG_Utils::hash_directory($livePath)
            : array();

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
            'routes'                       => array(),
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

        if ($preservationVerified && MSP_PG_Config::cloned_doorway_delete_enabled()) {
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
        }

        // Correct the manifest's outcome field to the actual result -- the
        // earlier write (line 241 above) necessarily still says 'Pending
        // Remediation', since it happens before the removal decision, by
        // design, so evidence exists on disk BEFORE any destructive action
        // is taken. This second write is what makes the manifest an
        // accurate final record instead of a stale snapshot of intent --
        // same pattern applied to MSP_PG_SC_Remediator, MSP_PG_WLH_Remediator,
        // and MSP_PG_DoorwayGen_Remediator; this class had the same gap they
        // did and is being brought into line with the original plugin
        // remediator's established two-write behavior.
        if (in_array('LIVE_ARTIFACT_REMOVED', $actions, true) && in_array('QUARANTINE_COMPLETED', $actions, true)) {
            $manifest['action'] = 'Quarantined';
        } elseif (in_array('LIVE_ARTIFACT_REMOVED', $actions, true)) {
            $manifest['action'] = 'Removed';
        } else {
            $manifest['action'] = 'Preserved Evidence';
        }
        MSP_PG_Utils::write_json($manifestPath, $manifest);

        $artifactReport = self::artifact_report($analysis, $artifactDir, $manifestPath, $actions, $errors, $warnings, $preservationVerified);
        $artifactReport['file_count'] = $fileCount;
        $artifactReport['directory_count'] = $dirCount;
        $artifactReport['total_bytes'] = $totalBytes;
        $artifactReport['sha256_directory_fingerprint'] = $fingerprint;

        MSP_PG_Utils::write_json($reportPath, $artifactReport);
        MSP_PG_Utils::write_text($markdownPath, self::artifact_markdown($artifactReport, $manifest, ''));
        MSP_PG_Utils::write_text($textPath, self::artifact_markdown($artifactReport, $manifest, ''));

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
            true
        );
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    private static function artifact_key($analysis)
    {
        return preg_replace('/[^A-Za-z0-9_-]+/', '_', $analysis['plugin_slug']);
    }

    private static function single_file_fingerprint($file)
    {
        $row = wp_json_encode(array(
            'path'   => basename($file),
            'size'   => (int) filesize($file),
            'sha256' => MSP_PG_Utils::hash_file_safe($file),
        ));

        return strtoupper(hash('sha256', $row));
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
     * Symlink-safe recursive delete -- see MSP_PG_Remediator::delete_directory()
     * for the full rationale (RecursiveDirectoryIterator follows symlinked
     * subdirectories during traversal by default; walked manually here so a
     * planted symlink inside an artifact directory is unlinked as a leaf and
     * never entered).
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
            'plugin_slug'         => $analysis['plugin_slug'],
            'artifact_type'       => $analysis['artifact_type'],
            'live_path'           => $analysis['plugin_dir'],
            'artifact_dir'        => $artifactDir,
            'evidence_manifest_path' => $manifestPath,
            'tier'                => $analysis['tier'],
            'score'               => $analysis['score'],
            'confidence'          => $analysis['confidence'],
            'source'              => $analysis['detection_source'],
            'reason_labels'       => array_values(array_map(function ($reason) { return $reason['label']; }, $analysis['reasons'])),
            'actions'             => $actions,
            'action_descriptions' => MSP_PG_Utils::describe_actions($actions),
            'exact_match_types'   => $analysis['exact_match_types'],
            'matched_indicators'  => $analysis['matched_indicators'],
            'errors'              => $errors,
            'warnings'            => $warnings,
            'protected_plugin'    => false,
            'variant_hash'        => $analysis['variant_hash'],
            'behavior_profiles'   => array(),
            'preservation_verified' => $preservationVerified,
        );
    }

    private static function artifact_markdown($artifactReport, $manifest, $operatorAction)
    {
        $lines = array(
            '# PG-ClonedDoorway Artifact Report',
            '',
            '- Artifact: `' . $artifactReport['plugin_slug'] . '`',
            '- Artifact type: `' . $artifactReport['artifact_type'] . '`',
            '- Live path: `' . $artifactReport['live_path'] . '`',
            '- Tier: `' . $artifactReport['tier'] . '`',
            '- Confidence: `' . $artifactReport['confidence'] . '`',
            '- Source: `' . $artifactReport['source'] . '`',
            '- Score: `' . $artifactReport['score'] . '`',
            '- Reasons: `' . implode(', ', $artifactReport['reason_labels']) . '`',
            '- Actions: `' . implode(', ', $artifactReport['actions']) . '`',
            '- Preservation verified: `' . ($artifactReport['preservation_verified'] ? 'yes' : 'no') . '`',
        );

        if ($operatorAction !== '') {
            $lines[] = '';
            $lines[] = '## Operator Action Required';
            $lines[] = '';
            $lines[] = $operatorAction;
        }

        if (!empty($artifactReport['warnings'])) {
            $lines[] = '';
            $lines[] = '## Warnings';
            foreach ($artifactReport['warnings'] as $warning) {
                $lines[] = '- ' . $warning;
            }
        }

        if (!empty($artifactReport['errors'])) {
            $lines[] = '';
            $lines[] = '## Errors';
            foreach ($artifactReport['errors'] as $error) {
                $lines[] = '- ' . $error;
            }
        }

        return implode("\n", $lines) . "\n";
    }

    private static function to_detection_record($analysis, $artifactDir, $manifestPath, $quarantinePath, $zipPath, $actions, $errors, $warnings, $preservationVerified, $bundleEligible)
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
            'reason_labels'           => array_values(array_map(function ($reason) { return $reason['label']; }, $analysis['reasons'])),
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
        );
    }
}
