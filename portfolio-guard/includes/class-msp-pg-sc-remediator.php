<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Remediation for PG-SC-MacroOptimizerCue detections produced by
 * MSP_PG_SC_Scanner::scan().
 *
 * Reuses the exact evidence-first safety sequence MSP_PG_Remediator and
 * MSP_PG_ClonedDoorway_Remediator already use (write + verify evidence
 * before any destructive action; shared MSP_PG_Utils primitives for
 * move/copy/zip/hash; independent per-scope delete flags) -- no new
 * remediation framework is introduced here.
 *
 * Per-artifact-type remediation eligibility (a Tier 1 detection does NOT by
 * itself imply an artifact may be removed automatically):
 *
 *  - ARTIFACT_MU_PLUGIN_FILE / ARTIFACT_HIDDEN_STATE_DIRECTORY: standalone,
 *    wholly attacker-created artifacts, not mixed with any legitimate
 *    content. Eligible for the real evidence-then-quarantine-then-remove
 *    sequence, gated by MSP_PG_Config::sc_macro_cue_delete_enabled() and a
 *    confidence gate requiring either a known payload hash or at least two
 *    corroborating exact-match signatures (mirrors
 *    MSP_PG_Remediator::remediate_detection()'s $canDeleteOriginal gate).
 *
 *  - ARTIFACT_DROPIN_FILE: ALWAYS report-only, unconditionally, regardless
 *    of configuration. advanced-cache.php/db.php/object-cache.php are
 *    legitimately owned by caching plugins and can contain this family's
 *    injected stub prepended to genuine content (confirmed by specimen
 *    diff: a verified WP Rocket tail survived untouched alongside the
 *    injected block in one recovered copy). The BEGIN/END injection-marker
 *    pairing needed to split "malicious stub" from "legitimate tail" safely
 *    was only independently confirmed for advanced-cache.php, not for
 *    db.php or object-cache.php -- this implementation does not attempt
 *    that split automatically. Portfolio Guard reports the exact marker
 *    found and an explicit operator action, never edits the live file.
 *
 *  - ARTIFACT_WPINCLUDES_RECOVERY_FILE: real removal is possible but gated
 *    behind FOUR independent, non-bypassable conditions, all required
 *    simultaneously (see remediate_wpincludes_file()) -- filename pattern
 *    match (already required to reach this method), symlink rejection,
 *    strict realpath containment inside wp-includes/, and an independently
 *    re-validated SC-specific content signature. A pattern-matched filename
 *    with no readable/matching content (e.g. an empty throttle-marker
 *    sibling file) is NEVER removed -- it is always report-only. This is a
 *    hard rule, not a configuration option.
 */
class MSP_PG_SC_Remediator
{
    public static function remediate($analysis, $siteMeta, $scanDir, $dryRun)
    {
        if ($analysis['artifact_type'] === MSP_PG_SC_Scanner::ARTIFACT_DROPIN_FILE) {
            return self::remediate_report_only(
                $analysis,
                $siteMeta,
                $scanDir,
                $dryRun,
                'This file is a WordPress wp-content drop-in (advanced-cache.php/db.php/object-cache.php) that may legitimately be owned by an active caching plugin. '
                . 'Portfolio Guard does not modify or remove it automatically: the injected block cannot yet be safely separated from any legitimate content it may '
                . 'be wrapping without risking damage to a live caching integration.',
                sprintf(
                    'Manually inspect %s for the injected comment block beginning `/* SC_*_BEGIN:... */` and ending `/* SC_*_END:... */`, remove only that block, '
                    . 'and verify the owning caching plugin (if any) still functions correctly afterward. If no legitimate content remains, delete the file and let '
                    . 'the owning caching plugin regenerate it.',
                    $analysis['plugin_dir']
                )
            );
        }

        if ($analysis['artifact_type'] === MSP_PG_SC_Scanner::ARTIFACT_WPINCLUDES_RECOVERY_FILE) {
            return self::remediate_wpincludes_file($analysis, $siteMeta, $scanDir, $dryRun);
        }

        return self::remediate_attacker_created_artifact($analysis, $siteMeta, $scanDir, $dryRun);
    }

    // -------------------------------------------------------------------------
    // wp-content drop-ins -- always report-only
    // -------------------------------------------------------------------------

    private static function remediate_report_only($analysis, $siteMeta, $scanDir, $dryRun, $warningText, $operatorAction)
    {
        $actions  = array('CONFIRMED_MALWARE_IDENTIFIED', 'REPORT_ONLY_NO_AUTOMATIC_REMOVAL', 'OPERATOR_ACTION_REQUIRED');
        $errors   = array();
        $warnings = array($warningText);

        $artifactDir  = MSP_PG_Utils::join_paths($scanDir, 'artifacts', self::artifact_key($analysis));
        $manifestPath = MSP_PG_Utils::join_paths($artifactDir, 'evidence.json');
        $reportPath   = MSP_PG_Utils::join_paths($artifactDir, 'report.json');
        $markdownPath = MSP_PG_Utils::join_paths($artifactDir, 'report.md');
        $textPath     = MSP_PG_Utils::join_paths($artifactDir, 'report.txt');
        $evidenceCopyPath = MSP_PG_Utils::join_paths($artifactDir, 'evidence-copy', basename($analysis['plugin_dir']));

        $preservationVerified = false;
        $evidenceCopied = false;

        if ($dryRun) {
            $actions[] = 'DRY_RUN_ENABLED';
            $actions[] = 'WOULD_EVIDENCE_MANIFEST_CREATE';
        } else {
            MSP_PG_Utils::ensure_directory($artifactDir);
            MSP_PG_Utils::ensure_directory(dirname($evidenceCopyPath));
            $evidenceCopied = is_file($analysis['plugin_dir']) && @copy($analysis['plugin_dir'], $evidenceCopyPath);
            if (!$evidenceCopied) {
                $errors[] = 'Failed to copy artifact into evidence storage; live file was not touched.';
            }
        }

        $manifest = array(
            'family'                   => $analysis['family'],
            'classification'           => 'Confirmed Malware',
            'tier'                     => 'TIER1',
            'confidence'               => $analysis['confidence'],
            'source'                   => $analysis['detection_source'],
            'action'                   => 'Reported — Manual Action Required',
            'remediation_status'       => 'Reported — Outstanding',
            'detected_at'              => gmdate('c'),
            'plugin_slug'              => $analysis['plugin_slug'],
            'artifact_type'            => $analysis['artifact_type'],
            'live_path'                => $analysis['plugin_dir'],
            'operator_action_required' => $operatorAction,
            'evidence_copy_path'       => $evidenceCopied ? $evidenceCopyPath : '',
            'sha256'                   => is_file($analysis['plugin_dir']) ? MSP_PG_Utils::hash_file_safe($analysis['plugin_dir']) : '',
            'dry_run'                  => $dryRun,
            'site_url'                 => $siteMeta['site_url'],
            'wordpress_version'        => $siteMeta['wordpress_version'],
            'php_version'              => $siteMeta['php_version'],
            'score'                    => $analysis['score'],
            'reasons'                  => $analysis['reasons'],
            'exact_match_types'        => $analysis['exact_match_types'],
            'matched_indicators'       => $analysis['matched_indicators'],
            'signature_version'        => MSP_PG_Config::signature_version(),
        );

        if (!$dryRun) {
            $manifestOk = MSP_PG_Utils::write_json($manifestPath, $manifest);
            $preservationVerified = $manifestOk && $evidenceCopied && is_readable($manifestPath) && is_readable($evidenceCopyPath);
            if ($preservationVerified) {
                $actions[] = 'EVIDENCE_MANIFEST_CREATED';
                $actions[] = 'BUNDLE_VERIFIED';
            } else {
                $errors[] = 'Evidence preservation could not be fully verified.';
            }
        }

        $artifactReport = self::artifact_report($analysis, $artifactDir, $manifestPath, $actions, $errors, $warnings, $preservationVerified);
        $artifactReport['operator_action_required'] = $operatorAction;

        if (!$dryRun) {
            MSP_PG_Utils::write_json($reportPath, $artifactReport);
            MSP_PG_Utils::write_text($markdownPath, self::artifact_markdown($artifactReport, $operatorAction));
            MSP_PG_Utils::write_text($textPath, self::artifact_markdown($artifactReport, $operatorAction));
        }

        return self::to_detection_record($analysis, $artifactDir, $manifestPath, '', '', $actions, $errors, $warnings, $preservationVerified, true, false);
    }

    // -------------------------------------------------------------------------
    // wp-includes/ recovery-loader files -- real removal only behind four
    // simultaneous, non-bypassable conditions.
    // -------------------------------------------------------------------------

    private static function remediate_wpincludes_file($analysis, $siteMeta, $scanDir, $dryRun)
    {
        $file = $analysis['plugin_dir'];
        // Validated against the same root the scanner used (threaded through
        // via $analysis['scan_root']), falling back to re-querying config
        // only if that's absent -- see MSP_PG_SC_Scanner::scan_wpincludes_recovery_files().
        $scanRoot = isset($analysis['scan_root']) && $analysis['scan_root'] !== ''
            ? $analysis['scan_root']
            : MSP_PG_Config::sc_macro_cue_scan_root();
        $wpIncludesRoot = realpath(MSP_PG_Utils::join_paths($scanRoot, 'wp-includes'));

        // Condition 1: filename pattern -- already true, MSP_PG_SC_Scanner only
        // ever creates this artifact type for a filename matching the
        // registry's wpincludes_recovery_file_pattern().

        // Condition 2: explicit symlink rejection.
        $isSymlink = is_link($file);

        // Condition 3: strict filesystem boundary validation. realpath() of
        // the candidate must resolve to inside wp-includes/ with no
        // traversal/symlink escape. A symlink already fails this
        // unconditionally (realpath() on a symlink resolves through it,
        // which is exactly the escape this check exists to catch, and the
        // explicit is_link() check above is kept as an independent,
        // redundant guard rather than relying on realpath() alone).
        $realFile = $isSymlink ? false : realpath($file);
        $boundaryOk = $wpIncludesRoot !== false
            && $realFile !== false
            && strpos($realFile, $wpIncludesRoot . DIRECTORY_SEPARATOR) === 0;

        // Condition 4: independently re-validated SC-specific content
        // signature -- re-read and re-check here rather than trusting the
        // scanner's classification, per this family's explicit requirement
        // that a filename match alone must never authorize deletion.
        $contentSignatureOk = false;
        if ($boundaryOk && is_readable($realFile) && (int) filesize($realFile) <= MSP_PG_Config::max_scan_file_bytes() * 10) {
            $content = @file_get_contents($realFile);
            if ($content !== false && $content !== '') {
                $hash = strtoupper(hash('sha256', $content));
                $contentSignatureOk = in_array($hash, MSP_PG_SC_Signatures::known_payload_hashes(), true)
                    || MSP_PG_SC_Signatures::has_version_stamp($content)
                    || MSP_PG_SC_Signatures::has_helper_function_set($content);
            }
        }

        $removalEligible = !$isSymlink && $boundaryOk && $contentSignatureOk
            && MSP_PG_Config::sc_macro_cue_delete_enabled()
            && MSP_PG_Config::sc_macro_cue_wpincludes_delete_enabled();

        if (!$removalEligible) {
            $reasonParts = array();
            if ($isSymlink) {
                $reasonParts[] = 'the matched path is a symlink';
            }
            if (!$boundaryOk) {
                $reasonParts[] = 'the matched path did not resolve strictly inside wp-includes/';
            }
            if (!$contentSignatureOk) {
                $reasonParts[] = 'no independently-verified SC-specific content signature was found (filename pattern alone is never sufficient)';
            }
            if ($boundaryOk && $contentSignatureOk && !MSP_PG_Config::sc_macro_cue_wpincludes_delete_enabled()) {
                $reasonParts[] = 'wp-includes removal is disabled by configuration';
            }

            return self::remediate_report_only(
                $analysis,
                $siteMeta,
                $scanDir,
                $dryRun,
                'This file matches the PG-SC-MacroOptimizerCue recovery-loader naming convention inside wp-includes/, but automatic removal was withheld because: '
                . implode('; ', $reasonParts) . '.',
                sprintf('Manually verify and remove %s after confirming it is not a legitimate WordPress core file.', $file)
            );
        }

        return self::remediate_attacker_created_artifact($analysis, $siteMeta, $scanDir, $dryRun, true);
    }

    // -------------------------------------------------------------------------
    // Standalone attacker-created artifacts (mu-plugin file, hidden state
    // directory, and verified-eligible wp-includes recovery files) --
    // full evidence-then-quarantine-then-remove sequence.
    // -------------------------------------------------------------------------

    private static function remediate_attacker_created_artifact($analysis, $siteMeta, $scanDir, $dryRun, $isWpIncludesVerified = false)
    {
        $isDirectory = $analysis['artifact_type'] === MSP_PG_SC_Scanner::ARTIFACT_HIDDEN_STATE_DIRECTORY;
        $livePath    = $analysis['plugin_dir'];
        $actions     = array('CONFIRMED_MALWARE_IDENTIFIED');
        $errors      = array();
        $warnings    = array();

        $canDeleteOriginal = in_array('known_payload_hash', $analysis['exact_match_types'], true)
            || count($analysis['exact_match_types']) >= 2
            || $isWpIncludesVerified;

        $evidenceMode  = MSP_PG_Config::evidence_retention_mode();
        $artifactDir   = MSP_PG_Utils::join_paths($scanDir, 'artifacts', self::artifact_key($analysis));
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
            if (MSP_PG_Config::sc_macro_cue_delete_enabled()) {
                $actions[] = 'WOULD_LIVE_ARTIFACT_REMOVE';
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

        // TOCTOU closure: for the wp-includes/ path specifically, re-run the
        // symlink/boundary guard immediately before the destructive action,
        // not just once at the top of remediate_wpincludes_file(). Evidence
        // writing/hashing above takes measurable time, during which the
        // filesystem could change (e.g. the file swapped for a symlink by a
        // concurrent attacker process). The earlier validation establishes
        // eligibility; this one is the actual go/no-go gate immediately
        // before unlink().
        if ($isWpIncludesVerified && $canDeleteOriginal) {
            $scanRootForRecheck = isset($analysis['scan_root']) && $analysis['scan_root'] !== '' ? $analysis['scan_root'] : MSP_PG_Config::sc_macro_cue_scan_root();
            $wpIncludesRootForRecheck = realpath(MSP_PG_Utils::join_paths($scanRootForRecheck, 'wp-includes'));
            $realLivePathForRecheck = is_link($livePath) ? false : realpath($livePath);
            $stillSafe = $wpIncludesRootForRecheck !== false
                && $realLivePathForRecheck !== false
                && strpos($realLivePathForRecheck, $wpIncludesRootForRecheck . DIRECTORY_SEPARATOR) === 0;
            if (!$stillSafe) {
                $canDeleteOriginal = false;
                $errors[] = 'Re-validation immediately before removal failed (path changed, became a symlink, or left the wp-includes/ boundary since initial validation); removal aborted.';
            }
        }

        if ($preservationVerified && $canDeleteOriginal && MSP_PG_Config::sc_macro_cue_delete_enabled()) {
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
        } elseif (!$canDeleteOriginal) {
            $actions[] = 'REMOVAL_WITHHELD_INSUFFICIENT_CONFIDENCE';
        } elseif ($preservationVerified && !MSP_PG_Config::sc_macro_cue_delete_enabled()) {
            // Evidence was verified and confidence was sufficient -- the
            // artifact was eligible for removal, but this family's delete
            // flag is configured off (e.g. a canary deployment running with
            // detection enabled and automatic deletion disabled). This must
            // be recorded explicitly: the absence of LIVE_ARTIFACT_REMOVED
            // here is a deliberate configuration choice, not an unexplained
            // gap, and an operator reading the report must be able to tell
            // the difference.
            $actions[] = 'REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION';
        }

        // Correct the manifest's outcome fields to the actual result (the
        // earlier write, before the removal decision, necessarily still
        // says 'Pending Remediation' -- that first write exists so evidence
        // is on disk BEFORE any destructive action, per the evidence-first
        // guarantee; this second write is what makes the manifest an
        // accurate final record rather than a stale snapshot of intent).
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
        MSP_PG_Utils::write_text($markdownPath, self::artifact_markdown($artifactReport, ''));
        MSP_PG_Utils::write_text($textPath, self::artifact_markdown($artifactReport, ''));

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
     * Symlink-safe recursive delete: walked manually (not via
     * RecursiveDirectoryIterator, which follows symlinked subdirectories
     * during traversal by default -- a real escape vector if an attacker
     * plants a symlink inside an artifact directory pointing elsewhere on
     * the filesystem). Any entry that is itself a symlink is unlinked as a
     * leaf -- its target is never entered or touched -- regardless of
     * whether the link points at a file or a directory.
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

    private static function artifact_markdown($artifactReport, $operatorAction)
    {
        $lines = array(
            '# PG-SC-MacroOptimizerCue Artifact Report',
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

        if ($operatorAction !== '') {
            $lines[] = '';
            $lines[] = '## Operator Action Required';
            $lines[] = '';
            $lines[] = $operatorAction;
        }

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
            'domains'                 => array(),
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
