<?php

if (!defined('ABSPATH')) {
    exit;
}

class MSP_PG_Remediator
{
    const SUBJECT_CLEAN   = 'CLEAN REPORT';
    const SUBJECT_REVIEW  = 'REVIEW REQUIRED';
    const SUBJECT_MALWARE = 'CONFIRMED MALWARE REMEDIATED';
    const SUBJECT_FAILED  = 'SCAN FAILED';

    public static function run_scan($trigger = 'manual', $args = array())
    {
        if (get_transient(MSP_PG_Config::scan_lock_key())) {
            return null;
        }

        set_transient(MSP_PG_Config::scan_lock_key(), 1, 15 * MINUTE_IN_SECONDS);

        if (!MSP_PG_Signatures::registry_available()) {
            $siteUrl      = home_url('/');
            $errorMessage = 'MSP Portfolio Guard: scan aborted — signature registry unavailable on ' . $siteUrl . '. Check portfolio-guard/data/signatures.json.';
            error_log($errorMessage);
            $failedSubject = sprintf('[MSP Portfolio Guard] %s - %s', self::SUBJECT_FAILED, $siteUrl);
            add_filter('wp_mail_content_type', array(__CLASS__, 'html_mail_content_type'));
            wp_mail(MSP_PG_Config::report_recipient(), $failedSubject, self::build_scan_failed_email($siteUrl, $errorMessage));
            remove_filter('wp_mail_content_type', array(__CLASS__, 'html_mail_content_type'));
            MSP_PG_Diagnostics::record_telemetry(array(
                'current_security_state'  => 'scan_failed',
                'last_failed_report_sent' => gmdate('c'),
            ));
            delete_transient(MSP_PG_Config::scan_lock_key());
            return array('registry_error' => true, 'trigger' => $trigger);
        }

        if (!function_exists('deactivate_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $state = get_option(MSP_PG_Config::state_option_name(), array());
        $scanTimestamp = gmdate('c');
        $siteMeta = self::site_metadata();
        $evidenceRetentionMode = MSP_PG_Config::evidence_retention_mode();
        $dryRun = !empty($args['dry_run']) || MSP_PG_Config::default_dry_run();
        $targetSlug      = isset($args['target_slug'])      ? (string) $args['target_slug']      : '';
        $operatorConfirm = isset($args['operator_confirm'])  ? (string) $args['operator_confirm']  : '';
        $cleanup = self::cleanup_expired_artifacts($dryRun, $evidenceRetentionMode);
        $detections = array();
        $errors = array();
        $scanDir = '';
        $pluginVersionMap = array();

        foreach (glob(trailingslashit(WP_PLUGIN_DIR) . '*', GLOB_ONLYDIR) ?: array() as $pluginDir) {
            $slug = basename($pluginDir);

            if ($slug === 'portfolio-guard' || strpos($slug, '.msp-') === 0) {
                continue;
            }

            if ($targetSlug !== '' && $slug !== $targetSlug) {
                continue;
            }

            $pluginVersion = MSP_PG_Utils::plugin_version($pluginDir);
            $pluginVersionMap[$slug] = $pluginVersion;

            $analysis = MSP_PG_Detector::detect($pluginDir);
            if ($analysis === null || $analysis['tier'] === 'tier3') {
                continue;
            }

            // Whitelist suppression: skip Tier 2 findings for operator-approved slug/version
            if ($analysis['tier'] === 'tier2' && $operatorConfirm === '' && MSP_PG_Whitelist::is_approved($slug, $pluginVersion)) {
                continue;
            }

            // Fleet baseline trust list: suppress Tier 2 behavioral findings for known-safe MSP plugins.
            // Tier 1 (signature) detections are never suppressed by this list.
            if ($analysis['tier'] === 'tier2' && $operatorConfirm === '' && in_array($slug, MSP_PG_Config::trusted_plugin_slugs(), true)) {
                continue;
            }

            // Operator-confirmed upgrade: treat a reviewed Tier 2 finding as Tier 1
            if ($operatorConfirm !== '' && $slug === $operatorConfirm && $analysis['tier'] === 'tier2') {
                $analysis['tier']             = 'tier1';
                $analysis['confidence']       = 'Operator Confirmed';
                $analysis['detection_source'] = 'Operator Review — Behavioral Classifier';
            }

            if ($scanDir === '') {
                $scanDir = self::scan_directory($siteMeta['site_slug'], $scanTimestamp);
                if (!$dryRun) {
                    MSP_PG_Utils::ensure_directory($scanDir);
                }
            }

            $detections[] = self::remediate_detection($analysis, $siteMeta, $scanDir, $dryRun);
        }

        // Second deterministic scan source: PG-ClonedDoorway. Its artifacts
        // (self-cloning directories, a tampered root index.php, loose loader
        // files) never live in wp-content/plugins/, so they are found by a
        // separate, narrowly-scoped filesystem scanner rather than the plugin
        // loop above. Detections are appended to the same $detections[] array
        // so reporting/email/state-storage below is unaware anything special
        // happened. See class-msp-pg-clonedoorway-scanner.php.
        if ($targetSlug === '') {
            foreach (MSP_PG_ClonedDoorway_Scanner::scan() as $cdAnalysis) {
                if ($scanDir === '') {
                    $scanDir = self::scan_directory($siteMeta['site_slug'], $scanTimestamp);
                    if (!$dryRun) {
                        MSP_PG_Utils::ensure_directory($scanDir);
                    }
                }

                $detections[] = MSP_PG_ClonedDoorway_Remediator::remediate($cdAnalysis, $siteMeta, $scanDir, $dryRun);
            }
        }

        $tierCounts = array(
            'tier1' => 0,
            'tier2' => 0,
        );

        foreach ($detections as $detection) {
            if (isset($tierCounts[$detection['tier']])) {
                $tierCounts[$detection['tier']]++;
            }
        }

        $scanReport = array(
            'family' => MSP_PG_Config::family_name(),
            'site_url' => $siteMeta['site_url'],
            'site_slug' => $siteMeta['site_slug'],
            'scan_timestamp' => $scanTimestamp,
            'trigger' => $trigger,
            'evidence_retention_mode' => $evidenceRetentionMode,
            'dry_run' => $dryRun,
            'cleanup' => $cleanup,
            'signature_version' => MSP_PG_Config::signature_version(),
            'heuristic_version' => MSP_PG_Config::heuristic_version(),
            'tier_counts' => $tierCounts,
            'detections' => $detections,
            'confirmed_malware' => array_values(array_filter($detections, function ($detection) { return $detection['tier'] === 'tier1'; })),
            'review_required' => array_values(array_filter($detections, function ($detection) { return $detection['tier'] === 'tier2'; })),
            'errors' => $errors,
            'wordpress_version' => $siteMeta['wordpress_version'],
            'php_version' => $siteMeta['php_version'],
            'active_plugins' => $siteMeta['active_plugins'],
            'active_theme' => $siteMeta['active_theme'],
        );

        // Build enriched review_required snapshot for admin display (re-extracts observations
        // for each Tier 2 plugin; these are report-only findings so the plugin still exists).
        $reviewForState = array();
        foreach ($scanReport['review_required'] as $detection) {
            $detSlug      = $detection['plugin_slug'];
            $detVersion   = isset($pluginVersionMap[$detSlug]) ? $pluginVersionMap[$detSlug] : '';
            $observations = MSP_PG_FeatureExtractor::extract(trailingslashit(WP_PLUGIN_DIR) . $detSlug);
            $reviewForState[] = array(
                'plugin_slug'       => $detSlug,
                'plugin_version'    => $detVersion,
                'behavior_profiles' => $detection['behavior_profiles'],
                'explain'           => MSP_PG_BehaviorClassifier::explain_all($observations),
                'detected_at'       => $scanTimestamp,
            );
        }

        $state['last_scan_at'] = $scanTimestamp;
        $state['last_scan_result'] = array(
            'trigger' => $trigger,
            'detections' => count($detections),
        );
        if ($targetSlug === '') {
            // Full scan: replace the stored review_required list
            $state['last_review_required'] = $reviewForState;
        } else {
            // Targeted scan: remove only the target plugin from the stored list
            $storedReview = isset($state['last_review_required']) ? (array) $state['last_review_required'] : array();
            $state['last_review_required'] = array_values(array_filter($storedReview, function ($entry) use ($targetSlug) {
                return $entry['plugin_slug'] !== $targetSlug;
            }));
        }
        update_option(MSP_PG_Config::state_option_name(), $state, false);

        if ($scanDir !== '' && !$dryRun) {
            self::write_scan_report($scanDir, $scanReport);
        }

        if (!$dryRun) {
            self::send_scan_report($scanDir, $scanReport);
        }

        delete_transient(MSP_PG_Config::scan_lock_key());

        $confirmedCount = count($scanReport['confirmed_malware']);
        $reviewCount    = count($scanReport['review_required']);
        if ($confirmedCount > 0) {
            $securityState = 'confirmed_malware';
        } elseif ($reviewCount > 0) {
            $securityState = 'review_required';
        } else {
            $securityState = 'healthy';
        }
        $telemetry = MSP_PG_Diagnostics::record_telemetry(array('current_security_state' => $securityState));
        MSP_PG_CloudPublisher::publish($telemetry);

        return $scanReport;
    }

    /**
     * Confirm operator-reviewed remediation for a specific plugin.
     * Upgrades the Tier 2 finding to Tier 1 and runs the existing remediation
     * pipeline (deactivation, evidence bundle, email) for that plugin only.
     */
    public static function confirm_remediation($slug)
    {
        return self::run_scan('operator_confirm', array(
            'target_slug'      => $slug,
            'operator_confirm' => $slug,
        ));
    }

    private static function remediate_detection($analysis, $siteMeta, $scanDir, $dryRun)
    {
        $actions = array();
        $errors = array();
        $warnings = array();
        $activePlugins = self::matching_active_plugins($analysis['plugin_slug']);
        $reportOnly = $analysis['tier'] !== 'tier1';
        $shouldModify = !$reportOnly && !$dryRun;
        $bundleEligible = in_array($analysis['tier'], array('tier1', 'tier2'), true);
        $canDeleteOriginal = in_array('known_hash', $analysis['exact_match_types'], true) || count($analysis['exact_match_types']) >= 2;
        $evidenceMode = MSP_PG_Config::evidence_retention_mode();
        $effectiveEvidenceMode = $analysis['tier'] === 'tier2' ? 'metadata_only' : $evidenceMode;
        $artifactDir = $bundleEligible ? MSP_PG_Utils::join_paths($scanDir, 'artifacts', $analysis['plugin_slug']) : '';
        $quarantineDir = $bundleEligible ? MSP_PG_Utils::join_paths($artifactDir, 'quarantine', $analysis['plugin_slug']) : '';
        $snapshotDir = $bundleEligible ? MSP_PG_Utils::join_paths($artifactDir, 'snapshot', $analysis['plugin_slug']) : '';
        $zipPath = $bundleEligible ? MSP_PG_Utils::join_paths($artifactDir, 'artifact.zip') : '';
        $manifestPath = $bundleEligible ? MSP_PG_Utils::join_paths($artifactDir, 'evidence.json') : '';
        $reportPath = $bundleEligible ? MSP_PG_Utils::join_paths($artifactDir, 'report.json') : '';
        $markdownPath = $bundleEligible ? MSP_PG_Utils::join_paths($artifactDir, 'report.md') : '';
        $textPath = $bundleEligible ? MSP_PG_Utils::join_paths($artifactDir, 'report.txt') : '';
        $livePluginDir = $analysis['plugin_dir'];
        $evidenceArchiveCreated = false;
        $fileCount = 0;
        $directoryCount = 0;
        $totalBytes = 0;
        $directoryFingerprint = '';

        if (!$dryRun && $bundleEligible) {
            MSP_PG_Utils::ensure_directory($artifactDir);
        }

        if ($analysis['tier'] === 'tier1') {
            $actions[] = 'CONFIRMED_MALWARE_IDENTIFIED';
        } elseif ($analysis['tier'] === 'tier2') {
            $actions[] = 'REVIEW_REQUIRED_IDENTIFIED';
        }

        if (!empty($activePlugins)) {
            $warnings[] = 'Deactivation may impact site functionality.';
        }

        if ($reportOnly) {
            $actions[] = 'REPORT_ONLY_NO_CHANGES';
        }

        if ($dryRun) {
            $actions[] = 'DRY_RUN_ENABLED';
        }

        if ($analysis['protected_plugin'] && $analysis['tier'] !== 'tier1') {
            $actions[] = 'PROTECTED_PLUGIN_REPORT_ONLY';
        }

        if ($shouldModify && !empty($activePlugins)) {
            deactivate_plugins($activePlugins, true);
            $actions[] = 'PLUGIN_DEACTIVATED';
        } elseif (!$shouldModify && !empty($activePlugins) && !$reportOnly) {
            $actions[] = 'WOULD_PLUGIN_DEACTIVATE';
        }

        if ($bundleEligible) {
            $counts = MSP_PG_Utils::directory_counts($livePluginDir);
            $fileCount = (int) $counts['file_count'];
            $directoryCount = (int) $counts['directory_count'];
            $totalBytes = (int) MSP_PG_Utils::directory_size($livePluginDir);
            $directoryFingerprint = MSP_PG_Utils::directory_fingerprint($livePluginDir);
        }

        $hashes = array();
        if ($evidenceMode === 'full_artifact_retention' && $bundleEligible) {
            $hashes = MSP_PG_Utils::hash_directory($livePluginDir);
        }

        // Behavior profiles are determined by the detector and carried through the
        // analysis array (Spec 005 §12.1). No recomputation needed here.
        $behaviorProfiles = !empty($analysis['behavior_profiles']) ? $analysis['behavior_profiles'] : array();

        if ($bundleEligible && $dryRun && !$reportOnly) {
            $actions[] = 'WOULD_EVIDENCE_MANIFEST_CREATE';
            if ($evidenceMode === 'compressed_archive') {
                $actions[] = 'WOULD_EVIDENCE_ARCHIVE_CREATE';
            } elseif ($evidenceMode === 'full_artifact_retention') {
                $actions[] = 'WOULD_FULL_ARTIFACT_RETAIN';
            }
        }

        $manifest = array();
        $preservationVerified = false;

        if ($bundleEligible) {
            $manifest = array(
                'family'                       => MSP_PG_Config::family_name(),
                'classification'               => $analysis['tier'] === 'tier1' ? 'Confirmed Malware' : 'Review Required',
                'tier'                         => strtoupper($analysis['tier']),
                'confidence'                   => $analysis['confidence'],
                'source'                       => $analysis['detection_source'],
                'action'                       => $shouldModify ? 'Pending Remediation' : 'Reported',
                'detected_at'                  => gmdate('c'),
                'plugin_slug'                  => $analysis['plugin_slug'],
                'file_count'                   => $fileCount,
                'directory_count'              => $directoryCount,
                'total_bytes'                  => $totalBytes,
                'sha256_directory_fingerprint' => $directoryFingerprint,
                'evidence_retention_mode'      => $effectiveEvidenceMode,
                'variant_fingerprint'          => $analysis['variant_hash'],
                'dry_run'                      => $dryRun,
                'site_url'                     => $siteMeta['site_url'],
                'wordpress_version'            => $siteMeta['wordpress_version'],
                'php_version'                  => $siteMeta['php_version'],
                'active_plugins'               => $siteMeta['active_plugins'],
                'active_theme'                 => $siteMeta['active_theme'],
                'protected_plugin'             => $analysis['protected_plugin'],
                'exact_match_types'            => $analysis['exact_match_types'],
                'matched_indicators'           => $analysis['matched_indicators'],
                'payload_hashes'               => $analysis['payload_hashes'],
                'hashes'                       => $hashes,
                'domains'                      => $analysis['domains'],
                'routes'                       => $analysis['routes'],
                'backdoor_indicators'          => $analysis['backdoor_indicators'],
                'structural_indicators'        => $analysis['structural_indicators'],
                'signature_version'            => MSP_PG_Config::signature_version(),
                'heuristic_version'            => MSP_PG_Config::heuristic_version(),
            );

            // Tier-specific evidence fields (Spec 005 §11.3, §12.1)
            // Tier 1: score and reasons represent the strength of exact-match evidence
            // Tier 2: behavior_profiles replace heuristic scores in operator-facing output
            if ($analysis['tier'] === 'tier1') {
                $manifest['score']             = $analysis['score'];
                $manifest['reasons']           = $analysis['reasons'];
                $manifest['behavior_profiles'] = array();
            } else {
                $manifest['behavior_profiles'] = $behaviorProfiles;
            }

            $artifactReport = array(
                'plugin_slug' => $analysis['plugin_slug'],
                'live_path' => $analysis['plugin_dir'],
                'quarantine_path' => $effectiveEvidenceMode === 'full_artifact_retention' ? $quarantineDir : '',
                'snapshot_path' => $effectiveEvidenceMode === 'full_artifact_retention' ? $snapshotDir : '',
                'artifact_dir' => $artifactDir,
                'evidence_manifest_path' => $manifestPath,
                'zip_path' => ($effectiveEvidenceMode === 'compressed_archive' || $effectiveEvidenceMode === 'full_artifact_retention') ? $zipPath : '',
                'evidence_retention_mode' => $effectiveEvidenceMode,
                'tier' => $analysis['tier'],
                'score' => $analysis['score'],
                'confidence' => $analysis['confidence'],
                'source' => $analysis['detection_source'],
                'reason_labels' => array_values(array_map(function ($reason) { return $reason['label']; }, $analysis['reasons'])),
                'actions' => $actions,
                'exact_match_types' => $analysis['exact_match_types'],
                'matched_indicators' => $analysis['matched_indicators'],
                'errors' => $errors,
                'warnings' => $warnings,
                'protected_plugin' => $analysis['protected_plugin'],
                'variant_hash'      => $analysis['variant_hash'],
                'known_variant'     => $analysis['known_variant'],
                'behavior_profiles' => $behaviorProfiles,
            );

            if (!$dryRun && $shouldModify && $evidenceMode === 'compressed_archive') {
                $evidenceArchiveCreated = MSP_PG_Utils::zip_live_directory($livePluginDir, $zipPath);
                if ($evidenceArchiveCreated) {
                    $actions[] = 'EVIDENCE_ARCHIVE_CREATED';
                } else {
                    $errors[] = 'Failed to create compressed evidence archive.';
                }
            } elseif (!$dryRun && $shouldModify && $evidenceMode === 'full_artifact_retention') {
                $copied = MSP_PG_Utils::copy_directory($livePluginDir, $snapshotDir);
                if ($copied) {
                    $actions[] = 'FULL_ARTIFACT_SNAPSHOT_CREATED';
                    $zipOkFull = MSP_PG_Utils::zip_directory($artifactDir, $zipPath);
                    $evidenceArchiveCreated = $zipOkFull;
                } else {
                    $errors[] = 'Failed to create evidence snapshot.';
                }
            } elseif ($dryRun && $bundleEligible && !$reportOnly) {
                $evidenceArchiveCreated = false;
            }

            $manifestOk = !$dryRun ? MSP_PG_Utils::write_json($manifestPath, $manifest) : true;
            if ($manifestOk) {
                if (!$dryRun) {
                    $actions[] = 'EVIDENCE_MANIFEST_CREATED';
                }
            }
            $preReportOk = !$dryRun ? MSP_PG_Utils::write_json($reportPath, $artifactReport) : true;
            $preMarkdownOk = !$dryRun ? MSP_PG_Utils::write_text($markdownPath, self::artifact_markdown($artifactReport, $manifest)) : true;
            $preTextOk = !$dryRun ? MSP_PG_Utils::write_text($textPath, self::artifact_markdown($artifactReport, $manifest)) : true;
            $zipOk = $dryRun ? true : (($effectiveEvidenceMode === 'compressed_archive' || $effectiveEvidenceMode === 'full_artifact_retention') ? $evidenceArchiveCreated && is_readable($zipPath) : true);
            $preservationVerified = $dryRun
                ? false
                : ($manifestOk && $preReportOk && $preMarkdownOk && $preTextOk
                    && is_readable($manifestPath) && is_readable($reportPath)
                    && (
                        $evidenceMode === 'metadata_only'
                        || (($evidenceMode === 'compressed_archive' || $evidenceMode === 'full_artifact_retention') && $zipOk)
                    ));

            if ($preservationVerified) {
                $actions[] = 'BUNDLE_VERIFIED';
            } elseif (!$dryRun) {
                $errors[] = 'Preservation verification failed; live plugin retained.';
            }

            if ($analysis['tier'] === 'tier1' && $shouldModify && MSP_PG_Config::delete_tier1_enabled() && $preservationVerified && $canDeleteOriginal) {
                if ($evidenceMode === 'full_artifact_retention') {
                    $moved = MSP_PG_Utils::move_directory($livePluginDir, $quarantineDir);
                    if ($moved) {
                        $actions[] = 'QUARANTINE_COMPLETED';
                        $actions[] = 'LIVE_PLUGIN_REMOVED';
                    } else {
                        $errors[] = 'Failed to move plugin directory into quarantine after verified preservation.';
                    }
                } else {
                    $temporaryQuarantineDir = MSP_PG_Utils::join_paths(
                        MSP_PG_Config::temporary_quarantine_base_dir(),
                        $analysis['plugin_slug'] . '-' . preg_replace('/[^0-9A-Za-z_-]/', '-', gmdate('Ymd-His'))
                    );

                    $moved = MSP_PG_Utils::move_directory($livePluginDir, $temporaryQuarantineDir);
                    if ($moved) {
                        self::delete_directory($temporaryQuarantineDir);
                        $actions[] = 'LIVE_PLUGIN_REMOVED';
                    } else {
                        $errors[] = 'Failed to remove live plugin directory after verified evidence preservation.';
                    }
                }
            }
        }

        if ($analysis['tier'] === 'tier2') {
            $actions[] = 'REVIEW_REQUIRED_REPORT_ONLY';
        }

        if ($dryRun && $analysis['tier'] === 'tier1') {
            $actions[] = 'WOULD_LIVE_PLUGIN_REMOVE';
        }

        if ($bundleEligible) {
            if (in_array('LIVE_PLUGIN_REMOVED', $actions, true)) {
                $manifest['action'] = 'Removed';
                $manifest['remediation_status'] = 'Removed';
            } elseif (in_array('QUARANTINE_COMPLETED', $actions, true)) {
                $manifest['action'] = 'Quarantined';
                $manifest['remediation_status'] = 'Quarantined';
            } elseif ($analysis['tier'] === 'tier2') {
                $manifest['action'] = 'Reported';
                $manifest['remediation_status'] = 'Awaiting Review';
            } elseif ($dryRun) {
                $manifest['action'] = 'Simulated';
                $manifest['remediation_status'] = 'Simulated';
            } elseif ($shouldModify) {
                $manifest['action'] = 'Preserved Evidence';
                $manifest['remediation_status'] = 'Evidence Preserved';
            } else {
                $manifest['action'] = 'Reported';
                $manifest['remediation_status'] = 'Reported';
            }

            $artifactReport['actions'] = $actions;
            $artifactReport['action_descriptions'] = MSP_PG_Utils::describe_actions($actions);
            $artifactReport['errors'] = $errors;
            $artifactReport['warnings'] = $warnings;
            $artifactReport['preservation_verified'] = $preservationVerified;
            $artifactReport['file_count'] = $fileCount;
            $artifactReport['directory_count'] = $directoryCount;
            $artifactReport['total_bytes'] = $totalBytes;
            $artifactReport['sha256_directory_fingerprint'] = $directoryFingerprint;
            if (!$dryRun) {
                MSP_PG_Utils::write_json($manifestPath, $manifest);
                MSP_PG_Utils::write_json($reportPath, $artifactReport);
                MSP_PG_Utils::write_text($markdownPath, self::artifact_markdown($artifactReport, $manifest));
                MSP_PG_Utils::write_text($textPath, self::artifact_markdown($artifactReport, $manifest));
            }
        }

        return array(
            'plugin_slug' => $analysis['plugin_slug'],
            'live_path' => $analysis['plugin_dir'],
            'artifact_dir' => $artifactDir,
            'quarantine_path' => $effectiveEvidenceMode === 'full_artifact_retention' ? $quarantineDir : '',
            'snapshot_path' => $effectiveEvidenceMode === 'full_artifact_retention' ? $snapshotDir : '',
            'zip_path' => ($effectiveEvidenceMode === 'compressed_archive' || $effectiveEvidenceMode === 'full_artifact_retention') ? $zipPath : '',
            'evidence_manifest_path' => $manifestPath,
            'tier' => $analysis['tier'],
            'family' => $analysis['family'],
            'score' => $analysis['score'],
            'confidence' => $analysis['confidence'],
            'source' => $analysis['detection_source'],
            'reason_labels' => array_values(array_map(function ($reason) { return $reason['label']; }, $analysis['reasons'])),
            'exact_match_types' => $analysis['exact_match_types'],
            'variant_hash' => $analysis['variant_hash'],
            'payload_hashes' => $analysis['payload_hashes'],
            'domains' => $analysis['domains'],
            'routes' => $analysis['routes'],
            'backdoor_indicators' => $analysis['backdoor_indicators'],
            'structural_indicators' => $analysis['structural_indicators'],
            'matched_indicators' => $analysis['matched_indicators'],
            'actions' => $actions,
            'action_descriptions' => MSP_PG_Utils::describe_actions($actions),
            'errors' => $errors,
            'warnings' => $warnings,
            'protected_plugin' => $analysis['protected_plugin'],
            'preservation_verified' => $preservationVerified,
            'bundle_eligible'       => $bundleEligible,
            'evidence_retention_mode' => $effectiveEvidenceMode,
            'behavior_profiles'     => $behaviorProfiles,
        );
    }

    private static function artifact_markdown($artifactReport, $manifest)
    {
        $isTier2 = $artifactReport['tier'] === 'tier2';

        $lines = array(
            '# Artifact Report',
            '',
            '- Plugin slug: `' . $artifactReport['plugin_slug'] . '`',
            '- Tier: `' . $artifactReport['tier'] . '`',
            '- Protected plugin: `' . ($artifactReport['protected_plugin'] ? 'yes' : 'no') . '`',
            '- Evidence mode: `' . $artifactReport['evidence_retention_mode'] . '`',
            '- Confidence: `' . $artifactReport['confidence'] . '`',
            '- Source: `' . $artifactReport['source'] . '`',
            '- Remediation status: `' . $manifest['remediation_status'] . '`',
        );

        // Tier-specific evidence representation (Spec 005 §11.3)
        if (!$isTier2) {
            $lines[] = '- Score: `' . $artifactReport['score'] . '`';
            $lines[] = '- Reasons: `' . implode(', ', $artifactReport['reason_labels']) . '`';
        } elseif (!empty($manifest['behavior_profiles'])) {
            $lines[] = '- Behavior Profiles:';
            foreach ($manifest['behavior_profiles'] as $profile) {
                $lines[] = '  - **' . $profile['profile_label'] . ':** ' . $profile['summary'];
            }
        }

        $lines[] = '- Variant fingerprint: `' . $artifactReport['variant_hash'] . '`';
        $lines[] = '- Evidence manifest: `' . $artifactReport['evidence_manifest_path'] . '`';
        $lines[] = '- Evidence archive: `' . (!empty($artifactReport['zip_path']) ? $artifactReport['zip_path'] : 'n/a') . '`';
        $lines[] = '- File count: `' . $artifactReport['file_count'] . '`';
        $lines[] = '- Directory count: `' . $artifactReport['directory_count'] . '`';
        $lines[] = '- Total bytes: `' . $artifactReport['total_bytes'] . '`';
        $lines[] = '- Directory fingerprint: `' . $artifactReport['sha256_directory_fingerprint'] . '`';
        $lines[] = '- Actions: `' . implode(', ', $artifactReport['actions']) . '`';
        $lines[] = '- Exact matches: `' . implode(', ', $artifactReport['exact_match_types']) . '`';
        $lines[] = '- Matched indicators: `' . implode(', ', $artifactReport['matched_indicators']) . '`';
        $lines[] = '- Domains: `' . implode(', ', $manifest['domains']) . '`';
        $lines[] = '- Routes: `' . implode(', ', $manifest['routes']) . '`';

        return implode("\n", $lines) . "\n";
    }

    private static function write_scan_report($scanDir, $scanReport)
    {
        MSP_PG_Utils::write_json(MSP_PG_Utils::join_paths($scanDir, 'report.json'), $scanReport);
        MSP_PG_Utils::write_text(MSP_PG_Utils::join_paths($scanDir, 'report.md'), MSP_PG_Utils::markdown_report($scanReport));
        MSP_PG_Utils::write_text(MSP_PG_Utils::join_paths($scanDir, 'report.txt'), MSP_PG_Utils::plain_text_report($scanReport));
    }

    public static function scan_email_subject(array $scanReport)
    {
        $confirmedCount = count($scanReport['confirmed_malware']);
        $reviewCount    = count($scanReport['review_required']);
        $siteUrl        = $scanReport['site_url'];

        if ($confirmedCount > 0) {
            return sprintf('[MSP Portfolio Guard] %s - %s', self::SUBJECT_MALWARE, $siteUrl);
        }
        if ($reviewCount > 0) {
            return sprintf('[MSP Portfolio Guard] %s - %s', self::SUBJECT_REVIEW, $siteUrl);
        }
        return sprintf('[MSP Portfolio Guard] %s - %s', self::SUBJECT_CLEAN, $siteUrl);
    }

    private static function send_scan_report($scanDir, $scanReport)
    {
        $confirmedCount = count($scanReport['confirmed_malware']);
        $reviewCount    = count($scanReport['review_required']);

        if ($confirmedCount > 0) {
            $outcome = self::SUBJECT_MALWARE . ': ' . $confirmedCount . ' confirmed malware instance(s)';
            $tsField = 'last_malware_report_sent';
        } elseif ($reviewCount > 0) {
            $outcome = self::SUBJECT_REVIEW . ': ' . $reviewCount . ' plugin(s) flagged for review';
            $tsField = 'last_review_report_sent';
        } else {
            $outcome = 'CLEAN — No threats detected';
            $tsField = 'last_clean_report_sent';
        }

        $nextTs   = wp_next_scheduled(MSP_PG_Config::cron_hook());
        $nextScan = $nextTs !== false ? gmdate('Y-m-d H:i \U\T\C', (int) $nextTs) : 'Not scheduled';

        $subject  = self::scan_email_subject($scanReport);
        $htmlBody = self::build_operational_email($scanReport, $outcome, $nextScan);

        add_filter('wp_mail_content_type', array(__CLASS__, 'html_mail_content_type'));
        wp_mail(MSP_PG_Config::report_recipient(), $subject, $htmlBody);
        remove_filter('wp_mail_content_type', array(__CLASS__, 'html_mail_content_type'));

        MSP_PG_Diagnostics::record_telemetry(array($tsField => gmdate('c')));
    }

    private static function build_operational_email($scanReport, $outcome, $nextScan)
    {
        $e = 'MSP_PG_Utils::html_escape';

        $html  = '<html><body style="font-family:Arial,sans-serif;color:#1f2328;">';
        $html .= '<h1>MSP Portfolio Guard &mdash; Operational Report</h1>';
        $html .= '<table style="border-collapse:collapse;">';
        foreach (array(
            'Site'                => $scanReport['site_url'],
            'Scan Completed'      => $scanReport['scan_timestamp'],
            'Outcome'             => $outcome,
            'Plugin Version'      => MSP_PG_VERSION,
            'Signature Registry'  => MSP_PG_Config::signature_version(),
            'Next Scheduled Scan' => $nextScan,
        ) as $label => $value) {
            $html .= '<tr>';
            $html .= '<td style="padding:5px 16px 5px 0;font-weight:bold;vertical-align:top;">'
                   . MSP_PG_Utils::html_escape($label) . '</td>';
            $html .= '<td style="padding:5px 0;">'
                   . MSP_PG_Utils::html_escape((string) $value) . '</td>';
            $html .= '</tr>';
        }
        $html .= '</table>';

        if (!empty($scanReport['detections'])) {
            $html .= '<hr style="margin:20px 0;">';
            foreach (array(
                'Confirmed Malware' => $scanReport['confirmed_malware'],
                'Review Required'   => $scanReport['review_required'],
            ) as $heading => $group) {
                if (empty($group)) {
                    continue;
                }
                $html .= '<h2>' . MSP_PG_Utils::html_escape($heading) . '</h2><ul>';
                foreach ($group as $detection) {
                    $html .= '<li><strong>' . MSP_PG_Utils::html_escape($detection['plugin_slug']) . '</strong>'
                           . ' &mdash; ' . MSP_PG_Utils::html_escape(implode('; ', $detection['action_descriptions']))
                           . '</li>';
                }
                $html .= '</ul>';
            }

            if (!empty($scanReport['errors'])) {
                $html .= '<h2>Errors</h2><ul>';
                foreach ($scanReport['errors'] as $error) {
                    $html .= '<li>' . MSP_PG_Utils::html_escape($error) . '</li>';
                }
                $html .= '</ul>';
            }
        }

        $html .= '</body></html>';
        return $html;
    }

    private static function build_scan_failed_email($siteUrl, $errorMessage)
    {
        $html  = '<html><body style="font-family:Arial,sans-serif;color:#1f2328;">';
        $html .= '<h1>MSP Portfolio Guard &mdash; Scan Failed</h1>';
        $html .= '<table style="border-collapse:collapse;">';
        foreach (array(
            'Site'           => $siteUrl,
            'Scan Attempted' => gmdate('Y-m-d H:i \U\T\C'),
            'Outcome'        => 'SCAN FAILED — Signature registry unavailable',
            'Plugin Version' => MSP_PG_VERSION,
        ) as $label => $value) {
            $html .= '<tr>';
            $html .= '<td style="padding:5px 16px 5px 0;font-weight:bold;vertical-align:top;">'
                   . MSP_PG_Utils::html_escape($label) . '</td>';
            $html .= '<td style="padding:5px 0;">'
                   . MSP_PG_Utils::html_escape((string) $value) . '</td>';
            $html .= '</tr>';
        }
        $html .= '</table>';
        $html .= '<p style="margin-top:16px;color:#d1242f;">' . MSP_PG_Utils::html_escape($errorMessage) . '</p>';
        $html .= '</body></html>';
        return $html;
    }

    public static function html_mail_content_type()
    {
        return 'text/html';
    }

    private static function cleanup_expired_artifacts($dryRun, $evidenceMode)
    {
        $baseDir = MSP_PG_Config::artifact_base_dir();
        $retentionDays = MSP_PG_Config::artifact_retention_days();
        $result = array(
            'retention_days' => $retentionDays,
            'deleted_count' => 0,
            'deleted_paths' => array(),
            'scrubbed_count' => 0,
            'scrubbed_paths' => array(),
            'mode' => $dryRun ? 'simulated' : 'live',
        );

        if (!is_dir($baseDir)) {
            return $result;
        }

        $threshold = time() - ($retentionDays * DAY_IN_SECONDS);
        $sites = glob(trailingslashit($baseDir) . '*', GLOB_ONLYDIR) ?: array();

        foreach ($sites as $siteDir) {
            $scanDirs = glob(trailingslashit($siteDir) . '*', GLOB_ONLYDIR) ?: array();
            foreach ($scanDirs as $scanDir) {
                if ($evidenceMode !== 'full_artifact_retention') {
                    foreach (array('snapshot', 'quarantine') as $legacyDirName) {
                        foreach (glob(trailingslashit($scanDir) . 'artifacts/*/' . $legacyDirName, GLOB_ONLYDIR) ?: array() as $legacyPath) {
                            $result['scrubbed_count']++;
                            $result['scrubbed_paths'][] = $legacyPath;
                            if (!$dryRun) {
                                self::delete_directory($legacyPath);
                            }
                        }
                    }
                }

                if (filemtime($scanDir) >= $threshold) {
                    continue;
                }

                $result['deleted_count']++;
                $result['deleted_paths'][] = $scanDir;

                if (!$dryRun) {
                    self::delete_directory($scanDir);
                }
            }
        }

        return $result;
    }

    private static function delete_directory($dir)
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($dir);
    }

    private static function matching_active_plugins($slug)
    {
        $active = (array) get_option('active_plugins', array());

        return array_values(array_filter($active, function ($plugin) use ($slug) {
            return strpos($plugin, $slug . '/') === 0;
        }));
    }

    private static function scan_directory($siteSlug, $scanTimestamp)
    {
        $normalizedTimestamp = preg_replace('/[^0-9TZ-]/', '-', $scanTimestamp);

        return MSP_PG_Utils::join_paths(
            MSP_PG_Config::artifact_base_dir(),
            $siteSlug,
            $normalizedTimestamp
        );
    }

    private static function site_metadata()
    {
        $theme = wp_get_theme();

        return array(
            'site_url' => home_url('/'),
            'site_slug' => MSP_PG_Config::site_slug(),
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'active_plugins' => (array) get_option('active_plugins', array()),
            'active_theme' => $theme->get('Name'),
        );
    }
}
