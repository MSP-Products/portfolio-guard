<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Remediation controls and remediation-outcome reporting, end to end through
 * a real MSP_PG_Remediator::run_scan():
 *
 *  - production defaults: eligible Tier 1 findings are deactivated/removed,
 *    report-only components stay outstanding
 *  - detection-only (every *_delete_enabled filter false, including
 *    msp_pg_delete_tier1_enabled): nothing on the site changes -- no file
 *    removed, no plugin deactivated -- while detection, evidence, email and
 *    telemetry all still happen and every withheld removal is explicit
 *  - dry-run: no changes, no evidence, no email, intended actions reported
 *  - failed evidence preservation: no destructive remediation
 *  - email subject/body/telemetry agree on the outcome
 *
 * Fixtures are inert: a validation-corpus plugin-directory stub (detected by
 * directory/file name), and SC / WP Link Helper sample shapes built from
 * split string fragments so this file never matches a signature itself.
 */
class RemediationControlTest
{
    private $workspace;
    private $site;
    private $registeredFilters = array();

    public function __construct()
    {
        $this->workspace = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pg-remediation-control-' . uniqid();
        $this->site = MSP_PG_Utils::join_paths($this->workspace, 'site');

        define('WP_PLUGIN_DIR', MSP_PG_Utils::join_paths($this->site, 'wp-content', 'plugins'));
        define('WPMU_PLUGIN_DIR', MSP_PG_Utils::join_paths($this->site, 'wp-content', 'mu-plugins'));
        $GLOBALS['msp_pg_test_uploads_base'] = MSP_PG_Utils::join_paths($this->site, 'wp-content', 'uploads');
    }

    public function run()
    {
        try {
            $this->test_production_defaults_remediate_eligible_and_keep_report_only_outstanding();
            $this->test_detection_only_changes_nothing_but_reports_everything();
            $this->test_dry_run_changes_nothing_and_writes_nothing();
            $this->test_dry_run_with_remediation_disabled_predicts_no_live_changes();
            $this->test_complete_remediation_subject();
            $this->test_failed_evidence_preservation_prevents_removal();
            $this->test_report_only_dropin_alone_is_action_required();
            $this->test_subject_tier2_and_clean_unchanged();
        } finally {
            $this->removeAllFilters();
            $this->deleteTree($this->workspace);
        }
    }

    // -------------------------------------------------------------------------
    // Scenarios
    // -------------------------------------------------------------------------

    private function test_production_defaults_remediate_eligible_and_keep_report_only_outstanding()
    {
        $this->buildSite();
        $this->withFilter('msp_pg_evidence_retention_mode', function () { return 'compressed_archive'; });
        $report = $this->scan('prod-defaults');

        $this->assertTrue(MSP_PG_Config::delete_tier1_enabled(), 'prod: msp_pg_delete_tier1_enabled must default to true');

        $plugin = $this->detection($report, 'laravel-janet');
        $this->assertContainsAction('PLUGIN_DEACTIVATED', $plugin, 'prod: active malicious plugin is deactivated');
        $this->assertContainsAction('LIVE_PLUGIN_REMOVED', $plugin, 'prod: malicious plugin directory is removed after verified evidence');
        $this->assertContainsAction('BUNDLE_VERIFIED', $plugin, 'prod: evidence verified before removal');
        $this->assertFalse(is_dir(MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'laravel-janet')), 'prod: plugin directory no longer on disk');
        $this->assertSame(array('classic-editor/classic-editor.php'), array_values(get_option('active_plugins')), 'prod: only the malicious plugin was deactivated');

        $this->assertContainsAction('LIVE_ARTIFACT_REMOVED', $this->detection($report, 'malicious-sc.php'), 'prod: SC mu-plugin removed');
        $this->assertContainsAction('LIVE_ARTIFACT_REMOVED', $this->detection($report, 'wlh-recovery-x1.php'), 'prod: WLH mu-plugin removed');
        $this->assertFalse(file_exists($this->path('wp-content/mu-plugins/malicious-sc.php')), 'prod: SC mu-plugin gone');
        $this->assertFalse(file_exists($this->path('wp-content/mu-plugins/wlh-recovery-x1.php')), 'prod: WLH mu-plugin gone');

        $dropin = $this->detection($report, 'advanced-cache.php');
        $this->assertContainsAction('REPORT_ONLY_NO_AUTOMATIC_REMOVAL', $dropin, 'prod: infected drop-in stays report-only');
        $this->assertTrue(file_exists($this->path('wp-content/advanced-cache.php')), 'prod: drop-in untouched');
        $this->assertTrue(file_exists($this->path('wp-content/mu-plugins/host-performance.php')), 'prod: legitimate headerless mu-plugin untouched');

        $this->assertFalse($report['infection_fully_resolved'], 'prod: infection not fully resolved while the drop-in remains');
        $this->assertSame(1, count($report['outstanding_components']), 'prod: exactly the drop-in is outstanding');

        $mail = $this->singleMail('prod');
        $this->assertContains('CONFIRMED MALWARE - PARTIAL REMEDIATION', $mail['subject'], 'prod: subject says partial remediation');
        $this->assertNotContains('REMEDIATED -', $mail['subject'], 'prod: subject does not claim full remediation');
        $this->assertContains('3 of 4 confirmed malware finding(s) removed', $mail['message'], 'prod: body states removed/total');
        $this->assertTelemetry('confirmed_malware', true, 'prod');
    }

    private function test_detection_only_changes_nothing_but_reports_everything()
    {
        $this->buildSite();
        $this->disableAllRemediation();
        $this->withFilter('msp_pg_evidence_retention_mode', function () { return 'compressed_archive'; });
        $before = $this->snapshot();
        $activeBefore = get_option('active_plugins');

        $report = $this->scan('detection-only');

        $this->assertSame($before, $this->snapshot(), 'detect-only: every live file is byte-identical after the scan');
        $this->assertSame($activeBefore, get_option('active_plugins'), 'detect-only: plugin activation records unchanged');
        $this->assertSame(array(), $GLOBALS['msp_pg_test_deactivated_plugins'], 'detect-only: deactivate_plugins() never called');

        $plugin = $this->detection($report, 'laravel-janet');
        $this->assertNotContainsAction('PLUGIN_DEACTIVATED', $plugin, 'detect-only: plugin not deactivated');
        $this->assertContainsAction('DEACTIVATION_WITHHELD_DISABLED_BY_CONFIGURATION', $plugin, 'detect-only: deactivation withheld explicitly');
        $this->assertContainsAction('REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION', $plugin, 'detect-only: plugin removal withheld explicitly');
        $this->assertContainsAction('EVIDENCE_ARCHIVE_CREATED', $plugin, 'detect-only: plugin evidence archived');
        $manifest = json_decode(file_get_contents($plugin['evidence_manifest_path']), true);
        $this->assertSame('Evidence Preserved — Removal Withheld', $manifest['remediation_status'], 'detect-only: manifest status explicit');

        foreach (array('malicious-sc.php', 'wlh-recovery-x1.php') as $name) {
            $d = $this->detection($report, $name);
            $this->assertContainsAction('REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION', $d, "detect-only: $name removal withheld explicitly");
            $this->assertTrue(is_readable($d['evidence_manifest_path']), "detect-only: $name evidence manifest written");
        }
        $this->assertContainsAction('REPORT_ONLY_NO_AUTOMATIC_REMOVAL', $this->detection($report, 'advanced-cache.php'), 'detect-only: drop-in report-only');

        $this->assertFalse($report['infection_fully_resolved'], 'detect-only: infection not resolved');
        $this->assertSame(4, count($report['outstanding_components']), 'detect-only: all four findings outstanding');
        $reasons = array_map(function ($c) { return $c['reason']; }, $report['outstanding_components']);
        $this->assertSame(3, count(array_filter($reasons, function ($r) { return strpos($r, 'disabled by configuration') !== false; })), 'detect-only: withheld findings give the configuration reason');

        $mail = $this->singleMail('detect-only');
        $this->assertContains('CONFIRMED MALWARE - ACTION REQUIRED', $mail['subject'], 'detect-only: subject says action required');
        $this->assertNotContains('REMEDIATION', $mail['subject'], 'detect-only: subject makes no remediation claim');
        $this->assertContains('none were removed automatically', $mail['message'], 'detect-only: body agrees with subject');
        $this->assertTelemetry('confirmed_malware', true, 'detect-only');
    }

    private function test_dry_run_changes_nothing_and_writes_nothing()
    {
        $this->buildSite();
        $before = $this->snapshot();

        $report = $this->scan('dry-run', array('dry_run' => true));

        $this->assertSame($before, $this->snapshot(), 'dry-run: no live file changed');
        $this->assertSame(array(), $GLOBALS['msp_pg_test_deactivated_plugins'], 'dry-run: no plugin deactivated');
        $this->assertFalse(is_dir(MSP_PG_Config::artifact_base_dir()), 'dry-run: no evidence directory created');
        $this->assertSame(array(), $GLOBALS['msp_pg_test_wp_mail_calls'], 'dry-run: no email');
        $plugin = $this->detection($report, 'laravel-janet');
        $this->assertContainsAction('WOULD_PLUGIN_DEACTIVATE', $plugin, 'dry-run: intended deactivation reported');
        $this->assertContainsAction('WOULD_LIVE_PLUGIN_REMOVE', $plugin, 'dry-run: intended removal reported');
        $this->assertContainsAction('WOULD_LIVE_ARTIFACT_REMOVE', $this->detection($report, 'malicious-sc.php'), 'dry-run: intended SC removal reported');
    }

    private function test_dry_run_with_remediation_disabled_predicts_no_live_changes()
    {
        $this->buildSite();
        $this->disableAllRemediation();

        $report = $this->scan('dry-run-detect-only', array('dry_run' => true));

        $plugin = $this->detection($report, 'laravel-janet');
        $this->assertNotContainsAction('WOULD_PLUGIN_DEACTIVATE', $plugin, 'dry-run+disabled: no deactivation predicted');
        $this->assertNotContainsAction('WOULD_LIVE_PLUGIN_REMOVE', $plugin, 'dry-run+disabled: no removal predicted');
        foreach (array('malicious-sc.php', 'wlh-recovery-x1.php') as $name) {
            $this->assertNotContainsAction('WOULD_LIVE_ARTIFACT_REMOVE', $this->detection($report, $name), "dry-run+disabled: no $name removal predicted");
        }
    }

    private function test_complete_remediation_subject()
    {
        $this->buildSite(false);
        $report = $this->scan('complete');

        $this->assertTrue($report['infection_fully_resolved'], 'complete: every finding removed');
        $mail = $this->singleMail('complete');
        $this->assertContains('CONFIRMED MALWARE REMEDIATED', $mail['subject'], 'complete: subject says remediated');
        $this->assertContains('does not establish that the site is free of undetected malware', $mail['message'], 'complete: body limits the claim to this scan');
        $this->assertTelemetry('confirmed_malware', false, 'complete');
    }

    private function test_failed_evidence_preservation_prevents_removal()
    {
        $this->buildSite(false);
        // A directory where the deny-all .htaccess must go: protection cannot
        // be established, so evidence writes are refused for this scan.
        wp_mkdir_p(MSP_PG_Utils::join_paths(MSP_PG_Config::artifact_base_dir(), '.htaccess'));

        $report = $this->scan('failed-preservation');

        $this->assertTrue(is_dir(MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'laravel-janet')), 'failed-preservation: plugin directory not removed');
        $this->assertTrue(file_exists($this->path('wp-content/mu-plugins/malicious-sc.php')), 'failed-preservation: SC mu-plugin not removed');
        foreach ($report['confirmed_malware'] as $d) {
            $this->assertFalse((bool) $d['preservation_verified'], 'failed-preservation: nothing reported as preserved');
            $this->assertFalse((bool) array_intersect(array('LIVE_PLUGIN_REMOVED', 'LIVE_ARTIFACT_REMOVED', 'QUARANTINE_COMPLETED'), $d['actions']), 'failed-preservation: no removal action recorded');
        }
        $this->assertSame(false, $report['evidence_storage']['secured'], 'failed-preservation: report marks storage unsecured');
        $this->assertTrue(count(array_filter($report['outstanding_components'], function ($c) { return strpos($c['reason'], 'evidence could not be preserved') !== false; })) === 2, 'failed-preservation: reason explains why');

        $mail = $this->singleMail('failed-preservation');
        $this->assertContains('CONFIRMED MALWARE - ACTION REQUIRED', $mail['subject'], 'failed-preservation: subject says action required');
        $this->assertContains('NOT SECURED', $mail['message'], 'failed-preservation: body flags evidence storage');
        $this->assertTelemetry('confirmed_malware', true, 'failed-preservation');
    }

    private function test_report_only_dropin_alone_is_action_required()
    {
        $this->resetSite();
        file_put_contents($this->path('wp-content/advanced-cache.php'), self::sample('sc_dropin'));

        $report = $this->scan('dropin-only');

        $this->assertSame(1, count($report['confirmed_malware']), 'dropin-only: drop-in detected');
        $mail = $this->singleMail('dropin-only');
        $this->assertContains('CONFIRMED MALWARE - ACTION REQUIRED', $mail['subject'], 'dropin-only: report-only infection is action required');
        $this->assertTrue(file_exists($this->path('wp-content/advanced-cache.php')), 'dropin-only: drop-in untouched');
    }

    private function test_subject_tier2_and_clean_unchanged()
    {
        $tier2 = array('plugin_slug' => 'x', 'tier' => 'tier2', 'actions' => array('REVIEW_REQUIRED_IDENTIFIED'));
        $report = array('site_url' => 'https://example.test/', 'confirmed_malware' => array(), 'review_required' => array($tier2));
        $this->assertContains('REVIEW REQUIRED', MSP_PG_Remediator::scan_email_subject($report), 'tier2: review subject unchanged');
        $report['review_required'] = array();
        $this->assertContains('CLEAN REPORT', MSP_PG_Remediator::scan_email_subject($report), 'clean: clean subject unchanged');
    }

    // -------------------------------------------------------------------------
    // Fixtures and helpers
    // -------------------------------------------------------------------------

    private function buildSite($withDropin = true)
    {
        $this->resetSite();

        $corpus = dirname(dirname(__DIR__)) . '/validation/corpus';
        wp_mkdir_p(MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'laravel-janet'));
        copy("$corpus/known-malware/laravel-janet/laravel-janet.php", MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'laravel-janet', 'laravel-janet.php'));
        wp_mkdir_p(MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'classic-editor'));
        copy("$corpus/clean-plugins/classic-editor-1.6.5/classic-editor.php", MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'classic-editor', 'classic-editor.php'));
        $GLOBALS['msp_pg_test_options']['active_plugins'] = array('laravel-janet/laravel-janet.php', 'classic-editor/classic-editor.php');

        file_put_contents($this->path('wp-content/mu-plugins/malicious-sc.php'), self::sample('sc_mu'));
        if ($withDropin) {
            file_put_contents($this->path('wp-content/advanced-cache.php'), self::sample('sc_dropin'));
            file_put_contents($this->path('wp-content/mu-plugins/wlh-recovery-x1.php'), self::sample('wlh_mu'));
            file_put_contents($this->path('wp-content/mu-plugins/host-performance.php'), "<?php\nfunction host_perf_tweak() { return true; }\n");
        }
    }

    private function resetSite()
    {
        $this->removeAllFilters();
        $this->deleteTree($this->site);
        foreach (array(WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, $GLOBALS['msp_pg_test_uploads_base']) as $dir) {
            wp_mkdir_p($dir);
        }
        $site = $this->site;
        foreach (array('msp_pg_sc_macro_cue_scan_root', 'msp_pg_clonedoorway_scan_root', 'msp_pg_wp_link_helper_scan_root', 'msp_pg_doorway_content_gen_scan_root') as $rootFilter) {
            $this->withFilter($rootFilter, function () use ($site) { return $site; });
        }
        $GLOBALS['msp_pg_test_options'] = array('active_plugins' => array());
        $GLOBALS['msp_pg_test_transients'] = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();
    }

    private function disableAllRemediation()
    {
        foreach (array(
            'msp_pg_delete_tier1_enabled',
            'msp_pg_clonedoorway_delete_enabled',
            'msp_pg_sc_macro_cue_delete_enabled',
            'msp_pg_sc_macro_cue_wpincludes_delete_enabled',
            'msp_pg_wp_link_helper_delete_enabled',
            'msp_pg_doorway_content_gen_delete_enabled',
        ) as $flag) {
            $this->withFilter($flag, function () { return false; });
        }
    }

    private function scan($trigger, $args = array())
    {
        $GLOBALS['msp_pg_test_transients'] = array();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();
        $report = MSP_PG_Remediator::run_scan('test-' . $trigger, $args);
        $this->assertTrue(is_array($report) && empty($report['registry_error']), "$trigger: run_scan returned a report");

        return $report;
    }

    private static function sample($which)
    {
        $j = function () { return implode('', func_get_args()); };
        switch ($which) {
            case 'sc_mu':
                return "<?php\n/* " . $j('SCV', ':4.5.7') . " */\nfunction " . $j('_sc', '_mkdir') . "(\$p) { return true; }\nfunction " . $j('_sc', '_fpc') . "(\$a,\$b) { return true; }\nfunction " . $j('_sc', '_ul') . "(\$a) { return true; }\n";
            case 'sc_dropin':
                return "<?php\n/* " . $j('SC_ADV_', 'BEGIN:4.5.7:68be1498') . " */\nfunction injected_stub() { return true; }\n/* " . $j('SC_ADV_', 'END:4.5.7:68be1498') . " */\n";
            case 'wlh_mu':
                return "<?php\nclass " . $j('WLH', '_Vault') . " {\n    public static function name(\$logical) {\n        return 'wp_' . substr(hash('sha256', ABSPATH . '|' . DB_NAME . '|' . \$logical), 0, 24);\n    }\n}\nclass " . $j('WLH', '_Client') . " {}\n";
        }
        return '';
    }

    private function path($relative)
    {
        return MSP_PG_Utils::join_paths($this->site, $relative);
    }

    private function detection($report, $needle)
    {
        foreach ($report['detections'] as $d) {
            if (substr(str_replace('\\', '/', rtrim($d['live_path'], '/\\')), -strlen($needle)) === $needle) {
                return $d;
            }
        }
        throw new RuntimeException("No detection for $needle; got: " . implode(', ', array_map(function ($d) { return $d['live_path']; }, $report['detections'])));
    }

    /** sha256 of every file under the site except PG's own evidence store. */
    private function snapshot()
    {
        $out = array();
        $evidence = str_replace('\\', '/', MSP_PG_Config::artifact_base_dir());
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->site, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            $p = str_replace('\\', '/', $file->getPathname());
            if (strpos($p, $evidence . '/') === 0) {
                continue;
            }
            $out[$p] = hash_file('sha256', $file->getPathname());
        }
        ksort($out);
        return $out;
    }

    private function singleMail($label)
    {
        $this->assertSame(1, count($GLOBALS['msp_pg_test_wp_mail_calls']), "$label: exactly one operational email");
        return $GLOBALS['msp_pg_test_wp_mail_calls'][0];
    }

    private function assertTelemetry($state, $partial, $label)
    {
        $t = get_option('msp_pg_telemetry');
        $this->assertSame($state, $t['current_security_state'], "$label: telemetry security state");
        $this->assertSame($partial, (bool) $t['partial_remediation'], "$label: telemetry partial_remediation agrees with subject");
    }

    private function withFilter($tag, $callback)
    {
        add_filter($tag, $callback);
        $this->registeredFilters[] = array($tag, $callback);
    }

    private function removeAllFilters()
    {
        foreach ($this->registeredFilters as $entry) {
            remove_filter($entry[0], $entry[1]);
        }
        $this->registeredFilters = array();
    }

    private function deleteTree($dir)
    {
        if (is_link($dir) || is_file($dir)) {
            @unlink($dir);
            return;
        }
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                $this->deleteTree($dir . DIRECTORY_SEPARATOR . $entry);
            }
        }
        @rmdir($dir);
    }

    private function assertContainsAction($action, $detection, $message)
    {
        $this->assertTrue(in_array($action, $detection['actions'], true), $message . ' [actions: ' . implode(', ', $detection['actions']) . ']');
    }

    private function assertNotContainsAction($action, $detection, $message)
    {
        $this->assertFalse(in_array($action, $detection['actions'], true), $message . ' [actions: ' . implode(', ', $detection['actions']) . ']');
    }

    private function assertTrue($condition, $message)
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    private function assertFalse($condition, $message)
    {
        $this->assertTrue(!$condition, $message);
    }

    private function assertSame($expected, $actual, $message)
    {
        if ($expected !== $actual) {
            throw new RuntimeException($message . ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')');
        }
    }

    private function assertContains($needle, $haystack, $message)
    {
        $this->assertTrue(strpos((string) $haystack, $needle) !== false, $message . ' [in: ' . $haystack . ']');
    }

    private function assertNotContains($needle, $haystack, $message)
    {
        $this->assertTrue(strpos((string) $haystack, $needle) === false, $message . ' [in: ' . $haystack . ']');
    }
}

$test = new RemediationControlTest();
$test->run();
echo "RemediationControlTest passed\n";
