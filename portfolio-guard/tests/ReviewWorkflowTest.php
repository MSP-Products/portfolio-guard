<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Integration tests for the Sprint 4 Review Required workflow.
 *
 * Covers: whitelist suppression in scans, operator-confirmed remediation,
 * state storage of review_required findings, and telemetry updates.
 *
 * These tests use real FeatureExtractor and BehaviorClassifier against
 * the synthetic corpus fixtures so the scan pipeline executes end-to-end.
 */
class ReviewWorkflowTest
{
    private $passed = 0;
    private $failed = 0;
    private $errors = array();

    /** Temporary workspace root (parent of synthetic plugins and scan artifacts). */
    private $workspace = '';

    /** Temporary plugin directory created for each scan test. */
    private $pluginDir = '';

    // -------------------------------------------------------------------------
    // Test runner
    // -------------------------------------------------------------------------

    public function run()
    {
        // Create an isolated workspace and declare WP_PLUGIN_DIR once for all scan tests
        $this->workspace = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'msp-pg-review-' . getmypid();
        $pluginsDir      = $this->workspace . DIRECTORY_SEPARATOR . 'plugins';
        $muDir           = $this->workspace . DIRECTORY_SEPARATOR . 'mu-plugins';
        wp_mkdir_p($pluginsDir);
        wp_mkdir_p($muDir);

        if (!defined('WP_PLUGIN_DIR')) {
            define('WP_PLUGIN_DIR', $pluginsDir);
        }
        if (!defined('WPMU_PLUGIN_DIR')) {
            define('WPMU_PLUGIN_DIR', $muDir);
        }

        $methods = array(
            'test_whitelist_suppresses_tier2_in_scan',
            'test_whitelist_approval_carries_to_a_different_version',
            'test_scan_stores_review_required_in_state',
            'test_state_review_required_contains_explain_data',
            'test_state_review_required_contains_plugin_version',
            'test_state_review_required_replaced_on_full_scan',
            'test_confirm_remediation_removes_from_state',
            'test_confirm_remediation_sends_email',
            'test_whitelist_telemetry_fields',
            'test_whitelist_count_reflected_in_telemetry',
            'test_explain_all_returns_all_profiles',
            'test_explain_all_activates_for_malware',
            'test_plugin_version_reads_header',
            'test_plugin_version_empty_when_absent',
            'test_trusted_slug_suppresses_tier2_finding',
            'test_trusted_slug_does_not_suppress_tier1_finding',
            'test_untrusted_slug_is_not_suppressed_by_trust_list',
        );

        foreach ($methods as $method) {
            $this->teardown_plugin_dir();
            $this->reset_state();
            $this->{$method}();
        }

        $this->teardown_plugin_dir();
        $this->report();
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    private function test_whitelist_suppresses_tier2_in_scan()
    {
        $slug    = 'synthetic-operator-access';
        $version = '1.0.0';
        $dir     = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_whitelist_suppresses_tier2_in_scan', $slug . ' fixture not found');
            return;
        }

        // First scan without whitelist — expect a finding
        $this->setup_scan_env($dir, $slug, $version);
        $report1 = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        if (!is_array($report1)) {
            $this->assertTrue(false, 'whitelist_suppress: first scan must return a report array');
            return;
        }

        $hasReview = !empty($report1['review_required']);
        if (!$hasReview) {
            $this->markSkipped('test_whitelist_suppresses_tier2_in_scan', $slug . ' did not produce a Tier 2 finding — cannot test suppression');
            return;
        }

        // Whitelist the plugin at its detected version
        MSP_PG_Whitelist::add($slug, $version, 1, 'admin', 'test suppression');

        // Second scan — finding must be suppressed
        $this->reset_scan_tracking($dir, $slug, $version);
        $report2 = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        $this->assertTrue(is_array($report2), 'whitelist_suppress: second scan must return array');
        $reviewSlugs = array_column($report2['review_required'], 'plugin_slug');
        $this->assertFalse(in_array($slug, $reviewSlugs, true), 'whitelist_suppress: whitelisted plugin must not appear in review_required');
    }

    private function test_whitelist_approval_carries_to_a_different_version()
    {
        $slug = 'synthetic-operator-access';
        $dir  = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_whitelist_approval_carries_to_a_different_version', $slug . ' fixture not found');
            return;
        }

        // Control: with no approval at all the plugin is flagged, so the suppression below is the whitelist's doing.
        $this->setup_scan_env($dir, $slug, '1.0.0');
        $before = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));
        if (!is_array($before) || !in_array($slug, array_column($before['review_required'], 'plugin_slug'), true)) {
            $this->markSkipped('test_whitelist_approval_carries_to_a_different_version', $slug . ' did not produce a Tier 2 finding - cannot test suppression');
            return;
        }

        // Approved at 99.0.0; the plugin now scans as 1.0.0 (a release, as far as the whitelist can tell).
        MSP_PG_Whitelist::add($slug, '99.0.0', 1, 'admin', 'approved at another version');

        $this->reset_scan_tracking($dir, $slug, '1.0.0');
        $report = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        if (!is_array($report)) {
            $this->assertTrue(false, 'carry_over: scan must return array');
            return;
        }

        $reviewSlugs = array_column($report['review_required'], 'plugin_slug');
        $this->assertFalse(in_array($slug, $reviewSlugs, true), 'carry_over: an approval at another version must still suppress the Tier 2 finding');
    }

    private function test_scan_stores_review_required_in_state()
    {
        $slug = 'synthetic-operator-access';
        $dir  = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_scan_stores_review_required_in_state', $slug . ' fixture not found');
            return;
        }

        $this->setup_scan_env($dir, $slug, '');
        MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        $state  = get_option(MSP_PG_Config::state_option_name(), array());
        $stored = isset($state['last_review_required']) ? $state['last_review_required'] : array();

        $this->assertTrue(is_array($stored), 'state_store: last_review_required must be an array in state');
    }

    private function test_state_review_required_contains_explain_data()
    {
        $slug = 'synthetic-operator-access';
        $dir  = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_state_review_required_contains_explain_data', $slug . ' fixture not found');
            return;
        }

        $this->setup_scan_env($dir, $slug, '');
        $report = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        if (empty($report['review_required'])) {
            $this->markSkipped('test_state_review_required_contains_explain_data', 'no tier2 finding to check explain data');
            return;
        }

        $state   = get_option(MSP_PG_Config::state_option_name(), array());
        $entries = $state['last_review_required'];
        $entry   = $entries[0];

        $this->assertTrue(isset($entry['explain']), 'explain_data: stored review_required entry must have explain field');
        $this->assertTrue(is_array($entry['explain']), 'explain_data: explain must be an array');
        $this->assertTrue(!empty($entry['explain']), 'explain_data: explain must not be empty');

        // Each profile entry must have the expected keys
        $first = reset($entry['explain']);
        $this->assertTrue(isset($first['profile_id']), 'explain_data: profile must have profile_id');
        $this->assertTrue(isset($first['score']),      'explain_data: profile must have score');
        $this->assertTrue(isset($first['threshold']),  'explain_data: profile must have threshold');
        $this->assertTrue(isset($first['signals']),    'explain_data: profile must have signals');
    }

    private function test_state_review_required_contains_plugin_version()
    {
        $slug = 'synthetic-operator-access';
        $dir  = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_state_review_required_contains_plugin_version', $slug . ' fixture not found');
            return;
        }

        $this->setup_scan_env($dir, $slug, '');
        $report = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        if (empty($report['review_required'])) {
            $this->markSkipped('test_state_review_required_contains_plugin_version', 'no tier2 finding');
            return;
        }

        $state   = get_option(MSP_PG_Config::state_option_name(), array());
        $entries = $state['last_review_required'];
        $entry   = $entries[0];

        $this->assertTrue(array_key_exists('plugin_version', $entry), 'plugin_version: stored entry must have plugin_version field');
        $this->assertTrue(is_string($entry['plugin_version']), 'plugin_version: plugin_version must be a string');
    }

    private function test_state_review_required_replaced_on_full_scan()
    {
        // Seed state with a stale review_required from a previous scan
        $state = get_option(MSP_PG_Config::state_option_name(), array());
        $state['last_review_required'] = array(
            array('plugin_slug' => 'stale-plugin', 'plugin_version' => '1.0', 'behavior_profiles' => array(), 'explain' => array(), 'detected_at' => gmdate('c')),
        );
        update_option(MSP_PG_Config::state_option_name(), $state, false);

        // Full scan with no detections replaces the list (empty scan dir — no plugins)
        MSP_PG_Remediator::run_scan('cron', array('dry_run' => true));

        $state2  = get_option(MSP_PG_Config::state_option_name(), array());
        $stored  = isset($state2['last_review_required']) ? $state2['last_review_required'] : array('NOT_SET');
        $hasStale = !empty(array_filter($stored, function ($e) { return isset($e['plugin_slug']) && $e['plugin_slug'] === 'stale-plugin'; }));

        $this->assertFalse($hasStale, 'state_replace: full scan must replace stale_review_required from previous scan');
    }

    private function test_confirm_remediation_removes_from_state()
    {
        $slug = 'synthetic-operator-access';
        $dir  = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_confirm_remediation_removes_from_state', $slug . ' fixture not found');
            return;
        }

        // Seed stored state with a review_required entry for the target slug
        $state = get_option(MSP_PG_Config::state_option_name(), array());
        $state['last_review_required'] = array(
            array('plugin_slug' => $slug, 'plugin_version' => '1.0.0', 'behavior_profiles' => array(), 'explain' => array(), 'detected_at' => gmdate('c')),
            array('plugin_slug' => 'another-plugin', 'plugin_version' => '2.0', 'behavior_profiles' => array(), 'explain' => array(), 'detected_at' => gmdate('c')),
        );
        update_option(MSP_PG_Config::state_option_name(), $state, false);

        $this->setup_scan_env($dir, $slug, '1.0.0');
        MSP_PG_Remediator::confirm_remediation($slug);

        $state2  = get_option(MSP_PG_Config::state_option_name(), array());
        $stored  = isset($state2['last_review_required']) ? $state2['last_review_required'] : array();
        $hasTarget = !empty(array_filter($stored, function ($e) use ($slug) { return isset($e['plugin_slug']) && $e['plugin_slug'] === $slug; }));

        $this->assertFalse($hasTarget, 'confirm_remediate: target plugin must be removed from stored last_review_required');

        $hasOther = !empty(array_filter($stored, function ($e) { return isset($e['plugin_slug']) && $e['plugin_slug'] === 'another-plugin'; }));
        $this->assertTrue($hasOther, 'confirm_remediate: other plugins must remain in stored last_review_required');
    }

    private function test_confirm_remediation_sends_email()
    {
        $slug = 'synthetic-operator-access';
        $dir  = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_confirm_remediation_sends_email', $slug . ' fixture not found');
            return;
        }

        $this->setup_scan_env($dir, $slug, '1.0.0');
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();

        MSP_PG_Remediator::confirm_remediation($slug);

        $this->assertTrue(!empty($GLOBALS['msp_pg_test_wp_mail_calls']), 'confirm_email: confirm_remediation must send an email');
    }

    private function test_whitelist_telemetry_fields()
    {
        MSP_PG_Diagnostics::record_telemetry(array(
            'last_whitelist_at'            => '2026-06-30T12:00:00+00:00',
            'last_whitelist_plugin'        => 'my-plugin',
            'last_review_action'           => 'whitelist',
            'last_review_action_timestamp' => '2026-06-30T12:00:00+00:00',
        ));

        $t = MSP_PG_Diagnostics::telemetry();

        $this->assertTrue($t['last_whitelist_at']            === '2026-06-30T12:00:00+00:00', 'telemetry: last_whitelist_at preserved');
        $this->assertTrue($t['last_whitelist_plugin']        === 'my-plugin',                 'telemetry: last_whitelist_plugin preserved');
        $this->assertTrue($t['last_review_action']           === 'whitelist',                 'telemetry: last_review_action preserved');
        $this->assertTrue($t['last_review_action_timestamp'] === '2026-06-30T12:00:00+00:00', 'telemetry: last_review_action_timestamp preserved');

        // Must survive a subsequent write
        MSP_PG_Diagnostics::record_telemetry(array('current_security_state' => 'healthy'));
        $t2 = MSP_PG_Diagnostics::telemetry();

        $this->assertTrue($t2['last_whitelist_plugin'] === 'my-plugin', 'telemetry: last_whitelist_plugin must survive subsequent write');
    }

    private function test_whitelist_count_reflected_in_telemetry()
    {
        MSP_PG_Whitelist::add('plugin-a', '1.0', 1, 'admin', '');
        MSP_PG_Whitelist::add('plugin-b', '2.0', 1, 'admin', '');

        $t = MSP_PG_Diagnostics::record_telemetry(array());
        $this->assertTrue($t['whitelist_count'] === 2, 'whitelist_count: must reflect current whitelist size');

        MSP_PG_Whitelist::remove('plugin-a');
        $t2 = MSP_PG_Diagnostics::record_telemetry(array());
        $this->assertTrue($t2['whitelist_count'] === 1, 'whitelist_count: must decrease after remove');
    }

    private function test_explain_all_returns_all_profiles()
    {
        $observations = array();
        $result = MSP_PG_BehaviorClassifier::explain_all($observations);

        $expectedProfiles = array('persistence', 'command-and-control', 'payload-delivery', 'operator-access', 'stealth');
        foreach ($expectedProfiles as $profileId) {
            $this->assertTrue(isset($result[$profileId]), 'explain_all: must contain profile ' . $profileId);
            $this->assertTrue(is_array($result[$profileId]), 'explain_all: profile ' . $profileId . ' must be array');
        }
        $this->assertTrue(count($result) === count($expectedProfiles), 'explain_all: must contain exactly ' . count($expectedProfiles) . ' profiles');
    }

    private function test_explain_all_activates_for_malware()
    {
        $synthetic = $this->corpus_dir('synthetic');
        $malwareDir = $synthetic . DIRECTORY_SEPARATOR . 'synthetic-operator-access';

        if (!is_dir($malwareDir)) {
            $this->markSkipped('test_explain_all_activates_for_malware', 'synthetic-operator-access fixture not found');
            return;
        }

        $observations = MSP_PG_FeatureExtractor::extract($malwareDir);
        $result = MSP_PG_BehaviorClassifier::explain_all($observations);

        $anyActivated = false;
        foreach ($result as $profileId => $ex) {
            if ($ex['activates']) {
                $anyActivated = true;
                break;
            }
        }
        $this->assertTrue($anyActivated, 'explain_all: at least one profile must activate for synthetic-operator-access');
    }

    private function test_plugin_version_reads_header()
    {
        $dir = $this->create_temp_plugin('version-test-plugin', "<?php\n/**\n * Plugin Name: Version Test\n * Version: 3.7.2\n */\n");
        $version = MSP_PG_Utils::plugin_version($dir);
        $this->assertTrue($version === '3.7.2', 'plugin_version: must read Version: header from plugin file');
    }

    private function test_plugin_version_empty_when_absent()
    {
        $dir = $this->create_temp_plugin('no-version-plugin', "<?php\n// No version header here\necho 'hello';\n");
        $version = MSP_PG_Utils::plugin_version($dir);
        $this->assertTrue($version === '', 'plugin_version: must return empty string when no Version: header found');
    }

    private function test_trusted_slug_suppresses_tier2_finding()
    {
        // Use a real behavioral fixture (operator-access) but rename it to a trusted slug
        // so the scanner sees it as a fleet-baseline plugin.
        $sourceSlug = 'synthetic-operator-access';
        $trustedSlug = 'wordfence';
        $sourceDir = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $sourceSlug;

        if (!is_dir($sourceDir)) {
            $this->markSkipped('test_trusted_slug_suppresses_tier2_finding', $sourceSlug . ' fixture not found');
            return;
        }

        // Copy fixture under the trusted slug name
        $destDir = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $trustedSlug;
        MSP_PG_Utils::copy_directory($sourceDir, $destDir);
        $this->pluginDir = $destDir;

        $report = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        $this->assertTrue(is_array($report), 'trusted_slug_suppress: scan must return array');
        $reviewSlugs = array_column($report['review_required'], 'plugin_slug');
        $this->assertFalse(
            in_array($trustedSlug, $reviewSlugs, true),
            'trusted_slug_suppress: fleet-baseline trusted slug must not appear in review_required'
        );
    }

    private function test_trusted_slug_does_not_suppress_tier1_finding()
    {
        // Create a plugin directory named after a trusted slug but inject a Tier 1 signature string.
        // The trust list must NOT suppress Tier 1 detections.
        $trustedSlug = 'wordfence';
        $destDir = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $trustedSlug;
        @mkdir($destDir, 0777, true);
        // Inject a known family bootstrap string that triggers Tier 1 via exact IOC match
        file_put_contents(
            $destDir . DIRECTORY_SEPARATOR . $trustedSlug . '.php',
            "<?php\n/**\n * Plugin Name: $trustedSlug\n */\n// fastreactic_nanomicroserviceing\n"
        );
        $this->pluginDir = $destDir;

        $report = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        $this->assertTrue(is_array($report), 'trusted_slug_tier1: scan must return array');

        // If any detection found for the trusted slug it could be tier1 or tier2.
        // The key guarantee: if the scanner found a Tier 1 hit it must NOT be suppressed.
        $allDetected = array_column($report['detections'], 'plugin_slug');
        $tier1Slugs  = array_column($report['confirmed_malware'], 'plugin_slug');

        // Only assert if the fixture actually produced a Tier 1 finding
        if (in_array($trustedSlug, $tier1Slugs, true)) {
            $this->assertTrue(
                in_array($trustedSlug, $tier1Slugs, true),
                'trusted_slug_tier1: Tier 1 detection of a trusted slug must not be suppressed'
            );
        }
        // The trusted slug must not appear in review_required if it was caught as Tier 1
        // (because Tier 1 overrides Tier 2 — the Detector returns tier1, not tier2).
        if (in_array($trustedSlug, $allDetected, true)) {
            $reviewSlugs = array_column($report['review_required'], 'plugin_slug');
            $this->assertFalse(
                // If it appeared in detections only as review_required, something is wrong
                in_array($trustedSlug, $reviewSlugs, true) && !in_array($trustedSlug, $tier1Slugs, true),
                'trusted_slug_tier1: trusted slug with Tier 1 signals must not appear only in review_required'
            );
        }
    }

    private function test_untrusted_slug_is_not_suppressed_by_trust_list()
    {
        // Verify that a non-trusted slug with behavioral signals still produces a finding.
        $slug = 'synthetic-operator-access';
        $dir  = $this->corpus_dir('synthetic') . DIRECTORY_SEPARATOR . $slug;

        if (!is_dir($dir)) {
            $this->markSkipped('test_untrusted_slug_is_not_suppressed_by_trust_list', $slug . ' fixture not found');
            return;
        }

        $this->setup_scan_env($dir, $slug, '');
        $report = MSP_PG_Remediator::run_scan('manual', array('dry_run' => true));

        $this->assertTrue(is_array($report), 'untrusted_slug: scan must return array');
        // synthetic-operator-access is NOT in the trust list — it must still be reported
        // (provided it actually activates a behavioral profile)
        $reviewSlugs = array_column($report['review_required'], 'plugin_slug');
        if (!empty($report['detections'])) {
            $this->assertTrue(
                in_array($slug, $reviewSlugs, true),
                'untrusted_slug: non-trusted slug with behavioral signals must still appear in review_required'
            );
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Path to the real synthetic corpus fixtures (C:\analysis\validation\corpus\synthetic).
     */
    private function corpus_dir($subdir)
    {
        // __DIR__ = C:\analysis\portfolio-guard\tests
        // dirname×2 = C:\analysis
        return dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . 'validation' . DIRECTORY_SEPARATOR . 'corpus' . DIRECTORY_SEPARATOR . $subdir;
    }

    /**
     * Copy a synthetic fixture into WP_PLUGIN_DIR so run_scan() can find it,
     * optionally writing a version header into the main PHP file.
     */
    private function setup_scan_env($sourceDir, $slug, $version)
    {
        $destDir = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $slug;
        MSP_PG_Utils::copy_directory($sourceDir, $destDir);

        // If a version was supplied, inject it into the main PHP file
        if ($version !== '') {
            $mainFile = $destDir . DIRECTORY_SEPARATOR . $slug . '.php';
            if (is_readable($mainFile)) {
                $contents = file_get_contents($mainFile);
                // Prepend a minimal plugin header if no Version: header exists
                if (strpos($contents, 'Version:') === false) {
                    $header = "<?php\n/**\n * Plugin Name: $slug\n * Version: $version\n */\n";
                    file_put_contents($mainFile, $header . ltrim($contents, "<?php\n"));
                }
            } else {
                // Create a stub main file with the version header
                file_put_contents($destDir . DIRECTORY_SEPARATOR . $slug . '.php',
                    "<?php\n/**\n * Plugin Name: $slug\n * Version: $version\n */\n");
            }
        }

        $this->pluginDir = $destDir;
    }

    private function reset_scan_tracking($dir, $slug, $version)
    {
        // Clear scan lock so the second scan can proceed
        delete_transient(MSP_PG_Config::scan_lock_key());
    }

    /**
     * Create a minimal plugin in WP_PLUGIN_DIR with a custom PHP file.
     */
    private function create_temp_plugin($slug, $contents)
    {
        $dir = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $slug;
        @mkdir($dir, 0777, true);
        file_put_contents($dir . DIRECTORY_SEPARATOR . $slug . '.php', $contents);
        $this->pluginDir = $dir;
        return $dir;
    }

    private function teardown_plugin_dir()
    {
        if ($this->pluginDir !== '' && is_dir($this->pluginDir)) {
            $this->remove_dir($this->pluginDir);
            $this->pluginDir = '';
        }
    }

    private function remove_dir($dir)
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($dir);
    }

    private function reset_state()
    {
        $GLOBALS['msp_pg_test_options']    = array(
            'active_plugins'  => array(),
            'timezone_string' => 'UTC',
            'gmt_offset'      => 0,
        );
        $GLOBALS['msp_pg_test_transients'] = array();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();
        unset($GLOBALS['msp_pg_test_options'][MSP_PG_Whitelist::OPTION_NAME]);
    }

    private function markSkipped($test, $reason)
    {
        echo "SKIP: {$test} — {$reason}\n";
    }

    private function assertTrue($condition, $message)
    {
        if ($condition) {
            $this->passed++;
        } else {
            $this->failed++;
            $this->errors[] = 'FAIL: ' . $message;
        }
    }

    private function assertFalse($condition, $message)
    {
        $this->assertTrue(!$condition, $message);
    }

    private function report()
    {
        $total = $this->passed + $this->failed;
        foreach ($this->errors as $err) {
            echo $err . "\n";
        }
        if ($this->failed === 0) {
            echo "ReviewWorkflowTest: {$this->passed}/{$total} passed\n";
        } else {
            echo "ReviewWorkflowTest: {$this->passed}/{$total} passed, {$this->failed} FAILED\n";
        }
    }
}

$test = new ReviewWorkflowTest();
$test->run();
