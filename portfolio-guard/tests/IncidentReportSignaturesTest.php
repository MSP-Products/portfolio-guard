<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Regression test for the signatures taken from the first two incident reports
 * (Apple Dental Longview MSP-WO-IR-2026-ADL, Levine Eye Care MSP-WO-IR-2026-001).
 *
 * The positive side (both stubs are confirmed malware) lives in the validation
 * gate's known-malware corpus. This file covers the false-positive side and the
 * indicators that were left out on purpose.
 */
class IncidentReportSignaturesTest
{
    private $workspace;
    private $pluginRoot;

    public function run()
    {
        $this->workspace  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'msp-pg-irs-' . uniqid();
        $this->pluginRoot = $this->workspace . DIRECTORY_SEPARATOR . 'plugins';
        wp_mkdir_p($this->pluginRoot);

        if (!defined('WP_PLUGIN_DIR')) {
            define('WP_PLUGIN_DIR', $this->pluginRoot);
        }
        if (!defined('WPMU_PLUGIN_DIR')) {
            define('WPMU_PLUGIN_DIR', $this->workspace . DIRECTORY_SEPARATOR . 'mu-plugins');
        }
        $GLOBALS['msp_pg_test_uploads_base'] = $this->workspace . DIRECTORY_SEPARATOR . 'uploads';
        wp_mkdir_p($GLOBALS['msp_pg_test_uploads_base']);

        try {
            $this->assertRegistryAdvancedAndEntriesPresent();
            $this->assertLowConfidenceIndicatorsAreNotRegistered();
            $this->assertCleanPluginInLoadHelperFolderIsNotFlagged();
            $this->assertScannerNeverFlagsItsOwnSignatures();
        } finally {
            $this->cleanup($this->workspace);
        }
    }

    private function assertRegistryAdvancedAndEntriesPresent()
    {
        $meta = MSP_PG_Signatures::registry_metadata();
        $this->assertTrue($meta !== null && $meta['version'] >= 3, 'Registry version must be 3 or higher so sites accept the new entries');

        $apple = MSP_PG_Signatures::variant_by_slug('wp-pup-plugin');
        $this->assertTrue($apple !== null, 'wp-pup-plugin must be registered');
        $this->assertSame('aggregate-smart.php', $apple['main_file'], 'wp-pup-plugin primary file');
        $this->assertSame(6, count($apple['hashes']), 'wp-pup-plugin must register the six reported hashes');
        foreach ($apple['hashes'] as $hash) {
            $this->assertTrue((bool) preg_match('/^[0-9A-F]{64}$/', $hash), 'Hash must be 64 uppercase hex characters: ' . $hash);
        }
        $this->assertTrue(in_array('aggregate-smart-b23258d37620/v1', $apple['routes'], true), 'wp-pup-plugin REST namespace');

        $levine = MSP_PG_Signatures::variant_by_slug('levine-load-helper-backdoor');
        $this->assertTrue($levine !== null, 'Levine backdoor entry must be registered');
        $this->assertSame('', $levine['main_file'], 'Levine entry must not name a primary file');
        $this->assertSame(array(), $levine['hashes'], 'Levine entry has no reported hashes');
        $this->assertSame(
            array('LOADHELPER_SVC_LOGIN', 'LoadHelper::handle_sync', 'load_helper_sync_token'),
            $levine['routes'],
            'Levine code strings'
        );
    }

    private function assertLowConfidenceIndicatorsAreNotRegistered()
    {
        $registry = file_get_contents(dirname(__DIR__) . '/data/signatures.json');
        // Each of these appears in a report but is too weak or too sensitive to act on automatically.
        $leftOut = array(
            'metamap-monoalpha.app'  => 'low-confidence domain (report: do not block without attribution)',
            'metadesign-lattice.io'  => 'low-confidence domain (report: do not block without attribution)',
            'media-build77'          => 'account name, intent only',
            '_19e4ff'                => 'too short to be a safe match',
            'plugin.upload_plugin'   => 'legitimate activity on its own',
        );
        foreach ($leftOut as $indicator => $reason) {
            $this->assertFalse(strpos($registry, $indicator) !== false, $indicator . ' must not be registered: ' . $reason);
        }
        $this->assertFalse(in_array('load-helper', MSP_PG_Signatures::known_slugs(), true), 'The folder name load-helper is too generic to match on its own');
    }

    private function assertCleanPluginInLoadHelperFolderIsNotFlagged()
    {
        $dir = $this->pluginRoot . DIRECTORY_SEPARATOR . 'load-helper';
        wp_mkdir_p($dir);
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . 'load-helper.php',
            "<?php\n/**\n * Plugin Name: Load Helper\n * Description: Defers non-critical scripts.\n */\nfunction load_helper_defer_scripts() { return true; }\n"
        );

        $analysis = MSP_PG_Detector::detect($dir);
        $this->assertTrue($analysis === null, 'A clean plugin that only shares the folder name load-helper must not be detected');

        $this->cleanup($dir);
    }

    private function assertScannerNeverFlagsItsOwnSignatures()
    {
        $own = $this->pluginRoot . DIRECTORY_SEPARATOR . 'portfolio-guard';
        wp_mkdir_p($own . DIRECTORY_SEPARATOR . 'data');
        file_put_contents($own . DIRECTORY_SEPARATOR . 'portfolio-guard.php', "<?php\n/**\n * Plugin Name: Portfolio Guard\n */\n");
        copy(dirname(__DIR__) . '/data/signatures.json', $own . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'signatures.json');

        // Positive control: the same files under another folder name do match, so the test proves something.
        $decoy = $this->pluginRoot . DIRECTORY_SEPARATOR . 'not-portfolio-guard';
        wp_mkdir_p($decoy . DIRECTORY_SEPARATOR . 'data');
        copy(dirname(__DIR__) . '/data/signatures.json', $decoy . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'signatures.json');
        $control = MSP_PG_Detector::detect($decoy);
        $this->assertTrue($control !== null && in_array('known_route', $control['exact_match_types'], true), 'Positive control: the registry contents under another folder name should match');
        $this->cleanup($decoy);

        $GLOBALS['msp_pg_test_options']             = array('active_plugins' => array('portfolio-guard/portfolio-guard.php'));
        $GLOBALS['msp_pg_test_transients']          = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();

        $report = MSP_PG_Remediator::run_scan('incident-report-signatures-test');
        foreach ($report['detections'] as $detection) {
            $this->assertFalse($detection['plugin_slug'] === 'portfolio-guard', 'Portfolio Guard must never flag its own signatures.json');
        }
        $this->assertSame(array(), $GLOBALS['msp_pg_test_deactivated_plugins'], 'Portfolio Guard must never deactivate itself');
        $this->assertTrue(is_dir($own), 'Portfolio Guard folder must still exist after a scan');
    }

    private function assertTrue($condition, $message)
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    private function assertFalse($condition, $message)
    {
        if ($condition) {
            throw new RuntimeException($message);
        }
    }

    private function assertSame($expected, $actual, $message)
    {
        if ($expected !== $actual) {
            throw new RuntimeException($message . ' Expected `' . var_export($expected, true) . '` but got `' . var_export($actual, true) . '`.');
        }
    }

    private function cleanup($dir)
    {
        if (!is_dir($dir)) {
            return;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($dir);
    }
}

$test = new IncidentReportSignaturesTest();
$test->run();
echo "IncidentReportSignaturesTest passed\n";
