<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Regression test for the PG-WPLinkHelper family (see
 * docs/malware-families/PG-WPLinkHelper.md).
 *
 * Fixtures are synthetic reproductions of each signature's trigger shape,
 * not copies of the live vcadentistry specimen. MSP_PG_WLH_Scanner's
 * private scan_* methods are invoked directly via reflection with an
 * explicit fixture root, same convention as ClonedDoorwayTest.php and
 * SCMacroOptimizerCueTest.php.
 */
class WPLinkHelperTest
{
    private $fixtureRoot;

    public function run()
    {
        $this->fixtureRoot = __DIR__ . DIRECTORY_SEPARATOR . 'wlh-fixture-' . uniqid();

        try {
            $this->buildFixture();
            $this->assertSignatureUnitsMatchFixture();
            $this->assertScanFindsExpectedArtifactsOnly();
            $this->assertDomainOnlyNeverAuthorizesBackupDirDeletion();
            $this->assertRemovalWithheldWhenDeleteDisabledByConfig();
            $this->assertRealArtifactsAreRemovedAndLegitimateFilesSurvive();
        } finally {
            $this->cleanup($this->fixtureRoot);
        }
    }

    private function buildFixture()
    {
        $muDir = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins');
        wp_mkdir_p($muDir);
        file_put_contents(MSP_PG_Utils::join_paths($muDir, 'wlh-recovery-x1.php'), self::sample('malicious_mu_plugin'));
        // Legitimate, headerless mu-plugin (e.g. a host-injected one) -- headerless-ness alone must never be a signature.
        file_put_contents(MSP_PG_Utils::join_paths($muDir, 'host-performance.php'), "<?php\nfunction host_perf_tweak() { return true; }\n");

        $wpContent = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content');

        $positiveBackupDir = MSP_PG_Utils::join_paths($wpContent, 'wp-ff6a416ee94d-prev');
        wp_mkdir_p($positiveBackupDir);
        file_put_contents(MSP_PG_Utils::join_paths($positiveBackupDir, 'wp-link-helper.php'), self::sample('plugin_main_file'));

        // Name matches the backup-dir convention, but contains nothing
        // identifiable as this family -- must never be reported.
        $emptyNameOnlyDir = MSP_PG_Utils::join_paths($wpContent, 'wp-aaaaaaaaaaaa-prev');
        wp_mkdir_p($emptyNameOnlyDir);
        file_put_contents(MSP_PG_Utils::join_paths($emptyNameOnlyDir, 'notes.txt'), 'unrelated backup notes');

        // Name matches the backup-dir convention AND contains the C2 domain
        // literal, but no IOC string/vault-derivation/hash -- domain alone
        // must corroborate a detection but must NEVER by itself authorize
        // deletion (see assertDomainOnlyNeverAuthorizesBackupDirDeletion()).
        $this->domainOnlyBackupDir = MSP_PG_Utils::join_paths($wpContent, 'wp-bbbbbbbbbbbb-prev');
        wp_mkdir_p($this->domainOnlyBackupDir);
        file_put_contents(MSP_PG_Utils::join_paths($this->domainOnlyBackupDir, 'notes.php'), "<?php\n// unrelated reference to cachelayer.top seen in a log excerpt\n");
    }

    private $domainOnlyBackupDir;

    private static function sample($which)
    {
        switch ($which) {
            case 'malicious_mu_plugin':
                return "<?php\n"
                    . "class WLH_Vault {\n"
                    . "    public static function name(\$logical) {\n"
                    . "        return 'wp_' . substr(hash('sha256', ABSPATH . '|' . DB_NAME . '|' . \$logical), 0, 24);\n"
                    . "    }\n"
                    . "}\n"
                    . "class WLH_Client {}\n";

            case 'plugin_main_file':
                return "<?php\n"
                    . "define('WLH_REMOTE_URL', base64_decode('aHR0cHM6Ly9jYWNoZWxheWVyLnRvcA=='));\n"
                    . "define('WLH_HANDSHAKE', 'deadbeefdeadbeefdeadbeefdeadbeef');\n"
                    . "class WLH_Client { public function heartbeat() { return true; } }\n";
        }

        return '';
    }

    private function assertSignatureUnitsMatchFixture()
    {
        $muContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins', 'wlh-recovery-x1.php'));
        $this->assertTrue(MSP_PG_WLH_Signatures::has_vault_derivation_pattern($muContent), 'WLH-VAULT-DERIVATION should match the fixture mu-plugin');
        $this->assertTrue(MSP_PG_WLH_Signatures::has_ioc_string($muContent), 'WLH-IOC should match WLH_Vault/WLH_Client class names');

        $legitMuContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins', 'host-performance.php'));
        $this->assertFalse(MSP_PG_WLH_Signatures::has_vault_derivation_pattern($legitMuContent), 'WLH-VAULT-DERIVATION must not match an unrelated legitimate headerless mu-plugin');
        $this->assertFalse(MSP_PG_WLH_Signatures::has_ioc_string($legitMuContent), 'WLH-IOC must not match an unrelated legitimate headerless mu-plugin');
        $this->assertTrue(MSP_PG_WLH_Signatures::has_no_plugin_header($legitMuContent), 'Fixture sanity: the legitimate mu-plugin is intentionally headerless, proving headerless-ness alone is not the signature');

        $this->assertTrue(MSP_PG_WLH_Signatures::is_backup_directory_name(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'wp-ff6a416ee94d-prev')), 'WLH-BACKUP-DIR should match `wp-ff6a416ee94d-prev`');
        $this->assertFalse(MSP_PG_WLH_Signatures::is_backup_directory_name(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'plugins')), 'WLH-BACKUP-DIR must not match an ordinary directory name');
    }

    private function assertScanFindsExpectedArtifactsOnly()
    {
        $byType = $this->scanFixtureByType($this->fixtureRoot);

        $this->assertSame(1, count($byType[MSP_PG_WLH_Scanner::ARTIFACT_MU_PLUGIN_FILE] ?? array()), 'Should detect exactly the malicious mu-plugin, not the legitimate headerless one');

        $backupDetections = $byType[MSP_PG_WLH_Scanner::ARTIFACT_BACKUP_DIRECTORY] ?? array();
        $this->assertSame(2, count($backupDetections), 'Should detect the IOC-bearing backup dir and the domain-only backup dir, but NOT the name-only-match-with-no-content dir');

        $reportedPaths = array_map(function ($a) { return basename($a['plugin_dir']); }, $backupDetections);
        $this->assertTrue(in_array('wp-ff6a416ee94d-prev', $reportedPaths, true), 'IOC-bearing backup directory must be reported');
        $this->assertFalse(in_array('wp-aaaaaaaaaaaa-prev', $reportedPaths, true), 'A backup-dir-named directory with no corroborating content must never be reported');
    }

    private function assertDomainOnlyNeverAuthorizesBackupDirDeletion()
    {
        $siteMeta = $this->siteMeta();
        $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out-domain-only';
        wp_mkdir_p($scanDir);

        $byType = $this->scanFixtureByType($this->fixtureRoot);
        $domainOnlyAnalysis = null;
        foreach ($byType[MSP_PG_WLH_Scanner::ARTIFACT_BACKUP_DIRECTORY] as $a) {
            if (basename($a['plugin_dir']) === 'wp-bbbbbbbbbbbb-prev') {
                $domainOnlyAnalysis = $a;
            }
        }
        $this->assertTrue($domainOnlyAnalysis !== null, 'Fixture setup: the domain-only backup directory must be among the detections');
        $this->assertFalse(in_array('ioc_string', $domainOnlyAnalysis['exact_match_types'], true), 'Fixture sanity: domain-only detection must not also carry an IOC-string hit');
        $this->assertFalse(in_array('vault_derivation', $domainOnlyAnalysis['exact_match_types'], true), 'Fixture sanity: domain-only detection must not also carry a vault-derivation hit');

        $detection = MSP_PG_WLH_Remediator::remediate($domainOnlyAnalysis, $siteMeta, $scanDir, false);
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), 'A known_domain + backup_dir_name match alone must never authorize deletion');
        $this->assertTrue(in_array('REMOVAL_WITHHELD_INSUFFICIENT_CONFIDENCE', $detection['actions'], true), 'Withheld removal must be recorded explicitly, not silently');
        $this->assertTrue(is_dir($this->domainOnlyBackupDir), 'Domain-only backup directory must remain in place');
    }

    /**
     * Canary-configuration regression -- see
     * SCMacroOptimizerCueTest::assertRemovalWithheldWhenDeleteDisabledByConfig()
     * for the full rationale.
     */
    private function assertRemovalWithheldWhenDeleteDisabledByConfig()
    {
        $disableFilter = function () { return false; };
        add_filter('msp_pg_wp_link_helper_delete_enabled', $disableFilter);

        try {
            $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out-disabled';
            wp_mkdir_p($scanDir);

            $byType = $this->scanFixtureByType($this->fixtureRoot);
            $muAnalysis = $byType[MSP_PG_WLH_Scanner::ARTIFACT_MU_PLUGIN_FILE][0];
            $muPath = $muAnalysis['plugin_dir'];

            $detection = MSP_PG_WLH_Remediator::remediate($muAnalysis, $this->siteMeta(), $scanDir, false);

            $this->assertTrue(in_array('REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION', $detection['actions'], true), 'Removal withheld by configuration must be recorded explicitly, not silently');
            $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), 'Artifact must not be removed while this family\'s delete flag is disabled');
            $this->assertTrue(file_exists($muPath), 'Live artifact must remain in place while deletion is disabled by configuration');
        } finally {
            remove_filter('msp_pg_wp_link_helper_delete_enabled', $disableFilter);
        }
    }

    private function assertRealArtifactsAreRemovedAndLegitimateFilesSurvive()
    {
        $siteMeta = $this->siteMeta();
        $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out-real';
        wp_mkdir_p($scanDir);

        $byType = $this->scanFixtureByType($this->fixtureRoot);

        $muDetection = MSP_PG_WLH_Remediator::remediate($byType[MSP_PG_WLH_Scanner::ARTIFACT_MU_PLUGIN_FILE][0], $siteMeta, $scanDir, false);
        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $muDetection['actions'], true), 'Malicious mu-plugin (vault-derivation + IOC) should be removed');
        $this->assertTrue(file_exists($muDetection['evidence_manifest_path']), 'Evidence manifest must exist before removal is trusted');

        $backupAnalysis = null;
        foreach ($byType[MSP_PG_WLH_Scanner::ARTIFACT_BACKUP_DIRECTORY] as $a) {
            if (basename($a['plugin_dir']) === 'wp-ff6a416ee94d-prev') {
                $backupAnalysis = $a;
            }
        }
        $backupDetection = MSP_PG_WLH_Remediator::remediate($backupAnalysis, $siteMeta, $scanDir, false);
        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $backupDetection['actions'], true), 'IOC-bearing backup directory should be removed');

        $legitMuPath = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins', 'host-performance.php');
        $this->assertTrue(file_exists($legitMuPath), 'Legitimate headerless mu-plugin must survive remediation untouched');
        $this->assertTrue(is_dir($this->domainOnlyBackupDir), 'Domain-only backup directory must still survive (never removed in this run)');

        $rescanByType = $this->scanFixtureByType($this->fixtureRoot);
        $this->assertTrue(empty($rescanByType[MSP_PG_WLH_Scanner::ARTIFACT_MU_PLUGIN_FILE] ?? array()), 'Removed mu-plugin must not be re-detected on rescan');
        $remainingBackupNames = array_map(function ($a) { return basename($a['plugin_dir']); }, $rescanByType[MSP_PG_WLH_Scanner::ARTIFACT_BACKUP_DIRECTORY] ?? array());
        $this->assertFalse(in_array('wp-ff6a416ee94d-prev', $remainingBackupNames, true), 'Removed backup directory must not be re-detected on rescan');
        $this->assertTrue(in_array('wp-bbbbbbbbbbbb-prev', $remainingBackupNames, true), 'Domain-only backup directory should still be detected (report-only) on rescan');
    }

    private function scanFixtureByType($root)
    {
        $ref = new ReflectionClass('MSP_PG_WLH_Scanner');
        $methods = array('scan_mu_plugins', 'scan_backup_directories');

        $byType = array();
        foreach ($methods as $methodName) {
            $method = $ref->getMethod($methodName);
            $method->setAccessible(true);
            foreach ($method->invoke(null, $root) as $analysis) {
                $byType[$analysis['artifact_type']][] = $analysis;
            }
        }

        return $byType;
    }

    private function siteMeta()
    {
        return array(
            'site_url' => 'https://example.test/',
            'site_slug' => 'example-test',
            'wordpress_version' => '6.6.1',
            'php_version' => PHP_VERSION,
            'active_plugins' => array(),
            'active_theme' => 'Test Theme',
        );
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
        if (is_dir($dir)) {
            $this->deleteDirectory($dir);
        }
    }

    private function deleteDirectory($dir)
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
}

$test = new WPLinkHelperTest();
$test->run();
echo "WPLinkHelperTest passed\n";
