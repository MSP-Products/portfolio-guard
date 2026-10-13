<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Integration tests for the full remediation lifecycle under
 * evidence_retention_mode = full_artifact_retention and compressed_archive
 * -- previously untested by any file in this suite, because
 * MSP_PG_Config::evidence_retention_mode() is read through apply_filters(),
 * and this harness's apply_filters() stub used to silently ignore every
 * registered add_filter() callback and always return the default
 * ('metadata_only'). That stub is now a real, minimal filter
 * implementation (see bootstrap.php) -- test-only infrastructure, no
 * production code changed to make this possible.
 *
 * Covers: evidence preservation, manifest readability and accuracy,
 * archive integrity, quarantine vs. deletion behavior, removal
 * authorization, remediation-status reporting, preservation-failure
 * safety, and infection-level partial-resolution tracking across a real
 * MSP_PG_Remediator::run_scan() call.
 */
class RemediationLifecycleIntegrationTest
{
    private $workspace;
    private $registeredFilters = array();

    public function run()
    {
        $this->workspace = __DIR__ . DIRECTORY_SEPARATOR . 'lifecycle-' . uniqid();
        wp_mkdir_p($this->workspace);

        try {
            foreach (array('full_artifact_retention', 'compressed_archive') as $mode) {
                $this->assertRemovableArtifactLifecycle($mode);
                $this->assertReportOnlyArtifactLifecycle($mode);
                $this->assertPreservationFailurePreventsRemoval($mode);
            }
            $this->assertPartialRemediationAcrossRealRunScan();
        } finally {
            $this->removeAllFilters();
            $this->cleanup($this->workspace);
        }
    }

    // -------------------------------------------------------------------------
    // Filter helpers (real add_filter()/apply_filters(), now wired up in
    // bootstrap.php -- see class docblock)
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Shared fixture builder: one standalone attacker-created SC mu-plugin
    // file (auto-removable) and one SC drop-in (report-only).
    // -------------------------------------------------------------------------

    private function buildScFixture($caseDir)
    {
        $muDir = MSP_PG_Utils::join_paths($caseDir, 'wp-content', 'mu-plugins');
        wp_mkdir_p($muDir);
        $muFile = MSP_PG_Utils::join_paths($muDir, 'malicious-sc.php');
        file_put_contents($muFile, "<?php\n/* SCV:4.5.7 */\nfunction _sc_mkdir(\$p){return true;}\nfunction _sc_fpc(\$a,\$b){return true;}\nfunction _sc_ul(\$a){return true;}\n");

        $wpContent = MSP_PG_Utils::join_paths($caseDir, 'wp-content');
        $dropinFile = MSP_PG_Utils::join_paths($wpContent, 'advanced-cache.php');
        file_put_contents($dropinFile, "<?php\n/* SC_ADV_BEGIN:4.5.7:68be1498 */\nfunction injected_stub(){return true;}\n/* SC_ADV_END:4.5.7:68be1498 */\n");

        return array('mu_file' => $muFile, 'dropin_file' => $dropinFile);
    }

    private function scanMuPluginFixture($caseDir)
    {
        $ref = new ReflectionClass('MSP_PG_SC_Scanner');
        $method = $ref->getMethod('scan_mu_plugins');
        $method->setAccessible(true);
        $results = $method->invoke(null, $caseDir);
        return $results[0];
    }

    private function scanDropinFixture($caseDir)
    {
        $ref = new ReflectionClass('MSP_PG_SC_Scanner');
        $method = $ref->getMethod('scan_dropin_files');
        $method->setAccessible(true);
        $results = $method->invoke(null, $caseDir);
        return $results[0];
    }

    private function artifactKeyFor($analysis)
    {
        return preg_replace('/[^A-Za-z0-9_-]+/', '_', $analysis['plugin_slug']);
    }

    // -------------------------------------------------------------------------
    // 1 & 3 & 4 (partial): removable artifact, full lifecycle, both modes
    // -------------------------------------------------------------------------

    private function assertRemovableArtifactLifecycle($mode)
    {
        $caseDir = MSP_PG_Utils::join_paths($this->workspace, 'removable-' . $mode);
        $fixture = $this->buildScFixture($caseDir);
        $analysis = $this->scanMuPluginFixture($caseDir);

        $this->withFilter('msp_pg_evidence_retention_mode', function () use ($mode) {
            return $mode;
        });
        $this->assertSame($mode, MSP_PG_Config::evidence_retention_mode(), "$mode: config override must actually take effect before remediation runs");

        $scanDir = MSP_PG_Utils::join_paths($caseDir, 'scan-out');
        wp_mkdir_p($scanDir);
        $siteMeta = $this->siteMeta();

        $detection = MSP_PG_SC_Remediator::remediate($analysis, $siteMeta, $scanDir, false);

        $this->assertTrue($detection['preservation_verified'], "$mode: evidence preservation must be verified before removal is reported");
        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), "$mode: removal must be authorized and recorded for a hash/structurally-confirmed artifact");
        $this->assertFalse(file_exists($fixture['mu_file']), "$mode: live artifact must no longer exist at its original path");

        // Manifest: exists, readable, valid JSON, and accurately reflects
        // the FINAL outcome (not the pre-removal 'Pending Remediation'
        // snapshot written before the destructive action).
        $this->assertTrue(file_exists($detection['evidence_manifest_path']), "$mode: evidence manifest must exist");
        $manifestRaw = file_get_contents($detection['evidence_manifest_path']);
        $manifest = json_decode($manifestRaw, true);
        $this->assertTrue(is_array($manifest), "$mode: manifest must be valid, readable JSON");
        $this->assertNotSame('Pending Remediation', $manifest['action'], "$mode: manifest action must be updated to the final outcome, not left at its pre-removal placeholder");

        if ($mode === 'full_artifact_retention') {
            $this->assertTrue(in_array('QUARANTINE_COMPLETED', $detection['actions'], true), "$mode: full_artifact_retention must quarantine (move), not just delete");
            $this->assertSame('Quarantined', $manifest['action'], "$mode: manifest action should read Quarantined");
            $this->assertSame('Quarantined', $manifest['remediation_status'], "$mode: manifest remediation_status should read Quarantined");
            $this->assertTrue($detection['quarantine_path'] !== '' && file_exists($detection['quarantine_path']), "$mode: the quarantined copy of the live artifact must exist on disk");
        } else {
            $this->assertFalse(in_array('QUARANTINE_COMPLETED', $detection['actions'], true), "$mode: compressed_archive must delete outright, not quarantine (no persistent quarantine exists in this mode)");
            $this->assertSame('Removed', $manifest['action'], "$mode: manifest action should read Removed");
            $this->assertSame('Removed', $manifest['remediation_status'], "$mode: manifest remediation_status should read Removed");
        }

        // Archive integrity: a non-empty, openable zip containing the
        // artifact's own file, in both modes.
        $this->assertTrue($detection['zip_path'] !== '' && file_exists($detection['zip_path']), "$mode: evidence archive must exist");
        $this->assertTrue(filesize($detection['zip_path']) > 0, "$mode: evidence archive must be non-empty");
        if (class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            $this->assertTrue($zip->open($detection['zip_path']) === true, "$mode: evidence archive must be openable as a valid zip");
            $this->assertTrue($zip->numFiles > 0, "$mode: evidence archive must contain at least one entry");
            $zip->close();
        }
    }

    // -------------------------------------------------------------------------
    // Report-only drop-in, full lifecycle, both modes
    // -------------------------------------------------------------------------

    private function assertReportOnlyArtifactLifecycle($mode)
    {
        $caseDir = MSP_PG_Utils::join_paths($this->workspace, 'reportonly-' . $mode);
        $fixture = $this->buildScFixture($caseDir);
        $analysis = $this->scanDropinFixture($caseDir);
        $beforeContent = file_get_contents($fixture['dropin_file']);

        $this->withFilter('msp_pg_evidence_retention_mode', function () use ($mode) {
            return $mode;
        });

        $scanDir = MSP_PG_Utils::join_paths($caseDir, 'scan-out');
        wp_mkdir_p($scanDir);

        $detection = MSP_PG_SC_Remediator::remediate($analysis, $this->siteMeta(), $scanDir, false);

        $this->assertTrue($detection['preservation_verified'], "$mode: evidence must still be preserved for a report-only artifact");
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), "$mode: a mixed-content drop-in must never be removed regardless of evidence_retention_mode");
        $this->assertTrue(in_array('REPORT_ONLY_NO_AUTOMATIC_REMOVAL', $detection['actions'], true), "$mode: report-only classification must be recorded");
        $this->assertSame($beforeContent, file_get_contents($fixture['dropin_file']), "$mode: live drop-in content must be byte-for-byte unchanged");

        $manifest = json_decode(file_get_contents($detection['evidence_manifest_path']), true);
        $this->assertTrue(isset($manifest['operator_action_required']) && $manifest['operator_action_required'] !== '', "$mode: manifest must record an explicit operator action for a report-only artifact");
    }

    // -------------------------------------------------------------------------
    // 5: preservation failure must prevent destructive remediation
    // -------------------------------------------------------------------------

    private function assertPreservationFailurePreventsRemoval($mode)
    {
        $caseDir = MSP_PG_Utils::join_paths($this->workspace, 'failcase-' . $mode);
        $fixture = $this->buildScFixture($caseDir);
        $analysis = $this->scanMuPluginFixture($caseDir);

        $this->withFilter('msp_pg_evidence_retention_mode', function () use ($mode) {
            return $mode;
        });

        $scanDir = MSP_PG_Utils::join_paths($caseDir, 'scan-out');
        wp_mkdir_p($scanDir);

        // Force the manifest write to fail deterministically (portable
        // across platforms, unlike relying on filesystem permission bits):
        // pre-create the exact path MSP_PG_SC_Remediator will try to write
        // evidence.json to, AS A DIRECTORY. file_put_contents() cannot write
        // through an existing directory, so MSP_PG_Utils::write_json()
        // returns false and preservationVerified must end up false.
        $artifactDir = MSP_PG_Utils::join_paths($scanDir, 'artifacts', $this->artifactKeyFor($analysis));
        wp_mkdir_p(MSP_PG_Utils::join_paths($artifactDir, 'evidence.json'));

        $detection = MSP_PG_SC_Remediator::remediate($analysis, $this->siteMeta(), $scanDir, false);

        $this->assertFalse($detection['preservation_verified'], "$mode: preservation must be reported as NOT verified when the manifest cannot be written");
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), "$mode: removal must never proceed when evidence preservation failed");
        $this->assertFalse(in_array('QUARANTINE_COMPLETED', $detection['actions'], true), "$mode: quarantine must never proceed when evidence preservation failed");
        $this->assertTrue(file_exists($fixture['mu_file']), "$mode: the live artifact must remain in place untouched after a preservation failure");
        $this->assertTrue(count($detection['errors']) > 0, "$mode: a preservation failure must be reported as an explicit error, not silently");
    }

    // -------------------------------------------------------------------------
    // 6: partial remediation across a real MSP_PG_Remediator::run_scan() --
    // one auto-removable artifact + one report-only artifact in the same
    // scan. The infection must remain unresolved after the removable
    // component is eliminated.
    // -------------------------------------------------------------------------

    private function assertPartialRemediationAcrossRealRunScan()
    {
        $caseDir = MSP_PG_Utils::join_paths($this->workspace, 'partial-remediation-real-scan');
        $fixture = $this->buildScFixture($caseDir);

        if (!defined('WP_PLUGIN_DIR')) {
            define('WP_PLUGIN_DIR', MSP_PG_Utils::join_paths($caseDir, 'wp-content', 'plugins'));
            wp_mkdir_p(WP_PLUGIN_DIR);
        }
        if (!defined('WPMU_PLUGIN_DIR')) {
            define('WPMU_PLUGIN_DIR', MSP_PG_Utils::join_paths($caseDir, 'wp-content', 'mu-plugins'));
        }
        if (empty($GLOBALS['msp_pg_test_uploads_base'])) {
            $GLOBALS['msp_pg_test_uploads_base'] = MSP_PG_Utils::join_paths($caseDir, 'uploads');
            wp_mkdir_p($GLOBALS['msp_pg_test_uploads_base']);
        }

        // Real production entry points, not reflection: every additive
        // scanner is redirected to this isolated fixture root via the now-
        // real apply_filters() mechanism, instead of scanning the real
        // ABSPATH (tests/ directory) a bare run_scan() call would otherwise
        // hit.
        foreach (array(
            'msp_pg_sc_macro_cue_scan_root',
            'msp_pg_clonedoorway_scan_root',
            'msp_pg_wp_link_helper_scan_root',
            'msp_pg_doorway_content_gen_scan_root',
        ) as $rootFilter) {
            $this->withFilter($rootFilter, function () use ($caseDir) {
                return $caseDir;
            });
        }

        $GLOBALS['msp_pg_test_options'] = array('active_plugins' => array());
        $GLOBALS['msp_pg_test_transients'] = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();

        $report = MSP_PG_Remediator::run_scan('integration-test-partial-remediation');

        $this->assertTrue(is_array($report), 'run_scan() must return a report');
        $this->assertFalse($report['infection_fully_resolved'], 'Infection must NOT be reported as fully resolved while the drop-in remains outstanding');
        $this->assertTrue(count($report['outstanding_components']) >= 1, 'At least one outstanding component (the report-only drop-in) must be listed');

        $outstandingFamilies = array_map(function ($c) { return $c['family']; }, $report['outstanding_components']);
        $this->assertTrue(in_array('pg-sc-macro-cue', $outstandingFamilies, true), 'The outstanding component must be attributed to the SC family');

        $muDetection = $this->findDetectionByLivePath($report['confirmed_malware'], $fixture['mu_file']);
        $dropinDetection = $this->findDetectionByLivePath($report['confirmed_malware'], $fixture['dropin_file']);

        $this->assertTrue($muDetection !== null, 'The mu-plugin detection must appear in confirmed_malware');
        $this->assertTrue($dropinDetection !== null, 'The drop-in detection must appear in confirmed_malware');
        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $muDetection['actions'], true), 'The mu-plugin must have actually been removed by this real scan');
        $this->assertTrue(in_array('REPORT_ONLY_NO_AUTOMATIC_REMOVAL', $dropinDetection['actions'], true), 'The drop-in must remain report-only');

        $this->assertFalse(file_exists($fixture['mu_file']), 'The removed mu-plugin must no longer exist on disk');
        $this->assertTrue(file_exists($fixture['dropin_file']), 'The report-only drop-in must still exist on disk, unresolved');
    }

    /**
     * Compares paths with separators normalized rather than by exact string
     * equality: the scanner builds its 'plugin_dir' via glob() on a
     * trailingslashit()-joined pattern, which can mix forward/back slashes
     * differently than MSP_PG_Utils::join_paths() does when this test built
     * the fixture path -- same file on disk, different separator style.
     * Also deliberately avoids realpath(), which would return false for an
     * already-removed artifact and defeat the comparison entirely.
     */
    private function findDetectionByLivePath($detections, $livePath)
    {
        $needle = str_replace('\\', '/', $livePath);
        foreach ($detections as $detection) {
            if (str_replace('\\', '/', $detection['live_path']) === $needle) {
                return $detection;
            }
        }
        return null;
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

    private function assertNotSame($expected, $actual, $message)
    {
        if ($expected === $actual) {
            throw new RuntimeException($message);
        }
    }

    private function cleanup($dir)
    {
        if (is_link($dir)) {
            @unlink($dir);
            return;
        }
        if (!is_dir($dir)) {
            return;
        }
        foreach (@scandir($dir) ?: array() as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_link($path)) {
                @unlink($path);
            } elseif (is_dir($path)) {
                $this->cleanup($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}

$test = new RemediationLifecycleIntegrationTest();
$test->run();
echo "RemediationLifecycleIntegrationTest passed\n";
