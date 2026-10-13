<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Regression test for the PG-SC-MacroOptimizerCue family (see
 * docs/malware-families/PG-SC-MacroOptimizerCue.md).
 *
 * Fixtures are small, synthetic reproductions of each signature's trigger
 * shape, assembled from fragments at runtime (same convention
 * ClonedDoorwayTest.php uses) -- not copies of the live vcadentistry
 * specimen, which stays out of the repository entirely.
 *
 * MSP_PG_SC_Scanner's private scan_* methods are invoked directly via
 * reflection with an explicit fixture root, bypassing
 * MSP_PG_Config::sc_macro_cue_scan_root() (which the test bootstrap's
 * apply_filters() stub cannot redirect -- see ClonedDoorwayTest.php's
 * docblock for the same constraint). The one exception is the wp-includes/
 * boundary check inside MSP_PG_SC_Remediator, which is independently
 * re-validated against $analysis['scan_root'] (threaded through by the
 * scanner) rather than re-querying config, so it is exercised correctly
 * against the fixture root without needing to touch the real ABSPATH.
 */
class SCMacroOptimizerCueTest
{
    private $fixtureRoot;

    public function run()
    {
        $this->fixtureRoot = __DIR__ . DIRECTORY_SEPARATOR . 'sc-fixture-' . uniqid();

        try {
            $this->buildFixture();
            $this->assertSignatureUnitsMatchFixture();
            $this->assertScanFindsExpectedArtifacts();
            $this->assertDropinIsReportOnlyAndPreserved();
            $this->assertWpIncludesGuardsHoldIndependently();
            $this->assertRemovalWithheldWhenDeleteDisabledByConfig();
            $this->assertRealArtifactsAreRemovedAndIdempotent();
        } finally {
            $this->cleanup($this->fixtureRoot);
        }
    }

    private function buildFixture()
    {
        $join = function () { return implode('', func_get_args()); };

        $muDir = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins');
        wp_mkdir_p($muDir);
        file_put_contents(MSP_PG_Utils::join_paths($muDir, 'macro-optimizer-cue.php'), self::sample('malicious_mu_plugin'));
        file_put_contents(MSP_PG_Utils::join_paths($muDir, 'legit-helper.php'), "<?php\n// Plugin Name: Legit Helper\nfunction legit_helper_init() { return true; }\n");

        $wpContent = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content');
        file_put_contents(MSP_PG_Utils::join_paths($wpContent, 'advanced-cache.php'), self::sample('mixed_content_dropin'));

        $hiddenDir = MSP_PG_Utils::join_paths($this->fixtureRoot, '.sc_abcdef12');
        wp_mkdir_p($hiddenDir);
        file_put_contents(MSP_PG_Utils::join_paths($hiddenDir, 'own_112233.php'), self::sample('own_beacon'));
        file_put_contents(MSP_PG_Utils::join_paths($hiddenDir, 'core_x.php'), self::sample('helper_set_only'));

        $wpIncludes = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-includes');
        wp_mkdir_p($wpIncludes);
        file_put_contents(MSP_PG_Utils::join_paths($wpIncludes, '.g_abcdef12.php'), self::sample('helper_set_only'));
        file_put_contents(MSP_PG_Utils::join_paths($wpIncludes, '.gl_abcdef12'), ''); // empty throttle marker -- filename matches, no content signature
        file_put_contents(MSP_PG_Utils::join_paths($wpIncludes, 'functions.php'), "<?php\nfunction wp_core_thing() { return 1; }\n"); // ordinary core file, must never match

        // Second, isolated fixture for the "legitimate drop-in only" negative case.
        $this->legitOnlyRoot = $this->fixtureRoot . '-legit-dropin';
        wp_mkdir_p(MSP_PG_Utils::join_paths($this->legitOnlyRoot, 'wp-content'));
        file_put_contents(
            MSP_PG_Utils::join_paths($this->legitOnlyRoot, 'wp-content', 'advanced-cache.php'),
            "<?php\nuse WP_Rocket\\Buffer\\Cache;\ndefine('WP_ROCKET_ADVANCED_CACHE', true);\n// genuine WP Rocket drop-in, no injected marker\n"
        );
    }

    private $legitOnlyRoot;

    private static function sample($which)
    {
        $join = function () { return implode('', func_get_args()); };

        switch ($which) {
            case 'malicious_mu_plugin':
                $ver = $join('SCV', ':', '4.5.7');
                $fn1 = $join('_sc', '_mkdir');
                $fn2 = $join('_sc', '_fpc');
                $fn3 = $join('_sc', '_ul');
                return "<?php\n/* $ver */\nfunction $fn1(\$p) { return true; }\nfunction $fn2(\$a,\$b) { return true; }\nfunction $fn3(\$a) { return true; }\n";

            case 'mixed_content_dropin':
                $beginMarker = $join('/', '*', ' ', 'SC_ADV_BEGIN:4.5.7:68be1498', ' ', '*', '/');
                $endMarker   = $join('/', '*', ' ', 'SC_ADV_END:4.5.7:68be1498', ' ', '*', '/');
                return "<?php\n$beginMarker\nfunction injected_stub() { return true; }\n$endMarker\n"
                    . "use WP_Rocket\\Buffer\\Cache;\ndefine('WP_ROCKET_ADVANCED_CACHE', true);\n// genuine WP Rocket tail, must survive untouched\n";

            case 'own_beacon':
                return $join('<', '?php', '{', '"v":"4.5.7","gen":"5aff3f0e","slug":"macro-optimizer-cue","state":"ok"', '}');

            case 'helper_set_only':
                $fn1 = $join('_sc', '_mkdir');
                $fn2 = $join('_sc', '_fpc');
                $fn3 = $join('_sc', '_samedir');
                return "<?php\nfunction $fn1(\$p) { return true; }\nfunction $fn2(\$a,\$b) { return true; }\nfunction $fn3(\$a) { return true; }\n";
        }

        return '';
    }

    private function assertSignatureUnitsMatchFixture()
    {
        $muContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins', 'macro-optimizer-cue.php'));
        $this->assertTrue(MSP_PG_SC_Signatures::has_version_stamp($muContent), 'SC-VER-STAMP should match the fixture mu-plugin');
        $this->assertTrue(MSP_PG_SC_Signatures::has_helper_function_set($muContent), 'SC-HELPER-SET should match the fixture mu-plugin');

        $legitMuContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins', 'legit-helper.php'));
        $this->assertFalse(MSP_PG_SC_Signatures::has_version_stamp($legitMuContent), 'SC-VER-STAMP must not match a legitimate headerless mu-plugin');
        $this->assertFalse(MSP_PG_SC_Signatures::has_helper_function_set($legitMuContent), 'SC-HELPER-SET must not match a legitimate headerless mu-plugin');

        $dropinContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'advanced-cache.php'));
        $this->assertTrue(MSP_PG_SC_Signatures::has_dropin_injection_marker($dropinContent), 'SC-DROPIN-MARKER should match the fixture mixed-content drop-in');

        $legitDropinContent = file_get_contents(MSP_PG_Utils::join_paths($this->legitOnlyRoot, 'wp-content', 'advanced-cache.php'));
        $this->assertFalse(MSP_PG_SC_Signatures::has_dropin_injection_marker($legitDropinContent), 'SC-DROPIN-MARKER must never match a genuine WP_ROCKET_ADVANCED_CACHE-only drop-in');

        $this->assertTrue(MSP_PG_SC_Signatures::is_hidden_state_directory(MSP_PG_Utils::join_paths($this->fixtureRoot, '.sc_abcdef12')), 'SC-HIDDEN-DIR should match `.sc_abcdef12`');
        $this->assertFalse(MSP_PG_SC_Signatures::is_hidden_state_directory(MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content')), 'SC-HIDDEN-DIR must not match an ordinary directory name');

        $beaconContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, '.sc_abcdef12', 'own_112233.php'));
        $this->assertTrue(MSP_PG_SC_Signatures::has_own_beacon_shape($beaconContent), 'SC-OWN-BEACON should match the fixture beacon file');

        $this->assertTrue(MSP_PG_SC_Signatures::is_wpincludes_recovery_filename('.g_abcdef12.php'), 'SC-WPINCLUDES-STRAY should match `.g_abcdef12.php`');
        $this->assertFalse(MSP_PG_SC_Signatures::is_wpincludes_recovery_filename('functions.php'), 'SC-WPINCLUDES-STRAY must not match an ordinary core filename');
    }

    private function assertScanFindsExpectedArtifacts()
    {
        $byType = $this->scanFixtureByType($this->fixtureRoot);

        $this->assertSame(1, count($byType[MSP_PG_SC_Scanner::ARTIFACT_MU_PLUGIN_FILE] ?? array()), 'Should detect exactly the malicious mu-plugin, not the legitimate one');
        $this->assertSame(1, count($byType[MSP_PG_SC_Scanner::ARTIFACT_HIDDEN_STATE_DIRECTORY] ?? array()), 'Should detect the hidden state directory as one unit');
        $this->assertSame(1, count($byType[MSP_PG_SC_Scanner::ARTIFACT_DROPIN_FILE] ?? array()), 'Should detect the tampered drop-in');
        $this->assertSame(2, count($byType[MSP_PG_SC_Scanner::ARTIFACT_WPINCLUDES_RECOVERY_FILE] ?? array()), 'Should detect both wp-includes filename-pattern matches (the real loader and the empty throttle marker), and only those');

        $legitByType = $this->scanFixtureByType($this->legitOnlyRoot);
        $this->assertTrue(empty($legitByType[MSP_PG_SC_Scanner::ARTIFACT_DROPIN_FILE] ?? array()), 'A genuine WP_ROCKET_ADVANCED_CACHE-only drop-in must never be detected');
    }

    private function assertDropinIsReportOnlyAndPreserved()
    {
        $siteMeta = $this->siteMeta();
        $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out';
        wp_mkdir_p($scanDir);

        $byType = $this->scanFixtureByType($this->fixtureRoot);
        $dropinAnalysis = $byType[MSP_PG_SC_Scanner::ARTIFACT_DROPIN_FILE][0];
        $dropinPath = $dropinAnalysis['plugin_dir'];
        $beforeContent = file_get_contents($dropinPath);

        $detection = MSP_PG_SC_Remediator::remediate($dropinAnalysis, $siteMeta, $scanDir, false);

        $this->assertTrue(in_array('REPORT_ONLY_NO_AUTOMATIC_REMOVAL', $detection['actions'], true), 'Drop-in must always be report-only');
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), 'Drop-in must never be auto-removed');
        $this->assertTrue(file_exists($dropinPath), 'Live drop-in file must remain in place');
        $this->assertSame($beforeContent, file_get_contents($dropinPath), 'Mixed-content drop-in must be byte-for-byte unchanged after remediation (legitimate WP Rocket tail preserved)');
        $this->assertTrue($detection['preservation_verified'], 'Evidence must still be preserved even though the artifact is report-only');
    }

    private function assertWpIncludesGuardsHoldIndependently()
    {
        $siteMeta = $this->siteMeta();
        $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out-wpincludes';
        wp_mkdir_p($scanDir);

        $byType = $this->scanFixtureByType($this->fixtureRoot);
        $wpIncludesDetections = $byType[MSP_PG_SC_Scanner::ARTIFACT_WPINCLUDES_RECOVERY_FILE];

        $realLoader = null;
        $emptyMarker = null;
        foreach ($wpIncludesDetections as $analysis) {
            if (basename($analysis['plugin_dir']) === '.g_abcdef12.php') {
                $realLoader = $analysis;
            } elseif (basename($analysis['plugin_dir']) === '.gl_abcdef12') {
                $emptyMarker = $analysis;
            }
        }
        $this->assertTrue($realLoader !== null, 'Fixture setup: the content-matching loader file must be among the detections');
        $this->assertTrue($emptyMarker !== null, 'Fixture setup: the empty throttle marker must be among the detections (filename-pattern match only)');

        // Content-matching file inside wp-includes/, boundary valid, not a symlink: eligible for real removal.
        $detection1 = MSP_PG_SC_Remediator::remediate($realLoader, $siteMeta, $scanDir, false);
        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $detection1['actions'], true), 'Content-validated wp-includes recovery file should be removed');
        $this->assertFalse(file_exists($realLoader['plugin_dir']), 'Removed wp-includes recovery file should no longer exist');

        // Filename matches, but there is no content signature (empty file): must NEVER be removed on filename alone.
        $detection2 = MSP_PG_SC_Remediator::remediate($emptyMarker, $siteMeta, $scanDir, false);
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection2['actions'], true), 'Filename-only match inside wp-includes must never be removed without a content signature');
        $this->assertTrue(file_exists($emptyMarker['plugin_dir']), 'Empty throttle marker must remain in place');

        // Boundary-escape case: a file located OUTSIDE wp-includes/, with an
        // analysis record hand-crafted to claim the wp-includes artifact
        // type and a matching content signature, must still be rejected by
        // the realpath-containment check -- filename/content match alone is
        // never sufficient if the path itself is not actually inside
        // wp-includes/. This exercises the boundary guard independently of
        // OS-level symlink support (symlink() requires elevated privileges
        // not available in every CI environment).
        $escapedFile = MSP_PG_Utils::join_paths($this->fixtureRoot, '.g_escaped99.php');
        file_put_contents($escapedFile, self::sample('helper_set_only'));
        $escapedAnalysis = $realLoader;
        $escapedAnalysis['plugin_dir'] = $escapedFile;
        $detection3 = MSP_PG_SC_Remediator::remediate($escapedAnalysis, $siteMeta, $scanDir, false);
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection3['actions'], true), 'A path outside wp-includes/ must never be removed via the wp-includes artifact path, even with a matching content signature');
        $this->assertTrue(file_exists($escapedFile), 'File outside the validated boundary must remain in place');

        // True symlink escape, when the environment supports it: a symlink
        // placed inside wp-includes/ pointing outside the fixture tree must
        // be rejected by the explicit is_link() check, never removed or
        // followed.
        $symlinkTarget = $this->fixtureRoot . '-symlink-target.php';
        file_put_contents($symlinkTarget, self::sample('helper_set_only'));
        $symlinkPath = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-includes', '.g_symlinked12.php');
        if (@symlink($symlinkTarget, $symlinkPath)) {
            $symlinkAnalysis = $realLoader;
            $symlinkAnalysis['plugin_dir'] = $symlinkPath;
            $detection4 = MSP_PG_SC_Remediator::remediate($symlinkAnalysis, $siteMeta, $scanDir, false);
            $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection4['actions'], true), 'A symlink inside wp-includes/ must never be removed');
            $this->assertTrue(is_link($symlinkPath) || file_exists($symlinkTarget), 'Symlink target must remain untouched');
            @unlink($symlinkPath);
        } else {
            echo "  (symlink() unavailable in this environment -- skipped true-symlink assertion; boundary-escape case above still covers path-containment safety)\n";
        }
        @unlink($symlinkTarget);
    }

    /**
     * Canary-configuration regression: a canary deployment is expected to
     * run with detection enabled but automatic deletion disabled for this
     * family (sc_macro_cue_delete_enabled() filtered to false). An artifact
     * that is otherwise fully eligible for removal (preservation verified,
     * sufficient confidence) must record an explicit
     * REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION action, never silently
     * record nothing -- an operator reading the report must be able to
     * tell "deliberately configured off" apart from an unexplained gap.
     */
    private function assertRemovalWithheldWhenDeleteDisabledByConfig()
    {
        $disableFilter = function () { return false; };
        add_filter('msp_pg_sc_macro_cue_delete_enabled', $disableFilter);

        try {
            $siteMeta = $this->siteMeta();
            $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out-disabled';
            wp_mkdir_p($scanDir);

            $byType = $this->scanFixtureByType($this->fixtureRoot);
            $muAnalysis = $byType[MSP_PG_SC_Scanner::ARTIFACT_MU_PLUGIN_FILE][0];
            $muPath = $muAnalysis['plugin_dir'];
            $beforeContent = file_get_contents($muPath);

            $detection = MSP_PG_SC_Remediator::remediate($muAnalysis, $siteMeta, $scanDir, false);

            $this->assertTrue(in_array('REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION', $detection['actions'], true), 'Removal withheld by configuration must be recorded explicitly, not silently');
            $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), 'Artifact must not be removed while this family\'s delete flag is disabled');
            $this->assertTrue(file_exists($muPath), 'Live artifact must remain in place while deletion is disabled by configuration');
            $this->assertSame($beforeContent, file_get_contents($muPath), 'Live artifact content must be unchanged');
            $this->assertTrue($detection['preservation_verified'], 'Evidence must still be preserved even though removal is withheld by configuration');
        } finally {
            remove_filter('msp_pg_sc_macro_cue_delete_enabled', $disableFilter);
        }
    }

    private function assertRealArtifactsAreRemovedAndIdempotent()
    {
        $siteMeta = $this->siteMeta();
        $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out-real';
        wp_mkdir_p($scanDir);

        $byType = $this->scanFixtureByType($this->fixtureRoot);

        $muAnalysis = $byType[MSP_PG_SC_Scanner::ARTIFACT_MU_PLUGIN_FILE][0];
        $muDetection = MSP_PG_SC_Remediator::remediate($muAnalysis, $siteMeta, $scanDir, false);
        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $muDetection['actions'], true), 'Malicious mu-plugin should be removed');
        $this->assertTrue(file_exists($muDetection['evidence_manifest_path']), 'Evidence manifest must exist before removal is trusted');

        $hiddenDirDetection = MSP_PG_SC_Remediator::remediate($byType[MSP_PG_SC_Scanner::ARTIFACT_HIDDEN_STATE_DIRECTORY][0], $siteMeta, $scanDir, false);
        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $hiddenDirDetection['actions'], true), 'Hidden state directory should be removed');

        $legitMuPath = MSP_PG_Utils::join_paths($this->fixtureRoot, 'wp-content', 'mu-plugins', 'legit-helper.php');
        $this->assertTrue(file_exists($legitMuPath), 'Legitimate mu-plugin must survive remediation of the malicious one untouched');

        // Idempotency: rescanning after remediation should no longer find
        // the removed artifacts, and remediating the same (now-stale)
        // analysis record a second time must not error or re-delete
        // anything that no longer exists.
        $rescanByType = $this->scanFixtureByType($this->fixtureRoot);
        $this->assertTrue(empty($rescanByType[MSP_PG_SC_Scanner::ARTIFACT_MU_PLUGIN_FILE] ?? array()), 'Removed mu-plugin must not be re-detected on rescan');
        $this->assertTrue(empty($rescanByType[MSP_PG_SC_Scanner::ARTIFACT_HIDDEN_STATE_DIRECTORY] ?? array()), 'Removed hidden directory must not be re-detected on rescan');

        $repeatDetection = MSP_PG_SC_Remediator::remediate($muAnalysis, $siteMeta, $scanDir, false);
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $repeatDetection['actions'], true), 'Re-remediating an already-removed artifact must not report another removal');
    }

    private function scanFixtureByType($root)
    {
        $ref = new ReflectionClass('MSP_PG_SC_Scanner');
        $methods = array('scan_mu_plugins', 'scan_hidden_state_directories', 'scan_dropin_files', 'scan_wpincludes_recovery_files');

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
        foreach (array($dir, $this->legitOnlyRoot, $dir . '-symlink-target.php') as $path) {
            if (is_dir($path)) {
                $this->deleteDirectory($path);
            } elseif (is_file($path) || is_link($path)) {
                @unlink($path);
            }
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
            if ($item->isLink() || $item->isFile()) {
                @unlink($item->getPathname());
            } elseif ($item->isDir()) {
                @rmdir($item->getPathname());
            }
        }
        @rmdir($dir);
    }
}

$test = new SCMacroOptimizerCueTest();
$test->run();
echo "SCMacroOptimizerCueTest passed\n";
