<?php

// Configurable site path for the default private-root derivation test; must
// be defined before bootstrap.php, which only stubs these if absent.
function home_url($path = '/')
{
    return 'https://example.test' . (isset($GLOBALS['pg_test_home_path']) ? $GLOBALS['pg_test_home_path'] : '') . $path;
}
function get_site_url($blog_id = null, $path = '', $scheme = null)
{
    return 'https://example.test' . (isset($GLOBALS['pg_test_home_path']) ? $GLOBALS['pg_test_home_path'] : '') . (string) $path;
}

require_once __DIR__ . '/bootstrap.php';

/**
 * Evidence storage: private-root selection, access-denial files, symlink and
 * traversal safety, fail-closed behaviour, all retention modes, the
 * full_artifact_retention fallback inside the web root, and compatibility
 * with (and preservation of) pre-2.1.0 evidence under uploads/.
 * Synthetic fixtures only.
 */
class EvidenceStorageTest
{
    private $workspace;
    private $site;
    private $privateBase;
    private $registeredFilters = array();
    private $symlinksSupported;

    public function __construct()
    {
        $this->workspace = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pg-evidence-storage-' . uniqid();
        $this->site = MSP_PG_Utils::join_paths($this->workspace, 'site');
        $this->privateBase = MSP_PG_Utils::join_paths($this->workspace, 'private', 'msp-pg-evidence');

        define('WP_PLUGIN_DIR', MSP_PG_Utils::join_paths($this->site, 'wp-content', 'plugins'));
        define('WPMU_PLUGIN_DIR', MSP_PG_Utils::join_paths($this->site, 'wp-content', 'mu-plugins'));
        $GLOBALS['msp_pg_test_uploads_base'] = MSP_PG_Utils::join_paths($this->site, 'wp-content', 'uploads');

        wp_mkdir_p($this->workspace);
        $probe = MSP_PG_Utils::join_paths($this->workspace, 'symlink-probe');
        $this->symlinksSupported = @symlink($this->workspace, $probe);
        if ($this->symlinksSupported) {
            @unlink($probe);
        }
    }

    public function run()
    {
        try {
            $this->test_private_storage_is_selected_and_initialized();
            $this->test_default_private_root_derivation();
            $this->test_private_root_rejections();
            $this->test_prepare_rejects_unsafe_layouts();
            $this->test_all_retention_modes_in_private_storage();
            $this->test_full_retention_falls_back_inside_web_root();
            $this->test_unsecurable_storage_fails_closed_then_recovers();
            $this->test_legacy_evidence_preserved_and_protected();
            $this->test_fallback_never_scrubs_historical_full_snapshots();
            $this->test_protection_files_not_detected_on_rescan();
        } finally {
            $this->removeAllFilters();
            unset($GLOBALS['msp_pg_test_private_base'], $GLOBALS['pg_test_home_path']);
            $this->deleteTree($this->workspace);
        }
        if (!$this->symlinksSupported) {
            echo "  (symlink() unavailable in this environment -- true-symlink assertions skipped; non-symlink rejection paths still asserted)\n";
        }
    }

    // -------------------------------------------------------------------------

    private function test_private_storage_is_selected_and_initialized()
    {
        $this->buildSite();
        $this->usePrivate();

        $this->assertSame($this->privateBase, MSP_PG_Config::artifact_base_dir(), 'private: private root selected');
        $this->assertSame('private', MSP_PG_Config::artifact_storage_scope($this->privateBase), 'private: classified outside the web root');
        $this->assertSame('web_root', MSP_PG_Config::artifact_storage_scope(MSP_PG_Config::legacy_artifact_base_dir()), 'private: legacy uploads location classified as web root');

        $report = $this->scan('private-init');

        $this->assertSame(MSP_PG_Utils::EVIDENCE_HTACCESS, @file_get_contents(MSP_PG_Utils::join_paths($this->privateBase, '.htaccess')), 'private: deny-all .htaccess written');
        $this->assertSame(MSP_PG_Utils::EVIDENCE_WEB_CONFIG, @file_get_contents(MSP_PG_Utils::join_paths($this->privateBase, 'web.config')), 'private: deny-all web.config written');
        $this->assertTrue(is_file(MSP_PG_Utils::join_paths($this->privateBase, 'index.html')), 'private: listing guard at root');

        $plugin = $this->detection($report, 'laravel-janet');
        $manifest = $plugin['evidence_manifest_path'];
        $this->assertTrue($this->within($manifest, $this->privateBase), 'private: evidence written under the private root');
        $scanDir = dirname(dirname(dirname($manifest)));
        $this->assertTrue((bool) preg_match('/^[0-9T-]+(Z|-00-00)?-[0-9a-f]{32}$/', basename($scanDir)), 'private: scan directory carries an unguessable suffix (' . basename($scanDir) . ')');
        $this->assertTrue(is_file(MSP_PG_Utils::join_paths($scanDir, 'index.html')) && is_file(MSP_PG_Utils::join_paths(dirname($scanDir), 'index.html')), 'private: listing guards in site and scan directories');
        $data = json_decode(file_get_contents($manifest), true);
        $this->assertSame('laravel-janet', $data['plugin_slug'], 'private: evidence manifest retrievable via its reported path');
        $this->assertFalse(is_dir(MSP_PG_Config::legacy_artifact_base_dir()), 'private: nothing written under uploads/');
        $this->assertSame('private', $report['evidence_storage']['scope'], 'private: report records scope');
        $this->assertSame(true, $report['evidence_storage']['secured'], 'private: report records storage secured');
    }

    private function test_default_private_root_derivation()
    {
        unset($GLOBALS['msp_pg_test_private_base']);
        $stash = $GLOBALS['msp_pg_test_filters']['msp_pg_private_artifact_base_dir'];
        unset($GLOBALS['msp_pg_test_filters']['msp_pg_private_artifact_base_dir']);
        try {
            $expected = dirname(rtrim(ABSPATH, '/\\')) . DIRECTORY_SEPARATOR . 'msp-pg-evidence';
            $GLOBALS['pg_test_home_path'] = '';
            $this->assertSame($expected, MSP_PG_Config::private_artifact_base_dir(), 'derive: root-served site uses the sibling of ABSPATH');
            $this->assertFalse(file_exists($expected), 'derive: resolution alone creates nothing');

            $GLOBALS['pg_test_home_path'] = '/blog';
            $this->assertSame('', MSP_PG_Config::private_artifact_base_dir(), 'derive: subdirectory install never uses the (web-served) parent of ABSPATH');
        } finally {
            $GLOBALS['pg_test_home_path'] = '';
            $GLOBALS['msp_pg_test_filters']['msp_pg_private_artifact_base_dir'] = $stash;
        }
    }

    private function test_private_root_rejections()
    {
        $this->buildSite();
        $GLOBALS['msp_pg_test_private_base'] = MSP_PG_Utils::join_paths($GLOBALS['msp_pg_test_uploads_base'], 'evidence');
        $this->assertSame('', MSP_PG_Config::private_artifact_base_dir(), 'reject: candidate inside uploads');
        $GLOBALS['msp_pg_test_private_base'] = MSP_PG_Utils::join_paths($this->site, 'evidence');
        $this->assertSame('web_root', MSP_PG_Config::artifact_storage_scope(MSP_PG_Utils::join_paths(ABSPATH, 'x')), 'reject: ABSPATH is web root');
        $GLOBALS['msp_pg_test_private_base'] = MSP_PG_Utils::join_paths($this->workspace, 'missing-parent', 'evidence');
        $this->assertSame('', MSP_PG_Config::private_artifact_base_dir(), 'reject: parent directory does not exist');
        $GLOBALS['msp_pg_test_private_base'] = '';
        $this->assertSame(MSP_PG_Config::legacy_artifact_base_dir(), MSP_PG_Config::artifact_base_dir(), 'reject: no private root falls back to the legacy location');

        if ($this->symlinksSupported) {
            $target = MSP_PG_Utils::join_paths($this->workspace, 'link-target');
            wp_mkdir_p($target);
            $link = MSP_PG_Utils::join_paths($this->workspace, 'linked-evidence');
            symlink($target, $link);
            $GLOBALS['msp_pg_test_private_base'] = $link;
            $this->assertSame('', MSP_PG_Config::private_artifact_base_dir(), 'reject: symlinked candidate');
            @unlink($link);
        }
        unset($GLOBALS['msp_pg_test_private_base']);
    }

    private function test_prepare_rejects_unsafe_layouts()
    {
        $base = MSP_PG_Utils::join_paths($this->workspace, 'prep', 'base');
        $scan = MSP_PG_Utils::join_paths($base, 'site', 'scan-1');
        $this->assertTrue(MSP_PG_Utils::prepare_evidence_directory($base, $scan), 'prepare: normal layout succeeds');
        $this->assertTrue(MSP_PG_Utils::prepare_evidence_directory($base, $scan), 'prepare: idempotent');

        $this->assertFalse(MSP_PG_Utils::prepare_evidence_directory($base, MSP_PG_Utils::join_paths($base, '..', 'escape', 'scan')), 'prepare: traversal outside the base refused');
        $this->assertFalse(is_dir(MSP_PG_Utils::join_paths($this->workspace, 'prep', 'escape')), 'prepare: nothing created outside the base');
        $this->assertFalse(MSP_PG_Utils::prepare_evidence_directory($base, MSP_PG_Utils::join_paths($base, 'too', 'deep', 'scan')), 'prepare: unexpected depth refused');

        $blockedBase = MSP_PG_Utils::join_paths($this->workspace, 'prep', 'blocked');
        wp_mkdir_p(MSP_PG_Utils::join_paths($blockedBase, '.htaccess'));
        $this->assertFalse(MSP_PG_Utils::prepare_evidence_directory($blockedBase, MSP_PG_Utils::join_paths($blockedBase, 's', 'x')), 'prepare: protection file that cannot be written refused');
        $this->assertFalse(is_dir(MSP_PG_Utils::join_paths($blockedBase, 's')), 'prepare: scan directory not created after refusal');

        if ($this->symlinksSupported) {
            $outside = MSP_PG_Utils::join_paths($this->workspace, 'prep', 'outside');
            wp_mkdir_p($outside);
            file_put_contents(MSP_PG_Utils::join_paths($outside, 'victim.txt'), 'must not change');

            $linkBase = MSP_PG_Utils::join_paths($this->workspace, 'prep', 'linkbase');
            symlink($outside, $linkBase);
            $this->assertFalse(MSP_PG_Utils::prepare_evidence_directory($linkBase, MSP_PG_Utils::join_paths($linkBase, 's', 'x')), 'prepare: symlinked base refused');

            $htBase = MSP_PG_Utils::join_paths($this->workspace, 'prep', 'htlink');
            wp_mkdir_p($htBase);
            symlink(MSP_PG_Utils::join_paths($outside, 'victim.txt'), MSP_PG_Utils::join_paths($htBase, '.htaccess'));
            $this->assertFalse(MSP_PG_Utils::prepare_evidence_directory($htBase, MSP_PG_Utils::join_paths($htBase, 's', 'x')), 'prepare: symlinked .htaccess refused');
            $this->assertSame('must not change', file_get_contents(MSP_PG_Utils::join_paths($outside, 'victim.txt')), 'prepare: symlink target never written through');

            $siteLinkBase = MSP_PG_Utils::join_paths($this->workspace, 'prep', 'sitelink');
            wp_mkdir_p($siteLinkBase);
            symlink($outside, MSP_PG_Utils::join_paths($siteLinkBase, 's'));
            $this->assertFalse(MSP_PG_Utils::prepare_evidence_directory($siteLinkBase, MSP_PG_Utils::join_paths($siteLinkBase, 's', 'x')), 'prepare: symlinked site directory refused');
            $this->assertFalse(is_dir(MSP_PG_Utils::join_paths($outside, 'x')), 'prepare: nothing created through a symlink');
        }
    }

    private function test_all_retention_modes_in_private_storage()
    {
        foreach (array('metadata_only', 'compressed_archive', 'full_artifact_retention') as $mode) {
            $this->buildSite();
            $this->usePrivate();
            $this->withFilter('msp_pg_evidence_retention_mode', function () use ($mode) { return $mode; });

            $report = $this->scan("mode-$mode");
            $plugin = $this->detection($report, 'laravel-janet');
            $artifactDir = dirname($plugin['evidence_manifest_path']);

            $this->assertSame($mode, $report['evidence_retention_mode'], "$mode: honored in private storage");
            $this->assertFalse($report['evidence_storage']['retention_mode_fallback'], "$mode: no fallback in private storage");
            $this->assertTrue(is_readable($plugin['evidence_manifest_path']), "$mode: manifest written");
            $this->assertTrue(in_array('LIVE_PLUGIN_REMOVED', $plugin['actions'], true), "$mode: Tier 1 remediation still runs");
            $zip = MSP_PG_Utils::join_paths($artifactDir, 'artifact.zip');
            if ($mode === 'metadata_only') {
                $this->assertFalse(file_exists($zip), "$mode: no archive");
            } else {
                $this->assertTrue($this->zipContains($zip, 'laravel-janet.php'), "$mode: archive holds the artifact");
            }
            if ($mode === 'full_artifact_retention') {
                $this->assertTrue(is_file(MSP_PG_Utils::join_paths($artifactDir, 'quarantine', 'laravel-janet', 'laravel-janet.php')), "$mode: raw quarantine copy kept in private storage");
            }
        }
    }

    private function test_full_retention_falls_back_inside_web_root()
    {
        $this->buildSite();
        $this->withFilter('msp_pg_evidence_retention_mode', function () { return 'full_artifact_retention'; });

        $report = $this->scan('web-root-full');
        $plugin = $this->detection($report, 'laravel-janet');
        $artifactDir = dirname($plugin['evidence_manifest_path']);

        $this->assertSame('web_root', $report['evidence_storage']['scope'], 'fallback: legacy location is web root');
        $this->assertSame('full_artifact_retention', $report['evidence_storage']['configured_retention_mode'], 'fallback: configured mode recorded');
        $this->assertSame('compressed_archive', $report['evidence_retention_mode'], 'fallback: effective mode is compressed_archive');
        $this->assertTrue($report['evidence_storage']['retention_mode_fallback'], 'fallback: flagged in report');
        $this->assertFalse(is_dir(MSP_PG_Utils::join_paths($artifactDir, 'quarantine')) || is_dir(MSP_PG_Utils::join_paths($artifactDir, 'snapshot')), 'fallback: no raw executable copies inside the web root');
        $this->assertTrue($this->zipContains(MSP_PG_Utils::join_paths($artifactDir, 'artifact.zip'), 'laravel-janet.php'), 'fallback: evidence still preserved as an archive');
        $this->assertTrue(in_array('LIVE_PLUGIN_REMOVED', $plugin['actions'], true), 'fallback: Tier 1 remediation still runs');
        $this->assertContains('full_artifact_retention was applied as compressed_archive', $GLOBALS['msp_pg_test_wp_mail_calls'][0]['message'], 'fallback: email explains');
        $this->assertSame('full_artifact_retention', MSP_PG_Config::evidence_retention_mode(), 'fallback: scoped to the scan, configured mode restored after');
        $this->assertSame(MSP_PG_Utils::EVIDENCE_HTACCESS, @file_get_contents(MSP_PG_Utils::join_paths(MSP_PG_Config::legacy_artifact_base_dir(), '.htaccess')), 'fallback: deny-all files installed in web-root storage');
    }

    private function test_unsecurable_storage_fails_closed_then_recovers()
    {
        $this->buildSite();
        $base = MSP_PG_Config::artifact_base_dir();
        $blocker = MSP_PG_Utils::join_paths($base, '.htaccess');
        wp_mkdir_p($blocker);

        $report = $this->scan('fail-closed');
        $this->assertSame(false, $report['evidence_storage']['secured'], 'fail-closed: reported unsecured');
        $this->assertTrue(count(array_filter($report['errors'], function ($e) { return strpos($e, 'could not be secured') !== false; })) === 1, 'fail-closed: one explanatory error');
        $this->assertSame(array(), $this->findFiles($base, 'evidence.json'), 'fail-closed: no evidence written to unprotected storage');
        $this->assertTrue(is_dir(MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'laravel-janet')), 'fail-closed: no destructive remediation');
        $this->assertTrue(count($this->detection($report, 'laravel-janet')['errors']) > 0, 'fail-closed: per-finding preservation errors recorded');
        foreach ($report['errors'] as $error) {
            $this->assertFalse(strpos($error, $base) !== false, 'fail-closed: error text does not expose storage paths');
        }

        rmdir($blocker);
        $this->assertTrue(MSP_PG_Utils::write_json(MSP_PG_Utils::join_paths($base, 'probe.json'), array('ok' => true)), 'fail-closed: write guard released after the scan');
        @unlink(MSP_PG_Utils::join_paths($base, 'probe.json'));
        $report = $this->scan('recovered');
        $this->assertSame(true, $report['evidence_storage']['secured'], 'recovered: next scan secures storage');
        $this->assertTrue(in_array('LIVE_PLUGIN_REMOVED', $this->detection($report, 'laravel-janet')['actions'], true), 'recovered: remediation resumes');
    }

    private function test_legacy_evidence_preserved_and_protected()
    {
        $this->buildSite();
        $legacy = MSP_PG_Config::legacy_artifact_base_dir();
        $oldScan = MSP_PG_Utils::join_paths($legacy, 'example-test', '2026-01-01T00-00-00-00-00');
        wp_mkdir_p(MSP_PG_Utils::join_paths($oldScan, 'artifacts', 'old-family', 'snapshot', 'old-family'));
        file_put_contents(MSP_PG_Utils::join_paths($oldScan, 'artifacts', 'old-family', 'evidence.json'), '{"historical":true}');
        file_put_contents(MSP_PG_Utils::join_paths($oldScan, 'artifacts', 'old-family', 'snapshot', 'old-family', 'payload.txt'), 'historical snapshot');
        touch($oldScan, time() - 90 * DAY_IN_SECONDS);
        $before = $this->hashTree($legacy);

        $this->usePrivate();
        $report = $this->scan('legacy');

        $after = $this->hashTree($legacy);
        foreach ($before as $path => $hash) {
            $this->assertSame($hash, isset($after[$path]) ? $after[$path] : null, "legacy: $path preserved unchanged");
        }
        $this->assertSame(MSP_PG_Utils::EVIDENCE_HTACCESS, @file_get_contents(MSP_PG_Utils::join_paths($legacy, '.htaccess')), 'legacy: deny-all .htaccess added');
        $this->assertTrue(is_file(MSP_PG_Utils::join_paths($legacy, 'web.config')) && is_file(MSP_PG_Utils::join_paths($legacy, 'index.html')), 'legacy: web.config and listing guard added');
        $this->assertTrue($report['evidence_storage']['legacy_evidence_present'], 'legacy: report flags remaining legacy evidence');
        $this->assertContains('Legacy Evidence', $GLOBALS['msp_pg_test_wp_mail_calls'][0]['message'], 'legacy: email tells the operator');
        $this->assertTrue($this->within($this->detection($report, 'laravel-janet')['evidence_manifest_path'], $this->privateBase), 'legacy: new evidence goes to private storage');
    }

    private function test_fallback_never_scrubs_historical_full_snapshots()
    {
        $this->buildSite();
        $legacy = MSP_PG_Config::legacy_artifact_base_dir();
        $recentScan = MSP_PG_Utils::join_paths($legacy, 'example-test', '2026-10-01T00-00-00-00-00');
        $snapshot = MSP_PG_Utils::join_paths($recentScan, 'artifacts', 'old-family', 'snapshot', 'old-family');
        wp_mkdir_p($snapshot);
        file_put_contents(MSP_PG_Utils::join_paths($snapshot, 'payload.txt'), 'historical snapshot');
        $this->withFilter('msp_pg_evidence_retention_mode', function () { return 'full_artifact_retention'; });

        $report = $this->scan('no-scrub');

        $this->assertTrue($report['evidence_storage']['retention_mode_fallback'], 'no-scrub: fallback active');
        $this->assertTrue(is_file(MSP_PG_Utils::join_paths($snapshot, 'payload.txt')), 'no-scrub: historical full-retention snapshot not scrubbed by the fallback');
        $this->assertSame(0, (int) $report['cleanup']['scrubbed_count'], 'no-scrub: cleanup scrubbed nothing');
    }

    private function test_protection_files_not_detected_on_rescan()
    {
        foreach (array('web-root' => false, 'private' => true) as $label => $private) {
            $this->buildSite();
            if ($private) {
                $this->usePrivate();
            }
            $this->scan("rescan-1-$label");
            $report = $this->scan("rescan-2-$label");
            $this->assertSame(array(), $report['detections'], "rescan ($label): evidence store and its protection files are never detected");
        }
    }

    // -------------------------------------------------------------------------

    private function buildSite()
    {
        $this->removeAllFilters();
        unset($GLOBALS['msp_pg_test_private_base']);
        $this->deleteTree($this->site);
        $this->deleteTree(dirname($this->privateBase));
        foreach (array(WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, $GLOBALS['msp_pg_test_uploads_base']) as $dir) {
            wp_mkdir_p($dir);
        }
        $site = $this->site;
        foreach (array('msp_pg_sc_macro_cue_scan_root', 'msp_pg_clonedoorway_scan_root', 'msp_pg_wp_link_helper_scan_root', 'msp_pg_doorway_content_gen_scan_root') as $rootFilter) {
            $this->withFilter($rootFilter, function () use ($site) { return $site; });
        }
        $corpus = dirname(dirname(__DIR__)) . '/validation/corpus';
        wp_mkdir_p(MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'laravel-janet'));
        copy("$corpus/known-malware/laravel-janet/laravel-janet.php", MSP_PG_Utils::join_paths(WP_PLUGIN_DIR, 'laravel-janet', 'laravel-janet.php'));
        $GLOBALS['msp_pg_test_options'] = array('active_plugins' => array('laravel-janet/laravel-janet.php'));
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();
    }

    private function usePrivate()
    {
        wp_mkdir_p(dirname($this->privateBase));
        $GLOBALS['msp_pg_test_private_base'] = $this->privateBase;
    }

    private function scan($trigger)
    {
        $GLOBALS['msp_pg_test_transients'] = array();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();
        $report = MSP_PG_Remediator::run_scan('test-' . $trigger);
        $this->assertTrue(is_array($report) && empty($report['registry_error']), "$trigger: run_scan returned a report");
        return $report;
    }

    private function detection($report, $slug)
    {
        foreach ($report['detections'] as $d) {
            if ($d['plugin_slug'] === $slug) {
                return $d;
            }
        }
        throw new RuntimeException("No detection for $slug");
    }

    private function within($path, $root)
    {
        $p = str_replace('\\', '/', $path);
        $r = rtrim(str_replace('\\', '/', $root), '/') . '/';
        return strpos($p, $r) === 0;
    }

    private function zipContains($zipPath, $basename)
    {
        if (!is_readable($zipPath)) {
            return false;
        }
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            return false;
        }
        $found = false;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            if (basename($zip->getNameIndex($i)) === $basename) {
                $found = true;
            }
        }
        $zip->close();
        return $found;
    }

    private function findFiles($dir, $name)
    {
        $out = array();
        if (!is_dir($dir)) {
            return $out;
        }
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->getFilename() === $name) {
                $out[] = $f->getPathname();
            }
        }
        return $out;
    }

    private function hashTree($dir)
    {
        $out = array();
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            $out[str_replace('\\', '/', $f->getPathname())] = hash_file('sha256', $f->getPathname());
        }
        ksort($out);
        return $out;
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
        $this->assertTrue(strpos((string) $haystack, $needle) !== false, $message);
    }
}

$test = new EvidenceStorageTest();
$test->run();
echo "EvidenceStorageTest passed\n";
