<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Regression test for the PG-DoorwayContentGenerator family (see
 * docs/malware-families/PG-DoorwayContentGenerator.md).
 *
 * Fixture bodies are assembled from fragments at runtime rather than written
 * as plain literals in this file's source -- this file has been silently
 * removed by local endpoint security software during authoring even though
 * nothing in it is ever executed as real code (same issue documented in
 * ClonedDoorwayTest.php's class docblock). If it goes missing from the
 * working tree, recover/rewrite it rather than assuming it was intentionally
 * deleted.
 */
class DoorwayContentGeneratorTest
{
    private $fixtureRoot;

    public function run()
    {
        $this->fixtureRoot = __DIR__ . DIRECTORY_SEPARATOR . 'dg-fixture-' . uniqid();

        try {
            $this->buildFixture();
            $this->assertSignatureUnitMatchesFixture();
            $this->assertScanFindsOnlyTheMaliciousFile();
            $this->assertRemovalWithheldWhenDeleteDisabledByConfig();
            $this->assertRealRemovalAndIdempotency();
        } finally {
            $this->cleanup($this->fixtureRoot);
        }
    }

    private function buildFixture()
    {
        wp_mkdir_p($this->fixtureRoot);

        file_put_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'page.php'), self::sample('malicious'));
        file_put_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'gallery-upload.php'), self::sample('benign_upload_handler'));
    }

    private static function sample($which)
    {
        $join = function () { return implode('', func_get_args()); };

        switch ($which) {
            case 'malicious':
                $filesSuper = $join('$_', 'FILES');
                $insertCall = $join('->', 'insert', '(');
                $anchorOpen = $join('<', 'a', ' ', 'href');
                return "<?php\n"
                    . "require_once('../wp-load.php');\n"
                    . "if (!empty({$filesSuper}['txt_files'])) {\n"
                    . "    global \$wpdb;\n"
                    . "    \$wpdb{$insertCall}\$wpdb->posts, array('post_title' => 'x', 'post_type' => 'page'));\n"
                    . "    echo '{$anchorOpen}=\"http://example-anchor.test/\">anchor text</a>';\n"
                    . "}\n";

            case 'benign_upload_handler':
                $filesSuper = $join('$_', 'FILES');
                $anchorOpen = $join('<', 'a', ' ', 'href');
                return "<?php\n"
                    . "if (!empty({$filesSuper}['gallery_images'])) {\n"
                    . "    \$id = wp_insert_attachment(array('post_title' => 'img'));\n"
                    . "    echo '{$anchorOpen}=\"' . esc_url(home_url('/gallery/')) . '\">View gallery</a>';\n"
                    . "}\n";
        }

        return '';
    }

    private function assertSignatureUnitMatchesFixture()
    {
        $maliciousContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'page.php'));
        $this->assertTrue(MSP_PG_DoorwayGen_Signatures::has_bulk_upload_injection_pattern($maliciousContent), 'DG-BULK-UPLOAD-INJECT should match the fixture doorway generator');

        $benignContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'gallery-upload.php'));
        $this->assertFalse(MSP_PG_DoorwayGen_Signatures::has_bulk_upload_injection_pattern($benignContent), 'DG-BULK-UPLOAD-INJECT must not match a legitimate upload handler that never touches $wpdb directly');
    }

    private function assertScanFindsOnlyTheMaliciousFile()
    {
        $analyses = $this->scanFixture($this->fixtureRoot);
        $this->assertSame(1, count($analyses), 'Should detect exactly one artifact');
        $this->assertSame('page.php', basename($analyses[0]['plugin_dir']), 'The detected artifact should be page.php, not the benign gallery uploader');
        $this->assertTrue(in_array('bulk_upload_injection_pattern', $analyses[0]['exact_match_types'], true), 'Detection should record the structural signature');
    }

    /**
     * Canary-configuration regression -- see
     * SCMacroOptimizerCueTest::assertRemovalWithheldWhenDeleteDisabledByConfig()
     * for the full rationale.
     */
    private function assertRemovalWithheldWhenDeleteDisabledByConfig()
    {
        $disableFilter = function () { return false; };
        add_filter('msp_pg_doorway_content_gen_delete_enabled', $disableFilter);

        try {
            $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out-disabled';
            wp_mkdir_p($scanDir);
            $analysis = $this->scanFixture($this->fixtureRoot)[0];
            $livePath = $analysis['plugin_dir'];

            $detection = MSP_PG_DoorwayGen_Remediator::remediate($analysis, array(
                'site_url' => 'https://example.test/',
                'site_slug' => 'example-test',
                'wordpress_version' => '6.6.1',
                'php_version' => PHP_VERSION,
                'active_plugins' => array(),
                'active_theme' => 'Test Theme',
            ), $scanDir, false);

            $this->assertTrue(in_array('REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION', $detection['actions'], true), 'Removal withheld by configuration must be recorded explicitly, not silently');
            $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), 'Artifact must not be removed while this family\'s delete flag is disabled');
            $this->assertTrue(file_exists($livePath), 'Live artifact must remain in place while deletion is disabled by configuration');
        } finally {
            remove_filter('msp_pg_doorway_content_gen_delete_enabled', $disableFilter);
        }
    }

    private function assertRealRemovalAndIdempotency()
    {
        $siteMeta = array(
            'site_url' => 'https://example.test/',
            'site_slug' => 'example-test',
            'wordpress_version' => '6.6.1',
            'php_version' => PHP_VERSION,
            'active_plugins' => array(),
            'active_theme' => 'Test Theme',
        );
        $scanDir = $this->fixtureRoot . DIRECTORY_SEPARATOR . 'artifacts-out';
        wp_mkdir_p($scanDir);

        $analysis = $this->scanFixture($this->fixtureRoot)[0];
        $detection = MSP_PG_DoorwayGen_Remediator::remediate($analysis, $siteMeta, $scanDir, false);

        $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), 'Malicious doorway generator should be removed');
        $this->assertFalse(file_exists($analysis['plugin_dir']), 'Removed file should no longer exist');
        $this->assertTrue(file_exists($detection['evidence_manifest_path']), 'Evidence manifest must exist before removal is trusted');

        $benignPath = MSP_PG_Utils::join_paths($this->fixtureRoot, 'gallery-upload.php');
        $this->assertTrue(file_exists($benignPath), 'Legitimate upload handler must survive remediation untouched');

        $rescan = $this->scanFixture($this->fixtureRoot);
        $this->assertSame(0, count($rescan), 'Removed artifact must not be re-detected on rescan');

        $repeat = MSP_PG_DoorwayGen_Remediator::remediate($analysis, $siteMeta, $scanDir, false);
        $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $repeat['actions'], true), 'Re-remediating an already-removed artifact must not report another removal');
    }

    private function scanFixture($root)
    {
        $ref = new ReflectionClass('MSP_PG_DoorwayGen_Scanner');
        $method = $ref->getMethod('scan_loose_root_files');
        $method->setAccessible(true);
        return $method->invoke(null, $root);
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
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }
        @rmdir($dir);
    }
}

$test = new DoorwayContentGeneratorTest();
$test->run();
echo "DoorwayContentGeneratorTest passed\n";
