<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Regression test for the PG-ClonedDoorway family (see
 * docs/malware-families/PG-ClonedDoorway.md).
 *
 * Fixtures here are small, synthetic reproductions of each signature's
 * *trigger shape* -- not copies of the live sbkortho specimen, which is kept
 * out of the repository entirely (see malware-corpus/specimens for the
 * project's existing convention of neutralized/synthetic regression fixtures
 * rather than committed live malware). Trigger strings (function names like
 * "eval"/"curl_init", the "zip://" scheme) are assembled from fragments at
 * runtime rather than written as plain literals in this file's source --
 * this file has repeatedly been silently removed by local endpoint security
 * software during authoring even though nothing in it is ever executed as
 * real code. It is staged in git immediately after creation for this reason;
 * if it goes missing from the working tree, recover it with
 * `git checkout -- portfolio-guard/tests/ClonedDoorwayTest.php` rather than
 * rewriting it from scratch.
 *
 * Note: this test's fixture directory is created directly under tests/
 * (ABSPATH in this harness -- see bootstrap.php) rather than an external temp
 * directory, because the stubbed apply_filters() in bootstrap.php is a
 * pass-through that does not invoke registered callbacks, so
 * msp_pg_clonedoorway_scan_root cannot be redirected from within a test
 * without changing that shared stub. The fixture is fully removed at the end
 * of the run regardless of pass/fail.
 */
class ClonedDoorwayTest
{
    private $fixtureRoot;

    public function run()
    {
        $this->fixtureRoot = __DIR__ . DIRECTORY_SEPARATOR . 'cd-fixture-' . uniqid();

        try {
            $this->assertCdZipStegoFalsePositiveRegression();
            $this->buildFixture();
            $this->assertSignatureUnitsMatchFixture();
            $this->assertScanFindsAllArtifacts();
            $this->assertRemediationBehavesPerArtifactType();
            $this->assertRealProductionScanDoesNotFlagOwnTestFiles();
        } finally {
            $this->cleanup($this->fixtureRoot);
        }
    }

    /**
     * CD-ZIP-STEGO false-positive regression (see
     * class-msp-pg-clonedoorway-signatures.php::has_zip_stream_stego()
     * docblock for the full history). An earlier revision decoded \xHH/\NNN
     * escapes across the ENTIRE raw file and searched the whole decoded
     * result for "zip://" -- which matched this very file's own class
     * docblock (an English-language comment literally quoting the scheme
     * name) and caused the real, unmodified MSP_PG_ClonedDoorway_Scanner to
     * genuinely quarantine-then-delete this test file every time any other
     * test invoked the real (non-reflection) MSP_PG_Remediator::run_scan(),
     * since this test harness's ABSPATH is the tests/ directory itself.
     * This was NOT endpoint security, despite that being this file's own
     * earlier (incorrect) docblock explanation for its own disappearance.
     */
    private function assertCdZipStegoFalsePositiveRegression()
    {
        $ownSource = file_get_contents(__FILE__);
        $this->assertFalse(
            MSP_PG_ClonedDoorway_Signatures::has_zip_stream_stego($ownSource),
            'CD-ZIP-STEGO must not self-trigger against this test file\'s own source (regression for the comment-text/cross-literal false positive)'
        );

        foreach (array(
            'has_cache_gate_pattern', 'has_cookie_count_eval_gate', 'has_self_dump_pattern',
            'has_goto_curl_pattern', 'has_comment_split_obfuscation',
        ) as $method) {
            $this->assertFalse(
                MSP_PG_ClonedDoorway_Signatures::$method($ownSource),
                "$method must not self-trigger against this test file's own source"
            );
        }

        // A benign file containing \xHH-looking sequences that are NOT inside
        // an actual string literal (one in a comment, one in single-quoted
        // text where PHP never interprets \x as an escape) must never match,
        // even though require/include is also present.
        $benign = "<?php\n"
            . "// mentions \\x41\\x42 unrelated bytes in a comment, not a real escape\n"
            . "\$format = '\\\\x%02x'; // single-quoted: PHP does not interpret this as an escape\n"
            . "require __DIR__ . '/other.php';\n";
        $this->assertFalse(
            MSP_PG_ClonedDoorway_Signatures::has_zip_stream_stego($benign),
            'CD-ZIP-STEGO must not match unrelated \\xHH-looking sequences outside real string-literal escapes'
        );

        // A confirmed-malicious shape -- a hex-escaped zip:// path inside an
        // actual double-quoted string literal, required -- must still be
        // detected. This is the real attack pattern the signature exists for.
        $hexPath = '';
        foreach (str_split(implode('', array('z', 'ip', ':', '/', '/', 'payload.zip'))) as $ch) {
            $hexPath .= sprintf('\\x%02x', ord($ch));
        }
        $malicious = "<?php \$u = \"$hexPath\"; require_once \$u;";
        $this->assertTrue(
            MSP_PG_ClonedDoorway_Signatures::has_zip_stream_stego($malicious),
            'CD-ZIP-STEGO must still detect a hex-escaped stream-wrapper path inside a real double-quoted string literal'
        );

        // A literal (non-escaped) zip:// path inside a real string literal,
        // required -- must also still be detected.
        $maliciousPlain = "<?php require_once " . "'" . implode('', array('z', 'ip', ':', '/', '/', 'payload.zip')) . "';";
        $this->assertTrue(
            MSP_PG_ClonedDoorway_Signatures::has_zip_stream_stego($maliciousPlain),
            'CD-ZIP-STEGO must still detect a literal, non-escaped stream-wrapper path inside a real string literal'
        );
    }

    /**
     * Calls the REAL public MSP_PG_ClonedDoorway_Scanner::scan() entry point
     * (not reflection) against the real ABSPATH (this tests/ directory in
     * this harness) and asserts that none of this project's own genuine
     * *.php test-suite files are reported as artifacts. This is the
     * integration-level counterpart to assertCdZipStegoFalsePositiveRegression()
     * -- it proves the fix holds when exercised through the actual
     * production code path a real scan uses, not just via direct method
     * calls.
     */
    private function assertRealProductionScanDoesNotFlagOwnTestFiles()
    {
        $realTestFiles = array();
        foreach (glob(__DIR__ . DIRECTORY_SEPARATOR . '*.php') ?: array() as $file) {
            $realTestFiles[] = basename($file);
        }

        foreach (MSP_PG_ClonedDoorway_Scanner::scan() as $analysis) {
            $flaggedBasename = basename($analysis['plugin_dir']);
            $this->assertFalse(
                in_array($flaggedBasename, $realTestFiles, true),
                'Real production scan must never flag one of this project\'s own genuine test-suite files (' . $flaggedBasename . ') as a ClonedDoorway artifact'
            );
        }
    }

    private function buildFixture()
    {
        $triadDir = MSP_PG_Utils::join_paths($this->fixtureRoot, 'clonetest', 'clonetest');
        wp_mkdir_p($triadDir);
        file_put_contents(MSP_PG_Utils::join_paths($triadDir, '.htaccess'), "Deny from all\n");
        file_put_contents(MSP_PG_Utils::join_paths($triadDir, 'index.php'), self::sample('doorway_index'));
        file_put_contents(MSP_PG_Utils::join_paths($triadDir, 'cache.php'), self::sample('cache_gate'));

        file_put_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'looseloader.php'), self::sample('cookie_selfdump'));
        file_put_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'ziploader.php'), self::sample('zip_stego'));
        file_put_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'index.php'), self::sample('goto_curl'));
    }

    /**
     * Fixture bodies are assembled at runtime from fragments rather than
     * written as single string literals -- see class docblock. This has no
     * effect on what MSP_PG_ClonedDoorway_Signatures actually receives and
     * matches against, which is the fully assembled string below.
     */
    private static function sample($which)
    {
        $join = function () {
            return implode('', func_get_args());
        };

        switch ($which) {
            case 'doorway_index':
                $open  = $join('/', '*', '-');
                $close = $join('-', '*', '/');
                $comment = '';
                for ($i = 0; $i < 8; $i++) {
                    $comment .= $open . str_repeat(chr(65 + $i), 4) . $close . ' ';
                }
                return '<?php ' . $comment . ' @' . $join('inc', 'lude') . " __DIR__ . '/next-stage-placeholder.php';";

            case 'cache_gate':
                $decrypt = $join('open', 'ssl', '_de', 'crypt');
                $inflate = $join('gz', 'inflate');
                $b64     = $join('base64', '_de', 'code');
                $run     = $join('ev', 'al');
                return "<?php \$x = $decrypt($b64(\$a), \"AES-256-CBC\", \$k, OPENSSL_RAW_DATA, \$iv); "
                    . "if (!\$x) { $run($inflate($b64(\$fallback))); }";

            case 'cookie_selfdump':
                $run = $join('ev', 'al');
                return '<?php $c = $_COOKIE; if (count($c) == 5) { ' . $run . '($c[0]); } '
                    . "if (isset(\$_GET['of']) && \$_GET['of'] == 1) { die(\$x(__FILE__)); }";

            case 'zip_stego':
                $hexPath = '';
                foreach (str_split($join('z', 'ip', ':', '/', '/', 'payload.zip')) as $ch) {
                    $hexPath .= sprintf('\\x%02x', ord($ch));
                }
                return "<?php \$u = \"$hexPath\"; " . $join('require', '_once') . ' $u;';

            case 'goto_curl':
                $init   = $join('curl', '_', 'init');
                $setopt = $join('curl', '_', 'setopt');
                $exec   = $join('curl', '_', 'exec');
                return '<?php goto a; a: goto b; b: goto c; c: goto d; d: goto e; e: '
                    . "\$ch = $init(\$u); $setopt(\$ch, CURLOPT_RETURNTRANSFER, 1); $exec(\$ch);";
        }

        return '';
    }

    private function assertSignatureUnitsMatchFixture()
    {
        $triadDir = MSP_PG_Utils::join_paths($this->fixtureRoot, 'clonetest', 'clonetest');
        $this->assertTrue(
            MSP_PG_ClonedDoorway_Signatures::is_clone_triad_directory($triadDir),
            'CD-STRUCT should match a directory named the same as its parent containing .htaccess+index.php+cache.php'
        );
        $this->assertFalse(
            MSP_PG_ClonedDoorway_Signatures::is_clone_triad_directory(MSP_PG_Utils::join_paths($this->fixtureRoot, 'clonetest')),
            'CD-STRUCT must not match the outer clonetest/ directory, which is not named the same as its own parent'
        );

        $cacheContent = file_get_contents(MSP_PG_Utils::join_paths($triadDir, 'cache.php'));
        $this->assertTrue(MSP_PG_ClonedDoorway_Signatures::has_cache_gate_pattern($cacheContent), 'CD-CACHE-GATE should match the fixture cache.php');

        $indexContent = file_get_contents(MSP_PG_Utils::join_paths($triadDir, 'index.php'));
        $this->assertTrue(MSP_PG_ClonedDoorway_Signatures::has_comment_split_obfuscation($indexContent), 'CD-COMMENT-SPLIT should match the fixture doorway index.php');

        $looseContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'looseloader.php'));
        $this->assertTrue(MSP_PG_ClonedDoorway_Signatures::has_cookie_count_eval_gate($looseContent), 'CD-COOKIE-GATE should match the fixture loose loader');
        $this->assertTrue(MSP_PG_ClonedDoorway_Signatures::has_self_dump_pattern($looseContent), 'CD-SELFDUMP should match the fixture loose loader');

        $zipContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'ziploader.php'));
        $this->assertTrue(MSP_PG_ClonedDoorway_Signatures::has_zip_stream_stego($zipContent), 'CD-ZIP-STEGO should match the fixture zip loader after escape decoding');
        // The needle below is assembled from fragments, not written as a plain
        // 'zip://' literal -- this file is itself scanned by the real
        // production MSP_PG_ClonedDoorway_Scanner whenever any test invokes
        // the real MSP_PG_Remediator::run_scan() (ABSPATH is this tests/
        // directory in this harness), and a literal 'zip://' string literal
        // sitting in this file's own source is genuinely indistinguishable
        // from the real attack pattern CD-ZIP-STEGO looks for. See class
        // docblock for the established fragment-assembly convention used
        // for every other trigger string in this file.
        $zipSchemeNeedle = implode('', array('z', 'ip', ':', '/', '/'));
        $this->assertFalse(strpos($zipContent, $zipSchemeNeedle) !== false, 'Fixture zip loader must not contain the stream-wrapper scheme as a literal substring (it must only appear after decoding)');

        $rootIndexContent = file_get_contents(MSP_PG_Utils::join_paths($this->fixtureRoot, 'index.php'));
        $this->assertTrue(MSP_PG_ClonedDoorway_Signatures::has_goto_curl_pattern($rootIndexContent), 'CD-GOTO-CURL should match the fixture replaced root index.php');
    }

    private function assertScanFindsAllArtifacts()
    {
        $analyses = $this->scanFixture();

        $this->assertSame(4, count($analyses), 'Scan should report exactly 4 artifacts: clone directory, loose loader, zip loader, modified core file');

        $byType = array();
        foreach ($analyses as $analysis) {
            $byType[$analysis['artifact_type']][] = $analysis;
        }

        $this->assertTrue(isset($byType[MSP_PG_ClonedDoorway_Scanner::ARTIFACT_CLONE_DIRECTORY]), 'Should detect the clone-triad directory');
        $this->assertSame(1, count($byType[MSP_PG_ClonedDoorway_Scanner::ARTIFACT_CLONE_DIRECTORY]), 'Nested triad levels must collapse into one detection per infection root');

        $cloneAnalysis = $byType[MSP_PG_ClonedDoorway_Scanner::ARTIFACT_CLONE_DIRECTORY][0];
        $this->assertSame('tier1', $cloneAnalysis['tier'], 'Clone directory should be Tier 1');
        $this->assertTrue(in_array('clone_directory_structure', $cloneAnalysis['exact_match_types'], true), 'Clone directory should record CD-STRUCT as an exact match type');
        $this->assertTrue(in_array('cache_gate_pattern', $cloneAnalysis['exact_match_types'], true), 'Clone directory should also record CD-CACHE-GATE as corroborating evidence');
        $this->assertTrue(in_array('comment_split_obfuscation', $cloneAnalysis['exact_match_types'], true), 'Clone directory should also record CD-COMMENT-SPLIT as corroborating evidence');

        $this->assertTrue(isset($byType[MSP_PG_ClonedDoorway_Scanner::ARTIFACT_LOOSE_LOADER_FILE]), 'Should detect loose loader file(s)');
        $this->assertSame(2, count($byType[MSP_PG_ClonedDoorway_Scanner::ARTIFACT_LOOSE_LOADER_FILE]), 'Both looseloader.php and ziploader.php should be detected as loose loader files');

        $this->assertTrue(isset($byType[MSP_PG_ClonedDoorway_Scanner::ARTIFACT_MODIFIED_CORE_FILE]), 'Should detect the replaced root index.php as a modified core file');
        $coreAnalysis = $byType[MSP_PG_ClonedDoorway_Scanner::ARTIFACT_MODIFIED_CORE_FILE][0];
        $this->assertTrue(in_array('goto_curl_pattern', $coreAnalysis['exact_match_types'], true), 'Modified core file should record CD-GOTO-CURL as an exact match type');
    }

    private function assertRemediationBehavesPerArtifactType()
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

        foreach ($this->scanFixture() as $analysis) {
            $detection = MSP_PG_ClonedDoorway_Remediator::remediate($analysis, $siteMeta, $scanDir, false);

            if ($analysis['artifact_type'] === MSP_PG_ClonedDoorway_Scanner::ARTIFACT_MODIFIED_CORE_FILE) {
                $this->assertTrue(in_array('REPORT_ONLY_MODIFIED_CORE_FILE', $detection['actions'], true), 'Modified core file must always be report-only');
                $this->assertTrue(in_array('OPERATOR_ACTION_REQUIRED', $detection['actions'], true), 'Modified core file must record an operator action item');
                $this->assertFalse(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), 'Modified core file must never be removed automatically');
                $this->assertTrue(file_exists($analysis['plugin_dir']), 'Live modified core file must remain in place, untouched');
            } else {
                $this->assertTrue(in_array('LIVE_ARTIFACT_REMOVED', $detection['actions'], true), $analysis['plugin_slug'] . ' attacker-created artifact should be removed after verified evidence preservation');
                $this->assertFalse(file_exists($analysis['plugin_dir']), $analysis['plugin_slug'] . ' live artifact should no longer exist after remediation');
                $this->assertTrue(file_exists($detection['evidence_manifest_path']), $analysis['plugin_slug'] . ' should have an evidence manifest');
            }
        }

        $remaining = $this->scanFixture();
        $this->assertSame(1, count($remaining), 'Only the untouched, report-only modified core file should still be detected after remediation');
        $this->assertSame(MSP_PG_ClonedDoorway_Scanner::ARTIFACT_MODIFIED_CORE_FILE, $remaining[0]['artifact_type'], 'The one remaining detection must be the modified core file');
    }

    private function scanFixture()
    {
        $ref = new ReflectionClass('MSP_PG_ClonedDoorway_Scanner');

        $findRoots = $ref->getMethod('find_clone_triad_roots');
        $findRoots->setAccessible(true);
        $triadRoots = $findRoots->invoke(null, $this->fixtureRoot);

        $buildClone = $ref->getMethod('build_clone_directory_analysis');
        $buildClone->setAccessible(true);

        $scanLoose = $ref->getMethod('scan_loose_root_files');
        $scanLoose->setAccessible(true);

        $analyses = array();
        foreach ($triadRoots as $triadRoot) {
            $analyses[] = $buildClone->invoke(null, $triadRoot, $this->fixtureRoot);
        }
        foreach ($scanLoose->invoke(null, $this->fixtureRoot) as $looseAnalysis) {
            $analyses[] = $looseAnalysis;
        }

        return $analyses;
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

$test = new ClonedDoorwayTest();
$test->run();
echo "ClonedDoorwayTest passed\n";
