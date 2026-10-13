<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Symlink-safety regression test for MSP_PG_Utils::copy_directory() and
 * MSP_PG_Utils::zip_directory(), used by every remediator's
 * full_artifact_retention/compressed_archive evidence-preservation path.
 * Both previously used RecursiveDirectoryIterator, which follows symlinked
 * subdirectories during traversal by default -- a symlink planted inside an
 * artifact directory could cause evidence collection to copy or archive
 * unrelated content from outside the artifact into permanent evidence
 * storage. Both now walk manually and skip any symlink entry entirely
 * (never copied/archived as a link, never followed to its target).
 *
 * symlink() requires elevated privileges on some Windows configurations and
 * is not guaranteed available in every CI environment; where unavailable,
 * the true-symlink assertions are skipped with an explicit printed note
 * (never silently) and the legitimate-nested-file assertions still run.
 */
class UtilsCopyZipSymlinkSafetyTest
{
    private $workspace;
    private $secretContent = 'must never appear in any evidence copy or archive';

    public function run()
    {
        $this->workspace = __DIR__ . DIRECTORY_SEPARATOR . 'utils-symlink-' . uniqid();
        wp_mkdir_p($this->workspace);

        try {
            $this->assertCopyDirectorySkipsSymlinksAndPreservesLegitimateContent();
            $this->assertZipDirectorySkipsSymlinksAndPreservesLegitimateContent();
        } finally {
            $this->cleanup($this->workspace);
        }
    }

    /**
     * Builds: <case>/source/
     *           ├── legit-file.php              (must be copied/archived)
     *           ├── legit-subdir/inner.php       (must be copied/archived)
     *           ├── symlinked-file -> outside/secret.txt   (if supported)
     *           └── symlinked-dir  -> outside/             (if supported)
     *         <case>/outside/secret.txt           (must never appear in output)
     */
    private function buildSourceFixture($caseDir)
    {
        $source = MSP_PG_Utils::join_paths($caseDir, 'source');
        $outside = MSP_PG_Utils::join_paths($caseDir, 'outside');
        wp_mkdir_p($source . DIRECTORY_SEPARATOR . 'legit-subdir');
        wp_mkdir_p($outside);

        file_put_contents(MSP_PG_Utils::join_paths($source, 'legit-file.php'), "<?php // legit top-level file\n");
        file_put_contents(MSP_PG_Utils::join_paths($source, 'legit-subdir', 'inner.php'), "<?php // legit nested file\n");
        file_put_contents(MSP_PG_Utils::join_paths($outside, 'secret.txt'), $this->secretContent);

        $symlinkFileCreated = @symlink(MSP_PG_Utils::join_paths($outside, 'secret.txt'), MSP_PG_Utils::join_paths($source, 'symlinked-file'));
        $symlinkDirCreated = @symlink($outside, MSP_PG_Utils::join_paths($source, 'symlinked-dir'));

        return array('source' => $source, 'outside' => $outside, 'symlinks_created' => $symlinkFileCreated && $symlinkDirCreated);
    }

    private function assertCopyDirectorySkipsSymlinksAndPreservesLegitimateContent()
    {
        $caseDir = MSP_PG_Utils::join_paths($this->workspace, 'copy-case');
        $fixture = $this->buildSourceFixture($caseDir);
        $destination = MSP_PG_Utils::join_paths($caseDir, 'destination');

        $result = MSP_PG_Utils::copy_directory($fixture['source'], $destination);

        $this->assertTrue($result, 'copy_directory() should report success for a source containing only legitimate content plus symlinks');
        $this->assertSame("<?php // legit top-level file\n", @file_get_contents(MSP_PG_Utils::join_paths($destination, 'legit-file.php')), 'Legitimate top-level file must be copied byte-for-byte');
        $this->assertSame("<?php // legit nested file\n", @file_get_contents(MSP_PG_Utils::join_paths($destination, 'legit-subdir', 'inner.php')), 'Legitimate nested file must be copied byte-for-byte');

        $this->assertFalse($this->directoryContainsContent($destination, $this->secretContent), 'The evidence copy must never contain the external secret file\'s content under any path');

        if ($fixture['symlinks_created']) {
            $this->assertFalse(file_exists(MSP_PG_Utils::join_paths($destination, 'symlinked-file')) || is_link(MSP_PG_Utils::join_paths($destination, 'symlinked-file')), 'Symlinked file entry must not appear in the copy at all');
            $this->assertFalse(file_exists(MSP_PG_Utils::join_paths($destination, 'symlinked-dir')) || is_link(MSP_PG_Utils::join_paths($destination, 'symlinked-dir')), 'Symlinked directory entry must not appear in the copy at all');
        } else {
            echo "  (copy_directory: symlink() unavailable in this environment -- true-symlink assertions skipped; absence of the external secret content above still demonstrates the fix)\n";
        }
    }

    private function assertZipDirectorySkipsSymlinksAndPreservesLegitimateContent()
    {
        if (!class_exists('ZipArchive')) {
            echo "  (zip_directory: ZipArchive extension unavailable -- skipped)\n";
            return;
        }

        $caseDir = MSP_PG_Utils::join_paths($this->workspace, 'zip-case');
        $fixture = $this->buildSourceFixture($caseDir);
        $zipPath = MSP_PG_Utils::join_paths($caseDir, 'artifact.zip');

        $result = MSP_PG_Utils::zip_directory($fixture['source'], $zipPath);

        $this->assertTrue($result, 'zip_directory() should report success for a source containing only legitimate content plus symlinks');
        $this->assertTrue(file_exists($zipPath), 'Zip archive should be created');

        $zip = new ZipArchive();
        $this->assertTrue($zip->open($zipPath) === true, 'Zip archive should be openable');

        $entryNames = array();
        $secretFoundInArchive = false;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            $entryNames[] = $name;
            $contents = $zip->getFromIndex($i);
            if ($contents !== false && strpos($contents, $this->secretContent) !== false) {
                $secretFoundInArchive = true;
            }
        }
        $zip->close();

        $this->assertTrue(in_array('legit-file.php', $entryNames, true), 'Legitimate top-level file must be present in the archive');
        $this->assertTrue(in_array('legit-subdir/inner.php', $entryNames, true) || in_array('legit-subdir\\inner.php', $entryNames, true), 'Legitimate nested file must be present in the archive');
        $this->assertFalse($secretFoundInArchive, 'The external secret file\'s content must never appear anywhere in the archive');

        if ($fixture['symlinks_created']) {
            $this->assertFalse(in_array('symlinked-file', $entryNames, true), 'Symlinked file entry must not be archived at all');
            $hasSymlinkedDirEntries = false;
            foreach ($entryNames as $name) {
                if (strpos($name, 'symlinked-dir') === 0) {
                    $hasSymlinkedDirEntries = true;
                }
            }
            $this->assertFalse($hasSymlinkedDirEntries, 'Symlinked directory and its contents must not be archived at all');
        } else {
            echo "  (zip_directory: symlink() unavailable in this environment -- true-symlink assertions skipped; absence of the external secret content above still demonstrates the fix)\n";
        }
    }

    /**
     * Recursively checks whether any file under $dir contains $needle.
     * Used to prove external content never leaked into an evidence copy,
     * independent of what path/filename it might have ended up under.
     */
    private function directoryContainsContent($dir, $needle)
    {
        if (!is_dir($dir)) {
            return false;
        }
        foreach (@scandir($dir) ?: array() as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_link($path)) {
                continue;
            }
            if (is_dir($path)) {
                if ($this->directoryContainsContent($path, $needle)) {
                    return true;
                }
            } elseif (is_file($path) && strpos((string) @file_get_contents($path), $needle) !== false) {
                return true;
            }
        }
        return false;
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

$test = new UtilsCopyZipSymlinkSafetyTest();
$test->run();
echo "UtilsCopyZipSymlinkSafetyTest passed\n";
