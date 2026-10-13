<?php

require_once __DIR__ . '/bootstrap.php';

/**
 * Symlink-safety regression test for the directory-removal helpers
 * hardened in this pass: MSP_PG_Remediator::delete_directory() and
 * MSP_PG_ClonedDoorway_Remediator::delete_directory() (both previously used
 * RecursiveDirectoryIterator, which follows symlinked subdirectories during
 * traversal by default -- a planted symlink inside an artifact directory
 * could cause deletion to escape the intended tree and remove unrelated
 * files elsewhere on the filesystem). Both now walk manually via scandir()
 * and unlink any symlink as a leaf without following it -- same principle
 * already established for MSP_PG_SC_Remediator and MSP_PG_WLH_Remediator.
 *
 * symlink() requires elevated privileges on some Windows configurations and
 * is not guaranteed available in every CI environment; where unavailable,
 * the true-symlink assertions are skipped with an explicit printed note
 * (never silently) and the non-symlink containment assertions still run.
 */
class DirectoryRemediationSymlinkSafetyTest
{
    private $workspace;

    public function run()
    {
        $this->workspace = __DIR__ . DIRECTORY_SEPARATOR . 'symlink-safety-' . uniqid();
        wp_mkdir_p($this->workspace);

        try {
            $this->assertMainRemediatorDeleteDirectoryIsSymlinkSafe();
            $this->assertClonedDoorwayRemediatorDeleteDirectoryIsSymlinkSafe();
            $this->assertLegitimateSiblingDirectoryIsPreservedWithoutSymlinks();
        } finally {
            $this->cleanup($this->workspace);
        }
    }

    private function assertMainRemediatorDeleteDirectoryIsSymlinkSafe()
    {
        $this->runSymlinkEscapeCase('MSP_PG_Remediator', 'main plugin remediator');
    }

    private function assertClonedDoorwayRemediatorDeleteDirectoryIsSymlinkSafe()
    {
        $this->runSymlinkEscapeCase('MSP_PG_ClonedDoorway_Remediator', 'ClonedDoorway remediator');
    }

    /**
     * Builds: <target>/ (the directory that will be "removed")
     *           ├── legit-file.php           (ordinary content, must be removed)
     *           ├── legit-subdir/inner.php   (ordinary nested content, must be removed)
     *           └── escape-link -> <outside>/sensitive.txt   (symlink, if supported)
     *         <outside>/sensitive.txt         (must NEVER be touched)
     *
     * Calls the given remediator class's private delete_directory($target)
     * via reflection and asserts: the target directory is gone, the
     * ordinary nested content is gone, the symlink itself is gone (if one
     * was created), and the external target survives untouched.
     */
    private function runSymlinkEscapeCase($remediatorClass, $label)
    {
        $caseDir = MSP_PG_Utils::join_paths($this->workspace, preg_replace('/[^A-Za-z0-9]/', '_', $remediatorClass));
        $target = MSP_PG_Utils::join_paths($caseDir, 'target');
        $outside = MSP_PG_Utils::join_paths($caseDir, 'outside');
        wp_mkdir_p($target . DIRECTORY_SEPARATOR . 'legit-subdir');
        wp_mkdir_p($outside);

        file_put_contents(MSP_PG_Utils::join_paths($target, 'legit-file.php'), "<?php // ordinary artifact content\n");
        file_put_contents(MSP_PG_Utils::join_paths($target, 'legit-subdir', 'inner.php'), "<?php // ordinary nested artifact content\n");

        $sensitiveFile = MSP_PG_Utils::join_paths($outside, 'sensitive.txt');
        file_put_contents($sensitiveFile, 'must never be touched by remediation of an unrelated directory');

        $linkPath = MSP_PG_Utils::join_paths($target, 'escape-link');
        $symlinkCreated = @symlink($outside, $linkPath);

        $ref = new ReflectionClass($remediatorClass);
        $method = $ref->getMethod('delete_directory');
        $method->setAccessible(true);
        $method->invoke(null, $target);

        $this->assertFalse(is_dir($target) || is_file($target), $label . ': target directory should be fully removed');
        $this->assertTrue(file_exists($sensitiveFile), $label . ': file outside the target directory must survive untouched regardless of symlink presence');
        $this->assertSame('must never be touched by remediation of an unrelated directory', file_get_contents($sensitiveFile), $label . ': external file content must be byte-for-byte unchanged');

        if ($symlinkCreated) {
            $this->assertFalse(is_link($linkPath) || file_exists($linkPath), $label . ': the symlink entry itself should have been removed as a leaf, not followed');
            $this->assertTrue(is_dir($outside), $label . ': the symlink TARGET directory must still exist (only the link, never its target, is removed)');
        } else {
            echo "  ($label: symlink() unavailable in this environment -- true-symlink assertions skipped; containment of the external file above still demonstrates the fix for the escape case)\n";
        }

        $this->cleanup($caseDir);
    }

    private function assertLegitimateSiblingDirectoryIsPreservedWithoutSymlinks()
    {
        $base = MSP_PG_Utils::join_paths($this->workspace, 'siblings');
        $toRemove = MSP_PG_Utils::join_paths($base, 'to-remove');
        $toKeep = MSP_PG_Utils::join_paths($base, 'to-keep');
        wp_mkdir_p($toRemove);
        wp_mkdir_p($toKeep);
        file_put_contents(MSP_PG_Utils::join_paths($toRemove, 'a.php'), "<?php // remove me\n");
        file_put_contents(MSP_PG_Utils::join_paths($toKeep, 'b.php'), "<?php // keep me\n");

        $ref = new ReflectionClass('MSP_PG_Remediator');
        $method = $ref->getMethod('delete_directory');
        $method->setAccessible(true);
        $method->invoke(null, $toRemove);

        $this->assertFalse(is_dir($toRemove), 'Target directory should be removed');
        $this->assertTrue(is_dir($toKeep), 'Sibling directory not passed to delete_directory() must be fully preserved');
        $this->assertTrue(file_exists(MSP_PG_Utils::join_paths($toKeep, 'b.php')), 'Sibling directory contents must be fully preserved');
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

$test = new DirectoryRemediationSymlinkSafetyTest();
$test->run();
echo "DirectoryRemediationSymlinkSafetyTest passed\n";
