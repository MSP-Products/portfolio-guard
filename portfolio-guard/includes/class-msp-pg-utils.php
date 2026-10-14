<?php
if (!defined('ABSPATH')) {
    exit;
}
class MSP_PG_Utils
{
    /**
     * Deny-all rules written into the evidence root. They protect Apache /
     * LiteSpeed (.htaccess) and IIS (web.config) only -- nginx ignores both,
     * which is why the default root is outside the web root when possible.
     * index.html stops directory listings on servers with autoindex enabled.
     */
    const EVIDENCE_HTACCESS = "# MSP Portfolio Guard evidence store -- no HTTP access.\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n";
    const EVIDENCE_WEB_CONFIG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- MSP Portfolio Guard evidence store -- no HTTP access. -->\n<configuration>\n  <system.webServer>\n    <authorization>\n      <deny users=\"*\" />\n    </authorization>\n  </system.webServer>\n</configuration>\n";

    /**
     * Evidence root that write helpers must refuse to write under, set by
     * MSP_PG_Remediator::run_scan() for the duration of a scan whose
     * evidence storage could not be secured. Evidence writes then fail,
     * preservation is never verified, and every remediator's existing
     * evidence-before-removal gate withholds destructive remediation.
     */
    private static $blockedEvidenceRoot = '';

    public static function block_evidence_writes($root)
    {
        self::$blockedEvidenceRoot = $root === '' ? '' : self::comparable_path($root);
    }

    private static function evidence_write_blocked($path)
    {
        if (self::$blockedEvidenceRoot === '') {
            return false;
        }
        $path = self::comparable_path($path);

        return $path === self::$blockedEvidenceRoot || strpos($path, self::$blockedEvidenceRoot . '/') === 0;
    }

    private static function comparable_path($path)
    {
        $path = rtrim(str_replace('\\', '/', (string) $path), '/');

        return DIRECTORY_SEPARATOR === '\\' ? strtolower($path) : $path;
    }

    /**
     * Creates {base}/{site}/{scan} for one scan's evidence and installs the
     * access-denial files. Fails (returns false, creating nothing further)
     * when the base or an intermediate directory is a symlink, a protection
     * file cannot be written or is a symlink, or the scan directory would
     * resolve outside the base.
     */
    public static function prepare_evidence_directory($baseDir, $scanDir)
    {
        $baseDir = rtrim((string) $baseDir, '/\\');
        $siteDir = dirname($scanDir);
        if ($baseDir === '' || is_link($baseDir) || self::comparable_path(dirname($siteDir)) !== self::comparable_path($baseDir)) {
            return false;
        }
        if (!self::ensure_directory($baseDir) || !self::write_evidence_protection($baseDir)) {
            return false;
        }
        foreach (array($siteDir, $scanDir) as $dir) {
            if (is_link($dir) || !self::ensure_directory($dir) || !self::write_protection_file($dir, 'index.html', '')) {
                return false;
            }
        }

        $realBase = realpath($baseDir);
        $realScan = realpath($scanDir);

        return $realBase !== false && $realScan !== false
            && strpos(self::comparable_path($realScan) . '/', self::comparable_path($realBase) . '/') === 0;
    }

    public static function write_evidence_protection($dir)
    {
        return self::write_protection_file($dir, '.htaccess', self::EVIDENCE_HTACCESS)
            && self::write_protection_file($dir, 'web.config', self::EVIDENCE_WEB_CONFIG)
            && self::write_protection_file($dir, 'index.html', '');
    }

    private static function write_protection_file($dir, $name, $contents)
    {
        $path = self::join_paths($dir, $name);
        if (is_link($path) || is_dir($path)) {
            return false;
        }
        if (is_file($path) && @file_get_contents($path) === $contents) {
            return true;
        }

        return @file_put_contents($path, $contents) !== false;
    }

    public static function ensure_directory($path)
    {
        if (self::evidence_write_blocked($path)) {
            return false;
        }
        if (is_dir($path)) {
            return true;
        }
        return wp_mkdir_p($path);
    }
    public static function join_paths()
    {
        $parts = func_get_args();
        $filtered = array();
        foreach ($parts as $index => $part) {
            $part = (string) $part;
            $part = $index === 0 ? rtrim($part, '/\\') : trim($part, '/\\');
            if ($part !== '') {
                $filtered[] = $part;
            }
        }
        return implode(DIRECTORY_SEPARATOR, $filtered);
    }
    public static function relative_path($path, $base)
    {
        $path = wp_normalize_path($path);
        $base = trailingslashit(wp_normalize_path($base));
        if (strpos($path, $base) === 0) {
            return ltrim(substr($path, strlen($base)), '/');
        }
        return ltrim($path, '/');
    }
    public static function recursive_files($dir)
    {
        $files = array();
        if (!is_dir($dir)) {
            return $files;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isFile()) {
                $files[] = $item->getPathname();
            }
        }
        sort($files);
        return $files;
    }
    public static function write_json($path, $data)
    {
        if (self::evidence_write_blocked($path)) {
            return false;
        }
        $json = wp_json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return false;
        }
        return file_put_contents($path, $json) !== false;
    }
    public static function write_text($path, $contents)
    {
        if (self::evidence_write_blocked($path)) {
            return false;
        }
        return file_put_contents($path, $contents) !== false;
    }
    public static function hash_file_safe($path)
    {
        return is_readable($path) ? strtoupper(hash_file('sha256', $path)) : '';
    }
    public static function hash_directory($dir)
    {
        $hashes = array();
        foreach (self::recursive_files($dir) as $file) {
            $hashes[self::relative_path($file, $dir)] = self::hash_file_safe($file);
        }
        ksort($hashes);
        return $hashes;
    }
    public static function directory_size($dir)
    {
        $size = 0;
        foreach (self::recursive_files($dir) as $file) {
            $size += (int) filesize($file);
        }
        return $size;
    }
    public static function directory_counts($dir)
    {
        $fileCount = 0;
        $directoryCount = 0;

        if (!is_dir($dir)) {
            return array(
                'file_count' => 0,
                'directory_count' => 0,
            );
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                $directoryCount++;
            } elseif ($item->isFile()) {
                $fileCount++;
            }
        }

        return array(
            'file_count' => $fileCount,
            'directory_count' => $directoryCount,
        );
    }
    public static function directory_fingerprint($dir)
    {
        $rows = array();

        foreach (self::recursive_files($dir) as $file) {
            $relative = self::relative_path($file, $dir);
            $rows[] = wp_json_encode(array(
                'path' => $relative,
                'size' => (int) filesize($file),
                'sha256' => self::hash_file_safe($file),
            ));
        }

        sort($rows);

        return strtoupper(hash('sha256', implode("\n", $rows)));
    }
    /**
     * Read the Version: header from a plugin's PHP files (checks root-level *.php, 8 KB read).
     * Returns the version string, or '' if not found.
     */
    public static function plugin_version($pluginDir)
    {
        $files = glob(trailingslashit($pluginDir) . '*.php') ?: array();
        foreach ($files as $file) {
            if (!is_readable($file)) {
                continue;
            }
            $contents = @file_get_contents($file, false, null, 0, 8192);
            if ($contents === false) {
                continue;
            }
            if (preg_match('/^\s*[\/*#]*\s*Version:\s*([^\r\n]+)/mi', $contents, $m)) {
                return trim($m[1]);
            }
        }
        return '';
    }

    public static function detect_plugin_files($plugin_dir)
    {
        $files = glob(trailingslashit($plugin_dir) . '*.php');
        $basenames = array();
        if ($files === false) {
            return $basenames;
        }
        foreach ($files as $file) {
            $basenames[] = basename(dirname($file)) . '/' . basename($file);
        }
        sort($basenames);
        return $basenames;
    }
    public static function move_directory($source, $destination)
    {
        if (self::evidence_write_blocked($destination)) {
            return false;
        }
        self::ensure_directory(dirname($destination));
        return @rename($source, $destination);
    }
    /**
     * Symlink-safe recursive copy, used for full_artifact_retention evidence
     * snapshots. Walked manually via scandir() rather than
     * RecursiveDirectoryIterator, which follows symlinked subdirectories
     * during traversal by default -- without this, a symlink planted inside
     * an artifact directory could cause evidence collection to copy
     * unrelated content from outside the artifact into permanent evidence
     * storage (an information-disclosure / evidence-integrity concern, and
     * a potential symlink-loop resource exhaustion). Any entry that is
     * itself a symlink (file or directory) is skipped entirely -- never
     * copied as a link, never followed to its target -- so evidence copies
     * only ever contain the artifact's own real file content. This is a
     * deliberate behavior change from the prior revision, which copied
     * through symlinks unconditionally; it does not change the return
     * contract (true/false) or any existing evidence_retention_mode logic.
     */
    public static function copy_directory($source, $destination)
    {
        if (is_link($source)) {
            return false; // never treat a symlinked path as a copyable artifact root
        }
        if (!is_dir($source) || self::evidence_write_blocked($destination)) {
            return false;
        }
        self::ensure_directory($destination);

        foreach (@scandir($source) ?: array() as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $sourcePath = self::join_paths($source, $entry);
            $targetPath = self::join_paths($destination, $entry);

            if (is_link($sourcePath)) {
                continue;
            }
            if (is_dir($sourcePath)) {
                self::ensure_directory($targetPath);
                if (!self::copy_directory($sourcePath, $targetPath)) {
                    return false;
                }
                continue;
            }
            if (!@copy($sourcePath, $targetPath)) {
                return false;
            }
        }

        return true;
    }
    /**
     * Symlink-safe zip archiving -- same rationale as copy_directory()
     * above. A manual recursive walk (via add_directory_to_zip_entries())
     * replaces RecursiveDirectoryIterator so a planted symlink anywhere in
     * $sourceDir is skipped rather than followed into the archive. Return
     * contract and the existing "never archive the zip file being written
     * into itself" check are unchanged.
     */
    public static function zip_directory($sourceDir, $zipPath)
    {
        if (!class_exists('ZipArchive') || self::evidence_write_blocked($zipPath)) {
            return false;
        }
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            return false;
        }
        $sourceDir = realpath($sourceDir);
        if ($sourceDir === false) {
            $zip->close();
            return false;
        }

        self::add_directory_to_zip_entries($zip, $sourceDir, $sourceDir, $zipPath);

        $zip->close();
        return file_exists($zipPath) && filesize($zipPath) > 0;
    }

    private static function add_directory_to_zip_entries(ZipArchive $zip, $currentDir, $rootDir, $zipPath)
    {
        foreach (@scandir($currentDir) ?: array() as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $fullPath = self::join_paths($currentDir, $entry);

            if (is_link($fullPath)) {
                continue;
            }
            if (wp_normalize_path($fullPath) === wp_normalize_path($zipPath)) {
                continue;
            }

            $localPath = ltrim(str_replace(wp_normalize_path($rootDir), '', wp_normalize_path($fullPath)), '/');

            if (is_dir($fullPath)) {
                $zip->addEmptyDir($localPath);
                self::add_directory_to_zip_entries($zip, $fullPath, $rootDir, $zipPath);
            } else {
                $zip->addFile($fullPath, $localPath);
            }
        }
    }
    public static function zip_live_directory($sourceDir, $zipPath)
    {
        return self::zip_directory($sourceDir, $zipPath);
    }
    public static function normalize_list($values)
    {
        $values = array_values(array_unique(array_filter($values)));
        sort($values);
        return $values;
    }
    public static function random_payload_structure($plugin_dir)
    {
        $matches = array(
            'directories' => array(),
            'php_files' => array(),
            'asset_js' => array(),
        );
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($plugin_dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            $relative = self::relative_path($item->getPathname(), $plugin_dir);
            if ($item->isDir() && preg_match('/^[a-z0-9]{5,6}$/i', basename($relative))) {
                $matches['directories'][] = $relative;
            }
            if ($item->isFile() && preg_match('/^[a-z0-9]{8}\.php$/i', basename($relative))) {
                $matches['php_files'][] = $relative;
            }
            if ($item->isFile() && preg_match('#^assets/[a-z0-9]{8}\.js$#i', str_replace('\\', '/', $relative))) {
                $matches['asset_js'][] = $relative;
            }
        }
        foreach ($matches as $key => $values) {
            $matches[$key] = self::normalize_list($values);
        }
        return $matches;
    }
    public static function markdown_report($scanReport)
    {
        $lines = array();
        $lines[] = '# MSP Portfolio Guard Scan Report';
        $lines[] = '';
        $lines[] = '- Site URL: `' . $scanReport['site_url'] . '`';
        $lines[] = '- Scan timestamp: `' . $scanReport['scan_timestamp'] . '`';
        $lines[] = '- Trigger: `' . $scanReport['trigger'] . '`';
        $lines[] = '- Evidence retention mode: `' . $scanReport['evidence_retention_mode'] . '`';
        $lines[] = '- Dry run: `' . ($scanReport['dry_run'] ? 'enabled' : 'disabled') . '`';
        $lines[] = '- Detections: `' . count($scanReport['detections']) . '`';
        if (!empty($scanReport['cleanup'])) {
            $lines[] = '- Cleanup: `' . self::cleanup_summary($scanReport['cleanup']) . '`';
        }
        $lines[] = '';
        $groups = array(
            'confirmed_malware' => 'Confirmed Malware',
            'review_required' => 'Review Required',
        );
        foreach ($groups as $key => $label) {
            if (empty($scanReport[$key])) {
                continue;
            }
            $lines[] = '## ' . $label;
            $lines[] = '';
            foreach ($scanReport[$key] as $detection) {
                $lines[] = '### ' . $detection['plugin_slug'] . ' (' . strtoupper($detection['tier']) . ')';
                $lines[] = '';
                $lines[] = '- Live path: `' . $detection['live_path'] . '`';
                $lines[] = '- Artifact path: `' . $detection['artifact_dir'] . '`';
                $lines[] = '- Evidence mode: `' . $detection['evidence_retention_mode'] . '`';
                $lines[] = '- Preservation verified: `' . ($detection['preservation_verified'] ? 'yes' : 'no') . '`';
                $lines[] = '- Protected plugin: `' . ($detection['protected_plugin'] ? 'yes' : 'no') . '`';
                // Tier-specific evidence representation (Spec 005 §11.3)
                if ($detection['tier'] !== 'tier2') {
                    $lines[] = '- Score: `' . $detection['score'] . '`';
                }
                if (!empty($detection['behavior_profiles'])) {
                    $labels = array_column($detection['behavior_profiles'], 'profile_label');
                    $lines[] = '- Behavior Profiles: `' . implode(', ', $labels) . '`';
                }
                $lines[] = '- Confidence: `' . $detection['confidence'] . '`';
                $lines[] = '- Source: `' . $detection['source'] . '`';
                $lines[] = '- Actions: `' . implode('; ', $detection['action_descriptions']) . '`';
                $lines[] = '- Exact matches: `' . implode(', ', $detection['exact_match_types']) . '`';
                $lines[] = '- Indicators: `' . implode(', ', $detection['matched_indicators']) . '`';
                if ($detection['tier'] !== 'tier2') {
                    $lines[] = '- Reasons: `' . implode(', ', $detection['reason_labels']) . '`';
                }
                if (!empty($detection['warnings'])) {
                    $lines[] = '- Warnings: `' . implode(', ', $detection['warnings']) . '`';
                }
                $lines[] = '';
            }
        }
        if (!empty($scanReport['errors'])) {
            $lines[] = '## Errors';
            $lines[] = '';
            foreach ($scanReport['errors'] as $error) {
                $lines[] = '- ' . $error;
            }
            $lines[] = '';
        }
        return implode("\n", $lines);
    }
    public static function plain_text_report($scanReport)
    {
        $summary = self::scan_summary_counts($scanReport);
        $lines = array(
            'MSP Portfolio Guard Scan Report',
            'Site: ' . $scanReport['site_url'],
            'Timestamp: ' . $scanReport['scan_timestamp'],
            'Trigger: ' . $scanReport['trigger'],
            'Evidence Retention Mode: ' . $scanReport['evidence_retention_mode'],
            'Dry Run: ' . ($scanReport['dry_run'] ? 'Enabled' : 'Disabled'),
        );
        if (!empty($scanReport['cleanup'])) {
            $lines[] = 'Retention cleanup: ' . self::cleanup_summary($scanReport['cleanup']);
        }
        $lines[] = '';
        $lines[] = 'Executive Summary';
        $lines[] = 'Confirmed Malware: ' . count($scanReport['confirmed_malware']);
        $lines[] = 'Review Required: ' . count($scanReport['review_required']);
        $lines[] = 'Remediated: ' . $summary['remediated'];
        $lines[] = 'Would Remediate: ' . $summary['would_remediate'];
        $sections = array(
            'confirmed_malware' => 'Confirmed Malware',
            'review_required' => 'Review Required',
        );
        foreach ($sections as $key => $label) {
            $lines[] = '';
            $lines[] = $label;
            if (empty($scanReport[$key])) {
                $lines[] = 'None.';
                continue;
            }
            foreach ($scanReport[$key] as $detection) {
                $lines[] = '- Plugin: ' . $detection['plugin_slug'];
                $lines[] = '  Tier: ' . strtoupper($detection['tier']);
                // Tier-specific evidence representation (Spec 005 §11.3)
                if ($detection['tier'] !== 'tier2') {
                    $lines[] = '  Score: ' . $detection['score'];
                }
                if (!empty($detection['behavior_profiles'])) {
                    $labels = implode(', ', array_column($detection['behavior_profiles'], 'profile_label'));
                    $lines[] = '  Behavior Profiles: ' . $labels;
                }
                $lines[] = '  Confidence: ' . $detection['confidence'];
                $lines[] = '  Source: ' . $detection['source'];
                $lines[] = '  Action: ' . implode('; ', $detection['action_descriptions']);
                if (!empty($detection['reason_labels'])) {
                    $lines[] = '  Reasons: ' . implode(', ', $detection['reason_labels']);
                }
                if (!empty($detection['exact_match_types'])) {
                    $lines[] = '  Exact Matches: ' . implode(', ', $detection['exact_match_types']);
                }
                if (!empty($detection['bundle_eligible'])) {
                    $lines[] = '  Evidence: ' . ($detection['preservation_verified'] ? 'Verified' : ($scanReport['dry_run'] ? 'Simulated' : 'Generated/Partial'));
                    $lines[] = '  Artifact Location: ' . $detection['artifact_dir'];
                    $lines[] = '  Evidence Mode: ' . $detection['evidence_retention_mode'];
                }
            }
        }
        if (!empty($scanReport['errors'])) {
            $lines[] = '';
            $lines[] = 'Errors';
            foreach ($scanReport['errors'] as $error) {
                $lines[] = '- ' . $error;
            }
        }
        return implode("\n", $lines) . "\n";
    }
    public static function html_escape($value)
    {
        return esc_html((string) $value);
    }
    public static function html_report($scanReport)
    {
        $confirmedCount = count($scanReport['confirmed_malware']);
        $reviewRequiredCount = count($scanReport['review_required']);
        $summary = self::scan_summary_counts($scanReport);
        $remediated = $summary['remediated'];
        $wouldRemediate = $summary['would_remediate'];
        $renderTable = function ($headers, $rows) {
            if (empty($rows)) {
                return '<p>None.</p>';
            }
            $html = '<table style="border-collapse:collapse;width:100%;margin:12px 0;">';
            $html .= '<thead><tr>';
            foreach ($headers as $header) {
                $html .= '<th style="border:1px solid #d0d7de;padding:8px;background:#f6f8fa;text-align:left;">' . $header . '</th>';
            }
            $html .= '</tr></thead><tbody>';
            foreach ($rows as $row) {
                $html .= '<tr>';
                foreach ($row as $cell) {
                    $html .= '<td style="border:1px solid #d0d7de;padding:8px;vertical-align:top;">' . $cell . '</td>';
                }
                $html .= '</tr>';
            }
            $html .= '</tbody></table>';
            return $html;
        };
        $badge = function ($bg, $fg, $label) {
            return '<span style="display:inline-block;font-weight:600;padding:2px 8px;border-radius:999px;background:' . $bg . ';color:' . $fg . ';">&#9679; ' . self::html_escape($label) . '</span>';
        };
        $evidenceRows = array();
        foreach ($scanReport['detections'] as $detection) {
            if (empty($detection['bundle_eligible'])) {
                continue;
            }
            $status = $detection['preservation_verified'] ? 'Verified' : ($scanReport['dry_run'] ? 'Simulated' : 'Generated/Partial');
            $evidenceRows[] = array(
                self::html_escape($detection['plugin_slug'] . ' Evidence Manifest'),
                self::html_escape($scanReport['dry_run'] ? 'Simulated' : 'Generated'),
            );
            if ($detection['evidence_retention_mode'] !== 'metadata_only') {
                $evidenceRows[] = array(
                    self::html_escape($detection['plugin_slug'] . ' Evidence Archive'),
                    self::html_escape($status),
                );
            }
            $evidenceRows[] = array(
                self::html_escape($detection['plugin_slug'] . ' Evidence Mode'),
                self::html_escape($detection['evidence_retention_mode']),
            );
        }
        $artifactRows = array();
        foreach ($scanReport['detections'] as $detection) {
            if (empty($detection['bundle_eligible'])) {
                continue;
            }
            $artifactRows[] = array(
                self::html_escape($detection['plugin_slug']),
                self::html_escape($detection['artifact_dir']),
            );
        }
        $html = '<html><body style="font-family:Arial,sans-serif;color:#1f2328;">';
        $html .= '<h1>MSP Portfolio Guard Scan Report</h1>';
        $html .= '<p>Site: <strong>' . self::html_escape($scanReport['site_url']) . '</strong><br>';
        $html .= 'Timestamp: <strong>' . self::html_escape($scanReport['scan_timestamp']) . '</strong><br>';
        $html .= 'Trigger: <strong>' . self::html_escape($scanReport['trigger']) . '</strong><br>';
        $html .= 'Evidence Retention Mode: <strong>' . self::html_escape($scanReport['evidence_retention_mode']) . '</strong></p>';
        if (!empty($scanReport['cleanup'])) {
            $html .= '<p><strong>Retention cleanup:</strong> ' . self::html_escape(self::cleanup_summary($scanReport['cleanup'])) . '</p>';
        }
        $html .= '<h2>Executive Summary</h2>';
        $html .= $renderTable(
            array('Metric', 'Value'),
            array(
                array($badge('#dcfce7', '#166534', 'Confirmed Malware'), self::html_escape($confirmedCount)),
                array($badge('#fef9c3', '#854d0e', 'Review Required'), self::html_escape($reviewRequiredCount)),
                array(self::html_escape('Evidence Retention Mode'), self::html_escape($scanReport['evidence_retention_mode'])),
                array(self::html_escape('Remediated'), self::html_escape($remediated)),
                array(self::html_escape('Would Remediate'), self::html_escape($wouldRemediate)),
            )
        );
        $html .= '<h2>Confirmed Malware</h2>';
        $html .= $renderTable(
            array('Plugin', 'Tier', 'Score', 'Confidence', 'Source', 'Action', 'Evidence'),
            array_map(function ($detection) {
                return array(
                    self::html_escape($detection['plugin_slug']),
                    self::html_escape(strtoupper($detection['tier'])),
                    self::html_escape($detection['score']),
                    self::html_escape($detection['confidence']),
                    self::html_escape($detection['source']),
                    self::html_escape(implode('; ', $detection['action_descriptions'])),
                    self::html_escape($detection['preservation_verified'] ? 'Yes' : 'No'),
                );
            }, $scanReport['confirmed_malware'])
        );
        $html .= '<h2>Review Required</h2>';
        $html .= $renderTable(
            array('Plugin', 'Behavior Profiles', 'Action'),
            array_map(function ($detection) {
                $profileLabels = array_column($detection['behavior_profiles'], 'profile_label');
                return array(
                    self::html_escape($detection['plugin_slug']),
                    self::html_escape(empty($profileLabels) ? '—' : implode(', ', $profileLabels)),
                    self::html_escape(implode('; ', $detection['action_descriptions'])),
                );
            }, $scanReport['review_required'])
        );
        $html .= '<h2>Evidence Status</h2>';
        $html .= $renderTable(array('Artifact', 'Status'), $evidenceRows);
        $html .= '<h2>Artifact Locations</h2>';
        $html .= $renderTable(array('Plugin', 'Artifact Location'), $artifactRows);
        $html .= '</body></html>';
        return $html;
    }
    public static function describe_action($action)
    {
        $map = array(
            'REPORT_ONLY_NO_CHANGES' => 'Reported only; no site changes made',
            'DRY_RUN_ENABLED' => 'Dry run simulated all actions',
            'PROTECTED_PLUGIN_REPORT_ONLY' => 'Protected plugin kept in report-only mode',
            'CONFIRMED_MALWARE_IDENTIFIED' => 'Confirmed malware identified',
            'REVIEW_REQUIRED_IDENTIFIED' => 'Review Required finding identified',
            'PLUGIN_DEACTIVATED' => 'Plugin deactivated before remediation',
            'EVIDENCE_MANIFEST_CREATED' => 'Evidence manifest created',
            'EVIDENCE_ARCHIVE_CREATED' => 'Compressed evidence archive created',
            'FULL_ARTIFACT_SNAPSHOT_CREATED' => 'Full artifact snapshot created',
            'BUNDLE_VERIFIED' => 'Evidence bundle verified',
            'QUARANTINE_COMPLETED' => 'Plugin moved to persistent quarantine directory',
            'LIVE_PLUGIN_REMOVED' => 'Live plugin directory removed',
            'REVIEW_REQUIRED_REPORT_ONLY' => 'Review Required finding reported; no site changes',
            'WOULD_PLUGIN_DEACTIVATE' => 'Would deactivate active plugin',
            'WOULD_EVIDENCE_MANIFEST_CREATE' => 'Would create evidence manifest',
            'WOULD_EVIDENCE_ARCHIVE_CREATE' => 'Would create compressed evidence archive',
            'WOULD_FULL_ARTIFACT_RETAIN' => 'Would retain full artifact set',
            'WOULD_LIVE_PLUGIN_REMOVE' => 'Would remove live plugin directory after verified evidence preservation',
            // PG-ClonedDoorway (see class-msp-pg-clonedoorway-remediator.php)
            'REPORT_ONLY_MODIFIED_CORE_FILE' => 'Modified legitimate file reported only; Portfolio Guard does not alter it automatically',
            'OPERATOR_ACTION_REQUIRED' => 'Manual operator action required; see operator_action_required field',
            'MODIFIED_FILE_EVIDENCE_COPIED' => 'Copy of modified file preserved as evidence (live file untouched)',
            'EVIDENCE_ARCHIVE_FAILED' => 'Failed to create compressed evidence archive',
            'WOULD_LIVE_ARTIFACT_REMOVE' => 'Would remove live artifact after verified evidence preservation',
            'LIVE_ARTIFACT_REMOVED' => 'Live attacker-created artifact removed',
            'REPORT_ONLY_NO_AUTOMATIC_REMOVAL' => 'Reported only; this artifact type is never removed automatically',
            'REMOVAL_WITHHELD_INSUFFICIENT_CONFIDENCE' => 'Removal withheld: insufficient confidence for automatic remediation',
            'REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION' => 'Removal withheld: automatic remediation is disabled by configuration (evidence preserved, live files untouched)',
            'DEACTIVATION_WITHHELD_DISABLED_BY_CONFIGURATION' => 'Deactivation withheld: automatic remediation is disabled by configuration (plugin left active)',
        );
        return isset($map[$action]) ? $map[$action] : $action;
    }
    public static function describe_actions($actions)
    {
        $descriptions = array();
        foreach ($actions as $action) {
            $descriptions[] = self::describe_action($action);
        }
        return $descriptions;
    }
    public static function scan_summary_counts($scanReport)
    {
        $remediated = 0;
        $wouldRemediate = 0;
        foreach ($scanReport['detections'] as $detection) {
            $hasRemediated = false;
            $hasWouldRemediate = false;
            foreach ($detection['actions'] as $action) {
                if ($action === 'PLUGIN_DEACTIVATED' || $action === 'QUARANTINE_COMPLETED' || $action === 'LIVE_PLUGIN_REMOVED' || $action === 'LIVE_ARTIFACT_REMOVED') {
                    $hasRemediated = true;
                }
                if (in_array($action, array('WOULD_PLUGIN_DEACTIVATE', 'WOULD_EVIDENCE_MANIFEST_CREATE', 'WOULD_EVIDENCE_ARCHIVE_CREATE', 'WOULD_FULL_ARTIFACT_RETAIN', 'WOULD_LIVE_PLUGIN_REMOVE'), true)) {
                    $hasWouldRemediate = true;
                }
            }
            if ($hasRemediated) {
                $remediated++;
            }
            if ($hasWouldRemediate) {
                $wouldRemediate++;
            }
        }
        return array(
            'remediated' => $remediated,
            'would_remediate' => $wouldRemediate,
        );
    }
    public static function cleanup_summary($cleanup)
    {
        if (empty($cleanup)) {
            return 'No cleanup performed.';
        }
        $parts = array();
        $parts[] = sprintf(
            '%d expired remediation directories %s',
            isset($cleanup['deleted_count']) ? (int) $cleanup['deleted_count'] : 0,
            (isset($cleanup['mode']) && $cleanup['mode'] === 'simulated') ? 'would be deleted' : 'deleted'
        );
        if (isset($cleanup['scrubbed_count'])) {
            $parts[] = sprintf(
                '%d legacy executable artifact directories %s',
                (int) $cleanup['scrubbed_count'],
                (isset($cleanup['mode']) && $cleanup['mode'] === 'simulated') ? 'would be scrubbed' : 'scrubbed'
            );
        }
        $parts[] = sprintf(
            'retention set to %d days',
            isset($cleanup['retention_days']) ? (int) $cleanup['retention_days'] : 0
        );

        return implode('; ', $parts) . '.';
    }
}
