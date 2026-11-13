<?php

require_once dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . 'portfolio-guard' . DIRECTORY_SEPARATOR . 'tests' . DIRECTORY_SEPARATOR . 'bootstrap.php';

class CleanPluginTest
{
    private $manifestPath;
    private $corpusRoot;

    public function run()
    {
        $this->manifestPath = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'corpus' . DIRECTORY_SEPARATOR . 'clean-plugins' . DIRECTORY_SEPARATOR . 'manifest.json';
        $this->corpusRoot   = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'corpus' . DIRECTORY_SEPARATOR . 'clean-plugins';

        $manifest = $this->loadManifest();
        $passed   = 0;
        $failed   = 0;
        $results  = array();

        foreach ($manifest['entries'] as $entry) {
            try {
                $this->runEntry($entry);
                $results[] = '[PASS] CleanPluginTest: ' . $entry['plugin_slug'] . ' ' . $entry['version'] . ' — no detection';
                $passed++;
            } catch (RuntimeException $e) {
                $results[] = '[FAIL] CleanPluginTest: ' . $entry['plugin_slug'] . ' ' . $entry['version'] . ' — ' . $e->getMessage();
                $failed++;
            }
        }

        return array(
            'results' => $results,
            'passed'  => $passed,
            'failed'  => $failed,
            'total'   => count($manifest['entries']),
        );
    }

    private function loadManifest()
    {
        if (!file_exists($this->manifestPath)) {
            throw new RuntimeException('Clean plugin manifest not found: ' . $this->manifestPath);
        }
        $manifest = json_decode(file_get_contents($this->manifestPath), true);
        if (!is_array($manifest) || !isset($manifest['entries'])) {
            throw new RuntimeException('Invalid clean-plugins manifest format');
        }
        return $manifest;
    }

    private function runEntry($entry)
    {
        $pluginDir = $this->corpusRoot . DIRECTORY_SEPARATOR . $entry['fixture_dir'];

        if (!is_dir($pluginDir)) {
            throw new RuntimeException(
                'corpus not staged — run validation/runner/stage-clean-corpus.ps1 (expected: ' . $entry['fixture_dir'] . ')'
            );
        }

        $GLOBALS['msp_pg_test_options']            = array('active_plugins' => array());
        $GLOBALS['msp_pg_test_transients']         = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();

        $analysis = MSP_PG_Detector::detect($pluginDir);

        // A plugin on the trusted list may show a Tier 2 behaviour finding (the remediator suppresses it), but never
        // an exact match: that would be Tier 1, which the trusted list cannot stop. An entry opts in explicitly.
        if ($analysis !== null && !empty($entry['trusted_tier2_allowed'])) {
            $trusted = in_array($entry['plugin_slug'], MSP_PG_Config::trusted_plugin_slugs(), true);
            if ($trusted && $analysis['tier'] === 'tier2' && empty($analysis['exact_match_types'])) {
                return;
            }
        }

        if ($analysis !== null) {
            throw new RuntimeException(
                'unexpected detection: tier=' . $analysis['tier'] .
                ', score=' . $analysis['score'] .
                ', matched=' . implode(', ', $analysis['exact_match_types']) .
                ', reasons=' . implode(', ', array_column($analysis['reasons'], 'key'))
            );
        }
    }
}
