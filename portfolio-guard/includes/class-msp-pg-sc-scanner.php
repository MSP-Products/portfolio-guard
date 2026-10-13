<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Filesystem scanner for the PG-SC-MacroOptimizerCue family (see
 * docs/malware-families/PG-SC-MacroOptimizerCue.md and
 * class-msp-pg-sc-signatures.php for signature rationale).
 *
 * This family's plugin-directory installation (the fake "Macro Optimizer
 * Cue" plugin) is deliberately NOT handled here -- it is registered as a
 * variant in data/signatures.json and detected/remediated through the
 * existing, already-reviewed MSP_PG_Detector / MSP_PG_Remediator plugin
 * loop, exactly like any other known plugin-directory malware family. This
 * scanner is additive, covering only the artifact types that pipeline
 * cannot reach: the headerless mu-plugin file, the hidden `.sc_<hex>` state
 * directory, the three wp-content drop-in filenames, and stray
 * recovery-loader files inside wp-includes/.
 *
 * Bounded, narrowly-scoped scanning (fleet-scale cost): mu-plugins/ and
 * wp-includes/ are each read with a single, non-recursive scandir() call;
 * drop-in detection is exactly three fixed-path file reads; only the hidden
 * state-directory search walks the tree, and it reuses the same bounded
 * scope PG-ClonedDoorway already established (everything at web root except
 * wp-content, plus wp-content's own children excluding plugins/uploads/themes).
 */
class MSP_PG_SC_Scanner
{
    const ARTIFACT_MU_PLUGIN_FILE          = 'sc_mu_plugin_file';
    const ARTIFACT_HIDDEN_STATE_DIRECTORY  = 'sc_hidden_state_directory';
    const ARTIFACT_DROPIN_FILE             = 'sc_dropin_file';
    const ARTIFACT_WPINCLUDES_RECOVERY_FILE = 'sc_wpincludes_recovery_file';

    private static $reasonWeights = array(
        'known_payload_hash'       => 100,
        'version_stamp'            => 75,
        'helper_function_set'      => 75,
        'dropin_injection_marker'  => 100,
        'hidden_dir_structure'     => 100,
        'own_beacon_shape'         => 50,
        'wpincludes_recovery_name' => 50,
    );

    public static function scan()
    {
        if (!MSP_PG_SC_Signatures::registry_available()) {
            return array();
        }

        $root = MSP_PG_Config::sc_macro_cue_scan_root();
        if ($root === '' || !is_dir($root)) {
            return array();
        }

        $analyses = array();

        foreach (self::scan_mu_plugins($root) as $a) {
            $analyses[] = $a;
        }
        foreach (self::scan_hidden_state_directories($root) as $a) {
            $analyses[] = $a;
        }
        foreach (self::scan_dropin_files($root) as $a) {
            $analyses[] = $a;
        }
        foreach (self::scan_wpincludes_recovery_files($root) as $a) {
            $analyses[] = $a;
        }

        return $analyses;
    }

    // -------------------------------------------------------------------------
    // mu-plugins/ -- single-level scan, standalone attacker files
    // -------------------------------------------------------------------------

    private static function scan_mu_plugins($root)
    {
        $muDir = MSP_PG_Utils::join_paths($root, 'wp-content/mu-plugins');
        if (!is_dir($muDir)) {
            return array();
        }

        $analyses = array();
        foreach (glob(trailingslashit($muDir) . '*.php') ?: array() as $file) {
            if ((int) filesize($file) > MSP_PG_Config::max_scan_file_bytes() * 10) {
                continue; // generous cap; this family's known builds run up to ~2.4MB
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $analysis = self::base_analysis(self::ARTIFACT_MU_PLUGIN_FILE, 'mu-plugin:' . basename($file), $file);
            self::apply_content_signatures($analysis, $content, basename($file));

            if (empty($analysis['exact_match_types'])) {
                continue;
            }

            $analysis['files_scanned'][] = basename($file);
            $analysis['payload_hashes'][] = MSP_PG_Utils::hash_file_safe($file);
            self::finalize($analysis);
            $analyses[] = $analysis;
        }

        return $analyses;
    }

    // -------------------------------------------------------------------------
    // Hidden `.sc_<hex>` state directories -- bounded web-root walk, same
    // scope PG-ClonedDoorway already established.
    // -------------------------------------------------------------------------

    private static function scan_hidden_state_directories($root)
    {
        $analyses = array();

        foreach (self::top_level_scan_dirs($root) as $startDir) {
            foreach (self::find_hidden_state_dirs($startDir) as $dir) {
                $analyses[] = self::build_hidden_dir_analysis($dir, $root);
            }
        }

        return $analyses;
    }

    private static function top_level_scan_dirs($root)
    {
        $dirs = array();
        $entries = @scandir($root) ?: array();

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = MSP_PG_Utils::join_paths($root, $entry);
            if (!is_dir($path)) {
                continue;
            }
            if ($entry === 'wp-content') {
                $skip = array('plugins', 'uploads', 'themes');
                foreach (@scandir($path) ?: array() as $subEntry) {
                    if ($subEntry === '.' || $subEntry === '..' || in_array($subEntry, $skip, true)) {
                        continue;
                    }
                    $subPath = MSP_PG_Utils::join_paths($path, $subEntry);
                    if (is_dir($subPath)) {
                        $dirs[] = $subPath;
                    }
                }
                continue;
            }
            $dirs[] = $path;
        }

        return $dirs;
    }

    private static function find_hidden_state_dirs($startDir)
    {
        $found = array();
        $stack = array($startDir);

        while (!empty($stack)) {
            $dir = array_pop($stack);

            if (MSP_PG_SC_Signatures::is_hidden_state_directory($dir)) {
                $found[] = $dir;
                continue; // whole matched directory is one artifact; do not descend further
            }

            foreach (@scandir($dir) ?: array() as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $path = MSP_PG_Utils::join_paths($dir, $entry);
                if (is_dir($path)) {
                    $stack[] = $path;
                }
            }
        }

        return $found;
    }

    private static function build_hidden_dir_analysis($dirPath, $scanRootBase)
    {
        $relative = MSP_PG_Utils::relative_path($dirPath, $scanRootBase);
        $analysis = self::base_analysis(
            self::ARTIFACT_HIDDEN_STATE_DIRECTORY,
            'webroot:' . str_replace('\\', '/', $relative),
            $dirPath
        );

        self::add_reason($analysis, 'hidden_dir_structure', 'hidden state directory matching this family\'s `.sc_<hex>` naming convention');
        $analysis['structural_indicators'][] = 'sc_hidden_state_directory:' . str_replace('\\', '/', $relative);

        foreach (MSP_PG_Utils::recursive_files($dirPath) as $file) {
            $relFile = str_replace('\\', '/', MSP_PG_Utils::relative_path($file, $dirPath));
            $analysis['files_scanned'][] = $relFile;
            $analysis['payload_hashes'][] = MSP_PG_Utils::hash_file_safe($file);

            if ((int) filesize($file) > MSP_PG_Config::max_scan_file_bytes() * 10) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            if (strpos(basename($file), 'own_') === 0 && MSP_PG_SC_Signatures::has_own_beacon_shape($content)) {
                self::add_reason($analysis, 'own_beacon_shape', 'status-beacon file matching this family\'s JSON-shaped own_<hex>.php content (' . $relFile . ')');
            }

            self::apply_content_signatures($analysis, $content, $relFile);
        }

        self::finalize($analysis);

        return $analysis;
    }

    // -------------------------------------------------------------------------
    // wp-content drop-ins -- exactly three fixed-path file reads
    // -------------------------------------------------------------------------

    private static function scan_dropin_files($root)
    {
        $analyses = array();
        $wpContent = MSP_PG_Utils::join_paths($root, 'wp-content');

        foreach (array('advanced-cache.php', 'db.php', 'object-cache.php') as $name) {
            $file = MSP_PG_Utils::join_paths($wpContent, $name);
            if (!is_file($file)) {
                continue;
            }
            if ((int) filesize($file) > MSP_PG_Config::max_scan_file_bytes()) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }
            if (!MSP_PG_SC_Signatures::has_dropin_injection_marker($content)) {
                continue;
            }

            $analysis = self::base_analysis(self::ARTIFACT_DROPIN_FILE, 'wp-content:' . $name, $file);
            self::add_reason($analysis, 'dropin_injection_marker', 'injected SC_*_BEGIN marker found in wp-content/' . $name);
            $analysis['files_scanned'][] = $name;
            $analysis['payload_hashes'][] = MSP_PG_Utils::hash_file_safe($file);
            self::finalize($analysis);
            $analyses[] = $analysis;
        }

        return $analyses;
    }

    // -------------------------------------------------------------------------
    // wp-includes/ -- single-level scan for stray recovery-loader filenames.
    // Detection only reports the filename-pattern match here; whether it is
    // SAFE TO REMOVE is decided independently by MSP_PG_SC_Remediator, which
    // re-validates the content signature, symlink status, and realpath
    // containment itself rather than trusting this scan's classification.
    // -------------------------------------------------------------------------

    private static function scan_wpincludes_recovery_files($root)
    {
        $wpIncludes = MSP_PG_Utils::join_paths($root, 'wp-includes');
        if (!is_dir($wpIncludes)) {
            return array();
        }

        $analyses = array();
        foreach (@scandir($wpIncludes) ?: array() as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            if (!MSP_PG_SC_Signatures::is_wpincludes_recovery_filename($entry)) {
                continue;
            }

            $file = MSP_PG_Utils::join_paths($wpIncludes, $entry);
            if (!is_file($file) && !is_link($file)) {
                continue;
            }

            $analysis = self::base_analysis(self::ARTIFACT_WPINCLUDES_RECOVERY_FILE, 'wp-includes:' . $entry, $file);
            // Threaded through explicitly so MSP_PG_SC_Remediator validates the
            // wp-includes/ boundary against the SAME root this scan used,
            // rather than re-querying MSP_PG_Config a second time -- keeps
            // scan-time and remediate-time boundary checks consistent and
            // makes the guard independently testable against an arbitrary
            // fixture root.
            $analysis['scan_root'] = $root;
            self::add_reason($analysis, 'wpincludes_recovery_name', 'filename matches this family\'s recovery-loader naming convention inside wp-includes/ (' . $entry . ')');
            $analysis['structural_indicators'][] = 'wpincludes_recovery_filename:' . $entry;

            $content = (!is_link($file) && is_readable($file) && (int) filesize($file) <= MSP_PG_Config::max_scan_file_bytes() * 10)
                ? @file_get_contents($file)
                : false;
            if ($content !== false && $content !== '') {
                self::apply_content_signatures($analysis, $content, $entry);
            }

            $analysis['files_scanned'][] = $entry;
            $analysis['payload_hashes'][] = is_link($file) ? '' : MSP_PG_Utils::hash_file_safe($file);
            self::finalize($analysis);
            $analyses[] = $analysis;
        }

        return $analyses;
    }

    // -------------------------------------------------------------------------
    // Shared content-signature application + analysis-record helpers
    // -------------------------------------------------------------------------

    private static function apply_content_signatures(&$analysis, $content, $relFile)
    {
        $hash = strtoupper(hash('sha256', $content));
        if (in_array($hash, MSP_PG_SC_Signatures::known_payload_hashes(), true)) {
            self::add_reason($analysis, 'known_payload_hash', 'exact match to a known PG-SC-MacroOptimizerCue payload hash (' . $relFile . ')');
        }
        if (MSP_PG_SC_Signatures::has_version_stamp($content)) {
            self::add_reason($analysis, 'version_stamp', 'SCV:#.#.# build-version stamp (' . $relFile . ')');
        }
        if (MSP_PG_SC_Signatures::has_helper_function_set($content)) {
            self::add_reason($analysis, 'helper_function_set', 'co-occurrence of this family\'s _sc_* helper function definitions (' . $relFile . ')');
        }
    }

    private static function base_analysis($artifactType, $slug, $path)
    {
        return array(
            'family'                => MSP_PG_SC_Signatures::family_id(),
            'artifact_type'         => $artifactType,
            'plugin_slug'           => $slug,
            'plugin_dir'            => $path,
            'main_files'            => array(),
            'known_variant'         => '',
            'score'                 => 0,
            'reasons'               => array(),
            'hash_hits'             => array(),
            'exact_match_types'     => array(),
            'matched_indicators'    => array(),
            'matched_strings'       => array(),
            'routes'                => array(),
            'domains'               => array(),
            'backdoor_indicators'   => array(),
            'structural_indicators' => array(),
            'payload_hashes'        => array(),
            'files_scanned'         => array(),
            'tier'                  => '',
            'variant_hash'          => '',
            'detection_source'      => '',
            'protected_plugin'      => false,
            'behavior_profiles'     => array(),
        );
    }

    private static function add_reason(&$analysis, $key, $label)
    {
        if (isset($analysis['reasons'][$key])) {
            return;
        }
        $weight = isset(self::$reasonWeights[$key]) ? self::$reasonWeights[$key] : 25;
        $analysis['reasons'][$key] = array('key' => $key, 'label' => $label, 'weight' => $weight);
        $analysis['score'] += $weight;
        $analysis['exact_match_types'][] = $key;
        $analysis['matched_indicators'][] = $key;
    }

    private static function finalize(&$analysis)
    {
        $analysis['reasons'] = array_values($analysis['reasons']);
        usort($analysis['reasons'], function ($left, $right) {
            return $right['weight'] <=> $left['weight'];
        });

        $analysis['exact_match_types']     = MSP_PG_Utils::normalize_list($analysis['exact_match_types']);
        $analysis['matched_indicators']    = MSP_PG_Utils::normalize_list($analysis['matched_indicators']);
        $analysis['structural_indicators'] = MSP_PG_Utils::normalize_list($analysis['structural_indicators']);
        $analysis['payload_hashes']        = MSP_PG_Utils::normalize_list($analysis['payload_hashes']);

        $analysis['tier']             = 'tier1';
        $analysis['confidence']       = 'Exact Match';
        $analysis['detection_source'] = 'Built-In Signature Registry (PG-SC-MacroOptimizerCue)';
        $analysis['variant_hash']     = self::variant_hash($analysis);
    }

    public static function variant_hash($analysis)
    {
        $fingerprint = array(
            'family'                => $analysis['family'],
            'artifact_type'         => $analysis['artifact_type'],
            'slug'                  => $analysis['plugin_slug'],
            'tier'                  => $analysis['tier'],
            'score'                 => $analysis['score'],
            'exact_match_types'     => $analysis['exact_match_types'],
            'structural_indicators' => $analysis['structural_indicators'],
            'reasons'               => array_map(function ($reason) { return $reason['key']; }, $analysis['reasons']),
        );

        return strtoupper(hash('sha256', wp_json_encode($fingerprint)));
    }
}
