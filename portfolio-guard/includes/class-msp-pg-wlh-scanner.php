<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Filesystem scanner for the PG-WPLinkHelper family (see
 * docs/malware-families/PG-WPLinkHelper.md and
 * class-msp-pg-wlh-signatures.php for signature rationale).
 *
 * As with PG-SC-MacroOptimizerCue, this family's plugin-directory
 * installation is registered in data/signatures.json and handled by the
 * existing MSP_PG_Detector/MSP_PG_Remediator pipeline. This scanner is
 * additive, covering only the two artifact types that pipeline cannot
 * reach: the headerless mu-plugin recovery file, and the randomized
 * wp-content backup directory (`wp-<hex>-prev/`).
 *
 * Per this family's explicit remediation rule: a backup-directory NAME
 * match is never, by itself, sufficient to report a detection -- it must be
 * corroborated by a content-level signature (known hash or a plain-text
 * IOC string/vault-derivation pattern) found inside the directory. See
 * build_backup_directory_analysis().
 */
class MSP_PG_WLH_Scanner
{
    const ARTIFACT_MU_PLUGIN_FILE  = 'wlh_mu_plugin_file';
    const ARTIFACT_BACKUP_DIRECTORY = 'wlh_backup_directory';

    private static $reasonWeights = array(
        'known_payload_hash'    => 100,
        'ioc_string'            => 75,
        'vault_derivation'      => 50,
        'known_domain'          => 75,
        'backup_dir_name'       => 25, // corroborating only, never sufficient alone
    );

    public static function scan()
    {
        if (!MSP_PG_WLH_Signatures::registry_available()) {
            return array();
        }

        $root = MSP_PG_Config::wp_link_helper_scan_root();
        if ($root === '' || !is_dir($root)) {
            return array();
        }

        $analyses = array();
        foreach (self::scan_mu_plugins($root) as $a) {
            $analyses[] = $a;
        }
        foreach (self::scan_backup_directories($root) as $a) {
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
            if ((int) filesize($file) > MSP_PG_Config::max_scan_file_bytes()) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            // Headerless-ness alone is never a signature (see
            // MSP_PG_WLH_Signatures::has_no_plugin_header() docblock) -- it
            // is only used here to decide this is worth content-scanning;
            // the detection itself always requires a content-level hit below.
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
    // wp-content/wp-<hex>-prev/ backup directories
    // -------------------------------------------------------------------------

    private static function scan_backup_directories($root)
    {
        $wpContent = MSP_PG_Utils::join_paths($root, 'wp-content');
        if (!is_dir($wpContent)) {
            return array();
        }

        $analyses = array();
        foreach (@scandir($wpContent) ?: array() as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = MSP_PG_Utils::join_paths($wpContent, $entry);
            if (!is_dir($path) || !MSP_PG_WLH_Signatures::is_backup_directory_name($path)) {
                continue;
            }

            $analysis = self::build_backup_directory_analysis($path, $root);
            if ($analysis !== null) {
                $analyses[] = $analysis;
            }
        }

        return $analyses;
    }

    /**
     * Returns null (no detection reported) unless at least one content-level
     * signature fires inside the directory -- the name match alone is
     * recorded only as corroborating evidence on top of that, never as the
     * sole basis for a detection or for remediation eligibility.
     */
    private static function build_backup_directory_analysis($dirPath, $scanRootBase)
    {
        $relative = MSP_PG_Utils::relative_path($dirPath, $scanRootBase);
        $analysis = self::base_analysis(
            self::ARTIFACT_BACKUP_DIRECTORY,
            'webroot:' . str_replace('\\', '/', $relative),
            $dirPath
        );

        foreach (MSP_PG_Utils::recursive_files($dirPath) as $file) {
            $relFile = str_replace('\\', '/', MSP_PG_Utils::relative_path($file, $dirPath));
            $analysis['files_scanned'][] = $relFile;
            $analysis['payload_hashes'][] = MSP_PG_Utils::hash_file_safe($file);

            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            if ($extension !== 'php' || (int) filesize($file) > MSP_PG_Config::max_scan_file_bytes()) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }
            self::apply_content_signatures($analysis, $content, $relFile);
        }

        if (empty($analysis['exact_match_types'])) {
            return null; // directory name matched, but no corroborating content signature -- not reported
        }

        self::add_reason($analysis, 'backup_dir_name', 'directory name matches this family\'s randomized backup-directory convention (' . str_replace('\\', '/', $relative) . ') -- corroborating only');
        $analysis['structural_indicators'][] = 'wlh_backup_directory:' . str_replace('\\', '/', $relative);

        self::finalize($analysis);

        return $analysis;
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    private static function apply_content_signatures(&$analysis, $content, $relFile)
    {
        $hash = strtoupper(hash('sha256', $content));
        if (in_array($hash, MSP_PG_WLH_Signatures::known_payload_hashes(), true)) {
            self::add_reason($analysis, 'known_payload_hash', 'exact match to a known PG-WPLinkHelper payload hash (' . $relFile . ')');
        }
        $iocHits = MSP_PG_WLH_Signatures::matched_ioc_strings($content);
        if (!empty($iocHits)) {
            self::add_reason($analysis, 'ioc_string', 'known PG-WPLinkHelper identifier(s) found: ' . implode(', ', $iocHits) . ' (' . $relFile . ')');
        }
        if (MSP_PG_WLH_Signatures::has_vault_derivation_pattern($content)) {
            self::add_reason($analysis, 'vault_derivation', 'WLH_Vault-style concealed option-name derivation pattern (' . $relFile . ')');
        }
        foreach (MSP_PG_WLH_Signatures::known_domains() as $domain) {
            if (strpos($content, $domain) !== false) {
                self::add_reason($analysis, 'known_domain', 'known PG-WPLinkHelper C2 domain: ' . $domain . ' (' . $relFile . ')');
                $analysis['domains'][] = $domain;
            }
        }
    }

    private static function base_analysis($artifactType, $slug, $path)
    {
        return array(
            'family'                => MSP_PG_WLH_Signatures::family_id(),
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
        $analysis['domains']               = MSP_PG_Utils::normalize_list($analysis['domains']);
        $analysis['payload_hashes']        = MSP_PG_Utils::normalize_list($analysis['payload_hashes']);

        $analysis['tier']             = 'tier1';
        $analysis['confidence']       = 'Exact Match';
        $analysis['detection_source'] = 'Built-In Signature Registry (PG-WPLinkHelper)';
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
            'domains'               => $analysis['domains'],
            'reasons'               => array_map(function ($r) { return $r['key']; }, $analysis['reasons']),
        );

        return strtoupper(hash('sha256', wp_json_encode($fingerprint)));
    }
}
