<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Filesystem scanner for the PG-DoorwayContentGenerator family (see
 * docs/malware-families/PG-DoorwayContentGenerator.md and
 * class-msp-pg-doorwaygen-signatures.php).
 *
 * Single artifact type: a loose PHP file directly at web root matching the
 * bulk-upload/raw-SQL-insert/link-injection content signature. Scanned the
 * same way PG-ClonedDoorway scans its loose root-level loader files
 * (non-recursive glob of *.php directly at web root) -- intentionally NOT
 * keyed on the filename "page.php", which is generic and has legitimate
 * WordPress template-file uses.
 */
class MSP_PG_DoorwayGen_Scanner
{
    const ARTIFACT_BULK_UPLOAD_INJECTOR = 'doorwaygen_bulk_upload_injector';

    public static function scan()
    {
        if (!MSP_PG_DoorwayGen_Signatures::registry_available()) {
            return array();
        }

        $root = MSP_PG_Config::doorway_content_gen_scan_root();
        if ($root === '' || !is_dir($root)) {
            return array();
        }

        return self::scan_loose_root_files($root);
    }

    private static function scan_loose_root_files($root)
    {
        $analyses = array();
        foreach (glob(trailingslashit($root) . '*.php') ?: array() as $file) {
            if ((int) filesize($file) > MSP_PG_Config::max_scan_file_bytes()) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $hash = strtoupper(hash('sha256', $content));
            $hashHit = in_array($hash, MSP_PG_DoorwayGen_Signatures::known_payload_hashes(), true);
            $structuralHit = MSP_PG_DoorwayGen_Signatures::has_bulk_upload_injection_pattern($content);

            if (!$hashHit && !$structuralHit) {
                continue;
            }

            $analysis = self::base_analysis(basename($file), $file);
            if ($hashHit) {
                self::add_reason($analysis, 'known_payload_hash', 'exact match to the known PG-DoorwayContentGenerator payload hash');
            }
            if ($structuralHit) {
                self::add_reason($analysis, 'bulk_upload_injection_pattern', 'bulk file-upload handler combined with a direct $wpdb post insert and anchor-link injection in one file');
            }

            $analysis['files_scanned'][] = basename($file);
            $analysis['payload_hashes'][] = $hash;
            self::finalize($analysis);
            $analyses[] = $analysis;
        }

        return $analyses;
    }

    private static function base_analysis($slug, $path)
    {
        return array(
            'family'                => MSP_PG_DoorwayGen_Signatures::family_id(),
            'artifact_type'         => self::ARTIFACT_BULK_UPLOAD_INJECTOR,
            'plugin_slug'           => 'webroot:' . $slug,
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
        $weight = $key === 'known_payload_hash' ? 100 : 100;
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

        $analysis['exact_match_types']  = MSP_PG_Utils::normalize_list($analysis['exact_match_types']);
        $analysis['matched_indicators'] = MSP_PG_Utils::normalize_list($analysis['matched_indicators']);
        $analysis['payload_hashes']     = MSP_PG_Utils::normalize_list($analysis['payload_hashes']);

        $analysis['tier']             = 'tier1';
        $analysis['confidence']       = 'Exact Match';
        $analysis['detection_source'] = 'Built-In Signature Registry (PG-DoorwayContentGenerator)';
        $analysis['variant_hash']     = self::variant_hash($analysis);
    }

    public static function variant_hash($analysis)
    {
        $fingerprint = array(
            'family'            => $analysis['family'],
            'artifact_type'     => $analysis['artifact_type'],
            'slug'              => $analysis['plugin_slug'],
            'tier'              => $analysis['tier'],
            'score'             => $analysis['score'],
            'exact_match_types' => $analysis['exact_match_types'],
            'reasons'           => array_map(function ($r) { return $r['key']; }, $analysis['reasons']),
        );

        return strtoupper(hash('sha256', wp_json_encode($fingerprint)));
    }
}
