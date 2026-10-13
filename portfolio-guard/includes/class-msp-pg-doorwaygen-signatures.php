<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Registry + deterministic content signature for the PG-DoorwayContentGenerator
 * family (see docs/malware-families/PG-DoorwayContentGenerator.md).
 *
 * Unrelated third tool recovered alongside PG-SC-MacroOptimizerCue and
 * PG-WPLinkHelper at the same incident site -- a plain, unobfuscated loose
 * PHP file (observed as the generic filename "page.php") that bulk-creates
 * WordPress pages/posts from uploaded .txt files and rewrites marked-up
 * anchor text into injected links. Intentionally NOT keyed on its filename
 * (page.php is a generic, legitimate-looking name) -- detection is the
 * content structure only.
 */
class MSP_PG_DoorwayGen_Signatures
{
    private static $registry    = null;
    private static $registry_ok = false;

    public static function registry_available()
    {
        if (self::$registry === null) {
            self::load();
        }
        return self::$registry_ok;
    }

    public static function family_id()
    {
        return 'pg-doorway-content-gen';
    }

    public static function family_display_name()
    {
        return 'PG-DoorwayContentGenerator';
    }

    public static function known_payload_hashes()
    {
        if (self::$registry === null) {
            self::load();
        }
        return self::$registry_ok ? array_map('strtoupper', (array) self::$registry['known_payload_hashes_sha256']) : array();
    }

    public static function reset()
    {
        self::$registry    = null;
        self::$registry_ok = false;
    }

    private static function load()
    {
        $path = defined('MSP_PG_PLUGIN_FILE')
            ? plugin_dir_path(MSP_PG_PLUGIN_FILE) . 'data/signatures-doorway-content-gen.json'
            : '';

        if ($path === '' || !file_exists($path) || !is_readable($path)) {
            return;
        }

        $raw = @file_get_contents($path);
        if ($raw === false) {
            return;
        }

        $data = @json_decode($raw, true);
        if (!is_array($data) || !isset($data['schema_version']) || $data['schema_version'] !== 1) {
            return;
        }

        self::$registry    = $data;
        self::$registry_ok = true;
    }

    /**
     * DG-BULK-UPLOAD-INJECT: co-occurrence, in one file, of (a) a bulk file
     * upload handler reading $_FILES, (b) a direct $wpdb post/page insert
     * (bypassing WordPress's own post APIs), and (c) an anchor-tag injection
     * pattern. Each element individually has ordinary legitimate uses (file
     * upload handling, direct $wpdb use, emitting an <a> tag); the specific
     * combination of all three in one file -- bulk-upload-driven, raw-SQL
     * post creation with link injection -- was not found in any legitimate
     * plugin/theme in this codebase's corpus and has no ordinary product use
     * case.
     */
    public static function has_bulk_upload_injection_pattern($content)
    {
        $hasFilesUpload = preg_match('/\$_FILES\s*\[\s*[\'"][A-Za-z0-9_]+[\'"]\s*\]/', $content) === 1;
        $hasRawPostInsert = strpos($content, '->insert(') !== false
            && (strpos($content, 'wp_posts') !== false || strpos($content, '$wpdb->posts') !== false);
        $hasAnchorInjection = strpos($content, '<a href') !== false || strpos($content, "<a href") !== false;

        return $hasFilesUpload && $hasRawPostInsert && $hasAnchorInjection;
    }
}
