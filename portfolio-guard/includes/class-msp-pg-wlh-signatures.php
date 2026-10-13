<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Registry + deterministic content/structure signatures for the
 * PG-WPLinkHelper family (see docs/malware-families/PG-WPLinkHelper.md).
 *
 * Separate, additive registry from MSP_PG_Signatures/data/signatures.json for
 * the same reason as PG-SC-MacroOptimizerCue and PG-ClonedDoorway: this
 * family's persistence artifacts include a headerless mu-plugin and a
 * randomly-named wp-content backup directory, neither of which live inside a
 * single wp-content/plugins/<slug> directory.
 *
 * Unlike PG-SC-MacroOptimizerCue, this family's code is plain, unobfuscated
 * PHP, so literal class/constant/cron-hook names are reliable signatures here
 * (no string-table decoding to defeat them).
 *
 * Every detection produced from this registry is REPORT-ONLY
 * (MSP_PG_WLH_Remediator never moves, quarantines, or deletes a live
 * artifact) -- see that class's docblock.
 */
class MSP_PG_WLH_Signatures
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
        return 'pg-wp-link-helper';
    }

    public static function family_display_name()
    {
        return 'PG-WPLinkHelper';
    }

    public static function known_payload_hashes()
    {
        if (self::$registry === null) {
            self::load();
        }
        return self::$registry_ok ? array_map('strtoupper', (array) self::$registry['known_payload_hashes_sha256']) : array();
    }

    public static function known_domains()
    {
        if (self::$registry === null) {
            self::load();
        }
        return self::$registry_ok ? (array) self::$registry['known_domains'] : array();
    }

    public static function ioc_strings()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty(self::$registry['ioc_strings'])) {
            return array('WLH_REMOTE_URL', 'WLH_HANDSHAKE', 'wlh_health_event', 'wlh_15min', 'WLH_Vault', 'WLH_Client', 'WLH_Cron', 'WLH_Adopt', 'WLH_Recovery_Installer');
        }
        return (array) self::$registry['ioc_strings'];
    }

    public static function backup_dir_name_pattern()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty(self::$registry['structural']['backup_dir_name_pattern'])) {
            return '/^wp-[0-9a-f]{8,16}-prev$/';
        }
        return '/' . str_replace('/', '\/', self::$registry['structural']['backup_dir_name_pattern']) . '/';
    }

    public static function vault_option_name_tokens()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty(self::$registry['structural']['vault_option_name_tokens'])) {
            return array('ABSPATH', 'DB_NAME');
        }
        return (array) self::$registry['structural']['vault_option_name_tokens'];
    }

    public static function reset()
    {
        self::$registry    = null;
        self::$registry_ok = false;
    }

    private static function load()
    {
        $path = defined('MSP_PG_PLUGIN_FILE')
            ? plugin_dir_path(MSP_PG_PLUGIN_FILE) . 'data/signatures-wp-link-helper.json'
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

    // -------------------------------------------------------------------------
    // Deterministic content signatures
    // -------------------------------------------------------------------------

    /**
     * WLH-IOC: at least one of this family's plain-text class names,
     * constant names, or cron-hook/schedule-key literals is present. Safe as
     * a standalone exact-match signal -- none of these strings have a known
     * legitimate-plugin collision.
     */
    public static function has_ioc_string($content)
    {
        foreach (self::ioc_strings() as $needle) {
            if (strpos($content, $needle) !== false) {
                return true;
            }
        }
        return false;
    }

    public static function matched_ioc_strings($content)
    {
        $hits = array();
        foreach (self::ioc_strings() as $needle) {
            if (strpos($content, $needle) !== false) {
                $hits[] = $needle;
            }
        }
        return $hits;
    }

    /**
     * WLH-VAULT-DERIVATION: the structural shape of WLH_Vault's option-name
     * derivation -- a `'wp_' .` string-concatenation literal combined with a
     * `hash(`/`sha256` call that also references both ABSPATH and DB_NAME in
     * the same expression. This is what makes the resulting option name look
     * like an ordinary `wp_<hex>` plugin option while actually being
     * deterministically derived per-site -- the expression shape survives
     * even if a future variant renames the WLH_Vault class itself.
     *
     * Per explicit mission guidance, this is a corroborating structural
     * signature only (used alongside WLH-IOC in practice); the resulting
     * `wp_<hex>` option name is never, by itself, treated as an indicator.
     */
    public static function has_vault_derivation_pattern($content)
    {
        if (strpos($content, "'wp_'") === false && strpos($content, '"wp_"') === false) {
            return false;
        }
        if (strpos($content, 'hash(') === false && stripos($content, 'sha256') === false) {
            return false;
        }
        foreach (self::vault_option_name_tokens() as $token) {
            if (strpos($content, $token) === false) {
                return false;
            }
        }
        return true;
    }

    /**
     * WLH-BACKUP-DIR: a directory basename matching the family's randomized
     * backup-directory naming convention (default `wp-<hex>-prev`). Pure
     * filesystem structure. Per class docblock, this must be corroborated by
     * a content-level signature inside the directory before being reported
     * (see MSP_PG_WLH_Scanner) -- a directory name match alone is not
     * reported as a detection.
     */
    public static function is_backup_directory_name($dirPath)
    {
        return preg_match(self::backup_dir_name_pattern(), basename($dirPath)) === 1;
    }

    /**
     * Headerless-mu-plugin heuristic: true when the file has no WordPress
     * `Plugin Name:` docblock field. NOT a standalone signature (many
     * legitimate, host-injected mu-plugins -- e.g. Kinsta's own -- also have
     * no header); only used by the scanner to decide which mu-plugin files
     * are worth content-scanning for the signatures above, never reported as
     * a finding by itself.
     */
    public static function has_no_plugin_header($content)
    {
        return preg_match('/Plugin\s+Name\s*:/i', substr($content, 0, 2000)) !== 1;
    }
}
