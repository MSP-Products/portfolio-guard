<?php

if (!defined('ABSPATH')) {
    exit;
}

class MSP_PG_Config
{
    public static function family_name()
    {
        return 'wordpress-shared-plugin-framework';
    }

    public static function report_recipient()
    {
        $stored = (string) get_option('msp_pg_report_recipient', '');
        return $stored !== '' ? $stored : 'joshua@mysocialpractice.com';
    }

    public static function cron_hook()
    {
        return 'msp_pg_run_scan';
    }

    public static function state_option_name()
    {
        return 'msp_pg_state';
    }

    public static function scan_lock_key()
    {
        return 'msp_pg_scan_lock';
    }

    public static function catchup_lock_key()
    {
        return 'msp_pg_catchup_lock';
    }

    public static function delete_tier1_enabled()
    {
        return (bool) apply_filters('msp_pg_delete_tier1_enabled', true);
    }

    public static function default_dry_run()
    {
        if (defined('PORTFOLIO_GUARD_DRY_RUN')) {
            return (bool) PORTFOLIO_GUARD_DRY_RUN;
        }

        return (bool) apply_filters('msp_pg_default_dry_run', false);
    }

    public static function signature_version()
    {
        return apply_filters('msp_pg_signature_version', '2026-06-05.1');
    }

    public static function heuristic_version()
    {
        return apply_filters('msp_pg_heuristic_version', '2026-06-30.1');
    }

    public static function cloud_url()
    {
        return (string) apply_filters('msp_pg_cloud_url', '');
    }

    public static function cloud_api_key()
    {
        return (string) apply_filters('msp_pg_cloud_api_key', '');
    }

    public static function max_scan_file_bytes()
    {
        return (int) apply_filters('msp_pg_max_scan_file_bytes', 2 * 1024 * 1024);
    }

    public static function scan_extensions()
    {
        return apply_filters('msp_pg_scan_extensions', array('php', 'js', 'json', 'txt'));
    }

    public static function artifact_base_dir()
    {
        $override = apply_filters('msp_pg_artifact_base_dir', '');
        if (!empty($override)) {
            return rtrim($override, '/\\');
        }

        $uploads = wp_upload_dir();

        return rtrim($uploads['basedir'], '/\\') . DIRECTORY_SEPARATOR . '.msp-remediation';
    }

    public static function evidence_retention_mode()
    {
        $mode = (string) apply_filters('msp_pg_evidence_retention_mode', 'metadata_only');
        $allowed = array('metadata_only', 'compressed_archive', 'full_artifact_retention');

        return in_array($mode, $allowed, true) ? $mode : 'metadata_only';
    }

    public static function temporary_quarantine_base_dir()
    {
        $override = apply_filters('msp_pg_temporary_quarantine_base_dir', '');
        if (!empty($override)) {
            return rtrim($override, '/\\');
        }

        return rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'msp-portfolio-guard-quarantine';
    }

    public static function site_slug()
    {
        $host = wp_parse_url(home_url('/'), PHP_URL_HOST);
        $slug = sanitize_title_with_dashes((string) $host);

        if ($slug === '') {
            $slug = 'site-' . substr(md5(home_url('/')), 0, 12);
        }

        return $slug;
    }

    public static function mu_loader_filename()
    {
        return 'portfolio-guard-loader.php';
    }

    public static function mu_loader_path()
    {
        return trailingslashit(WPMU_PLUGIN_DIR) . self::mu_loader_filename();
    }

    public static function pending_activation_option_name()
    {
        return 'msp_pg_pending_activation_scan';
    }

    public static function setup_notice_option_name()
    {
        return 'msp_pg_setup_notice';
    }

    public static function protected_plugin_slugs()
    {
        return apply_filters('msp_pg_protected_plugin_slugs', array(
            'elementor',
            'elementor-pro',
            'gravityforms',
            'seo-by-rank-math',
            'seo-by-rank-math-pro',
            'wp-rocket',
            'wp-smush-pro',
            'wpmudev-updates',
            'mainwp-child',
            'pojo-accessibility',
        ));
    }

    public static function score_weights()
    {
        return apply_filters('msp_pg_score_weights', array(
            'known_hash' => 100,
            'known_filename' => 100,
            'known_primary_plugin_file' => 100,
            'known_plugin_directory' => 100,
            'known_route' => 75,
            'known_domain' => 75,
            'known_auth_cookie_impersonation_pattern' => 50,
            'known_family_bootstrap_pattern' => 50,
            'known_family_payload_structure' => 50,
            'suspicious_remote_javascript' => 10,
            'custom_rest_namespace' => 10,
            'ajax_handlers' => 5,
            'remote_requests' => 5,
            'cookie_manipulation' => 5,
            'dynamic_script_registration' => 5,
        ));
    }

    public static function artifact_retention_days()
    {
        return (int) apply_filters('msp_pg_artifact_retention_days', 7);
    }

    // -------------------------------------------------------------------------
    // Update infrastructure (Spec 007)
    // -------------------------------------------------------------------------

    /**
     * Slugs of plugins that are part of the standard MSP fleet baseline.
     *
     * Tier 2 (behavioral) Review Required findings for these slugs are
     * suppressed automatically. Tier 1 (signature) detections are unaffected.
     * Extend via the msp_pg_trusted_plugin_slugs filter to add site-specific slugs.
     */
    public static function trusted_plugin_slugs()
    {
        return apply_filters('msp_pg_trusted_plugin_slugs', array(
            'disable-comments',
            'essential-addons-for-elementor-lite',
            'seo-by-rank-math',
            'wordfence',
            'wp-rocket',
            'wpmudev-updates',
        ));
    }

    public static function update_manifest_url()
    {
        return 'https://github.com/joshualee791/portfolio-guard/releases/latest/download/registry-manifest.json';
    }

    public static function update_key()
    {
        return '3a7f9c2d4e1b6a8f0c9d2e5b3a7c4f1d8e2b6a9c0d3f5b1e4a7c2d6b9f0e3a8c';
    }

    public static function applied_registry_path()
    {
        $uploads = wp_upload_dir();
        return !empty($uploads['basedir'])
            ? $uploads['basedir'] . DIRECTORY_SEPARATOR . 'portfolio-guard' . DIRECTORY_SEPARATOR . 'signatures.json'
            : '';
    }

    // -------------------------------------------------------------------------
    // Plugin update infrastructure (Spec 009)
    // -------------------------------------------------------------------------

    public static function plugin_update_url()
    {
        return 'https://github.com/joshualee791/portfolio-guard/releases/latest/download/plugin.json';
    }

    public static function plugin_update_check_interval()
    {
        return (int) apply_filters('msp_pg_plugin_update_check_interval', HOUR_IN_SECONDS);
    }

    // -------------------------------------------------------------------------
    // PG-ClonedDoorway filesystem scanner (additive second scan source; see
    // class-msp-pg-clonedoorway-scanner.php)
    // -------------------------------------------------------------------------

    /**
     * Root directory the PG-ClonedDoorway scanner walks. Defaults to the web
     * root (ABSPATH). Filterable so tests (and, if ever needed, operators)
     * can point it elsewhere without touching scanner code.
     */
    public static function cloned_doorway_scan_root()
    {
        return (string) apply_filters('msp_pg_clonedoorway_scan_root', defined('ABSPATH') ? ABSPATH : '');
    }

    /**
     * Mirrors delete_tier1_enabled() but scoped to PG-ClonedDoorway
     * attacker-created artifacts only. Never applies to modified legitimate
     * files (e.g. a tampered core index.php), which are always report-only
     * regardless of this setting -- see MSP_PG_ClonedDoorway_Remediator.
     */
    public static function cloned_doorway_delete_enabled()
    {
        return (bool) apply_filters('msp_pg_clonedoorway_delete_enabled', true);
    }

    // -------------------------------------------------------------------------
    // PG-SC-MacroOptimizerCue filesystem scanner (additive scan source; see
    // class-msp-pg-sc-scanner.php)
    // -------------------------------------------------------------------------

    public static function sc_macro_cue_scan_root()
    {
        return (string) apply_filters('msp_pg_sc_macro_cue_scan_root', defined('ABSPATH') ? ABSPATH : '');
    }

    /**
     * Governs real removal of this family's standalone attacker-created
     * artifacts only (mu-plugin file, hidden state directory). Never applies
     * to wp-content drop-ins (always report-only -- mixed-content risk) or
     * to wp-includes/ recovery-loader files, which have their own
     * independent, non-bypassable guard set regardless of this flag -- see
     * MSP_PG_SC_Remediator.
     */
    public static function sc_macro_cue_delete_enabled()
    {
        return (bool) apply_filters('msp_pg_sc_macro_cue_delete_enabled', true);
    }

    /**
     * Separate, narrower flag specifically for the wp-includes/
     * recovery-loader removal path. Independent of
     * sc_macro_cue_delete_enabled() on purpose: an operator/future policy
     * change should be able to disable removal inside WordPress core
     * directories without affecting removal of this family's other,
     * lower-risk artifacts, and vice versa. Even when true, removal still
     * requires every other guard in MSP_PG_SC_Remediator::remediate_wpincludes_file()
     * to pass (filename pattern + symlink rejection + realpath containment +
     * content signature) -- this flag can only turn removal off, never
     * substitute for any of those checks.
     */
    public static function sc_macro_cue_wpincludes_delete_enabled()
    {
        return (bool) apply_filters('msp_pg_sc_macro_cue_wpincludes_delete_enabled', true);
    }

    // -------------------------------------------------------------------------
    // PG-WPLinkHelper filesystem scanner (additive scan source; see
    // class-msp-pg-wlh-scanner.php)
    // -------------------------------------------------------------------------

    public static function wp_link_helper_scan_root()
    {
        return (string) apply_filters('msp_pg_wp_link_helper_scan_root', defined('ABSPATH') ? ABSPATH : '');
    }

    public static function wp_link_helper_delete_enabled()
    {
        return (bool) apply_filters('msp_pg_wp_link_helper_delete_enabled', true);
    }

    // -------------------------------------------------------------------------
    // PG-DoorwayContentGenerator filesystem scanner (additive scan source;
    // see class-msp-pg-doorwaygen-scanner.php)
    // -------------------------------------------------------------------------

    public static function doorway_content_gen_scan_root()
    {
        return (string) apply_filters('msp_pg_doorway_content_gen_scan_root', defined('ABSPATH') ? ABSPATH : '');
    }

    public static function doorway_content_gen_delete_enabled()
    {
        return (bool) apply_filters('msp_pg_doorway_content_gen_delete_enabled', true);
    }
}
