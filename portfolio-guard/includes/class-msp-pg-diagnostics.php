<?php

if (!defined('ABSPATH')) {
    exit;
}

class MSP_PG_Diagnostics
{
    /**
     * Collect all diagnostic data. Pure read operation — no side effects.
     * All state is obtained through intentional public interfaces.
     */
    public static function collect()
    {
        return array(
            'plugin'        => self::collect_plugin(),
            'scanning'      => self::collect_scanning(),
            'scheduler'     => self::collect_scheduler(),
            'registry'      => self::collect_registry(),
            'configuration' => self::collect_configuration(),
        );
    }

    // -------------------------------------------------------------------------
    // Telemetry contract (schema version 1)
    // -------------------------------------------------------------------------

    /**
     * Return the stored telemetry record, or build a fresh one if none is stored.
     */
    public static function telemetry()
    {
        $stored = get_option('msp_pg_telemetry', null);
        if ($stored === null) {
            return self::build_telemetry(array());
        }
        return (array) $stored;
    }

    /**
     * Merge $updates into a freshly built telemetry record and persist it.
     * Caller-supplied $updates take precedence; previously stored report delivery
     * timestamps are always preserved via build_telemetry().
     */
    public static function record_telemetry(array $updates = array())
    {
        $stored    = (array) get_option('msp_pg_telemetry', array());
        $telemetry = array_merge(self::build_telemetry($stored), $updates);
        update_option('msp_pg_telemetry', $telemetry, true);
        return $telemetry;
    }

    private static function build_telemetry(array $stored)
    {
        $data        = self::collect();
        $scanData    = $data['scanning'];
        $schedData   = $data['scheduler'];
        $regData     = $data['registry'];

        return array(
            'telemetry_schema_version'      => 1,
            'plugin_version'                => MSP_PG_VERSION,
            'signature_version'             => MSP_PG_Config::signature_version(),
            'heuristic_version'             => MSP_PG_Config::heuristic_version(),
            'site_url'                      => home_url('/'),
            'site_slug'                     => MSP_PG_Config::site_slug(),
            'current_security_state'        => isset($stored['current_security_state']) ? $stored['current_security_state'] : 'healthy',
            'last_scan_at'                  => $scanData['last_scan_at'] !== '' ? $scanData['last_scan_at'] : null,
            'last_scan_trigger'             => $scanData['trigger'] !== '' ? $scanData['trigger'] : null,
            'last_scan_detections'          => (int) $scanData['detections'],
            'scan_in_progress'              => (bool) $scanData['scan_in_progress'],
            'next_scan_at'                  => $schedData['scan_next'] !== false ? (int) $schedData['scan_next'] : null,
            'registry_version'              => $regData['version'],
            'registry_source'               => $regData['source'],
            'registry_consecutive_failures' => (int) $regData['consecutive_failures'],
            'last_update_checked'           => $regData['last_checked'],
            'report_recipient_configured'   => get_option('msp_pg_report_recipient', '') !== '',
            'last_clean_report_sent'        => isset($stored['last_clean_report_sent'])  ? $stored['last_clean_report_sent']  : null,
            'last_review_report_sent'       => isset($stored['last_review_report_sent']) ? $stored['last_review_report_sent'] : null,
            'last_malware_report_sent'      => isset($stored['last_malware_report_sent'])? $stored['last_malware_report_sent']: null,
            'last_failed_report_sent'       => isset($stored['last_failed_report_sent']) ? $stored['last_failed_report_sent'] : null,
            // Infection-level resolution status (additive — no schema version bump required).
            // Distinct from current_security_state: a scan can be 'confirmed_malware'
            // AND partial_remediation=true in the same report when one or more
            // confirmed artifacts could not be automatically removed (see
            // MSP_PG_Remediator::run_scan()'s outstanding_components computation).
            'partial_remediation'           => isset($stored['partial_remediation']) ? (bool) $stored['partial_remediation'] : false,
            // Whitelist and review-workflow fields (additive — no schema version bump required)
            'whitelist_count'               => MSP_PG_Whitelist::count(),
            'last_whitelist_at'             => isset($stored['last_whitelist_at'])             ? $stored['last_whitelist_at']             : null,
            'last_whitelist_plugin'         => isset($stored['last_whitelist_plugin'])         ? $stored['last_whitelist_plugin']         : null,
            'last_review_action'            => isset($stored['last_review_action'])            ? $stored['last_review_action']            : null,
            'last_review_action_timestamp'  => isset($stored['last_review_action_timestamp'])  ? $stored['last_review_action_timestamp']  : null,
            'telemetry_recorded_at'         => gmdate('c'),
        );
    }

    // -------------------------------------------------------------------------
    // Section collectors
    // -------------------------------------------------------------------------

    private static function collect_plugin()
    {
        return array(
            'version' => MSP_PG_VERSION,
        );
    }

    private static function collect_scanning()
    {
        $state      = get_option(MSP_PG_Config::state_option_name(), array());
        $lastScanAt = isset($state['last_scan_at'])                  ? (string) $state['last_scan_at']                   : '';
        $trigger    = isset($state['last_scan_result']['trigger'])    ? (string) $state['last_scan_result']['trigger']    : '';
        $detections = isset($state['last_scan_result']['detections']) ? (int)    $state['last_scan_result']['detections'] : 0;

        return array(
            'last_scan_at'     => $lastScanAt,
            'trigger'          => $trigger,
            'detections'       => $detections,
            'scan_in_progress' => (bool) get_transient(MSP_PG_Config::scan_lock_key()),
        );
    }

    private static function collect_scheduler()
    {
        $nextScan   = wp_next_scheduled(MSP_PG_Config::cron_hook());
        $nextUpdate = wp_next_scheduled(MSP_PG_UpdateScheduler::HOOK);

        return array(
            'scan_next'         => $nextScan   !== false ? (int) $nextScan   : false,
            'update_next'       => $nextUpdate !== false ? (int) $nextUpdate : false,
            'mu_loader_present' => file_exists(MSP_PG_Config::mu_loader_path()),
        );
    }

    private static function collect_registry()
    {
        $available   = MSP_PG_Signatures::registry_available();
        $metadata    = $available ? MSP_PG_Signatures::registry_metadata() : null;
        $lastApplied = MSP_PG_Updater::last_applied();
        $failures    = MSP_PG_Updater::consecutive_failures();
        $lastChecked = MSP_PG_Updater::last_checked();

        return array(
            'available'            => $available,
            'version'              => $metadata !== null ? $metadata['version'] : null,
            'source'               => $metadata !== null ? $metadata['source']  : null,
            'last_applied_version' => !empty($lastApplied['version'])   ? (int)    $lastApplied['version']   : null,
            'last_applied_at'      => !empty($lastApplied['timestamp']) ? (string) $lastApplied['timestamp'] : null,
            'consecutive_failures' => $failures,
            'failure_threshold'    => MSP_PG_Updater::MAX_FAILURES_BEFORE_NOTIFY,
            'last_checked'         => $lastChecked,
        );
    }

    private static function collect_configuration()
    {
        return array(
            'dry_run'          => MSP_PG_Config::default_dry_run(),
            'tier1_deletion'   => MSP_PG_Config::delete_tier1_enabled(),
            'evidence_mode'    => MSP_PG_Config::evidence_retention_mode(),
            'report_recipient' => MSP_PG_Config::report_recipient(),
        );
    }
}
