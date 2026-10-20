<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Best-effort outbound reporting to the MSP report app (so a practice's client report can show whether its
 * site is clean and up).
 *
 * Separate from MSP_PG_CloudPublisher and its msp_pg_cloud_url / msp_pg_cloud_api_key settings, which are
 * untouched: a site configured for something else through those keeps working exactly as before. This
 * class has its own address (msp_pg_report_app_url, defaulting to the report app) and its own stored key.
 *
 * It is an observability channel only; it never influences endpoint behavior. Nothing here may affect scan
 * or remediation results: every failure mode (missing config, refused enrollment, network error, bad
 * response) is swallowed.
 *
 * A site reports in two steps:
 *   1. Enroll, once. The site sends its home URL; if the Cloud knows that address it answers with a key
 *      for this site alone, which is stored in the msp_pg_report_app_key option. A refusal (enrollment not open
 *      yet, an unknown address, an address that already enrolled) is retried at most once a day.
 *   2. Publish, after every scan, with that key: the telemetry record plus the recent daily availability
 *      checks (sent every time, so a missed delivery loses nothing - the Cloud ignores repeats).
 * A 401 means the key was revoked or reset on the Cloud side, so the stored key is dropped and the site
 * enrolls again on its next scan.
 */
class MSP_PG_ReportPublisher
{
    const TIMEOUT_SECONDS       = 3;
    const WIRE_SCHEMA_VERSION   = 2;
    const KEY_OPTION            = 'msp_pg_report_app_key';
    const ENROLL_AFTER_OPTION   = 'msp_pg_report_app_enroll_after';
    const ENROLL_RETRY_SECONDS  = 86400;
    const AVAILABILITY_DAYS     = 35;
    const AVAILABILITY_MAX_ROWS = 100;
    const ENROLL_PATH           = 'api/portfolio_guard/enroll';
    const TELEMETRY_PATH        = 'api/portfolio_guard/telemetry';

    /**
     * Publish a telemetry snapshot to Portfolio Guard Cloud, if configured and enrolled.
     * Never throws; return value is informational only and unused by callers.
     */
    public static function publish(array $telemetry)
    {
        $baseUrl = trim(MSP_PG_Config::report_app_url());
        if ($baseUrl === '') {
            return false;
        }

        try {
            $key = self::enrolled_key($baseUrl);
            if ($key === '') {
                return false;
            }

            return self::send_telemetry($baseUrl, $key, self::build_payload($telemetry));
        } catch (\Throwable $e) {
            error_log('MSP Portfolio Guard: cloud telemetry publish threw — ' . $e->getMessage());
            return false;
        }
    }

    /**
     * The key this site reports with, enrolling first when it has none and the daily retry allows it.
     * Returns '' when there is no key to use.
     */
    private static function enrolled_key($baseUrl)
    {
        $key = MSP_PG_Config::report_app_key();
        if ($key !== '') {
            return $key;
        }

        if (time() < (int) get_option(self::ENROLL_AFTER_OPTION, 0)) {
            return '';
        }

        return self::enroll($baseUrl);
    }

    private static function enroll($baseUrl)
    {
        // Set before the request, so an error or a crash part-way cannot make every scan retry.
        update_option(self::ENROLL_AFTER_OPTION, time() + self::ENROLL_RETRY_SECONDS, false);

        $response = self::post($baseUrl, self::ENROLL_PATH, '', array(
            'site_url'       => home_url('/'),
            'plugin_version' => MSP_PG_VERSION,
        ));
        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 201) {
            return '';
        }

        $body = json_decode((string) wp_remote_retrieve_body($response), true);
        $key  = is_array($body) && isset($body['key']) ? (string) $body['key'] : '';
        if (!preg_match('/^pgk_[A-Za-z0-9_-]{20,}$/', $key)) {
            return '';
        }

        update_option(self::KEY_OPTION, $key, false);
        delete_option(self::ENROLL_AFTER_OPTION);
        return $key;
    }

    private static function send_telemetry($baseUrl, $key, array $payload)
    {
        $response = self::post($baseUrl, self::TELEMETRY_PATH, $key, $payload);

        if (is_wp_error($response)) {
            error_log('MSP Portfolio Guard: cloud telemetry publish failed — ' . $response->get_error_message());
            return false;
        }

        $statusCode = (int) wp_remote_retrieve_response_code($response);
        if ($statusCode === 401) {
            self::forget_stored_key();
            return false;
        }
        if ($statusCode < 200 || $statusCode >= 300) {
            error_log('MSP Portfolio Guard: cloud telemetry publish rejected — HTTP ' . $statusCode);
            return false;
        }

        return true;
    }

    /**
     * The Cloud no longer knows this key (reset or revoked). Only a key the site was given is dropped; one
     * set by a filter is the operator's to manage.
     */
    private static function forget_stored_key()
    {
        if (apply_filters('msp_pg_report_app_key', '') === '') {
            delete_option(self::KEY_OPTION);
        }
    }

    private static function post($baseUrl, $path, $key, array $payload)
    {
        $headers = array('Content-Type' => 'application/json');
        if ($key !== '') {
            $headers['Authorization'] = 'Bearer ' . $key;
        }

        return wp_remote_post(trailingslashit($baseUrl) . $path, array(
            'sslverify'  => true,
            'timeout'    => self::TIMEOUT_SECONDS,
            'user-agent' => 'MSP-PortfolioGuard/' . MSP_PG_VERSION,
            'headers'    => $headers,
            'body'       => wp_json_encode($payload),
        ));
    }

    /**
     * Own the Cloud wire protocol: the local telemetry record plus the recent availability checks. The
     * local record (and its schema version 1) is unchanged; only what goes over the wire is version 2.
     */
    private static function build_payload(array $telemetry)
    {
        return array_merge($telemetry, array(
            'telemetry_schema_version' => self::WIRE_SCHEMA_VERSION,
            'availability_checks'      => self::availability_checks(),
        ));
    }

    private static function availability_checks()
    {
        if (!class_exists('MSP_PG_Availability')) {
            return array();
        }

        $rows = MSP_PG_Availability::between(
            time() - self::AVAILABILITY_DAYS * 86400,
            time(),
            self::AVAILABILITY_MAX_ROWS,
            'DESC'
        );

        return array_map(function ($row) {
            return array(
                'checked_at'  => gmdate('c', (int) strtotime($row['checked_at'] . ' UTC')),
                'status'      => $row['status'],
                'http_code'   => $row['http_code'],
                'response_ms' => $row['response_ms'],
                'error_type'  => $row['error_type'],
            );
        }, $rows);
    }
}
