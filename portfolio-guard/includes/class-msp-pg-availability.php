<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Site availability observations (v1).
 *
 * Once a day (WP-Cron hook msp_pg_availability_observation) the site requests
 * its own home URL once and stores the outcome in
 * {$wpdb->prefix}msp_pg_availability, keeping 90 days of history.
 *
 * These are self-originated point-in-time observations, not uptime
 * monitoring: they only run when WP-Cron runs, so when the site is down the
 * check usually does not run at all. Missed checks stay missing; nothing is
 * backfilled and no uptime percentage is derived here.
 *
 * Independent of scanning, remediation, email and Cloud telemetry. Nothing
 * here can modify the site beyond its own table, option and cron event.
 */
class MSP_PG_Availability
{
    const HOOK            = 'msp_pg_availability_observation';
    const SCHEMA_OPTION   = 'msp_pg_availability_schema';
    const SCHEMA_VERSION  = '1';
    const LOCK_KEY        = 'msp_pg_availability_lock';
    const RETRY_KEY       = 'msp_pg_availability_install_retry';
    const RETENTION_DAYS  = 90;
    const PURGE_BATCH     = 1000;
    const MAX_RESULTS     = 1000;
    const TIMEOUT_SECONDS = 10;
    const MAX_BODY_BYTES  = 4096;

    const STATUS_REACHABLE   = 'reachable';
    const STATUS_DEGRADED    = 'degraded';
    const STATUS_UNREACHABLE = 'unreachable';

    public static function register()
    {
        add_action('init', array(__CLASS__, 'maybe_install'));
        add_action(self::HOOK, array(__CLASS__, 'observe'));
    }

    public static function table()
    {
        global $wpdb;
        return $wpdb->prefix . 'msp_pg_availability';
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public static function activate()
    {
        self::install_schema();
        self::schedule();
    }

    public static function deactivate()
    {
        // History is kept; only the schedule stops.
        wp_clear_scheduled_hook(self::HOOK);
        delete_transient(self::LOCK_KEY);
    }

    public static function uninstall()
    {
        global $wpdb;
        wp_clear_scheduled_hook(self::HOOK);
        delete_transient(self::LOCK_KEY);
        delete_transient(self::RETRY_KEY);
        delete_option(self::SCHEMA_OPTION);
        $wpdb->query('DROP TABLE IF EXISTS ' . self::table());
    }

    /**
     * Runs on every init; cheap when nothing is needed (one autoloaded option
     * read plus the cron array). Covers fresh installs, upgrades (activation
     * hooks do not run on update) and a deleted cron event. A failed table
     * creation is retried at most hourly.
     */
    public static function maybe_install()
    {
        if (get_option(self::SCHEMA_OPTION) !== self::SCHEMA_VERSION && !get_transient(self::RETRY_KEY)) {
            if (!self::install_schema()) {
                set_transient(self::RETRY_KEY, 1, HOUR_IN_SECONDS);
            }
        }

        if (!wp_next_scheduled(self::HOOK)) {
            self::schedule();
        }
    }

    /**
     * Idempotent: dbDelta() creates or alters the table and never drops data.
     */
    public static function install_schema()
    {
        global $wpdb;

        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }

        $table = self::table();
        $sql = "CREATE TABLE {$table} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  checked_at datetime NOT NULL,
  http_code smallint(5) unsigned DEFAULT NULL,
  response_ms int(10) unsigned DEFAULT NULL,
  status varchar(16) NOT NULL,
  error_type varchar(32) DEFAULT NULL,
  PRIMARY KEY  (id),
  KEY checked_at (checked_at)
) " . $wpdb->get_charset_collate() . ';';

        $suppress = $wpdb->suppress_errors(true);
        dbDelta($sql);
        $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table;
        $wpdb->suppress_errors($suppress);

        if (!$exists) {
            error_log('MSP Portfolio Guard: availability table could not be created.');
            return false;
        }

        update_option(self::SCHEMA_OPTION, self::SCHEMA_VERSION, true);
        return true;
    }

    /**
     * First run an hour after scheduling, so the first stored record is a real
     * request rather than anything made during activation.
     */
    private static function schedule()
    {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::HOOK);
    }

    // -------------------------------------------------------------------------
    // Observation
    // -------------------------------------------------------------------------

    /**
     * Cron callback. Returns the stored observation, or null when skipped
     * (another observation in progress). Never throws.
     */
    public static function observe()
    {
        if (get_transient(self::LOCK_KEY)) {
            return null;
        }
        set_transient(self::LOCK_KEY, 1, 2 * MINUTE_IN_SECONDS);

        $observation = null;
        try {
            $observation = self::measure();
            self::record($observation);
            self::purge_expired();
        } catch (\Throwable $e) {
            error_log('MSP Portfolio Guard: availability observation failed.');
        }

        delete_transient(self::LOCK_KEY);
        return $observation;
    }

    /**
     * One GET to the home URL. Redirects are not followed (a 3xx is recorded
     * as-is, so the request can never be sent elsewhere), no cookies or
     * credentials are sent, at most MAX_BODY_BYTES of the body is read and
     * none of it is kept.
     */
    public static function measure()
    {
        $checkedAt = gmdate('Y-m-d H:i:s');
        $start = self::clock();

        $response = wp_remote_get(home_url('/'), self::request_args());

        $elapsedMs = (int) max(0, round((self::clock() - $start) / 1000000));

        return array_merge(
            array('checked_at' => $checkedAt, 'response_ms' => $elapsedMs),
            self::classify($response)
        );
    }

    public static function request_args()
    {
        return array(
            'timeout'             => self::TIMEOUT_SECONDS,
            'redirection'         => 0,
            'cookies'             => array(),
            'limit_response_size' => self::MAX_BODY_BYTES,
            'user-agent'          => 'MSP-PortfolioGuard/' . MSP_PG_VERSION . ' (availability observation)',
        );
    }

    /**
     * reachable: 200-399. degraded: 400-499. unreachable: 500-599, any
     * transport failure, or a missing/invalid status.
     */
    public static function classify($response)
    {
        if (is_wp_error($response)) {
            return array(
                'http_code'  => null,
                'status'     => self::STATUS_UNREACHABLE,
                'error_type' => self::transport_error_type($response),
            );
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code < 100 || $code > 599) {
            return array('http_code' => null, 'status' => self::STATUS_UNREACHABLE, 'error_type' => 'invalid_response');
        }
        if ($code >= 200 && $code <= 399) {
            return array('http_code' => $code, 'status' => self::STATUS_REACHABLE, 'error_type' => null);
        }
        if ($code >= 400 && $code <= 499) {
            return array('http_code' => $code, 'status' => self::STATUS_DEGRADED, 'error_type' => 'http_client_error');
        }
        if ($code >= 500) {
            return array('http_code' => $code, 'status' => self::STATUS_UNREACHABLE, 'error_type' => 'http_server_error');
        }

        // 1xx as a final response.
        return array('http_code' => $code, 'status' => self::STATUS_UNREACHABLE, 'error_type' => 'invalid_response');
    }

    /**
     * Maps a WP_Error to a fixed category; the message itself is never stored.
     */
    public static function transport_error_type($error)
    {
        $message = strtolower((string) $error->get_error_message());

        if (preg_match('/curl error (\d+)/', $message, $m)) {
            $curl = (int) $m[1];
            if ($curl === 28) {
                return 'timeout';
            }
            if ($curl === 5 || $curl === 6) {
                return 'dns';
            }
            if ($curl === 7) {
                return 'connection';
            }
            if (in_array($curl, array(35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91), true)) {
                return 'tls';
            }
            return 'transport';
        }

        if (strpos($message, 'timed out') !== false || strpos($message, 'timeout') !== false) {
            return 'timeout';
        }
        if (strpos($message, 'resolve') !== false || strpos($message, 'getaddrinfo') !== false || strpos($message, 'name or service') !== false) {
            return 'dns';
        }
        if (strpos($message, 'ssl') !== false || strpos($message, 'tls') !== false || strpos($message, 'certificate') !== false) {
            return 'tls';
        }
        if (strpos($message, 'refused') !== false || strpos($message, 'connect') !== false) {
            return 'connection';
        }
        return 'transport';
    }

    /** Nanoseconds from a monotonic clock where available. */
    private static function clock()
    {
        return function_exists('hrtime') ? hrtime(true) : microtime(true) * 1e9;
    }

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    public static function record(array $observation)
    {
        global $wpdb;

        $suppress = $wpdb->suppress_errors(true);
        $ok = $wpdb->insert(
            self::table(),
            array(
                'checked_at'  => $observation['checked_at'],
                'http_code'   => $observation['http_code'],
                'response_ms' => $observation['response_ms'],
                'status'      => $observation['status'],
                'error_type'  => $observation['error_type'],
            ),
            array('%s', '%d', '%d', '%s', '%s')
        );
        $wpdb->suppress_errors($suppress);

        if ($ok === false) {
            error_log('MSP Portfolio Guard: availability observation could not be stored.');
            return false;
        }
        return true;
    }

    /**
     * Deletes rows older than RETENTION_DAYS, at most PURGE_BATCH per run,
     * never the newest row.
     */
    public static function purge_expired()
    {
        global $wpdb;
        $table = self::table();
        $cutoff = gmdate('Y-m-d H:i:s', time() - self::RETENTION_DAYS * DAY_IN_SECONDS);

        $suppress = $wpdb->suppress_errors(true);
        $newestId = (int) $wpdb->get_var("SELECT MAX(id) FROM {$table}");
        $deleted = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE checked_at < %s AND id <> %d LIMIT %d",
            $cutoff,
            $newestId,
            self::PURGE_BATCH
        ));
        $wpdb->suppress_errors($suppress);

        return $deleted === false ? 0 : (int) $deleted;
    }

    // -------------------------------------------------------------------------
    // Retrieval (internal PHP interface for future integrations)
    // -------------------------------------------------------------------------

    /** Most recent observation, or null. */
    public static function latest()
    {
        global $wpdb;
        $table = self::table();

        $suppress = $wpdb->suppress_errors(true);
        $row = $wpdb->get_row(
            "SELECT id, checked_at, http_code, response_ms, status, error_type FROM {$table} ORDER BY checked_at DESC, id DESC LIMIT 1",
            ARRAY_A
        );
        $wpdb->suppress_errors($suppress);

        return is_array($row) ? self::normalize_row($row) : null;
    }

    /**
     * Observations with $startUtc <= checked_at <= $endUtc (Unix timestamps or
     * date strings; no offset means UTC), ordered by time, at most $limit rows
     * (clamped to 1..MAX_RESULTS). Invalid input returns an empty array.
     */
    public static function between($startUtc, $endUtc, $limit = 100, $order = 'ASC')
    {
        global $wpdb;

        $start = self::utc_datetime($startUtc);
        $end = self::utc_datetime($endUtc);
        if ($start === null || $end === null || $start > $end) {
            return array();
        }
        $limit = max(1, min(self::MAX_RESULTS, (int) $limit));
        $order = strtoupper((string) $order) === 'DESC' ? 'DESC' : 'ASC';
        $table = self::table();

        $suppress = $wpdb->suppress_errors(true);
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT id, checked_at, http_code, response_ms, status, error_type FROM {$table} WHERE checked_at >= %s AND checked_at <= %s ORDER BY checked_at {$order}, id {$order} LIMIT %d",
            $start,
            $end,
            $limit
        ), ARRAY_A);
        $wpdb->suppress_errors($suppress);

        return is_array($rows) ? array_map(array(__CLASS__, 'normalize_row'), $rows) : array();
    }

    /** Unix timestamp or date string (explicit offsets honored, otherwise UTC). */
    private static function utc_datetime($value)
    {
        if (is_int($value)) {
            return gmdate('Y-m-d H:i:s', $value);
        }
        try {
            $dt = new DateTime((string) $value, new DateTimeZone('UTC'));
        } catch (\Exception $e) {
            return null;
        }
        return gmdate('Y-m-d H:i:s', $dt->getTimestamp());
    }

    private static function normalize_row(array $row)
    {
        return array(
            'id'          => (int) $row['id'],
            'checked_at'  => (string) $row['checked_at'],
            'http_code'   => $row['http_code'] === null ? null : (int) $row['http_code'],
            'response_ms' => $row['response_ms'] === null ? null : (int) $row['response_ms'],
            'status'      => (string) $row['status'],
            'error_type'  => $row['error_type'] === null ? null : (string) $row['error_type'],
        );
    }
}
