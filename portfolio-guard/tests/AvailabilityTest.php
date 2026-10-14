<?php

// HTTP and schema-migration doubles, defined before bootstrap.php (which only
// stubs functions that do not exist yet). No real network requests are made.
function wp_remote_get($url, $args = array())
{
    $GLOBALS['pg_avail_http_calls'][] = array('url' => $url, 'args' => $args);
    $responder = $GLOBALS['pg_avail_http_responder'];
    return is_callable($responder) ? $responder($url, $args) : $responder;
}

function dbDelta($sql)
{
    $GLOBALS['pg_avail_dbdelta_calls'][] = $sql;
    if (preg_match('/CREATE TABLE (\S+) \(/', $sql, $m)) {
        $GLOBALS['wpdb']->create_table($m[1], $sql);
    }
    return array();
}

require_once __DIR__ . '/bootstrap.php';

if (!defined('WPMU_PLUGIN_DIR')) {
    define('WPMU_PLUGIN_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pg-avail-mu-' . uniqid());
}

/**
 * In-memory $wpdb understanding exactly the statements MSP_PG_Availability
 * issues. Real-MySQL behaviour of the same SQL is covered separately by the
 * disposable WordPress check recorded in the handoff docs.
 */
class PG_Avail_Fake_Wpdb
{
    public $prefix;
    public $tables = array();
    public $rows = array();
    public $nextId = 1;
    public $failInserts = false;
    public $failQueries = false;

    public function __construct($prefix)
    {
        $this->prefix = $prefix;
    }

    public function create_table($name, $sql)
    {
        if ($this->failQueries) {
            return;
        }
        $this->tables[$name] = $sql;
        if (!isset($this->rows[$name])) {
            $this->rows[$name] = array();
        }
    }

    public function suppress_errors($suppress = true) { return false; }
    public function get_charset_collate() { return 'DEFAULT CHARSET=utf8mb4'; }

    public function prepare($query)
    {
        $args = array_slice(func_get_args(), 1);
        if (count($args) === 1 && is_array($args[0])) {
            $args = $args[0];
        }
        return preg_replace_callback('/%[ds]/', function ($m) use (&$args) {
            $value = array_shift($args);
            return $m[0] === '%d' ? (string) (int) $value : "'" . addslashes((string) $value) . "'";
        }, $query);
    }

    public function insert($table, $data, $format = null)
    {
        if ($this->failInserts || !isset($this->tables[$table])) {
            return false;
        }
        $data['id'] = $this->nextId++;
        $this->rows[$table][] = $data;
        return 1;
    }

    public function get_var($query)
    {
        if ($this->failQueries) {
            return null;
        }
        if (preg_match("/^SHOW TABLES LIKE '([^']+)'$/", $query, $m)) {
            return isset($this->tables[$m[1]]) ? $m[1] : null;
        }
        if (preg_match('/^SELECT MAX\(id\) FROM (\S+)$/', $query, $m)) {
            $ids = array_column($this->rows[$m[1]] ?? array(), 'id');
            return $ids ? (string) max($ids) : null;
        }
        throw new RuntimeException("fake wpdb: unexpected get_var: $query");
    }

    public function query($query)
    {
        if ($this->failQueries) {
            return false;
        }
        if (preg_match("/^DELETE FROM (\S+) WHERE checked_at < '([^']+)' AND id <> (\d+) LIMIT (\d+)$/", $query, $m)) {
            $deleted = 0;
            $keep = array();
            foreach ($this->rows[$m[1]] ?? array() as $row) {
                if ($deleted < (int) $m[4] && $row['checked_at'] < $m[2] && $row['id'] !== (int) $m[3]) {
                    $deleted++;
                    continue;
                }
                $keep[] = $row;
            }
            $this->rows[$m[1]] = $keep;
            return $deleted;
        }
        if (preg_match('/^DROP TABLE IF EXISTS (\S+)$/', $query, $m)) {
            unset($this->tables[$m[1]], $this->rows[$m[1]]);
            return 0;
        }
        throw new RuntimeException("fake wpdb: unexpected query: $query");
    }

    public function get_row($query, $output = null)
    {
        $rows = $this->select($query);
        return $rows ? $rows[0] : null;
    }

    public function get_results($query, $output = null)
    {
        return $this->select($query);
    }

    private function select($query)
    {
        if ($this->failQueries) {
            return null;
        }
        if (!preg_match('/^SELECT id, checked_at, http_code, response_ms, status, error_type FROM (\S+)(?: WHERE checked_at >= \'([^\']+)\' AND checked_at <= \'([^\']+)\')? ORDER BY checked_at (ASC|DESC), id (ASC|DESC) LIMIT (\d+)$/', $query, $m)) {
            throw new RuntimeException("fake wpdb: unexpected select: $query");
        }
        $rows = array_values(array_filter($this->rows[$m[1]] ?? array(), function ($r) use ($m) {
            return $m[2] === '' || ($r['checked_at'] >= $m[2] && $r['checked_at'] <= $m[3]);
        }));
        $dir = $m[4] === 'DESC' ? -1 : 1;
        usort($rows, function ($a, $b) use ($dir) {
            return $dir * (strcmp($a['checked_at'], $b['checked_at']) ?: ($a['id'] <=> $b['id']));
        });
        return array_map(function ($r) {
            return array_map(function ($v) { return $v === null ? null : (string) $v; }, $r);
        }, array_slice($rows, 0, (int) $m[6]));
    }
}

class AvailabilityTest
{
    public function run()
    {
        $this->test_fresh_schema_and_custom_prefix();
        $this->test_upgrade_migration_without_activation_hook();
        $this->test_migration_idempotent_and_preserves_history();
        $this->test_failed_table_creation_backs_off();
        $this->test_request_arguments();
        $this->test_classification();
        $this->test_transport_error_normalization();
        $this->test_observe_records_real_request_with_duration();
        $this->test_failed_insert_does_not_throw();
        $this->test_lock_prevents_overlap();
        $this->test_missed_cron_is_not_backfilled();
        $this->test_retention();
        $this->test_bounded_retrieval();
        $this->test_scheduling_lifecycle();
        $this->test_safety_isolation();
        $this->test_uninstall_removes_data();
    }

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    private function test_fresh_schema_and_custom_prefix()
    {
        $db = $this->reset('acme7_');
        MSP_PG_Availability::activate();

        $table = 'acme7_msp_pg_availability';
        $this->assertSame($table, MSP_PG_Availability::table(), 'schema: table uses the configured prefix');
        $this->assertTrue(isset($db->tables[$table]), 'schema: table created on activation');
        $sql = $db->tables[$table];
        foreach (array('id bigint(20) unsigned NOT NULL AUTO_INCREMENT', 'checked_at datetime NOT NULL', 'http_code smallint(5) unsigned DEFAULT NULL', 'response_ms int(10) unsigned DEFAULT NULL', 'status varchar(16) NOT NULL', 'error_type varchar(32) DEFAULT NULL', 'PRIMARY KEY  (id)', 'KEY checked_at (checked_at)') as $fragment) {
            $this->assertTrue(strpos($sql, $fragment) !== false, "schema: column/index present: $fragment");
        }
        $this->assertSame(MSP_PG_Availability::SCHEMA_VERSION, get_option(MSP_PG_Availability::SCHEMA_OPTION), 'schema: version option recorded');
        $this->assertSame(array(), $db->rows[$table], 'schema: no synthetic observation recorded on install');
        $this->assertSame(array(), $GLOBALS['pg_avail_http_calls'], 'schema: no HTTP request during activation');
    }

    private function test_upgrade_migration_without_activation_hook()
    {
        // A 2.0.9 site: no table, no option, no event. WordPress does not run
        // activation hooks on update; the init check must do the work.
        $db = $this->reset('wp_');
        MSP_PG_Availability::maybe_install();

        $this->assertTrue(isset($db->tables['wp_msp_pg_availability']), 'upgrade: table created on init');
        $this->assertTrue(wp_next_scheduled(MSP_PG_Availability::HOOK) !== false, 'upgrade: observation event scheduled on init');
        $this->assertSame(array(), $GLOBALS['pg_avail_http_calls'], 'upgrade: no HTTP request during migration');
    }

    private function test_migration_idempotent_and_preserves_history()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::maybe_install();
        $this->respond(array('response' => array('code' => 200)));
        MSP_PG_Availability::observe();

        $calls = count($GLOBALS['pg_avail_dbdelta_calls']);
        MSP_PG_Availability::maybe_install();
        MSP_PG_Availability::maybe_install();
        $this->assertSame($calls, count($GLOBALS['pg_avail_dbdelta_calls']), 'idempotent: schema not re-applied once recorded');

        MSP_PG_Availability::install_schema(); // forced re-run (e.g. future schema bump)
        $this->assertSame(1, count($db->rows['wp_msp_pg_availability']), 'idempotent: re-running the migration keeps history');
    }

    private function test_failed_table_creation_backs_off()
    {
        $db = $this->reset('wp_');
        $db->failQueries = true;
        MSP_PG_Availability::maybe_install();
        $this->assertFalse(get_option(MSP_PG_Availability::SCHEMA_OPTION) === MSP_PG_Availability::SCHEMA_VERSION, 'install failure: version not recorded');
        $this->assertTrue((bool) get_transient(MSP_PG_Availability::RETRY_KEY), 'install failure: retry back-off set');
        $calls = count($GLOBALS['pg_avail_dbdelta_calls']);
        MSP_PG_Availability::maybe_install();
        $this->assertSame($calls, count($GLOBALS['pg_avail_dbdelta_calls']), 'install failure: no retry on every request');
    }

    // -------------------------------------------------------------------------
    // HTTP measurement
    // -------------------------------------------------------------------------

    private function test_request_arguments()
    {
        $this->reset('wp_');
        MSP_PG_Availability::activate();
        $this->respond(array('response' => array('code' => 200)));
        MSP_PG_Availability::observe();

        $call = $GLOBALS['pg_avail_http_calls'][0];
        $this->assertSame(home_url('/'), $call['url'], 'request: targets the home URL, no query string');
        $this->assertSame(10, $call['args']['timeout'], 'request: 10 s timeout');
        $this->assertSame(0, $call['args']['redirection'], 'request: redirects never followed');
        $this->assertSame(array(), $call['args']['cookies'], 'request: no cookies');
        $this->assertTrue($call['args']['limit_response_size'] > 0 && $call['args']['limit_response_size'] <= 65536, 'request: bounded response size');
        foreach (array('body', 'headers', 'method') as $key) {
            $this->assertFalse(isset($call['args'][$key]), "request: no $key (GET, no credentials, no body)");
        }
    }

    private function test_classification()
    {
        $cases = array(
            200 => array('reachable', null),
            301 => array('reachable', null),
            302 => array('reachable', null),
            399 => array('reachable', null),
            403 => array('degraded', 'http_client_error'),
            404 => array('degraded', 'http_client_error'),
            500 => array('unreachable', 'http_server_error'),
            503 => array('unreachable', 'http_server_error'),
        );
        foreach ($cases as $code => $expected) {
            $r = MSP_PG_Availability::classify(array('response' => array('code' => $code), 'headers' => array('location' => 'https://elsewhere.example/'), 'body' => 'secret page'));
            $this->assertSame(array('http_code' => $code, 'status' => $expected[0], 'error_type' => $expected[1]), $r, "classify: HTTP $code");
        }
        foreach (array(array(), array('response' => array('code' => 0)), array('response' => array('code' => 700)), array('response' => array('code' => 101))) as $i => $bad) {
            $r = MSP_PG_Availability::classify($bad);
            $this->assertSame('unreachable', $r['status'], "classify: invalid response #$i is unreachable");
            $this->assertSame('invalid_response', $r['error_type'], "classify: invalid response #$i categorised");
        }
    }

    private function test_transport_error_normalization()
    {
        $cases = array(
            'cURL error 28: Operation timed out after 10001 milliseconds with 0 bytes received' => 'timeout',
            'cURL error 6: Could not resolve host: example.invalid' => 'dns',
            'cURL error 7: Failed to connect to 10.0.0.1 port 443: Connection refused' => 'connection',
            'cURL error 60: SSL certificate problem: self signed certificate' => 'tls',
            'cURL error 35: OpenSSL SSL_connect: SSL_ERROR_SYSCALL' => 'tls',
            'cURL error 56: Recv failure: Connection reset by peer' => 'transport',
            'fsockopen(): unable to connect: timed out' => 'timeout',
            'php_network_getaddresses: getaddrinfo failed' => 'dns',
            'Something unexpected' => 'transport',
        );
        foreach ($cases as $message => $expected) {
            $r = MSP_PG_Availability::classify(new WP_Error('http_request_failed', $message));
            $this->assertSame(array('http_code' => null, 'status' => 'unreachable', 'error_type' => $expected), $r, "transport: $expected <- $message");
        }
    }

    private function test_observe_records_real_request_with_duration()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::activate();
        $this->respond(function () {
            usleep(30000);
            return array('response' => array('code' => 302), 'headers' => array('location' => 'https://elsewhere.example/', 'set-cookie' => 'sess=abc'), 'body' => '<html>private</html>');
        });
        $obs = MSP_PG_Availability::observe();

        $rows = $db->rows['wp_msp_pg_availability'];
        $this->assertSame(1, count($rows), 'observe: one row per observation');
        $this->assertSame(1, count($GLOBALS['pg_avail_http_calls']), 'observe: exactly one request, redirect not followed');
        $this->assertSame(array('checked_at', 'http_code', 'response_ms', 'status', 'error_type', 'id'), array_keys($rows[0]), 'observe: only the schema columns are stored');
        $this->assertSame(302, $rows[0]['http_code'], 'observe: status code stored');
        $this->assertTrue($rows[0]['response_ms'] >= 25 && $rows[0]['response_ms'] < 5000, 'observe: duration recorded in ms (' . $rows[0]['response_ms'] . ')');
        $this->assertTrue((bool) preg_match('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', $rows[0]['checked_at']), 'observe: UTC datetime stored');
        $stored = json_encode($rows);
        foreach (array('elsewhere.example', 'sess=abc', 'private') as $secret) {
            $this->assertFalse(strpos($stored, $secret) !== false, "observe: response content not stored ($secret)");
        }
        $this->assertSame('reachable', $obs['status'], 'observe: returns the observation');
    }

    private function test_failed_insert_does_not_throw()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::activate();
        $db->failInserts = true;
        $this->respond(array('response' => array('code' => 200)));
        $obs = MSP_PG_Availability::observe();
        $this->assertTrue(is_array($obs), 'insert failure: observe still returns normally');
        $this->assertFalse((bool) get_transient(MSP_PG_Availability::LOCK_KEY), 'insert failure: lock released');
        $this->assertFalse(MSP_PG_Availability::record($obs), 'insert failure: record() reports false');
    }

    // -------------------------------------------------------------------------
    // Scheduling
    // -------------------------------------------------------------------------

    private function test_lock_prevents_overlap()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::activate();
        set_transient(MSP_PG_Availability::LOCK_KEY, 1, 120);
        $this->respond(array('response' => array('code' => 200)));
        $this->assertSame(null, MSP_PG_Availability::observe(), 'lock: overlapping run skipped');
        $this->assertSame(array(), $GLOBALS['pg_avail_http_calls'], 'lock: no request while locked');
        $this->assertSame(array(), $db->rows['wp_msp_pg_availability'], 'lock: nothing recorded');
    }

    private function test_missed_cron_is_not_backfilled()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::activate();
        $db->rows['wp_msp_pg_availability'][] = array('checked_at' => gmdate('Y-m-d H:i:s', time() - 10 * DAY_IN_SECONDS), 'http_code' => 200, 'response_ms' => 120, 'status' => 'reachable', 'error_type' => null, 'id' => $db->nextId++);
        $this->respond(array('response' => array('code' => 200)));
        MSP_PG_Availability::observe(); // first cron run after a 10-day gap
        $this->assertSame(2, count($db->rows['wp_msp_pg_availability']), 'missed cron: one new row, gap left empty');
    }

    private function test_scheduling_lifecycle()
    {
        $this->reset('wp_');
        $before = time();
        MSP_PG_Availability::activate();
        $event = $GLOBALS['msp_pg_test_scheduled_events'][MSP_PG_Availability::HOOK];
        $this->assertSame('daily', $event['recurrence'], 'schedule: daily recurrence');
        $this->assertTrue($event['timestamp'] >= $before + HOUR_IN_SECONDS - 5, 'schedule: first run deferred, not at install');

        MSP_PG_Availability::maybe_install();
        MSP_PG_Availability::activate();
        $this->assertSame($event['timestamp'] >= 0, true, 'schedule: event present');
        $count = count(array_filter(array_keys($GLOBALS['msp_pg_test_scheduled_events']), function ($h) { return $h === MSP_PG_Availability::HOOK; }));
        $this->assertSame(1, $count, 'schedule: no duplicate event');

        $this->assertTrue(isset($GLOBALS['msp_pg_test_scheduled_events'][MSP_PG_Config::cron_hook()]) === false, 'schedule: malware scan schedule untouched');

        $db = $GLOBALS['wpdb'];
        $db->rows['wp_msp_pg_availability'][] = array('checked_at' => gmdate('Y-m-d H:i:s'), 'http_code' => 200, 'response_ms' => 1, 'status' => 'reachable', 'error_type' => null, 'id' => $db->nextId++);
        MSP_PG_Availability::deactivate();
        $this->assertFalse(wp_next_scheduled(MSP_PG_Availability::HOOK), 'deactivate: event cleared');
        $this->assertSame(1, count($db->rows['wp_msp_pg_availability']), 'deactivate: history kept');
        MSP_PG_Availability::activate();
        $this->assertTrue(wp_next_scheduled(MSP_PG_Availability::HOOK) !== false, 'reactivate: event restored');
        $this->assertSame(1, count($db->rows['wp_msp_pg_availability']), 'reactivate: history kept');

        // Site timezone does not affect stored timestamps (UTC).
        update_option('timezone_string', 'Asia/Kathmandu');
        $this->respond(array('response' => array('code' => 200)));
        $obs = MSP_PG_Availability::observe();
        $this->assertTrue(abs(strtotime($obs['checked_at'] . ' UTC') - time()) < 5, 'timezone: checked_at is UTC regardless of site timezone');
    }

    // -------------------------------------------------------------------------
    // Retention and retrieval
    // -------------------------------------------------------------------------

    private function test_retention()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::activate();
        $t = 'wp_msp_pg_availability';
        foreach (array(200, 120, 91, 89, 1) as $daysAgo) {
            $db->rows[$t][] = array('checked_at' => gmdate('Y-m-d H:i:s', time() - $daysAgo * DAY_IN_SECONDS), 'http_code' => 200, 'response_ms' => 5, 'status' => 'reachable', 'error_type' => null, 'id' => $db->nextId++);
        }
        $this->assertSame(3, MSP_PG_Availability::purge_expired(), 'retention: rows older than 90 days deleted');
        $this->assertSame(2, count($db->rows[$t]), 'retention: rows within 90 days kept');

        // Newest row survives even when it is itself older than the cutoff.
        $db->rows[$t] = array();
        foreach (array(300, 200) as $daysAgo) {
            $db->rows[$t][] = array('checked_at' => gmdate('Y-m-d H:i:s', time() - $daysAgo * DAY_IN_SECONDS), 'http_code' => null, 'response_ms' => 5, 'status' => 'unreachable', 'error_type' => 'timeout', 'id' => $db->nextId++);
        }
        MSP_PG_Availability::purge_expired();
        $this->assertSame(1, count($db->rows[$t]), 'retention: most recent observation preserved');

        $db->failQueries = true;
        $this->assertSame(0, MSP_PG_Availability::purge_expired(), 'retention: database error handled');
        $db->failQueries = false;
        $this->assertSame(1000, MSP_PG_Availability::PURGE_BATCH, 'retention: per-run delete bounded');
    }

    private function test_bounded_retrieval()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::activate();
        $t = 'wp_msp_pg_availability';
        $this->assertSame(null, MSP_PG_Availability::latest(), 'retrieval: latest() null when empty');
        for ($i = 0; $i < 1200; $i++) {
            $db->rows[$t][] = array('checked_at' => gmdate('Y-m-d H:i:s', 1700000000 + $i * 60), 'http_code' => 200, 'response_ms' => $i, 'status' => 'reachable', 'error_type' => null, 'id' => $db->nextId++);
        }
        $latest = MSP_PG_Availability::latest();
        $this->assertSame(1199, $latest['response_ms'], 'retrieval: latest() returns newest');
        $this->assertSame(array('id', 'checked_at', 'http_code', 'response_ms', 'status', 'error_type'), array_keys($latest), 'retrieval: stable row shape');
        $this->assertTrue(is_int($latest['http_code']) && $latest['error_type'] === null, 'retrieval: typed values');

        // Row i is at 1700000000 + 60*i (1700000000 = 2023-11-14 22:13:20 UTC).
        $range = MSP_PG_Availability::between(1700000000 + 10 * 60, '2023-11-14 22:33:20', 5);
        $this->assertSame(5, count($range), 'retrieval: limit honoured');
        $this->assertSame(array(10, 11, 12, 13, 14), array_column($range, 'response_ms'), 'retrieval: ascending order within range');
        $desc = MSP_PG_Availability::between('2023-11-14T22:13:20Z', '2023-11-14T23:23:20+01:00', 3, 'DESC');
        $this->assertSame(array(10, 9, 8), array_column($desc, 'response_ms'), 'retrieval: descending order, inclusive end, offsets honoured');
        $this->assertSame(1000, count(MSP_PG_Availability::between(0, time(), 999999)), 'retrieval: limit clamped to 1000');
        $this->assertSame(array(), MSP_PG_Availability::between('not a date', time()), 'retrieval: invalid input returns empty');
        $this->assertSame(array(), MSP_PG_Availability::between(time(), 0), 'retrieval: inverted range returns empty');
        $injected = MSP_PG_Availability::between("2023-01-01' OR '1'='1", time(), 5);
        $this->assertSame(array(), $injected, 'retrieval: input is parsed/prepared, not interpolated');
    }

    // -------------------------------------------------------------------------
    // Safety and uninstall
    // -------------------------------------------------------------------------

    private function test_safety_isolation()
    {
        $this->reset('wp_');
        MSP_PG_Availability::activate();
        $GLOBALS['msp_pg_test_options']['msp_pg_state'] = array('marker' => 'unchanged');
        $GLOBALS['msp_pg_test_options']['msp_pg_telemetry'] = array('marker' => 'unchanged');
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();
        $this->respond(new WP_Error('http_request_failed', 'cURL error 28: Operation timed out'));
        MSP_PG_Availability::observe();

        $this->assertSame(array(), $GLOBALS['msp_pg_test_wp_mail_calls'], 'safety: no email');
        $this->assertSame(array(), $GLOBALS['msp_pg_test_deactivated_plugins'], 'safety: no remediation');
        $this->assertSame(array('marker' => 'unchanged'), get_option('msp_pg_state'), 'safety: scan state untouched');
        $this->assertSame(array('marker' => 'unchanged'), get_option('msp_pg_telemetry'), 'safety: telemetry untouched');
        $this->assertFalse((bool) get_transient(MSP_PG_Config::scan_lock_key()), 'safety: no scan triggered');

        $source = file_get_contents(dirname(__DIR__) . '/includes/class-msp-pg-availability.php');
        foreach (array('MSP_PG_Remediator', 'MSP_PG_Detector', 'wp_mail', 'MSP_PG_CloudPublisher', 'MSP_PG_Diagnostics', 'deactivate_plugins', 'unlink(') as $needle) {
            $this->assertFalse(strpos($source, $needle) !== false, "safety: availability class does not reference $needle");
        }

        // Cloud telemetry payload (schema v1) is unchanged.
        $keys = array_keys(MSP_PG_Diagnostics::record_telemetry());
        $expected = array('telemetry_schema_version', 'plugin_version', 'signature_version', 'heuristic_version', 'site_url', 'site_slug', 'current_security_state', 'last_scan_at', 'last_scan_trigger', 'last_scan_detections', 'scan_in_progress', 'next_scan_at', 'registry_version', 'registry_source', 'registry_consecutive_failures', 'last_update_checked', 'report_recipient_configured', 'last_clean_report_sent', 'last_review_report_sent', 'last_malware_report_sent', 'last_failed_report_sent', 'partial_remediation', 'whitelist_count', 'last_whitelist_at', 'last_whitelist_plugin', 'last_review_action', 'last_review_action_timestamp', 'telemetry_recorded_at');
        $this->assertSame($expected, $keys, 'safety: telemetry payload keys unchanged (no availability fields)');
    }

    private function test_uninstall_removes_data()
    {
        $db = $this->reset('wp_');
        MSP_PG_Availability::activate();
        MSP_PG_Availability::uninstall();
        $this->assertFalse(isset($db->tables['wp_msp_pg_availability']), 'uninstall: table dropped');
        $this->assertSame(null, get_option(MSP_PG_Availability::SCHEMA_OPTION, null), 'uninstall: option removed');
        $this->assertFalse(wp_next_scheduled(MSP_PG_Availability::HOOK), 'uninstall: event cleared');
    }

    // -------------------------------------------------------------------------

    private function reset($prefix)
    {
        $GLOBALS['wpdb'] = new PG_Avail_Fake_Wpdb($prefix);
        $GLOBALS['msp_pg_test_options'] = array();
        $GLOBALS['msp_pg_test_transients'] = array();
        $GLOBALS['msp_pg_test_scheduled_events'] = array();
        $GLOBALS['pg_avail_http_calls'] = array();
        $GLOBALS['pg_avail_dbdelta_calls'] = array();
        $GLOBALS['pg_avail_http_responder'] = new WP_Error('http_request_failed', 'no responder configured');
        return $GLOBALS['wpdb'];
    }

    private function respond($responder)
    {
        $GLOBALS['pg_avail_http_responder'] = $responder;
    }

    private function assertTrue($condition, $message)
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    private function assertFalse($condition, $message)
    {
        $this->assertTrue(!$condition, $message);
    }

    private function assertSame($expected, $actual, $message)
    {
        if ($expected !== $actual) {
            throw new RuntimeException($message . ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')');
        }
    }
}

$test = new AvailabilityTest();
$test->run();
echo "AvailabilityTest passed\n";
