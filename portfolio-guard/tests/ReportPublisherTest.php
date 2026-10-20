<?php

// HTTP double, defined before bootstrap.php (which only stubs functions that do not exist yet). No real
// network requests are made.
function wp_remote_post($url, $args = array())
{
    $GLOBALS['pg_report_http_calls'][] = array('url' => $url, 'args' => $args, 'body' => json_decode($args['body'], true));
    $responder = $GLOBALS['pg_report_responder'];
    return is_callable($responder) ? $responder($url, $args) : $responder;
}

require_once __DIR__ . '/bootstrap.php';

if (!defined('WPMU_PLUGIN_DIR')) {
    define('WPMU_PLUGIN_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pg-report-mu-' . uniqid());
}

/**
 * Availability rows as the fake $wpdb returns them to MSP_PG_Availability::between().
 */
class PG_Report_Fake_Wpdb
{
    public $prefix = 'wp_';
    public $rows = array();

    public function suppress_errors($suppress = true) { return false; }
    public function get_charset_collate() { return ''; }
    public function prepare($query) { return $query; }
    public function query($query) { return 0; }
    public function get_var($query) { return null; }
    public function get_row($query, $output = null) { return null; }
    public function get_results($query, $output = null) { return $this->rows; }
    public function insert($table, $data, $format = null) { return false; }
}

class ReportPublisherTest
{
    const KEY = 'pgk_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcd';

    public function run()
    {
        $this->test_the_existing_cloud_settings_keep_their_original_meaning();
        $this->test_a_site_using_the_old_cloud_settings_is_unaffected_and_does_not_enroll();
        $this->test_default_address_is_the_report_app();
        $this->test_an_empty_report_app_url_filter_stops_all_reporting();
        $this->test_a_site_enrolls_then_publishes_with_its_own_key();
        $this->test_the_payload_carries_availability_checks_in_utc_and_schema_two();
        $this->test_the_local_telemetry_record_is_not_changed_by_publishing();
        $this->test_a_refused_enrollment_is_retried_only_after_a_day();
        $this->test_enrollment_is_retried_once_the_day_has_passed();
        $this->test_a_key_that_does_not_look_like_one_is_not_stored();
        $this->test_an_unreachable_report_app_changes_nothing_and_never_throws();
        $this->test_a_rejected_key_is_dropped_so_the_site_enrolls_again();
        $this->test_a_key_set_by_a_filter_is_used_without_enrolling_and_never_dropped();
        $this->test_a_stored_key_is_used_without_enrolling_again();
        $this->test_uninstall_forgets_the_key();
    }

    private function test_the_existing_cloud_settings_keep_their_original_meaning()
    {
        $this->reset();

        $this->assertSame('', MSP_PG_Config::cloud_url(), 'legacy: msp_pg_cloud_url still defaults to empty (off)');
        $this->assertSame('', MSP_PG_Config::cloud_api_key(), 'legacy: msp_pg_cloud_api_key still defaults to empty');
        update_option('msp_pg_report_app_key', self::KEY);
        $this->assertSame('', MSP_PG_Config::cloud_api_key(), 'legacy: the enrolled report-app key is never read as the legacy key');
        $this->assertSame(false, MSP_PG_CloudPublisher::publish(array('plugin_version' => '2.2.0')), 'legacy: off by default');
        $this->assertSame(0, count($GLOBALS['pg_report_http_calls']), 'legacy: no request when msp_pg_cloud_url is unset');
    }

    private function test_a_site_using_the_old_cloud_settings_is_unaffected_and_does_not_enroll()
    {
        $this->reset();
        add_filter('msp_pg_cloud_url', function () { return 'https://other-service.example.test'; });
        add_filter('msp_pg_cloud_api_key', function () { return 'legacy-key'; });
        add_filter('msp_pg_report_app_url', function () { return ''; });
        $this->respond($this->response(202, array()));

        MSP_PG_CloudPublisher::publish(array('plugin_version' => '2.1.0', 'current_security_state' => 'healthy'));

        $call = $GLOBALS['pg_report_http_calls'][0];
        $this->assertSame(1, count($GLOBALS['pg_report_http_calls']), 'legacy: exactly one request');
        $this->assertSame('https://other-service.example.test/api/telemetry', $call['url'], 'legacy: original path');
        $this->assertSame('Bearer legacy-key', $call['args']['headers']['Authorization'], 'legacy: original key');
        $this->assertSame(array('plugin_version' => '2.1.0', 'current_security_state' => 'healthy'), $call['body'], 'legacy: payload exactly as before, nothing added');

        $this->reset();
        add_filter('msp_pg_cloud_url', function () { return 'https://other-service.example.test'; });
        $this->respond($this->response(403, array()));
        MSP_PG_ReportPublisher::publish(array());
        $urls = array_map(function ($c) { return $c['url']; }, $GLOBALS['pg_report_http_calls']);
        $this->assertSame(array('https://reporting.mysocialpractice.com/api/portfolio_guard/enroll'), $urls, 'report app: uses its own address, never the legacy cloud address');
    }

    private function test_default_address_is_the_report_app()
    {
        $this->reset();

        $this->assertSame('https://reporting.mysocialpractice.com', MSP_PG_Config::report_app_url(), 'default: reports to the MSP report app');
        $this->assertSame('', MSP_PG_Config::report_app_key(), 'default: no key before enrolling');
    }

    private function test_an_empty_report_app_url_filter_stops_all_reporting()
    {
        $this->reset();
        add_filter('msp_pg_report_app_url', function () { return ''; });

        $this->assertSame(false, MSP_PG_ReportPublisher::publish(array('plugin_version' => '2.2.0')), 'off: nothing published');
        $this->assertSame(0, count($GLOBALS['pg_report_http_calls']), 'off: no request at all, not even to enroll');
        $this->assertSame(null, get_option(MSP_PG_ReportPublisher::ENROLL_AFTER_OPTION, null), 'off: no enrolment state written');
    }

    private function test_a_site_enrolls_then_publishes_with_its_own_key()
    {
        $this->reset();
        $this->respond(function ($url) {
            return strpos($url, '/enroll') !== false ? $this->response(201, array('status' => 'enrolled', 'key' => ReportPublisherTest::KEY)) : $this->response(202, array());
        });

        $ok = MSP_PG_ReportPublisher::publish(array('plugin_version' => '2.2.0', 'current_security_state' => 'healthy'));

        $calls = $GLOBALS['pg_report_http_calls'];
        $this->assertSame(true, $ok, 'enroll: published');
        $this->assertSame(2, count($calls), 'enroll: one enrolment request then one telemetry request');
        $this->assertSame('https://reporting.mysocialpractice.com/api/portfolio_guard/enroll', $calls[0]['url'], 'enroll: path');
        $this->assertSame(array('site_url' => 'https://example.test/', 'plugin_version' => MSP_PG_VERSION), $calls[0]['body'], 'enroll: sends only the address and version');
        $this->assertFalse(isset($calls[0]['args']['headers']['Authorization']), 'enroll: no credentials yet');
        $this->assertSame('https://reporting.mysocialpractice.com/api/portfolio_guard/telemetry', $calls[1]['url'], 'telemetry: path');
        $this->assertSame('Bearer ' . self::KEY, $calls[1]['args']['headers']['Authorization'], 'telemetry: authenticates with the site\'s own key');
        $this->assertSame(self::KEY, get_option(MSP_PG_ReportPublisher::KEY_OPTION), 'enroll: key stored');
        $this->assertSame(null, get_option(MSP_PG_ReportPublisher::ENROLL_AFTER_OPTION, null), 'enroll: back-off cleared on success');
        $this->assertTrue($calls[1]['args']['sslverify'] === true && $calls[1]['args']['timeout'] === 3, 'telemetry: TLS verified, short timeout');
    }

    private function test_the_payload_carries_availability_checks_in_utc_and_schema_two()
    {
        $this->reset();
        update_option(MSP_PG_ReportPublisher::KEY_OPTION, self::KEY);
        $GLOBALS['wpdb']->rows = array(
            array('id' => '2', 'checked_at' => '2026-10-19 06:30:00', 'http_code' => '200', 'response_ms' => '120', 'status' => 'reachable', 'error_type' => null),
            array('id' => '1', 'checked_at' => '2026-10-18 06:30:00', 'http_code' => null, 'response_ms' => null, 'status' => 'unreachable', 'error_type' => 'timeout'),
        );
        $this->respond($this->response(202, array()));

        MSP_PG_ReportPublisher::publish(array('telemetry_schema_version' => 1, 'plugin_version' => '2.2.0'));

        $body = $GLOBALS['pg_report_http_calls'][0]['body'];
        $this->assertSame(2, $body['telemetry_schema_version'], 'payload: wire schema version is 2');
        $this->assertSame(array(
            array('checked_at' => '2026-10-19T06:30:00+00:00', 'status' => 'reachable', 'http_code' => 200, 'response_ms' => 120, 'error_type' => null),
            array('checked_at' => '2026-10-18T06:30:00+00:00', 'status' => 'unreachable', 'http_code' => null, 'response_ms' => null, 'error_type' => 'timeout'),
        ), $body['availability_checks'], 'payload: checks carry an explicit UTC time, status and codes');
    }

    private function test_the_local_telemetry_record_is_not_changed_by_publishing()
    {
        $this->reset();
        update_option(MSP_PG_ReportPublisher::KEY_OPTION, self::KEY);
        $this->respond($this->response(202, array()));
        $record = MSP_PG_Diagnostics::record_telemetry();

        MSP_PG_ReportPublisher::publish($record);

        $this->assertSame($record, get_option('msp_pg_telemetry'), 'local record: untouched by publishing');
        $this->assertSame(1, $record['telemetry_schema_version'], 'local record: still schema version 1');
        $this->assertFalse(isset($record['availability_checks']), 'local record: no availability field');
    }

    private function test_a_refused_enrollment_is_retried_only_after_a_day()
    {
        $this->reset();
        $this->respond($this->response(403, array('status' => 'closed')));

        $this->assertSame(false, MSP_PG_ReportPublisher::publish(array()), 'refused: nothing published');
        $this->assertSame(1, count($GLOBALS['pg_report_http_calls']), 'refused: one request');
        $this->assertSame('', MSP_PG_Config::report_app_key(), 'refused: no key stored');
        $retryAt = (int) get_option(MSP_PG_ReportPublisher::ENROLL_AFTER_OPTION);
        $this->assertTrue($retryAt > time() + 86000 && $retryAt <= time() + 86400, 'refused: next attempt about a day away');

        MSP_PG_ReportPublisher::publish(array());
        MSP_PG_ReportPublisher::publish(array());
        $this->assertSame(1, count($GLOBALS['pg_report_http_calls']), 'refused: later scans make no request until the day has passed');
    }

    private function test_enrollment_is_retried_once_the_day_has_passed()
    {
        $this->reset();
        update_option(MSP_PG_ReportPublisher::ENROLL_AFTER_OPTION, time() - 1);
        $this->respond($this->response(403, array('status' => 'closed')));

        MSP_PG_ReportPublisher::publish(array());

        $this->assertSame(1, count($GLOBALS['pg_report_http_calls']), 'retry: asks again after the wait');
    }

    private function test_a_key_that_does_not_look_like_one_is_not_stored()
    {
        foreach (array('short', 'pgk_', 'not-a-key-at-all-not-a-key-at-all', 'pgk_has spaces in it which is not allowed ok') as $bad) {
            $this->reset();
            $this->respond($this->response(201, array('key' => $bad)));

            $this->assertSame(false, MSP_PG_ReportPublisher::publish(array()), 'bad key: not published');
            $this->assertSame('', MSP_PG_Config::report_app_key(), 'bad key: not stored (' . $bad . ')');
        }

        $this->reset();
        $this->respond($this->response(201, array()));
        $this->assertSame(false, MSP_PG_ReportPublisher::publish(array()), 'no key in a 201: not published');
    }

    private function test_an_unreachable_report_app_changes_nothing_and_never_throws()
    {
        $this->reset();
        $this->respond(new WP_Error('http_request_failed', 'cURL error 28: timed out'));

        $this->assertSame(false, MSP_PG_ReportPublisher::publish(array()), 'unreachable: returns false');
        $this->assertSame('', MSP_PG_Config::report_app_key(), 'unreachable: no key');

        $this->reset();
        update_option(MSP_PG_ReportPublisher::KEY_OPTION, self::KEY);
        $this->respond(function () { throw new RuntimeException('boom'); });
        $this->assertSame(false, MSP_PG_ReportPublisher::publish(array()), 'throwing transport: swallowed');
        $this->assertSame(self::KEY, get_option(MSP_PG_ReportPublisher::KEY_OPTION), 'throwing transport: key kept');

        $this->reset();
        update_option(MSP_PG_ReportPublisher::KEY_OPTION, self::KEY);
        $this->respond($this->response(500, array()));
        $this->assertSame(false, MSP_PG_ReportPublisher::publish(array()), 'server error: returns false');
        $this->assertSame(self::KEY, get_option(MSP_PG_ReportPublisher::KEY_OPTION), 'server error: key kept - only a 401 drops it');
    }

    private function test_a_rejected_key_is_dropped_so_the_site_enrolls_again()
    {
        $this->reset();
        update_option(MSP_PG_ReportPublisher::KEY_OPTION, self::KEY);
        $this->respond($this->response(401, array()));

        $this->assertSame(false, MSP_PG_ReportPublisher::publish(array()), '401: not published');
        $this->assertSame(null, get_option(MSP_PG_ReportPublisher::KEY_OPTION, null), '401: the stored key is dropped');
        $this->assertSame(null, get_option(MSP_PG_ReportPublisher::ENROLL_AFTER_OPTION, null), '401: no wait before enrolling again');

        $this->respond($this->response(201, array('key' => self::KEY)));
        MSP_PG_ReportPublisher::publish(array());
        $this->assertSame(self::KEY, get_option(MSP_PG_ReportPublisher::KEY_OPTION), '401: the next scan enrolls again');
    }

    private function test_a_key_set_by_a_filter_is_used_without_enrolling_and_never_dropped()
    {
        $this->reset();
        add_filter('msp_pg_report_app_key', function () { return 'operator-key'; });
        $this->respond($this->response(401, array()));

        MSP_PG_ReportPublisher::publish(array());

        $this->assertSame(1, count($GLOBALS['pg_report_http_calls']), 'filter key: no enrolment request');
        $this->assertSame('Bearer operator-key', $GLOBALS['pg_report_http_calls'][0]['args']['headers']['Authorization'], 'filter key: used as given');
        $this->assertSame('operator-key', MSP_PG_Config::report_app_key(), 'filter key: still the operator\'s after a 401');
    }

    private function test_a_stored_key_is_used_without_enrolling_again()
    {
        $this->reset();
        update_option(MSP_PG_ReportPublisher::KEY_OPTION, self::KEY);
        $this->respond($this->response(202, array()));

        MSP_PG_ReportPublisher::publish(array());
        MSP_PG_ReportPublisher::publish(array());

        $urls = array_map(function ($call) { return $call['url']; }, $GLOBALS['pg_report_http_calls']);
        $this->assertSame(array_fill(0, 2, 'https://reporting.mysocialpractice.com/api/portfolio_guard/telemetry'), $urls, 'stored key: only telemetry, never enrol again');
    }

    private function test_uninstall_forgets_the_key()
    {
        $this->reset();
        update_option(MSP_PG_ReportPublisher::KEY_OPTION, self::KEY);
        update_option(MSP_PG_ReportPublisher::ENROLL_AFTER_OPTION, time() + 100);

        MSP_PG_Plugin::uninstall();

        $this->assertSame(null, get_option(MSP_PG_ReportPublisher::KEY_OPTION, null), 'uninstall: key removed');
        $this->assertSame(null, get_option(MSP_PG_ReportPublisher::ENROLL_AFTER_OPTION, null), 'uninstall: back-off removed');
    }

    private function reset()
    {
        $GLOBALS['msp_pg_test_options'] = array();
        $GLOBALS['msp_pg_test_transients'] = array();
        $GLOBALS['msp_pg_test_filters'] = array();
        $GLOBALS['pg_report_http_calls'] = array();
        $GLOBALS['pg_report_responder'] = new WP_Error('http_request_failed', 'no responder configured');
        $GLOBALS['wpdb'] = new PG_Report_Fake_Wpdb();
    }

    private function respond($responder)
    {
        $GLOBALS['pg_report_responder'] = $responder;
    }

    private function response($code, array $body)
    {
        return array('response' => array('code' => $code), 'body' => json_encode($body));
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

$test = new ReportPublisherTest();
$test->run();
echo "ReportPublisherTest passed\n";
