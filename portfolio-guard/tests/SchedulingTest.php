<?php

// Use the real plugin version (bootstrap.php otherwise defines a placeholder),
// so the upgrade-lifecycle test checks the version actually recorded.
if (!defined('MSP_PG_VERSION') && preg_match("/define\('MSP_PG_VERSION', '([^']+)'\)/", (string) file_get_contents(dirname(__DIR__) . '/portfolio-guard.php'), $m)) {
    define('MSP_PG_VERSION', $m[1]);
}

require_once __DIR__ . '/bootstrap.php';

class SchedulingTest
{
    private $workspace;
    private $hook;
    private $plugin;

    public function run()
    {
        $this->workspace = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'msp-pg-scheduling-' . uniqid();
        wp_mkdir_p($this->workspace);

        $pluginRoot = $this->workspace . DIRECTORY_SEPARATOR . 'plugins';
        $muRoot     = $this->workspace . DIRECTORY_SEPARATOR . 'mu-plugins';
        wp_mkdir_p($pluginRoot);
        wp_mkdir_p($muRoot);

        if (!defined('WP_PLUGIN_DIR')) {
            define('WP_PLUGIN_DIR', $pluginRoot);
        }
        if (!defined('WPMU_PLUGIN_DIR')) {
            define('WPMU_PLUGIN_DIR', $muRoot);
        }

        $GLOBALS['msp_pg_test_uploads_base'] = $this->workspace . DIRECTORY_SEPARATOR . 'uploads';
        wp_mkdir_p($GLOBALS['msp_pg_test_uploads_base']);

        $this->hook   = MSP_PG_Config::cron_hook();
        $this->plugin = MSP_PG_Plugin::instance();

        $this->test_before_6am_utc();
        $this->test_after_6am_utc();
        $this->test_named_timezone_chicago_winter();
        $this->test_named_timezone_tokyo();
        $this->test_gmt_offset_half_hour();
        $this->test_gmt_offset_negative_half_hour();
        $this->test_gmt_offset_45_minutes();
        $this->test_gmt_offset_boundary_extremes();
        $this->test_named_timezone_dst_aware_chicago_summer();
        $this->test_dst_transition_day_chicago();
        $this->test_schedule_scan_registers_daily_future_timestamp();
        $this->test_upgrade_migration_replaces_hourly_with_daily();
        $this->test_upgrade_reschedules_through_real_hook_order();
        $this->test_catchup_fires_when_overdue();
        $this->test_catchup_suppressed_when_recent();

        $this->cleanup($this->workspace);
    }

    // -------------------------------------------------------------------------
    // Next-6am algorithm tests (tested via the schedule_scan path)
    // -------------------------------------------------------------------------

    private function test_before_6am_utc()
    {
        // 2026-01-15 05:59:00 UTC → target is today at 06:00:00 UTC
        $mockTime = gmmktime(5, 59, 0, 1, 15, 2026);
        $expected = gmmktime(6, 0, 0, 1, 15, 2026);

        $event = $this->call_schedule_via_setup('UTC', 0, $mockTime);

        $this->assertNotNull($event, 'before_6am_utc: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'before_6am_utc: should schedule today at 06:00 UTC');
        $this->assertSame('daily', $event['recurrence'], 'before_6am_utc: recurrence must be daily');
    }

    private function test_after_6am_utc()
    {
        // 2026-01-15 06:01:00 UTC → target is tomorrow at 06:00:00 UTC
        $mockTime = gmmktime(6, 1, 0, 1, 15, 2026);
        $expected = gmmktime(6, 0, 0, 1, 16, 2026);

        $event = $this->call_schedule_via_setup('UTC', 0, $mockTime);

        $this->assertNotNull($event, 'after_6am_utc: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'after_6am_utc: should schedule tomorrow at 06:00 UTC');
    }

    private function test_named_timezone_chicago_winter()
    {
        // America/Chicago, January (CST = UTC-6)
        // 05:59 CST = 11:59 UTC → target 06:00 CST = 12:00 UTC (same day)
        $mockTime = gmmktime(11, 59, 0, 1, 15, 2026);
        $expected = gmmktime(12, 0, 0, 1, 15, 2026);

        $event = $this->call_schedule_via_setup('America/Chicago', -6, $mockTime);

        $this->assertNotNull($event, 'chicago_winter: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'chicago_winter: should schedule 06:00 CST (12:00 UTC)');
    }

    private function test_named_timezone_tokyo()
    {
        // Asia/Tokyo (JST = UTC+9, no DST)
        // 05:59 JST on Jan 16 = 20:59 UTC on Jan 15 → target 06:00 JST = 21:00 UTC on Jan 15
        $mockTime = gmmktime(20, 59, 0, 1, 15, 2026);
        $expected = gmmktime(21, 0, 0, 1, 15, 2026);

        $event = $this->call_schedule_via_setup('Asia/Tokyo', 9, $mockTime);

        $this->assertNotNull($event, 'tokyo: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'tokyo: should schedule 06:00 JST (21:00 UTC)');
    }

    private function test_gmt_offset_half_hour()
    {
        // India: gmt_offset = 5.5, timezone_string = '' (offset-only config)
        // 05:59 IST on Jan 15 = 00:29 UTC on Jan 15 → target 06:00 IST = 00:30 UTC
        $mockTime = gmmktime(0, 29, 0, 1, 15, 2026);
        $expected = gmmktime(0, 30, 0, 1, 15, 2026);

        $event = $this->call_schedule_via_setup('', 5.5, $mockTime);

        $this->assertNotNull($event, 'india_half_hour: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'india_half_hour: should schedule 06:00 IST (00:30 UTC), correctly handling UTC+05:30');
    }

    private function test_gmt_offset_negative_half_hour()
    {
        // Newfoundland: gmt_offset = -3.5, timezone_string = '' (offset-only config)
        // 05:59 NST on Jan 15 = 09:29 UTC → target 06:00 NST = 09:30 UTC
        $mockTime = gmmktime(9, 29, 0, 1, 15, 2026);
        $expected = gmmktime(9, 30, 0, 1, 15, 2026);

        $event = $this->call_schedule_via_setup('', -3.5, $mockTime);

        $this->assertNotNull($event, 'newfoundland_negative_half_hour: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'newfoundland_negative_half_hour: should schedule 06:00 NST (09:30 UTC), correctly handling UTC-03:30');
    }

    private function test_gmt_offset_45_minutes()
    {
        // Nepal: gmt_offset = 5.75, timezone_string = '' (offset-only config, 45-minute remainder)
        // 05:59 NPT on Jan 15 = 00:14 UTC → target 06:00 NPT = 00:15 UTC
        $mockTime = gmmktime(0, 14, 0, 1, 15, 2026);
        $expected = gmmktime(0, 15, 0, 1, 15, 2026);

        $event = $this->call_schedule_via_setup('', 5.75, $mockTime);

        $this->assertNotNull($event, 'nepal_45_minutes: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'nepal_45_minutes: should schedule 06:00 NPT (00:15 UTC), correctly handling UTC+05:45');
    }

    private function test_gmt_offset_boundary_extremes()
    {
        // UTC+14:00 (Kiribati/Line Islands) -- the maximum real-world offset.
        // 05:59 local on Jan 15 = 15:59 UTC on Jan 14 → target 06:00 local = 16:00 UTC Jan 14
        $mockTimePlus14 = gmmktime(15, 59, 0, 1, 14, 2026);
        $expectedPlus14 = gmmktime(16, 0, 0, 1, 14, 2026);

        $eventPlus14 = $this->call_schedule_via_setup('', 14.0, $mockTimePlus14);

        $this->assertNotNull($eventPlus14, 'boundary_plus14: event should be registered');
        $this->assertSame($expectedPlus14, $eventPlus14['timestamp'], 'boundary_plus14: should schedule 06:00 local (UTC+14:00) correctly at the maximum real-world offset');

        // UTC-12:00 (Baker/Howland Islands) -- the minimum real-world offset.
        // 05:59 local on Jan 15 = 17:59 UTC on Jan 15 → target 06:00 local = 18:00 UTC Jan 15
        $mockTimeMinus12 = gmmktime(17, 59, 0, 1, 15, 2026);
        $expectedMinus12 = gmmktime(18, 0, 0, 1, 15, 2026);

        $eventMinus12 = $this->call_schedule_via_setup('', -12.0, $mockTimeMinus12);

        $this->assertNotNull($eventMinus12, 'boundary_minus12: event should be registered');
        $this->assertSame($expectedMinus12, $eventMinus12['timestamp'], 'boundary_minus12: should schedule 06:00 local (UTC-12:00) correctly at the minimum real-world offset');
    }

    private function test_dst_transition_day_chicago()
    {
        // America/Chicago, 2026-03-08 -- the US spring-forward date (clocks
        // skip 02:00-03:00 local). By 05:59 local the transition has already
        // happened, so the site is already on CDT (UTC-5), not the CST
        // (UTC-6) that was in effect earlier that same calendar day.
        // 05:59 CDT = 10:59 UTC → target 06:00 CDT = 11:00 UTC (NOT 12:00 UTC,
        // which is what a stale/pre-transition UTC-6 offset would wrongly give).
        $mockTime        = gmmktime(10, 59, 0, 3, 8, 2026);
        $expected        = gmmktime(11, 0, 0, 3, 8, 2026);
        $wrongIfStillCst = gmmktime(12, 0, 0, 3, 8, 2026);

        $event = $this->call_schedule_via_setup('America/Chicago', -6, $mockTime);

        $this->assertNotNull($event, 'dst_transition_day: event should be registered');
        $this->assertSame($expected, $event['timestamp'], 'dst_transition_day: should schedule 06:00 CDT (11:00 UTC) on the spring-forward date itself');
        $this->assertNotSame($wrongIfStillCst, $event['timestamp'], 'dst_transition_day: must not use the pre-transition CST offset on the transition day');
    }

    private function test_named_timezone_dst_aware_chicago_summer()
    {
        // America/Chicago in June (CDT = UTC-5, not UTC-6)
        // 05:59 CDT on Jun 15 = 10:59 UTC → target 06:00 CDT = 11:00 UTC
        // A fixed UTC-6 offset would wrongly give 12:00 UTC during summer
        $mockTime          = gmmktime(10, 59, 0, 6, 15, 2026);
        $expectedCdt       = gmmktime(11, 0, 0, 6, 15, 2026);
        $wrongIfFixedUtc6  = gmmktime(12, 0, 0, 6, 15, 2026);

        $event = $this->call_schedule_via_setup('America/Chicago', -6, $mockTime);

        $this->assertNotNull($event, 'chicago_summer_dst: event should be registered');
        $this->assertSame($expectedCdt, $event['timestamp'],
            'chicago_summer_dst: should schedule 06:00 CDT (11:00 UTC), respecting DST transition'
        );
        $this->assertNotSame($wrongIfFixedUtc6, $event['timestamp'],
            'chicago_summer_dst: must not use fixed UTC-6 offset during CDT — PHP DateTimeZone must handle DST'
        );
    }

    // -------------------------------------------------------------------------
    // Scheduler state contract
    // -------------------------------------------------------------------------

    private function test_schedule_scan_registers_daily_future_timestamp()
    {
        $mockTime = gmmktime(5, 59, 0, 3, 1, 2026);

        $event = $this->call_schedule_via_setup('UTC', 0, $mockTime);

        $this->assertNotNull($event, 'state_contract: event should be registered');
        $this->assertTrue($event['timestamp'] > $mockTime, 'state_contract: registered timestamp must be in the future');
        $this->assertSame('daily', $event['recurrence'], 'state_contract: recurrence must be daily');
    }

    // -------------------------------------------------------------------------
    // Upgrade migration
    // -------------------------------------------------------------------------

    private function test_upgrade_migration_replaces_hourly_with_daily()
    {
        // Simulate a v1.5.5 install (stale hourly event) upgrading to current version
        $oldTimestamp = gmmktime(6, 0, 0, 1, 14, 2026);
        $mockTime     = gmmktime(5, 59, 0, 1, 15, 2026);

        $GLOBALS['msp_pg_test_current_time']      = $mockTime;
        $GLOBALS['msp_pg_test_scheduled_events']  = array(
            $this->hook => array('timestamp' => $oldTimestamp, 'recurrence' => 'hourly'),
        );
        $GLOBALS['msp_pg_test_options'] = array(
            'msp_pg_version'   => '1.5.5',
            'timezone_string'  => 'UTC',
            'gmt_offset'       => 0,
        );

        $muLoaderPath = MSP_PG_Config::mu_loader_path();
        file_put_contents($muLoaderPath, '<?php // test mu-loader');

        $this->plugin->maybe_complete_setup();

        @unlink($muLoaderPath);

        $event = isset($GLOBALS['msp_pg_test_scheduled_events'][$this->hook])
            ? $GLOBALS['msp_pg_test_scheduled_events'][$this->hook]
            : null;

        $this->assertNotNull($event, 'upgrade_migration: new event should be registered after version bump');
        $this->assertSame('daily', $event['recurrence'], 'upgrade_migration: new event must use daily recurrence');
        $this->assertNotSame($oldTimestamp, $event['timestamp'], 'upgrade_migration: old hourly timestamp must be replaced');

        $GLOBALS['msp_pg_test_current_time'] = null;
    }

    /**
     * Upgrade via WordPress's real hook order: plugins_loaded
     * (maybe_sync_mu_loader, priority 1) runs before init
     * (maybe_complete_setup, priority 1). Calling maybe_complete_setup()
     * directly, as the test above does, hides an ordering defect in which
     * plugins_loaded recorded the new version first, so init never saw the
     * upgrade and the stale scan schedule was kept.
     */
    private function test_upgrade_reschedules_through_real_hook_order()
    {
        // A 2.0.9 site with an offset-only UTC+05:30 timezone. 2.0.9 ignored
        // the offset, so its daily scan sits at 06:00 UTC instead of 06:00 IST.
        $mockTime   = gmmktime(0, 0, 0, 10, 14, 2026);   // 05:30 IST
        $staleEvent = gmmktime(6, 0, 0, 10, 14, 2026);   // 06:00 UTC
        $expected   = gmmktime(0, 30, 0, 10, 14, 2026);  // 06:00 IST today

        $GLOBALS['msp_pg_test_current_time']     = $mockTime;
        $GLOBALS['msp_pg_test_scheduled_events'] = array(
            $this->hook => array('timestamp' => $staleEvent, 'recurrence' => 'daily'),
        );
        $GLOBALS['msp_pg_test_options'] = array(
            'msp_pg_version'  => '2.0.9',
            'timezone_string' => '',
            'gmt_offset'      => 5.5,
        );
        $muLoaderPath = MSP_PG_Config::mu_loader_path();
        file_put_contents($muLoaderPath, "<?php\n/**\n * Version: 2.0.9\n */\n");

        // WordPress request order. add_action() registers through the real
        // filter list; do_action() is a no-op in this harness.
        apply_filters('plugins_loaded', null);
        apply_filters('init', null);

        $event = isset($GLOBALS['msp_pg_test_scheduled_events'][$this->hook]) ? $GLOBALS['msp_pg_test_scheduled_events'][$this->hook] : null;
        $this->assertNotNull($event, 'upgrade_hook_order: scan event must exist after upgrade');
        $this->assertSame($expected, $event['timestamp'], 'upgrade_hook_order: scan must move from 06:00 UTC to 06:00 UTC+05:30 (' . gmdate('c', $expected) . ')');
        $this->assertSame('daily', $event['recurrence'], 'upgrade_hook_order: daily recurrence');
        $this->assertSame(MSP_PG_VERSION, get_option('msp_pg_version'), 'upgrade_hook_order: msp_pg_version recorded as the new version');
        $loader = (string) @file_get_contents($muLoaderPath);
        $this->assertSame(true, strpos($loader, 'Version: ' . MSP_PG_VERSION) !== false, 'upgrade_hook_order: MU-loader rewritten for the new version');

        // Later requests in the same version must not reschedule again.
        $GLOBALS['msp_pg_test_scheduled_events'][$this->hook]['timestamp'] = $expected + 12345;
        apply_filters('plugins_loaded', null);
        apply_filters('init', null);
        apply_filters('plugins_loaded', null);
        apply_filters('init', null);
        $this->assertSame($expected + 12345, $GLOBALS['msp_pg_test_scheduled_events'][$this->hook]['timestamp'], 'upgrade_hook_order: repeated initialization must not reschedule');

        @unlink($muLoaderPath);
        $GLOBALS['msp_pg_test_current_time'] = null;
    }

    // -------------------------------------------------------------------------
    // Catch-up scan threshold
    // -------------------------------------------------------------------------

    private function test_catchup_fires_when_overdue()
    {
        // last scan was 23h1m ago → catch-up should fire
        $overdueAt = time() - (23 * HOUR_IN_SECONDS + 60);

        $GLOBALS['msp_pg_test_options'] = array(
            MSP_PG_Config::state_option_name() => array(
                'last_scan_at' => gmdate('c', $overdueAt),
            ),
            'active_plugins'  => array(),
            'timezone_string' => 'UTC',
            'gmt_offset'      => 0,
        );
        $GLOBALS['msp_pg_test_transients']         = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();
        $GLOBALS['msp_pg_test_scheduled_events']   = array(
            $this->hook => array('timestamp' => time() + DAY_IN_SECONDS, 'recurrence' => 'daily'),
        );

        $this->plugin->maybe_run_catchup_scan();

        $state = get_option(MSP_PG_Config::state_option_name(), array());
        $this->assertTrue(
            isset($state['last_scan_result']['trigger']) && $state['last_scan_result']['trigger'] === 'admin-catchup',
            'catchup_overdue: scan must have run with trigger=admin-catchup'
        );
    }

    private function test_catchup_suppressed_when_recent()
    {
        // last scan was 22h59m ago → catch-up must NOT fire
        $recentAt       = time() - (22 * HOUR_IN_SECONDS + 59 * 60);
        $sentinelTrigger = 'previous-trigger';

        $GLOBALS['msp_pg_test_options'] = array(
            MSP_PG_Config::state_option_name() => array(
                'last_scan_at'    => gmdate('c', $recentAt),
                'last_scan_result' => array('trigger' => $sentinelTrigger),
            ),
            'active_plugins'  => array(),
        );
        $GLOBALS['msp_pg_test_transients']         = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();
        $GLOBALS['msp_pg_test_scheduled_events']   = array(
            $this->hook => array('timestamp' => time() + DAY_IN_SECONDS, 'recurrence' => 'daily'),
        );

        $this->plugin->maybe_run_catchup_scan();

        $state = get_option(MSP_PG_Config::state_option_name(), array());
        $this->assertSame(
            $sentinelTrigger,
            $state['last_scan_result']['trigger'],
            'catchup_recent: catch-up must not fire; last_scan_result trigger must be unchanged'
        );
    }

    // -------------------------------------------------------------------------
    // Helper: invoke schedule_scan() via maybe_complete_setup() version mismatch
    // -------------------------------------------------------------------------

    private function call_schedule_via_setup($timezoneString, $gmtOffset, $mockTime)
    {
        $GLOBALS['msp_pg_test_current_time']     = $mockTime;
        $GLOBALS['msp_pg_test_scheduled_events'] = array();
        $GLOBALS['msp_pg_test_options']          = array(
            'msp_pg_version'  => 'old-version',
            'timezone_string' => $timezoneString,
            'gmt_offset'      => $gmtOffset,
        );

        $muLoaderPath = MSP_PG_Config::mu_loader_path();
        file_put_contents($muLoaderPath, '<?php // test mu-loader');

        $this->plugin->maybe_complete_setup();

        @unlink($muLoaderPath);

        $event = isset($GLOBALS['msp_pg_test_scheduled_events'][$this->hook])
            ? $GLOBALS['msp_pg_test_scheduled_events'][$this->hook]
            : null;

        $GLOBALS['msp_pg_test_current_time'] = null;

        return $event;
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private function assertTrue($condition, $message)
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    private function assertSame($expected, $actual, $message)
    {
        if ($expected !== $actual) {
            throw new RuntimeException(
                $message . ' Expected ' . var_export($expected, true) . ' but got ' . var_export($actual, true)
            );
        }
    }

    private function assertNotSame($expected, $actual, $message)
    {
        if ($expected === $actual) {
            throw new RuntimeException(
                $message . ' Expected values to differ but both are ' . var_export($actual, true)
            );
        }
    }

    private function assertNotNull($value, $message)
    {
        if ($value === null) {
            throw new RuntimeException($message . ' (got null)');
        }
    }

    // -------------------------------------------------------------------------
    // Cleanup
    // -------------------------------------------------------------------------

    private function cleanup($dir)
    {
        if (!is_dir($dir)) {
            return;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }
        @rmdir($dir);
    }
}

$test = new SchedulingTest();
$test->run();
echo "SchedulingTest passed\n";
