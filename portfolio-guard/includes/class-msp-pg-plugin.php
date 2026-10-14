<?php

if (!defined('ABSPATH')) {
    exit;
}

class MSP_PG_Plugin
{
    private static $instance = null;

    public static function instance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct()
    {
        add_action('init', array($this, 'maybe_complete_setup'), 1);
        add_action(MSP_PG_Config::cron_hook(), array($this, 'run_cron_scan'));
        add_action('admin_init', array($this, 'maybe_run_catchup_scan'));
        add_action('plugins_loaded', array($this, 'maybe_sync_mu_loader'), 1);
        add_action('admin_notices', array($this, 'render_setup_notice'));
    }

    public static function activate()
    {
        update_option(MSP_PG_Config::pending_activation_option_name(), gmdate('c'), false);
        update_option('msp_pg_version', MSP_PG_VERSION, false);
        self::schedule_scan();
    }

    public static function deactivate()
    {
        self::clear_scan_schedule();
        self::remove_mu_loader();
    }

    public static function uninstall()
    {
        self::clear_scan_schedule();
        wp_clear_scheduled_hook(MSP_PG_UpdateScheduler::HOOK);
        self::remove_mu_loader();

        // Availability observations: table, schema option, cron event (2.1.0)
        MSP_PG_Availability::uninstall();

        // Options — pre-2.0.0
        delete_option(MSP_PG_Config::state_option_name());
        delete_option(MSP_PG_Config::pending_activation_option_name());
        delete_option(MSP_PG_Config::setup_notice_option_name());
        delete_option('msp_pg_allow_tier1_remediation');
        delete_option('msp_pg_version');
        delete_option('msp_pg_report_recipient');

        // Options — Spec 007 update infrastructure
        delete_option('msp_pg_last_update_checked');
        delete_option('msp_pg_last_update_applied');
        delete_option('msp_pg_max_registry_version');
        delete_option('msp_pg_update_consecutive_failures');

        // Options — Spec 009 plugin updater
        delete_option('msp_pg_plugin_update_last_checked');
        delete_option('msp_pg_plugin_update_cache');

        // Options — telemetry contract
        delete_option('msp_pg_telemetry');

        // Options — Review Required workflow (2.0.3)
        delete_option(MSP_PG_Whitelist::OPTION_NAME);

        // Transients
        delete_transient(MSP_PG_Config::scan_lock_key());
        delete_transient(MSP_PG_Config::catchup_lock_key());
        delete_transient('msp_pg_update_notice');

        // Applied registry directory ({uploads}/portfolio-guard/)
        $registryPath = MSP_PG_Config::applied_registry_path();
        if (!empty($registryPath)) {
            $registryDir = dirname($registryPath);
            self::remove_directory($registryDir);
        }
    }

    private static function remove_directory($dir)
    {
        if (empty($dir) || !is_dir($dir)) {
            return;
        }

        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($items as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($dir);
    }

    public function run_cron_scan()
    {
        MSP_PG_Remediator::run_scan('cron');
    }

    public function maybe_run_catchup_scan()
    {
        if (!is_admin() || !current_user_can('manage_options')) {
            return;
        }

        if (get_transient(MSP_PG_Config::catchup_lock_key())) {
            return;
        }

        $state = get_option(MSP_PG_Config::state_option_name(), array());
        $lastScan = isset($state['last_scan_at']) ? strtotime($state['last_scan_at']) : 0;
        $pendingActivation = get_option(MSP_PG_Config::pending_activation_option_name());

        if (!empty($pendingActivation)) {
            MSP_PG_Remediator::run_scan('activation-catchup');
            delete_option(MSP_PG_Config::pending_activation_option_name());
            return;
        }

        if ($lastScan > 0 && (time() - $lastScan) < 23 * HOUR_IN_SECONDS) {
            return;
        }

        set_transient(MSP_PG_Config::catchup_lock_key(), 1, 5 * MINUTE_IN_SECONDS);
        MSP_PG_Remediator::run_scan('admin-catchup');
        delete_transient(MSP_PG_Config::catchup_lock_key());
    }

    public function maybe_complete_setup()
    {
        $installedVersion = get_option('msp_pg_version');

        if ($installedVersion !== MSP_PG_VERSION) {
            update_option('msp_pg_version', MSP_PG_VERSION, false);
            self::clear_scan_schedule();
            self::schedule_scan();
        }

        if ($this->has_setup_completed()) {
            return;
        }

        $errors = array();

        if (!self::ensure_mu_loader()) {
            $errors[] = 'Could not create or update the MU-loader.';
        }

        $scheduleResult = self::schedule_scan();
        if (!$scheduleResult['ok']) {
            $errors[] = $scheduleResult['message'];
        }

        if (!empty($errors)) {
            update_option(MSP_PG_Config::setup_notice_option_name(), implode(' ', $errors), false);
            return;
        }

        delete_option(MSP_PG_Config::setup_notice_option_name());
    }

    public function maybe_sync_mu_loader()
    {
        $installedVersion = get_option('msp_pg_version');
        $muLoaderPath = MSP_PG_Config::mu_loader_path();

        // Do not record msp_pg_version here: this runs on plugins_loaded, before
        // maybe_complete_setup() on init, which must still see the version change
        // to re-register the scan schedule and then records the new version itself.
        if ($installedVersion !== MSP_PG_VERSION || !file_exists($muLoaderPath)) {
            self::ensure_mu_loader();
        }
    }

    public function render_setup_notice()
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $message = get_option(MSP_PG_Config::setup_notice_option_name());
        if (empty($message)) {
            return;
        }

        echo '<div class="notice notice-error"><p>MSP Portfolio Guard setup warning: ' . esc_html($message) . '</p></div>';
    }

    private static function schedule_scan()
    {
        $hook = MSP_PG_Config::cron_hook();

        if (wp_next_scheduled($hook)) {
            return array('ok' => true, 'message' => '');
        }

        $timestamp = self::next_6am_timestamp();
        $scheduled = wp_schedule_event($timestamp, 'daily', $hook, array(), true);
        if ($scheduled === true || wp_next_scheduled($hook)) {
            return array('ok' => true, 'message' => '');
        }

        $fallback = wp_schedule_single_event(time() + (5 * MINUTE_IN_SECONDS), $hook, array(), true);
        if ($fallback === true || wp_next_scheduled($hook)) {
            return array(
                'ok'      => true,
                'message' => 'Recurring scan could not be registered; using fallback scheduling and admin catch-up scans.',
            );
        }

        $errorMessage = 'Could not register automated scan scheduling.';
        if (is_wp_error($scheduled)) {
            $errorMessage .= ' ' . $scheduled->get_error_message();
        } elseif (is_wp_error($fallback)) {
            $errorMessage .= ' ' . $fallback->get_error_message();
        }

        return array('ok' => false, 'message' => $errorMessage);
    }

    private static function next_6am_timestamp()
    {
        $now = isset($GLOBALS['msp_pg_test_current_time'])
            ? (int) $GLOBALS['msp_pg_test_current_time']
            : time();

        $timezone = self::site_timezone();
        $nowDt    = new DateTime('@' . $now);
        $nowDt->setTimezone($timezone);

        $target = clone $nowDt;
        $target->setTime(6, 0, 0);

        if ($nowDt >= $target) {
            $target->modify('+1 day');
        }

        return (int) $target->format('U');
    }

    private static function site_timezone()
    {
        $tzString = (string) get_option('timezone_string', '');

        if ($tzString !== '') {
            try {
                return new DateTimeZone($tzString);
            } catch (Exception $e) {
                // fall through to offset-based resolution
            }
        }

        $gmtOffset = (float) get_option('gmt_offset', 0);

        if ($gmtOffset !== 0.0) {
            $sign      = $gmtOffset >= 0 ? '+' : '-';
            $absOffset = abs($gmtOffset);
            $hours     = (int) $absOffset;
            $minutes   = (int) round(($absOffset - $hours) * 60);

            try {
                // PHP's DateTimeZone constructor requires a bare GMT-offset
                // string ("+05:30"), not one prefixed with "UTC"
                // ("UTC+05:30") -- the latter throws unconditionally for
                // every offset, including whole-hour ones, which is why
                // this branch always fell through to UTC regardless of the
                // site's actual gmt_offset setting (confirmed via direct
                // testing: new DateTimeZone('UTC+05:00') throws the same as
                // 'UTC+05:30'). This affects any WordPress install
                // configured with an offset-only timezone (Settings ->
                // General -> "UTC+5:30" etc., as opposed to a named city),
                // which silently had its daily scan scheduled in UTC
                // instead of the configured local time.
                return new DateTimeZone(sprintf('%s%02d:%02d', $sign, $hours, $minutes));
            } catch (Exception $e) {
                // fall through to UTC
            }
        }

        return new DateTimeZone('UTC');
    }

    private static function clear_scan_schedule()
    {
        wp_clear_scheduled_hook(MSP_PG_Config::cron_hook());
    }

    private static function ensure_mu_loader()
    {
        if (!defined('WPMU_PLUGIN_DIR')) {
            return false;
        }

        if (!MSP_PG_Utils::ensure_directory(WPMU_PLUGIN_DIR)) {
            return false;
        }

        $pluginDirName = basename(dirname(MSP_PG_PLUGIN_FILE));

$contents = <<<'PHP'
<?php
/**
 * Plugin Name: MSP Portfolio Guard Loader
 * Description: Early boot loader for MSP Portfolio Guard.
 * Version: __VERSION__
 */

if (!defined('ABSPATH')) {
    exit;
}

$boot = WP_PLUGIN_DIR . '/__PLUGIN_DIR__/portfolio-guard.php';

if (is_readable($boot)) {
    require_once $boot;
}
PHP;

        $contents = str_replace('__PLUGIN_DIR__', $pluginDirName, $contents);
        $contents = str_replace('__VERSION__', MSP_PG_VERSION, $contents);
        return file_put_contents(MSP_PG_Config::mu_loader_path(), $contents) !== false;
    }

    private static function remove_mu_loader()
    {
        $path = MSP_PG_Config::mu_loader_path();

        if (file_exists($path)) {
            @unlink($path);
        }
    }

    private function has_setup_completed()
    {
        return file_exists(MSP_PG_Config::mu_loader_path());
    }
}
