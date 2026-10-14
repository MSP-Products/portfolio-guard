<?php

require_once __DIR__ . '/bootstrap.php';

class OperationalReportTest
{
    private $workspace;

    public function run()
    {
        $this->workspace = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'msp-pg-optest-' . uniqid();
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

        // Objective 1: Daily operational report
        $this->test_clean_scan_sends_clean_report_email();
        $this->test_clean_scan_email_contains_operational_fields();
        $this->test_dry_run_does_not_send_email();
        $this->test_scan_email_subject_clean();
        $this->test_scan_email_subject_review_required();
        $this->test_scan_email_subject_confirmed_malware();

        // Objective 4: Email configuration
        $this->test_report_recipient_defaults_to_engineering_email();
        $this->test_report_recipient_reads_from_option();
        $this->test_report_recipient_persists();
        $this->test_report_recipient_falls_back_when_option_empty();

        // Objective 3: Scan Now
        $this->test_manual_scan_updates_state_trigger();
        $this->test_manual_scan_sends_email();
        $this->test_cron_and_manual_produce_same_state_structure();

        // Objective 2: Settings page
        $this->test_settings_page_renders_email_input();
        $this->test_settings_page_renders_scan_now_form();
        $this->test_settings_page_shows_existing_recipient_in_form();

        $this->cleanup($this->workspace);
    }

    // -------------------------------------------------------------------------
    // Objective 1: Daily operational report
    // -------------------------------------------------------------------------

    private function test_clean_scan_sends_clean_report_email()
    {
        $this->reset_state();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();

        MSP_PG_Remediator::run_scan('cron');

        $this->assertNotEmpty($GLOBALS['msp_pg_test_wp_mail_calls'], 'clean_scan_email: wp_mail must be called for a clean scan');
        $subject = $GLOBALS['msp_pg_test_wp_mail_calls'][0]['subject'];
        $this->assertContains('CLEAN REPORT', $subject, 'clean_scan_email: subject must contain CLEAN REPORT');
    }

    private function test_clean_scan_email_contains_operational_fields()
    {
        $this->reset_state();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();

        MSP_PG_Remediator::run_scan('cron');

        $this->assertNotEmpty($GLOBALS['msp_pg_test_wp_mail_calls'], 'op_fields: wp_mail must be called');
        $body = $GLOBALS['msp_pg_test_wp_mail_calls'][0]['message'];

        $this->assertContains('example.test', $body, 'op_fields: email body must contain site URL');
        $this->assertContains(MSP_PG_VERSION, $body, 'op_fields: email body must contain plugin version');
        $this->assertContains(MSP_PG_Config::signature_version(), $body, 'op_fields: email body must contain signature registry version');
        $this->assertContains('Next Scheduled Scan', $body, 'op_fields: email body must contain next scheduled scan label');
        $this->assertContains('CLEAN', $body, 'op_fields: email body must contain outcome');
    }

    private function test_dry_run_does_not_send_email()
    {
        $this->reset_state();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();

        MSP_PG_Remediator::run_scan('cron', array('dry_run' => true));

        // Registry error email may fire — but the operational scan email must not
        $operationalCalls = array_filter(
            $GLOBALS['msp_pg_test_wp_mail_calls'],
            function ($call) {
                return strpos($call['subject'], 'CLEAN REPORT') !== false
                    || strpos($call['subject'], 'CONFIRMED MALWARE') !== false
                    || strpos($call['subject'], 'REVIEW REQUIRED') !== false;
            }
        );

        $this->assertEmpty($operationalCalls, 'dry_run_no_email: dry-run must not send operational report email');
    }

    private function test_scan_email_subject_clean()
    {
        $report = $this->minimal_scan_report(array(), array());
        $subject = MSP_PG_Remediator::scan_email_subject($report);
        $this->assertContains('CLEAN REPORT', $subject, 'subject_clean: must contain CLEAN REPORT');
        $this->assertContains('example.test', $subject, 'subject_clean: must contain site URL');
    }

    private function test_scan_email_subject_review_required()
    {
        $report = $this->minimal_scan_report(array('fake-plugin'), array());
        $subject = MSP_PG_Remediator::scan_email_subject($report);
        $this->assertContains('REVIEW REQUIRED', $subject, 'subject_review: must contain REVIEW REQUIRED');
        $this->assertNotContains('CLEAN REPORT', $subject, 'subject_review: must not contain CLEAN REPORT');
        $this->assertNotContains('CONFIRMED MALWARE REMEDIATED', $subject, 'subject_review: must not contain CONFIRMED MALWARE REMEDIATED');
    }

    private function test_scan_email_subject_confirmed_malware()
    {
        // Removed -> REMEDIATED.
        $report = $this->minimal_scan_report(array(), array('fake-malware'), array('CONFIRMED_MALWARE_IDENTIFIED', 'BUNDLE_VERIFIED', 'LIVE_PLUGIN_REMOVED'));
        $subject = MSP_PG_Remediator::scan_email_subject($report);
        $this->assertContains('CONFIRMED MALWARE REMEDIATED', $subject, 'subject_malware: removed finding must say CONFIRMED MALWARE REMEDIATED');
        $this->assertNotContains('CLEAN REPORT', $subject, 'subject_malware: must not contain CLEAN REPORT');

        // Detected but not removed -> must not claim remediation.
        $report = $this->minimal_scan_report(array(), array('fake-malware'));
        $subject = MSP_PG_Remediator::scan_email_subject($report);
        $this->assertContains('CONFIRMED MALWARE - ACTION REQUIRED', $subject, 'subject_malware: unremoved finding must say ACTION REQUIRED');
        $this->assertNotContains('REMEDIATED', $subject, 'subject_malware: unremoved finding must not claim remediation');
    }

    // -------------------------------------------------------------------------
    // Objective 4: Email configuration
    // -------------------------------------------------------------------------

    private function test_report_recipient_defaults_to_engineering_email()
    {
        unset($GLOBALS['msp_pg_test_options']['msp_pg_report_recipient']);
        $recipient = MSP_PG_Config::report_recipient();
        $this->assertSame('joshua@mysocialpractice.com', $recipient, 'default_recipient: must default to engineering email');
    }

    private function test_report_recipient_reads_from_option()
    {
        $GLOBALS['msp_pg_test_options']['msp_pg_report_recipient'] = 'operator@example.com';
        $recipient = MSP_PG_Config::report_recipient();
        $this->assertSame('operator@example.com', $recipient, 'option_recipient: must read from msp_pg_report_recipient option');
        unset($GLOBALS['msp_pg_test_options']['msp_pg_report_recipient']);
    }

    private function test_report_recipient_persists()
    {
        update_option('msp_pg_report_recipient', 'admin@client.com', false);
        $stored    = get_option('msp_pg_report_recipient', '');
        $recipient = MSP_PG_Config::report_recipient();
        $this->assertSame('admin@client.com', $stored, 'persist_recipient: option value must persist after save');
        $this->assertSame('admin@client.com', $recipient, 'persist_recipient: Config::report_recipient must return persisted value');
        delete_option('msp_pg_report_recipient');
    }

    private function test_report_recipient_falls_back_when_option_empty()
    {
        update_option('msp_pg_report_recipient', '', false);
        $recipient = MSP_PG_Config::report_recipient();
        $this->assertSame('joshua@mysocialpractice.com', $recipient, 'fallback_recipient: empty option must fall back to engineering email');
        delete_option('msp_pg_report_recipient');
    }

    // -------------------------------------------------------------------------
    // Objective 3: Scan Now
    // -------------------------------------------------------------------------

    private function test_manual_scan_updates_state_trigger()
    {
        $this->reset_state();

        MSP_PG_Remediator::run_scan('manual');

        $state = get_option(MSP_PG_Config::state_option_name(), array());
        $this->assertSame('manual', $state['last_scan_result']['trigger'], 'manual_trigger: state must record trigger=manual');
        $this->assertTrue(isset($state['last_scan_at']), 'manual_trigger: state must record last_scan_at');
    }

    private function test_manual_scan_sends_email()
    {
        $this->reset_state();
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();

        MSP_PG_Remediator::run_scan('manual');

        $this->assertNotEmpty($GLOBALS['msp_pg_test_wp_mail_calls'], 'manual_email: Scan Now must produce a report email');
    }

    private function test_cron_and_manual_produce_same_state_structure()
    {
        $this->reset_state();
        MSP_PG_Remediator::run_scan('cron');
        $cronState = get_option(MSP_PG_Config::state_option_name(), array());

        $this->reset_state();
        MSP_PG_Remediator::run_scan('manual');
        $manualState = get_option(MSP_PG_Config::state_option_name(), array());

        $this->assertTrue(isset($cronState['last_scan_at']),                   'state_structure: cron must record last_scan_at');
        $this->assertTrue(isset($manualState['last_scan_at']),                  'state_structure: manual must record last_scan_at');
        $this->assertTrue(isset($cronState['last_scan_result']['detections']),   'state_structure: cron must record detections count');
        $this->assertTrue(isset($manualState['last_scan_result']['detections']), 'state_structure: manual must record detections count');
        $this->assertSame(
            array_keys($cronState['last_scan_result']),
            array_keys($manualState['last_scan_result']),
            'state_structure: cron and manual must produce same last_scan_result keys'
        );
    }

    // -------------------------------------------------------------------------
    // Objective 2: Settings page
    // -------------------------------------------------------------------------

    private function test_settings_page_renders_email_input()
    {
        $this->reset_state();

        ob_start();
        MSP_PG_DiagnosticsPage::render();
        $html = ob_get_clean();

        $this->assertContains('msp_pg_report_recipient', $html, 'settings_form: page must contain report recipient input field');
        $this->assertContains('type="email"', $html, 'settings_form: recipient field must be type=email');
        $this->assertContains('msp_pg_save_settings', $html, 'settings_form: page must include save settings action');
    }

    private function test_settings_page_renders_scan_now_form()
    {
        $this->reset_state();

        ob_start();
        MSP_PG_DiagnosticsPage::render();
        $html = ob_get_clean();

        $this->assertContains('msp_pg_scan_now', $html, 'scan_now_form: page must contain scan now action');
        $this->assertContains('Scan Now', $html, 'scan_now_form: page must contain Scan Now button label');
    }

    private function test_settings_page_shows_existing_recipient_in_form()
    {
        $this->reset_state();
        update_option('msp_pg_report_recipient', 'existing@example.com', false);

        ob_start();
        MSP_PG_DiagnosticsPage::render();
        $html = ob_get_clean();

        $this->assertContains('existing@example.com', $html, 'recipient_in_form: current recipient must appear as form value');
        delete_option('msp_pg_report_recipient');
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function reset_state()
    {
        $GLOBALS['msp_pg_test_options'] = array(
            'active_plugins'  => array(),
            'timezone_string' => 'UTC',
            'gmt_offset'      => 0,
        );
        $GLOBALS['msp_pg_test_transients']          = array();
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array();
        $GLOBALS['msp_pg_test_scheduled_events']    = array(
            MSP_PG_Config::cron_hook() => array(
                'timestamp'  => time() + DAY_IN_SECONDS,
                'recurrence' => 'daily',
            ),
        );
        $GLOBALS['msp_pg_test_wp_mail_calls'] = array();
    }

    private function minimal_scan_report(array $reviewSlugs, array $confirmedSlugs, array $confirmedActions = array('CONFIRMED_MALWARE_IDENTIFIED'))
    {
        $mkDetection = function ($slug, $tier) use ($confirmedActions) {
            return array(
                'plugin_slug'        => $slug,
                'tier'               => $tier,
                'actions'            => $tier === 'tier1' ? $confirmedActions : array('REVIEW_REQUIRED_IDENTIFIED'),
                'action_descriptions' => array('Reported'),
                'behavior_profiles'  => array(),
                'bundle_eligible'    => false,
            );
        };

        $review    = array_map(function ($s) use ($mkDetection) { return $mkDetection($s, 'tier2'); }, $reviewSlugs);
        $confirmed = array_map(function ($s) use ($mkDetection) { return $mkDetection($s, 'tier1'); }, $confirmedSlugs);

        return array(
            'site_url'         => 'https://example.test/',
            'scan_timestamp'   => gmdate('c'),
            'detections'       => array_merge($review, $confirmed),
            'confirmed_malware' => $confirmed,
            'review_required'  => $review,
            'errors'           => array(),
        );
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private function assertTrue($condition, $message)
    {
        if (!$condition) {
            throw new RuntimeException('FAIL: ' . $message);
        }
    }

    private function assertSame($expected, $actual, $message)
    {
        if ($expected !== $actual) {
            throw new RuntimeException(
                'FAIL: ' . $message . ' — expected ' . var_export($expected, true) . ', got ' . var_export($actual, true)
            );
        }
    }

    private function assertNotSame($expected, $actual, $message)
    {
        if ($expected === $actual) {
            throw new RuntimeException(
                'FAIL: ' . $message . ' — expected values to differ, both are ' . var_export($actual, true)
            );
        }
    }

    private function assertContains($needle, $haystack, $message)
    {
        if (strpos($haystack, $needle) === false) {
            throw new RuntimeException(
                'FAIL: ' . $message . ' — "' . $needle . '" not found in: ' . substr($haystack, 0, 200)
            );
        }
    }

    private function assertNotContains($needle, $haystack, $message)
    {
        if (strpos($haystack, $needle) !== false) {
            throw new RuntimeException(
                'FAIL: ' . $message . ' — "' . $needle . '" unexpectedly found in: ' . substr($haystack, 0, 200)
            );
        }
    }

    private function assertNotEmpty($value, $message)
    {
        if (empty($value)) {
            throw new RuntimeException('FAIL: ' . $message . ' (got empty)');
        }
    }

    private function assertEmpty($value, $message)
    {
        if (!empty($value)) {
            throw new RuntimeException('FAIL: ' . $message . ' (expected empty, got non-empty)');
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

$test = new OperationalReportTest();
$test->run();
echo "OperationalReportTest passed\n";
