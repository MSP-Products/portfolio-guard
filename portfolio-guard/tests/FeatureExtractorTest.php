<?php

require_once __DIR__ . '/bootstrap.php';

class FeatureExtractorTest
{
    private $workspace;
    private $syntheticRoot;

    public function run()
    {
        $this->workspace     = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'msp-pg-extractor-' . uniqid();
        $this->syntheticRoot = dirname(dirname(dirname(__FILE__)))
            . DIRECTORY_SEPARATOR . 'validation'
            . DIRECTORY_SEPARATOR . 'corpus'
            . DIRECTORY_SEPARATOR . 'synthetic';

        wp_mkdir_p($this->workspace);

        $this->test_sm_signals();
        $this->test_fc_signals();
        $this->test_hp_signals();
        $this->test_dm_signals();
        $this->test_cb_signals();
        $this->test_structural_sp01();
        $this->test_structural_sp02();
        $this->test_kb01_backdoor_triplet();
        $this->test_kb02_bootstrap_pattern();
        $this->test_lb01_login_backdoor_combination();
        $this->test_lb01_needs_every_part_in_one_php_file();
        $this->test_hp01_matches_double_quote_form_but_not_wordpress_spacing();
        $this->test_deduplication();
        $this->test_no_signals_in_minimal_plugin();
        $this->test_files_outside_scan_extensions_ignored();
        $this->test_synthetic_c2_channel();
        $this->test_synthetic_payload_delivery();
        $this->test_synthetic_operator_access();
        $this->test_synthetic_persistence();
        $this->test_synthetic_stealth();
        $this->test_determinism();

        $this->cleanup($this->workspace);
    }

    // ─── String Marker Signals ────────────────────────────────────────────────

    private function test_sm_signals()
    {
        $cases = array(
            array('SM-01', 'fastreactic_nanomicroserviceing'),
            array('SM-02', 'tridatation_quicktypescriptal'),
            array('SM-03', 'data-ph-pid'),
            array('SM-04', '/api/config/'),
            array('SM-05', '/api/click'),
        );

        foreach ($cases as list($signalId, $str)) {
            $dir = $this->makePlugin('test-' . strtolower($signalId), "<?php echo '" . $str . "';");
            $obs = MSP_PG_FeatureExtractor::extract($dir);
            $this->assertHasSignal($obs, $signalId, $signalId . ' should be detected for string: ' . $str);
            $this->cleanup($dir);
        }
    }

    // ─── Function Call Signals ────────────────────────────────────────────────

    private function test_fc_signals()
    {
        $cases = array(
            array('FC-01', 'register_rest_route('),
            array('FC-02', 'wp_remote_get('),
            array('FC-02', 'wp_remote_post('),
            array('FC-02', 'wp_remote_request('),
            array('FC-03', 'wp_set_auth_cookie('),
            array('FC-04', 'setcookie('),
            array('FC-05', '$_COOKIE'),
            array('FC-06', 'wp_safe_redirect('),
            array('FC-07', 'wp_register_script('),
            array('FC-07', 'wp_enqueue_script('),
            array('FC-07', 'wp_add_inline_script('),
            array('FC-08', 'wp_ajax_'),
            array('FC-08', 'wp_ajax_nopriv_'),
        );

        foreach ($cases as list($signalId, $str)) {
            $safe = preg_replace('/[^a-z0-9]/', '-', strtolower($signalId . '-' . $str));
            $dir  = $this->makePlugin('test-fc-' . $safe . '-' . uniqid(), "<?php " . $str . ";");
            $obs  = MSP_PG_FeatureExtractor::extract($dir);
            $this->assertHasSignal($obs, $signalId, $signalId . ' should be detected for: ' . $str);
            $this->cleanup($dir);
        }
    }

    // ─── Hook Pattern Signals ─────────────────────────────────────────────────

    private function test_hp_signals()
    {
        $dir = $this->makePlugin('test-hp01', "<?php add_filter('all_plugins', '__return_array');");
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'HP-01', 'HP-01 should fire for add_filter all_plugins');
        $this->cleanup($dir);

        $dir = $this->makePlugin('test-hp02', "<?php add_action('template_redirect', '__return_false');");
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'HP-02', 'HP-02 should fire for add_action template_redirect');
        $this->cleanup($dir);
    }

    // ─── DOM Manipulation Signals ─────────────────────────────────────────────

    private function test_dm_signals()
    {
        // Single-quoted form
        $dir = $this->makePlugin('test-dm01-sq', "<?php echo \"document.createElement('script');\";");
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'DM-01', 'DM-01 should fire for createElement single-quote form');
        $this->cleanup($dir);

        // Double-quoted form
        $dir = $this->makePlugin('test-dm01-dq', '<?php echo \'document.createElement("script");\';');
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'DM-01', 'DM-01 should fire for createElement double-quote form');
        $this->cleanup($dir);
    }

    // ─── Callback Pattern Signals ─────────────────────────────────────────────

    private function test_cb_signals()
    {
        $dir = $this->makePlugin('test-cb01', "<?php \$args = array('permission_callback' => '__return_true');");
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'CB-01', 'CB-01 should fire for permission_callback __return_true');
        $this->cleanup($dir);
    }

    // ─── Structural Signals ───────────────────────────────────────────────────

    private function test_structural_sp01()
    {
        // SP-01: 5-6 char alphanumeric subdir + 8-char alphanumeric PHP file
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test-sp01-' . uniqid();
        wp_mkdir_p($dir . DIRECTORY_SEPARATOR . 'abc12');
        file_put_contents($dir . DIRECTORY_SEPARATOR . 'abc12' . DIRECTORY_SEPARATOR . 'abc12.php', "<?php\n/** Plugin Name: sp01-test */\n");
        file_put_contents($dir . DIRECTORY_SEPARATOR . 'abc12' . DIRECTORY_SEPARATOR . 'defgh123.php', "<?php echo 'payload';");

        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'SP-01', 'SP-01 should fire for random-named payload structure');

        $this->cleanup($dir);
    }

    private function test_structural_sp02()
    {
        // SP-02: 8-char alphanumeric JS file under assets/
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test-sp02-' . uniqid();
        wp_mkdir_p($dir . DIRECTORY_SEPARATOR . 'assets');
        file_put_contents($dir . DIRECTORY_SEPARATOR . 'sp02test.php', "<?php\n/** Plugin Name: sp02-test */\n");
        file_put_contents($dir . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'abcdef12.js', "/* asset */");

        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'SP-02', 'SP-02 should fire for random-named JS under assets/');

        $this->cleanup($dir);
    }

    // ─── Compound Signals ─────────────────────────────────────────────────────

    private function test_kb01_backdoor_triplet()
    {
        $pairs = MSP_PG_Signatures::backdoor_pairs();
        if (empty($pairs)) {
            return;
        }
        $pair = reset($pairs);
        $content = "<?php if (isset(\$_GET['" . $pair['id_param'] . "']) && \$_GET['" . $pair['token_param'] . "'] === '" . $pair['token_value'] . "') {}";

        $dir = $this->makePlugin('test-kb01', $content);
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'KB-01', 'KB-01 should fire when backdoor triplet is present');
        $this->cleanup($dir);
    }

    private function test_kb02_bootstrap_pattern()
    {
        // KB-02 fires on any of the three bootstrap strings
        foreach (array('fastreactic_nanomicroserviceing', 'tridatation_quicktypescriptal', 'data-ph-pid') as $str) {
            $dir = $this->makePlugin('test-kb02-' . uniqid(), "<?php echo '" . $str . "';");
            $obs = MSP_PG_FeatureExtractor::extract($dir);
            $this->assertHasSignal($obs, 'KB-02', 'KB-02 should fire for bootstrap string: ' . $str);
            $this->cleanup($dir);
        }
    }

    // ─── Login backdoor combination (LB-01) ───────────────────────────────────

    private function loginBackdoorCode(array $omit = array())
    {
        $parts = array(
            'request'   => "if (!isset(\$_GET['t']) || \$_GET['t'] !== 'FIXTURE') { return; }",
            'create'    => "\$id = wp_create_user('fixture-account', 'x', 'nobody@example.invalid');",
            'privilege' => "\$user->add_cap('manage_options');",
            'cookie'    => "wp_set_auth_cookie(\$user->ID, true);",
        );
        foreach ($omit as $key) {
            unset($parts[$key]);
        }
        return "<?php\nfunction fixture_handler() {\n    " . implode("\n    ", $parts) . "\n}\n";
    }

    private function test_lb01_login_backdoor_combination()
    {
        $dir = $this->makePlugin('test-lb01', $this->loginBackdoorCode());
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'LB-01', 'LB-01 should fire when one PHP file holds a request parameter, account creation, a privileged capability and an auth cookie');
        $matched = MSP_PG_FeatureExtractor::find_by_signal($obs, 'LB-01');
        $this->assertTrue(
            strpos($matched[0]['matched_string'], 'wp_set_auth_cookie(') !== false && strpos($matched[0]['matched_string'], 'wp_create_user(') !== false,
            'LB-01 matched_string should name the parts that matched so an operator can read it'
        );
        $this->cleanup($dir);

        // Granting the capability to an existing account counts the same as creating one.
        $variant = str_replace("wp_create_user('fixture-account', 'x', 'nobody@example.invalid')", "get_user_by('login', 'fixture-account')", $this->loginBackdoorCode());
        $dir = $this->makePlugin('test-lb01-grant', $variant);
        $this->assertHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'LB-01', 'LB-01 should fire when an account is elevated with add_cap instead of created');
        $this->cleanup($dir);
    }

    private function test_lb01_needs_every_part_in_one_php_file()
    {
        foreach (array('request', 'privilege', 'cookie') as $missing) {
            $dir = $this->makePlugin('test-lb01-no-' . $missing, $this->loginBackdoorCode(array($missing)));
            $this->assertNotHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'LB-01', 'LB-01 must not fire without the ' . $missing . ' part');
            $this->cleanup($dir);
        }

        // Account step missing: no creation and no add_cap/set_role.
        $noAccount = str_replace(array("\$id = wp_create_user('fixture-account', 'x', 'nobody@example.invalid');", "\$user->add_cap('manage_options');"), array('', "\$role = 'manage_options';"), $this->loginBackdoorCode());
        $dir = $this->makePlugin('test-lb01-no-account', $noAccount);
        $this->assertNotHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'LB-01', 'LB-01 must not fire when nothing creates or elevates an account');
        $this->cleanup($dir);

        // wp_set_auth_cookie alone is what legitimate remote-management plugins do.
        $dir = $this->makePlugin('test-lb01-cookie-only', "<?php\nfunction fixture_login(\$id) { wp_set_auth_cookie(\$id); }\n");
        $this->assertNotHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'LB-01', 'LB-01 must not fire on wp_set_auth_cookie alone');
        $this->cleanup($dir);

        // The parts are spread over two files: that is not the pattern.
        $dir = $this->workspace . DIRECTORY_SEPARATOR . 'test-lb01-split';
        wp_mkdir_p($dir);
        file_put_contents($dir . '/a.php', "<?php\nfunction a() { \$u = wp_create_user('x', 'y', 'z'); \$u->add_cap('manage_options'); }\n");
        file_put_contents($dir . '/b.php', "<?php\nfunction b() { if (isset(\$_GET['t'])) { wp_set_auth_cookie(1); } }\n");
        $this->assertNotHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'LB-01', 'LB-01 must not fire when the parts are in different files');
        $this->cleanup($dir);

        // Only PHP can run: the same text in a .txt file (documentation, a changelog) is not a backdoor.
        $dir = $this->workspace . DIRECTORY_SEPARATOR . 'test-lb01-txt';
        wp_mkdir_p($dir);
        file_put_contents($dir . '/notes.txt', $this->loginBackdoorCode());
        $this->assertNotHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'LB-01', 'LB-01 must only be read from PHP files');
        $this->cleanup($dir);
    }

    private function test_hp01_matches_double_quote_form_but_not_wordpress_spacing()
    {
        $dir = $this->makePlugin('test-hp01-dq', '<?php add_filter("all_plugins", "hide");');
        $this->assertHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'HP-01', 'HP-01 should fire for the double-quoted form of add_filter all_plugins');
        $this->cleanup($dir);

        // Calibration (mainwp-child 4.6): legitimate plugins write the filter in WordPress style, with spaces.
        // Matching it would flag them all, so it stays unmatched on purpose.
        foreach (array("<?php add_filter( 'all_plugins', 'hide' );", '<?php add_filter( "all_plugins", "hide" );') as $i => $code) {
            $dir = $this->makePlugin('test-hp01-spaced-' . $i, $code);
            $this->assertNotHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'HP-01', 'HP-01 must not fire on the WordPress-style spaced form (mainwp-child calibration)');
            $this->cleanup($dir);
        }

        $dir = $this->makePlugin('test-hp01-other-filter', "<?php add_filter('plugin_action_links', 'x'); // mentions all_plugins in a comment only\n");
        $this->assertNotHasSignal(MSP_PG_FeatureExtractor::extract($dir), 'HP-01', 'HP-01 must not fire when all_plugins is only mentioned, not filtered');
        $this->cleanup($dir);
    }

    // ─── Deduplication ───────────────────────────────────────────────────────

    private function test_deduplication()
    {
        // Same signal appearing multiple times in the same file produces one observation
        $content = "<?php wp_remote_get('a'); wp_remote_get('b'); wp_remote_post('c');";
        $dir     = $this->makePlugin('test-dedup', $content);
        $obs     = MSP_PG_FeatureExtractor::extract($dir);

        $fc02 = MSP_PG_FeatureExtractor::find_by_signal($obs, 'FC-02');
        $this->assertTrue(count($fc02) === 1, 'FC-02 should appear once per file even if string found multiple times');

        $this->cleanup($dir);
    }

    // ─── Negative Cases ───────────────────────────────────────────────────────

    private function test_no_signals_in_minimal_plugin()
    {
        $dir = $this->makePlugin('test-clean', "<?php\n/**\n * Plugin Name: Minimal Clean Plugin\n */\n");
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertTrue(empty($obs), 'A minimal plugin with no signal strings should produce no observations');
        $this->cleanup($dir);
    }

    private function test_files_outside_scan_extensions_ignored()
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test-ext-' . uniqid();
        wp_mkdir_p($dir);
        // Write signal string to a file type not in scan extensions
        file_put_contents($dir . DIRECTORY_SEPARATOR . 'plugin.py', 'wp_remote_get(');
        file_put_contents($dir . DIRECTORY_SEPARATOR . 'plugin.php', "<?php\n/** Plugin Name: Ext Test */\n");

        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertNotHasSignal($obs, 'FC-02', 'FC-02 must not fire for signals in non-PHP/JS/JSON/TXT files');

        $this->cleanup($dir);
    }

    // ─── Synthetic Fixture Integration ───────────────────────────────────────

    private function test_synthetic_c2_channel()
    {
        $dir = $this->syntheticRoot . DIRECTORY_SEPARATOR . 'synthetic-c2-channel';
        if (!is_dir($dir)) {
            return;
        }
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'FC-01', 'synthetic-c2-channel: FC-01 (register_rest_route)');
        $this->assertHasSignal($obs, 'FC-02', 'synthetic-c2-channel: FC-02 (wp_remote_*)');
        $this->assertHasSignal($obs, 'CB-01', 'synthetic-c2-channel: CB-01 (permission_callback)');
        $this->assertHasSignal($obs, 'SM-04', 'synthetic-c2-channel: SM-04 (/api/config/)');
    }

    private function test_synthetic_payload_delivery()
    {
        $dir = $this->syntheticRoot . DIRECTORY_SEPARATOR . 'synthetic-payload-delivery';
        if (!is_dir($dir)) {
            return;
        }
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'DM-01', 'synthetic-payload-delivery: DM-01 (createElement)');
        $this->assertHasSignal($obs, 'FC-07', 'synthetic-payload-delivery: FC-07 (wp_enqueue_script)');
    }

    private function test_synthetic_operator_access()
    {
        $dir = $this->syntheticRoot . DIRECTORY_SEPARATOR . 'synthetic-operator-access';
        if (!is_dir($dir)) {
            return;
        }
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'FC-03', 'synthetic-operator-access: FC-03 (wp_set_auth_cookie)');
        $this->assertHasSignal($obs, 'FC-04', 'synthetic-operator-access: FC-04 (setcookie)');
        $this->assertHasSignal($obs, 'FC-05', 'synthetic-operator-access: FC-05 ($_COOKIE)');
        $this->assertHasSignal($obs, 'FC-06', 'synthetic-operator-access: FC-06 (wp_safe_redirect)');
        $this->assertHasSignal($obs, 'FC-08', 'synthetic-operator-access: FC-08 (wp_ajax_)');
    }

    private function test_synthetic_persistence()
    {
        $dir = $this->syntheticRoot . DIRECTORY_SEPARATOR . 'synthetic-persistence';
        if (!is_dir($dir)) {
            return;
        }
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'HP-01', 'synthetic-persistence: HP-01 (add_filter all_plugins)');
        $this->assertHasSignal($obs, 'FC-01', 'synthetic-persistence: FC-01 (register_rest_route)');
        $this->assertHasSignal($obs, 'FC-08', 'synthetic-persistence: FC-08 (wp_ajax_)');
        $this->assertHasSignal($obs, 'FC-02', 'synthetic-persistence: FC-02 (wp_remote_get)');
        $this->assertHasSignal($obs, 'CB-01', 'synthetic-persistence: CB-01 (permission_callback)');
    }

    private function test_synthetic_stealth()
    {
        $dir = $this->syntheticRoot . DIRECTORY_SEPARATOR . 'synthetic-stealth';
        if (!is_dir($dir)) {
            return;
        }
        $obs = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertHasSignal($obs, 'HP-01', 'synthetic-stealth: HP-01 (add_filter all_plugins)');
        $this->assertHasSignal($obs, 'FC-01', 'synthetic-stealth: FC-01 (register_rest_route)');
        $this->assertHasSignal($obs, 'CB-01', 'synthetic-stealth: CB-01 (permission_callback)');
        $this->assertHasSignal($obs, 'FC-07', 'synthetic-stealth: FC-07 (wp_register_script)');
    }

    // ─── Determinism ─────────────────────────────────────────────────────────

    private function test_determinism()
    {
        $dir = $this->syntheticRoot . DIRECTORY_SEPARATOR . 'synthetic-c2-channel';
        if (!is_dir($dir)) {
            return;
        }
        $run1 = MSP_PG_FeatureExtractor::extract($dir);
        $run2 = MSP_PG_FeatureExtractor::extract($dir);
        $this->assertTrue(
            $run1 === $run2,
            'extract() must return identical results on repeated calls against the same directory'
        );
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private function makePlugin($slug, $phpContent)
    {
        $dir = $this->workspace . DIRECTORY_SEPARATOR . $slug;
        wp_mkdir_p($dir);
        file_put_contents($dir . DIRECTORY_SEPARATOR . $slug . '.php', $phpContent);
        return $dir;
    }

    private function assertHasSignal(array $obs, $signalId, $message)
    {
        if (!MSP_PG_FeatureExtractor::has_signal($obs, $signalId)) {
            throw new RuntimeException($message . ' — signal ' . $signalId . ' not found in observations');
        }
    }

    private function assertNotHasSignal(array $obs, $signalId, $message)
    {
        if (MSP_PG_FeatureExtractor::has_signal($obs, $signalId)) {
            throw new RuntimeException($message . ' — signal ' . $signalId . ' should not be present');
        }
    }

    private function assertTrue($condition, $message)
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

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
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($dir);
    }
}

$test = new FeatureExtractorTest();
$test->run();
echo "FeatureExtractorTest passed\n";
