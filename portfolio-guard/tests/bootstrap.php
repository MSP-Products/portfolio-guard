<?php

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

if (!defined('MSP_PG_PLUGIN_FILE')) {
    define('MSP_PG_PLUGIN_FILE', dirname(__DIR__) . DIRECTORY_SEPARATOR . 'portfolio-guard.php');
}

if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file)
    {
        return trailingslashit(dirname($file));
    }
}

if (!function_exists('plugin_basename')) {
    function plugin_basename($file)
    {
        $normalized = str_replace('\\', '/', $file);
        $pluginsDir = defined('WP_PLUGIN_DIR') ? str_replace('\\', '/', WP_PLUGIN_DIR) : '';
        if ($pluginsDir !== '' && strpos($normalized, $pluginsDir . '/') === 0) {
            return ltrim(substr($normalized, strlen($pluginsDir)), '/');
        }
        return basename(dirname($file)) . '/' . basename($file);
    }
}

if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}

if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}

if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

$GLOBALS['msp_pg_test_options'] = array();
$GLOBALS['msp_pg_test_transients'] = array();
$GLOBALS['msp_pg_test_deactivated_plugins'] = array();
$GLOBALS['msp_pg_test_filters'] = array();
$GLOBALS['msp_pg_test_uploads_base'] = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'msp-pg-test-uploads';
$GLOBALS['msp_pg_test_scheduled_events'] = array();
$GLOBALS['msp_pg_test_current_time'] = null;
$GLOBALS['msp_pg_test_wp_mail_calls'] = array();
$GLOBALS['msp_pg_test_redirect_to'] = null;

if (!defined('MSP_PG_VERSION')) {
    define('MSP_PG_VERSION', '2.0.5');
}

if (!function_exists('apply_filters')) {
    function apply_filters($tag, $value)
    {
        return $value;
    }
}

if (!function_exists('add_filter')) {
    function add_filter($tag, $callback, $priority = 10, $acceptedArgs = 1)
    {
        $GLOBALS['msp_pg_test_filters'][$tag][] = array($callback, $priority, $acceptedArgs);
        return true;
    }
}

if (!function_exists('remove_filter')) {
    function remove_filter($tag, $callback, $priority = 10)
    {
        return true;
    }
}

if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p($target)
    {
        return is_dir($target) || mkdir($target, 0777, true);
    }
}

if (!function_exists('wp_normalize_path')) {
    function wp_normalize_path($path)
    {
        return str_replace('\\', '/', $path);
    }
}

if (!function_exists('trailingslashit')) {
    function trailingslashit($string)
    {
        return rtrim($string, '/\\') . '/';
    }
}

if (!function_exists('wp_json_encode')) {
    function wp_json_encode($value, $flags = 0)
    {
        return json_encode($value, $flags);
    }
}

if (!function_exists('sanitize_title_with_dashes')) {
    function sanitize_title_with_dashes($title)
    {
        $title = strtolower($title);
        $title = preg_replace('/[^a-z0-9]+/', '-', $title);
        return trim($title, '-');
    }
}

if (!function_exists('home_url')) {
    function home_url($path = '/')
    {
        return 'https://example.test' . $path;
    }
}

if (!function_exists('wp_parse_url')) {
    function wp_parse_url($url, $component = -1)
    {
        return parse_url($url, $component);
    }
}

if (!function_exists('wp_get_schedules')) {
    function wp_get_schedules()
    {
        return array(
            'hourly' => array(
                'interval' => HOUR_IN_SECONDS,
                'display'  => 'Hourly',
            ),
            'daily' => array(
                'interval' => DAY_IN_SECONDS,
                'display'  => 'Daily',
            ),
        );
    }
}

if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir()
    {
        return array(
            'basedir' => $GLOBALS['msp_pg_test_uploads_base'],
        );
    }
}

if (!function_exists('get_option')) {
    function get_option($name, $default = false)
    {
        return array_key_exists($name, $GLOBALS['msp_pg_test_options']) ? $GLOBALS['msp_pg_test_options'][$name] : $default;
    }
}

if (!function_exists('update_option')) {
    function update_option($name, $value, $autoload = false)
    {
        $GLOBALS['msp_pg_test_options'][$name] = $value;
        return true;
    }
}

if (!function_exists('add_option')) {
    function add_option($name, $value = '', $deprecated = '', $autoload = false)
    {
        if (!array_key_exists($name, $GLOBALS['msp_pg_test_options'])) {
            $GLOBALS['msp_pg_test_options'][$name] = $value;
        }
        return true;
    }
}

if (!function_exists('delete_option')) {
    function delete_option($name)
    {
        unset($GLOBALS['msp_pg_test_options'][$name]);
        return true;
    }
}

if (!function_exists('set_transient')) {
    function set_transient($name, $value, $expiration)
    {
        $GLOBALS['msp_pg_test_transients'][$name] = $value;
        return true;
    }
}

if (!function_exists('get_transient')) {
    function get_transient($name)
    {
        return array_key_exists($name, $GLOBALS['msp_pg_test_transients']) ? $GLOBALS['msp_pg_test_transients'][$name] : false;
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient($name)
    {
        unset($GLOBALS['msp_pg_test_transients'][$name]);
        return true;
    }
}

if (!function_exists('deactivate_plugins')) {
    function deactivate_plugins($plugins, $silent = false)
    {
        $plugins = (array) $plugins;
        $GLOBALS['msp_pg_test_deactivated_plugins'] = array_values(array_unique(array_merge($GLOBALS['msp_pg_test_deactivated_plugins'], $plugins)));
        $active = (array) get_option('active_plugins', array());
        $active = array_values(array_diff($active, $plugins));
        update_option('active_plugins', $active, false);
        return true;
    }
}

if (!function_exists('add_action')) {
    function add_action($tag, $callback, $priority = 10, $acceptedArgs = 1)
    {
        return add_filter($tag, $callback, $priority, $acceptedArgs);
    }
}

if (!function_exists('do_action')) {
    function do_action($tag)
    {
        // no-op in test context
    }
}

if (!function_exists('is_admin')) {
    function is_admin()
    {
        return true;
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can($capability)
    {
        return true;
    }
}

if (!function_exists('wp_schedule_event')) {
    function wp_schedule_event($timestamp, $recurrence, $hook, $args = array(), $wp_error = false)
    {
        $GLOBALS['msp_pg_test_scheduled_events'][$hook] = array(
            'timestamp'  => (int) $timestamp,
            'recurrence' => $recurrence,
        );
        return true;
    }
}

if (!function_exists('wp_schedule_single_event')) {
    function wp_schedule_single_event($timestamp, $hook, $args = array(), $wp_error = false)
    {
        $GLOBALS['msp_pg_test_scheduled_events'][$hook] = array(
            'timestamp'  => (int) $timestamp,
            'recurrence' => 'single',
        );
        return true;
    }
}

if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled($hook, $args = array())
    {
        if (isset($GLOBALS['msp_pg_test_scheduled_events'][$hook])) {
            return $GLOBALS['msp_pg_test_scheduled_events'][$hook]['timestamp'];
        }
        return false;
    }
}

if (!function_exists('wp_clear_scheduled_hook')) {
    function wp_clear_scheduled_hook($hook)
    {
        unset($GLOBALS['msp_pg_test_scheduled_events'][$hook]);
        return 0;
    }
}

if (!function_exists('wp_mail')) {
    function wp_mail($to, $subject, $message, $headers = '', $attachments = array())
    {
        $GLOBALS['msp_pg_test_wp_mail_calls'][] = compact('to', 'subject', 'message', 'headers');
        return true;
    }
}

if (!function_exists('esc_html')) {
    function esc_html($text)
    {
        return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('add_submenu_page')) {
    function add_submenu_page($parent_slug, $page_title, $menu_title, $capability, $menu_slug, $callback = '', $position = null)
    {
        return null;
    }
}

if (!function_exists('wp_die')) {
    function wp_die($message = '', $title = '', $args = array())
    {
        exit((string) $message);
    }
}

if (!function_exists('human_time_diff')) {
    function human_time_diff($from, $to = null)
    {
        if ($to === null) {
            $to = time();
        }
        $diff = abs((int) $to - (int) $from);
        if ($diff < 60) {
            return $diff . ' seconds';
        }
        if ($diff < 3600) {
            return round($diff / 60) . ' minutes';
        }
        return round($diff / 3600) . ' hours';
    }
}

if (!function_exists('get_bloginfo')) {
    function get_bloginfo($show = '')
    {
        return $show === 'version' ? '6.6.1' : '';
    }
}

if (!function_exists('wp_get_theme')) {
    function wp_get_theme()
    {
        return new class {
            public function get($field)
            {
                return $field === 'Name' ? 'Test Theme' : '';
            }
        };
    }
}

if (!class_exists('ZipArchive')) {
    class ZipArchive
    {
        const CREATE = 1;
        const OVERWRITE = 8;

        private $path = '';
        private $entries = array();

        public function open($path, $flags = 0)
        {
            $this->path = $path;
            $this->entries = array();
            return true;
        }

        public function addEmptyDir($localPath)
        {
            $this->entries[] = 'DIR:' . $localPath;
            return true;
        }

        public function addFile($fullPath, $localPath)
        {
            $this->entries[] = 'FILE:' . $localPath . ':' . (is_readable($fullPath) ? sha1_file($fullPath) : '');
            return true;
        }

        public function close()
        {
            return file_put_contents($this->path, implode("\n", $this->entries)) !== false;
        }
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        private $code;
        private $message;

        public function __construct($code = '', $message = '')
        {
            $this->code    = $code;
            $this->message = $message;
        }

        public function get_error_message()
        {
            return $this->message;
        }

        public function get_error_code()
        {
            return $this->code;
        }
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($thing)
    {
        return $thing instanceof WP_Error;
    }
}

if (!function_exists('get_site_url')) {
    function get_site_url($blog_id = null, $path = '', $scheme = null)
    {
        return 'https://example.test' . (string) $path;
    }
}

if (!function_exists('wp_remote_get')) {
    function wp_remote_get($url, $args = array())
    {
        return new WP_Error('http_request_failed', 'HTTP requests are not available in the test environment.');
    }
}

if (!function_exists('wp_remote_retrieve_response_code')) {
    function wp_remote_retrieve_response_code($response)
    {
        return isset($response['response']['code']) ? (int) $response['response']['code'] : 0;
    }
}

if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body($response)
    {
        return isset($response['body']) ? (string) $response['body'] : '';
    }
}

if (!function_exists('wp_unslash')) {
    function wp_unslash($value)
    {
        return is_array($value) ? array_map('wp_unslash', $value) : stripslashes((string) $value);
    }
}

if (!function_exists('wp_create_nonce')) {
    function wp_create_nonce($action = -1)
    {
        return 'test-nonce';
    }
}

if (!function_exists('wp_verify_nonce')) {
    function wp_verify_nonce($nonce, $action = -1)
    {
        return 1;
    }
}

if (!function_exists('check_admin_referer')) {
    function check_admin_referer($action = -1, $query_arg = '_wpnonce')
    {
        return 1;
    }
}

if (!function_exists('wp_nonce_field')) {
    function wp_nonce_field($action = -1, $name = '_wpnonce', $referer = true, $echo = true)
    {
        $field = '<input type="hidden" name="' . esc_attr((string) $name) . '" value="test-nonce">';
        if ($echo) {
            echo $field;
        }
        return $field;
    }
}

if (!function_exists('wp_redirect')) {
    function wp_redirect($location, $status = 302, $x_redirect_by = 'WordPress')
    {
        $GLOBALS['msp_pg_test_redirect_to'] = $location;
        return true;
    }
}

if (!function_exists('sanitize_email')) {
    function sanitize_email($email)
    {
        return filter_var(trim((string) $email), FILTER_SANITIZE_EMAIL);
    }
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str)
    {
        return trim(strip_tags((string) $str));
    }
}

if (!function_exists('sanitize_key')) {
    function sanitize_key($key)
    {
        return preg_replace('/[^a-z0-9_-]/', '', strtolower((string) $key));
    }
}

if (!function_exists('wp_get_current_user')) {
    function wp_get_current_user()
    {
        return (object) array('ID' => 1, 'user_login' => 'admin');
    }
}

if (!function_exists('get_current_user_id')) {
    function get_current_user_id()
    {
        return 1;
    }
}

if (!function_exists('register_setting')) {
    function register_setting($option_group, $option_name, $args = array())
    {
        return true;
    }
}

if (!function_exists('esc_attr')) {
    function esc_attr($text)
    {
        return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_url')) {
    function esc_url($url, $protocols = null, $_context = 'display')
    {
        return (string) $url;
    }
}

if (!function_exists('admin_url')) {
    function admin_url($path = '', $scheme = 'admin')
    {
        return 'https://example.test/wp-admin/' . ltrim((string) $path, '/');
    }
}

if (!function_exists('submit_button')) {
    function submit_button($text = 'Save Changes', $type = 'primary', $name = 'submit', $wrap = true, $other_attributes = '')
    {
        echo '<input type="submit" name="' . esc_attr($name) . '" value="' . esc_attr($text) . '">';
    }
}

if (!function_exists('settings_errors')) {
    function settings_errors($setting = '', $sanitize = false, $hide_on_update = false)
    {
    }
}

require_once dirname(__DIR__) . '/includes/class-msp-pg-config.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-signatures.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-clonedoorway-signatures.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-utils.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-clonedoorway-scanner.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-clonedoorway-remediator.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-feature-extractor.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-behavior-classifier.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-detector.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-runtime.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-whitelist.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-remediator.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-update-verifier.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-updater.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-update-scheduler.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-diagnostics.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-cloud-publisher.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-diagnostics-page.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-plugin-updater.php';
require_once dirname(__DIR__) . '/includes/class-msp-pg-plugin.php';

MSP_PG_UpdateScheduler::init();
MSP_PG_DiagnosticsPage::register();
MSP_PG_PluginUpdater::register();
