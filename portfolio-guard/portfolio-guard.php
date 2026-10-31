<?php
/**
 * Plugin Name: MSP Portfolio Guard
 * Description: Family-specific WordPress malware detection and remediation for MSP fleet deployment.
 * Version: 2.2.1
 * Author: My Social Practice
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

define('MSP_PG_VERSION', '2.2.1');
define('MSP_PG_PLUGIN_FILE', __FILE__);
define('MSP_PG_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('MSP_PG_PLUGIN_BASENAME', plugin_basename(__FILE__));

require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-config.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-signatures.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-clonedoorway-signatures.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-utils.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-clonedoorway-scanner.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-clonedoorway-remediator.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-sc-signatures.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-sc-scanner.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-sc-remediator.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-wlh-signatures.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-wlh-scanner.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-wlh-remediator.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-doorwaygen-signatures.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-doorwaygen-scanner.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-doorwaygen-remediator.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-feature-extractor.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-behavior-classifier.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-detector.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-runtime.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-whitelist.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-remediator.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-update-verifier.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-updater.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-update-scheduler.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-diagnostics.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-cloud-publisher.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-report-publisher.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-diagnostics-page.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-plugin-updater.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-availability.php';
require_once MSP_PG_PLUGIN_DIR . 'includes/class-msp-pg-plugin.php';

register_activation_hook(MSP_PG_PLUGIN_FILE, array('MSP_PG_Plugin', 'activate'));
register_activation_hook(MSP_PG_PLUGIN_FILE, array('MSP_PG_UpdateScheduler', 'activate'));
register_activation_hook(MSP_PG_PLUGIN_FILE, array('MSP_PG_Availability', 'activate'));
register_deactivation_hook(MSP_PG_PLUGIN_FILE, array('MSP_PG_Plugin', 'deactivate'));
register_deactivation_hook(MSP_PG_PLUGIN_FILE, array('MSP_PG_UpdateScheduler', 'deactivate'));
register_deactivation_hook(MSP_PG_PLUGIN_FILE, array('MSP_PG_Availability', 'deactivate'));
register_uninstall_hook(MSP_PG_PLUGIN_FILE, array('MSP_PG_Plugin', 'uninstall'));

add_action('plugins_loaded', array('MSP_PG_UpdateScheduler', 'init'));
MSP_PG_DiagnosticsPage::register();
MSP_PG_PluginUpdater::register();
MSP_PG_Availability::register();
MSP_PG_Plugin::instance();
