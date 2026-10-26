<?php

if (!defined('ABSPATH')) {
    exit;
}

class MSP_PG_Whitelist
{
    const OPTION_NAME = 'msp_pg_whitelist';

    /**
     * Approve a plugin.
     *
     * Approval follows the plugin, not the version: once an operator has approved a slug, its Tier 2
     * findings stay suppressed on every later version. A plugin that trips the behavioural rules at one
     * version trips them at the next, so a per-version approval only raised the same finding again on
     * every release (and, on a fleet, on every site at once). The version recorded is the one the operator
     * reviewed. Tier 1 (signature) detections are never suppressed.
     */
    public static function add($slug, $version, $userId = 0, $userLogin = '', $note = '')
    {
        $data              = self::load();
        $data[self::key($slug, $version)] = array(
            'slug'       => (string) $slug,
            'version'    => (string) $version,
            'timestamp'  => gmdate('c'),
            'user_id'    => (int) $userId,
            'user_login' => (string) $userLogin,
            'note'       => (string) $note,
        );
        self::save($data);
        return true;
    }

    /**
     * Revoke a plugin's approval, for every version of it: approval follows the plugin, so leaving another
     * version's entry behind would keep the plugin approved. Returns true if anything was removed.
     */
    public static function remove($slug)
    {
        $data      = self::load();
        $remaining = array_filter($data, function ($entry) use ($slug) {
            return !self::is_entry_for($entry, $slug);
        });
        if (count($remaining) === count($data)) {
            return false;
        }
        self::save($remaining);
        return true;
    }

    /**
     * Return true if any version of this plugin has been approved.
     */
    public static function is_approved($slug)
    {
        foreach (self::load() as $entry) {
            if (self::is_entry_for($entry, $slug)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return the whitelist entry for a specific slug/version, or null if absent.
     */
    public static function entry($slug, $version)
    {
        $data = self::load();
        $key  = self::key($slug, $version);
        return isset($data[$key]) ? $data[$key] : null;
    }

    /**
     * Return all whitelist entries as an indexed array, sorted by timestamp descending.
     */
    public static function all()
    {
        $data = array_values(self::load());
        usort($data, function ($a, $b) {
            return strcmp($b['timestamp'], $a['timestamp']);
        });
        return $data;
    }

    /**
     * Return the count of current whitelist entries.
     */
    public static function count()
    {
        return count(self::load());
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private static function key($slug, $version)
    {
        return $slug . ':' . $version;
    }

    private static function is_entry_for($entry, $slug)
    {
        return is_array($entry) && isset($entry['slug']) && $entry['slug'] === (string) $slug;
    }

    private static function load()
    {
        return (array) get_option(self::OPTION_NAME, array());
    }

    private static function save(array $data)
    {
        update_option(self::OPTION_NAME, $data, false);
    }
}
