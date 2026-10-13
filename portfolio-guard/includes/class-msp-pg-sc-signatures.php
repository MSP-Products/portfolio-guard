<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Registry + deterministic content/structure signatures for the
 * PG-SC-MacroOptimizerCue family (see docs/malware-families/PG-SC-MacroOptimizerCue.md).
 *
 * This is a separate, additive registry from MSP_PG_Signatures/data/signatures.json,
 * for the same reason PG-ClonedDoorway's registry is separate (see that class's
 * docblock): this family's persistence artifacts live in wp-content/mu-plugins/,
 * hidden dot-directories, wp-content's own drop-in filenames, and wp-includes/ --
 * never only inside a single wp-content/plugins/<slug> directory that the existing
 * registry/detector pipeline is built around.
 *
 * Unlike PG-ClonedDoorway, every detection produced from this registry is
 * treated as REPORT-ONLY by MSP_PG_SC_Remediator (no live artifact is moved,
 * quarantined, or deleted) -- a deliberate, explicit scope decision for this
 * family's first release, not a technical limitation. See that class's docblock.
 */
class MSP_PG_SC_Signatures
{
    private static $registry    = null;
    private static $registry_ok = false;

    public static function registry_available()
    {
        if (self::$registry === null) {
            self::load();
        }
        return self::$registry_ok;
    }

    public static function family_id()
    {
        return 'pg-sc-macro-cue';
    }

    public static function family_display_name()
    {
        return 'PG-SC-MacroOptimizerCue';
    }

    public static function known_payload_hashes()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok) {
            return array();
        }
        return array_map('strtoupper', (array) self::$registry['known_payload_hashes_sha256']);
    }

    public static function known_domains()
    {
        if (self::$registry === null) {
            self::load();
        }
        return self::$registry_ok ? (array) self::$registry['known_domains'] : array();
    }

    public static function helper_function_names()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty(self::$registry['structural']['helper_function_names'])) {
            return array('_sc_mkdir', '_sc_fpc', '_sc_ul', '_sc_samedir', '_sc_unp', '_sc_fam', '_sc_phpok_src');
        }
        return (array) self::$registry['structural']['helper_function_names'];
    }

    public static function helper_function_min_matches()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty(self::$registry['structural']['helper_function_min_matches'])) {
            return 3;
        }
        return (int) self::$registry['structural']['helper_function_min_matches'];
    }

    public static function hidden_dir_name_pattern()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty(self::$registry['structural']['hidden_dir_name_pattern'])) {
            return '/^\.sc_[0-9a-f]{6,12}$/';
        }
        return '/' . str_replace('/', '\/', self::$registry['structural']['hidden_dir_name_pattern']) . '/';
    }

    public static function wpincludes_recovery_file_pattern()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty(self::$registry['structural']['wpincludes_recovery_file_pattern'])) {
            return '/^\.g[a-z]?_[0-9a-f]{6,12}(\.php)?$/';
        }
        return '/' . str_replace('/', '\/', self::$registry['structural']['wpincludes_recovery_file_pattern']) . '/';
    }

    public static function reset()
    {
        self::$registry    = null;
        self::$registry_ok = false;
    }

    private static function load()
    {
        $path = defined('MSP_PG_PLUGIN_FILE')
            ? plugin_dir_path(MSP_PG_PLUGIN_FILE) . 'data/signatures-sc-macrocue.json'
            : '';

        if ($path === '' || !file_exists($path) || !is_readable($path)) {
            return;
        }

        $raw = @file_get_contents($path);
        if ($raw === false) {
            return;
        }

        $data = @json_decode($raw, true);
        if (!is_array($data) || !isset($data['schema_version']) || $data['schema_version'] !== 1) {
            return;
        }

        self::$registry    = $data;
        self::$registry_ok = true;
    }

    // -------------------------------------------------------------------------
    // Deterministic content signatures
    //
    // The core payload (core_07a1cd1d.php in the vcadentistry specimen) stores
    // every family-identifying literal (SCV, SC_ADV_BEGIN, sc_cron_fetch,
    // fp9yndwhh1gohpm, ...) in an obfuscated string table decoded only at
    // runtime -- none of those strings exist as plain text in the file. A
    // literal-string signature against that file has zero coverage. Detection
    // here is therefore built on (a) exact hash match against the three known
    // builds, and (b) structural checks that do NOT depend on any of the
    // decoded literals: a version-stamp comment left unobfuscated as a plain
    // PHP comment (comments are never run through the string-table decoder),
    // a drop-in injection marker comment of the same unobfuscated-comment
    // style, and co-occurrence of the kit's helper function *definitions*
    // (bareword `function _sc_xxx(...)` declarations), which appear in the
    // "junk dead-code" obfuscation stage used by the drop-ins/hidden-dir
    // loader files and are never run through the string-table decoder either.
    // -------------------------------------------------------------------------

    /**
     * SC-VER-STAMP: the family's self-reported build-version comment,
     * `/* SCV:#.#.# * /` (any version), used as a boot-version gate marker in
     * every build examined (slim self-heal-directory build and both full-size
     * fake-plugin builds). This is a plain PHP comment, never escaped or
     * decoded, so it survives regardless of per-file string obfuscation.
     */
    public static function has_version_stamp($content)
    {
        return preg_match('/\/\*\s*SCV:\d+\.\d+\.\d+\s*\*\//', $content) === 1;
    }

    /**
     * SC-DROPIN-MARKER: the injection marker this kit leaves at the top of a
     * wp-content drop-in it has tampered with -- `/* SC_<NAME>_BEGIN:ver:buildid * /`
     * (e.g. SC_ADV_BEGIN for advanced-cache.php, SC_DB_BEGIN for db.php).
     *
     * Deliberately NOT keyed on the presence/absence of WP_ROCKET_ADVANCED_CACHE
     * or any other legitimate caching-plugin marker -- confirmed via specimen
     * diff that a genuine WP Rocket advanced-cache.php tail can coexist with
     * this marker (the kit prepends its stub ahead of whatever drop-in already
     * existed) or be entirely absent (observed after WP Rocket was
     * deactivated, the kit regenerated the drop-in containing only its own
     * stub). WP_ROCKET_ADVANCED_CACHE must never be used as a malware signal
     * by any caller of this method.
     */
    public static function has_dropin_injection_marker($content)
    {
        return preg_match('/\/\*\s*SC_[A-Z]+_BEGIN:\d+\.\d+\.\d+:[0-9a-f]{6,8}\s*\*\//', $content) === 1;
    }

    /**
     * SC-HELPER-SET: co-occurrence of at least helper_function_min_matches()
     * (default 3) of the kit's helper function *definitions* in one file.
     * These are bareword `function` declarations -- unescapable PHP syntax --
     * found identically (byte-for-byte dead-code filler included) across the
     * drop-in stubs and the hidden-directory loader-stage files in the
     * specimen, despite those files otherwise using different obfuscation
     * styles from the core payload.
     */
    public static function has_helper_function_set($content)
    {
        $matches = 0;
        foreach (self::helper_function_names() as $name) {
            if (preg_match('/\bfunction\s+' . preg_quote($name, '/') . '\s*\(/', $content) === 1) {
                $matches++;
            }
        }
        return $matches >= self::helper_function_min_matches();
    }

    /**
     * SC-OWN-BEACON: the content shape of this family's own_<hex>.php status
     * beacon file -- `<?php{"v":...,"gen":...,"slug":...,"state":...}`. This
     * is JSON written with a `.php` extension purely to blend into a
     * directory listing; `<?php{` is not valid executable PHP (a parse
     * error), so the file is read, never executed, by the kit itself. Keying
     * on this exact multi-key shape (not just the presence of a dot-file)
     * keeps this check from matching an unrelated plugin's cache/lock file.
     */
    public static function has_own_beacon_shape($content)
    {
        return strpos($content, '<?php{') === 0
            && strpos($content, '"v":') !== false
            && strpos($content, '"gen":') !== false
            && strpos($content, '"slug":') !== false
            && strpos($content, '"state":') !== false;
    }

    /**
     * SC-HIDDEN-DIR: a directory whose basename matches the family's hidden
     * state-directory naming convention (default `.sc_<6-12 hex>`). Pure
     * filesystem structure, independent of file content obfuscation.
     */
    public static function is_hidden_state_directory($dirPath)
    {
        return preg_match(self::hidden_dir_name_pattern(), basename($dirPath)) === 1;
    }

    /**
     * SC-WPINCLUDES-STRAY: a filename directly inside wp-includes/ matching
     * the recovery-loader naming convention this family searches for when
     * self-healing (`.g_<hash>.php` and its sibling throttle/lock markers
     * `.g[a-z]_<hash>`). No legitimate WordPress core file uses a dot-prefixed
     * name matching this shape anywhere in wp-includes/.
     */
    public static function is_wpincludes_recovery_filename($filename)
    {
        return preg_match(self::wpincludes_recovery_file_pattern(), $filename) === 1;
    }
}
