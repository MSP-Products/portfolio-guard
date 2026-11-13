<?php

if (!defined('ABSPATH')) {
    exit;
}

class MSP_PG_FeatureExtractor
{
    /**
     * Extract all observable signals from a plugin directory.
     *
     * Returns an array of signal observation records, each containing:
     *   signal_id      — identifier from the Spec 005 signal taxonomy
     *   signal_label   — human-readable description
     *   file           — relative file path where the signal was observed
     *   matched_string — the exact string or pattern description that fired
     *
     * Output is sorted by signal_id then file for determinism.
     * One observation is produced per unique (signal_id, file) pair.
     *
     * This method observes only. It does not classify, score, or determine
     * whether any profile activates or any Tier 2 outcome is warranted.
     */
    public static function extract($pluginDir)
    {
        $observations = array();

        self::extract_file_signals($pluginDir, $observations);
        self::extract_structural_signals($pluginDir, $observations);

        usort($observations, function ($a, $b) {
            $cmp = strcmp($a['signal_id'], $b['signal_id']);
            return $cmp !== 0 ? $cmp : strcmp($a['file'], $b['file']);
        });

        return $observations;
    }

    /**
     * Return all observations for a specific signal ID.
     */
    public static function find_by_signal(array $observations, $signalId)
    {
        return array_values(array_filter($observations, function ($obs) use ($signalId) {
            return $obs['signal_id'] === $signalId;
        }));
    }

    /**
     * Return true if the given signal ID is present in the observations.
     */
    public static function has_signal(array $observations, $signalId)
    {
        foreach ($observations as $obs) {
            if ($obs['signal_id'] === $signalId) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Internal extraction
    // -------------------------------------------------------------------------

    private static function extract_file_signals($pluginDir, array &$observations)
    {
        $extensions = MSP_PG_Config::scan_extensions();
        $maxBytes   = MSP_PG_Config::max_scan_file_bytes();
        $stringDefs = self::string_signal_definitions();
        $seen       = array();

        foreach (MSP_PG_Utils::recursive_files($pluginDir) as $file) {
            $relative  = str_replace('\\', '/', MSP_PG_Utils::relative_path($file, $pluginDir));
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));

            if (!in_array($extension, $extensions, true)) {
                continue;
            }
            if ((int) filesize($file) > $maxBytes) {
                continue;
            }

            $contents = @file_get_contents($file);
            if ($contents === false) {
                continue;
            }

            // String-based signals: one observation per (signal_id, file) pair
            // DM-01 is only meaningful in PHP output context; skip it for JS/other files
            // to avoid false positives from bundled JS libraries (e.g. jQuery).
            $phpOnly = array('DM-01');
            foreach ($stringDefs as $signalId => $def) {
                if (in_array($signalId, $phpOnly, true) && $extension !== 'php') {
                    continue;
                }
                $dedupKey = $signalId . ':' . $relative;
                if (isset($seen[$dedupKey])) {
                    continue;
                }
                foreach ($def['strings'] as $search) {
                    if (strpos($contents, $search) !== false) {
                        $observations[] = self::observation($signalId, $def['label'], $relative, $search);
                        $seen[$dedupKey] = true;
                        break;
                    }
                }
            }

            // KB-01: authentication impersonation triplet (all three strings in one file)
            foreach (MSP_PG_Signatures::backdoor_pairs() as $pair) {
                if (
                    strpos($contents, $pair['id_param']) !== false &&
                    strpos($contents, $pair['token_param']) !== false &&
                    strpos($contents, $pair['token_value']) !== false
                ) {
                    $dedupKey = 'KB-01:' . $relative;
                    if (!isset($seen[$dedupKey])) {
                        $observations[] = self::observation(
                            'KB-01',
                            'Known authentication impersonation triplet',
                            $relative,
                            $pair['id_param']
                        );
                        $seen[$dedupKey] = true;
                    }
                    break;
                }
            }

            // KB-02: bootstrap pattern (any of SM-01, SM-02, SM-03 strings)
            foreach (array('fastreactic_nanomicroserviceing', 'tridatation_quicktypescriptal', 'data-ph-pid') as $bootstrapStr) {
                if (strpos($contents, $bootstrapStr) !== false) {
                    $dedupKey = 'KB-02:' . $relative;
                    if (!isset($seen[$dedupKey])) {
                        $observations[] = self::observation(
                            'KB-02',
                            'Known family bootstrap pattern',
                            $relative,
                            $bootstrapStr
                        );
                        $seen[$dedupKey] = true;
                    }
                    break;
                }
            }

            if ($extension === 'php') {
                self::add_login_backdoor_signal($contents, $relative, $observations, $seen);
            }
        }
    }

    /**
     * LB-01: one PHP file that issues a login cookie, creates or elevates an account, names a
     * privileged capability, and is triggered by a request parameter. Each part is common in
     * legitimate code (remote-management plugins set auth cookies), so only the combination
     * in a single file counts. A plugin-wide score cannot express "same file", which is why
     * this is a signal of its own rather than a weight on the existing ones.
     */
    private static function add_login_backdoor_signal($contents, $relative, array &$observations, array &$seen)
    {
        $dedupKey = 'LB-01:' . $relative;
        if (isset($seen[$dedupKey])) {
            return;
        }

        $evidence = self::login_backdoor_evidence($contents);
        if ($evidence === '') {
            return;
        }

        $observations[] = self::observation('LB-01', 'Login backdoor combination', $relative, $evidence);
        $seen[$dedupKey] = true;
    }

    private static function login_backdoor_evidence($contents)
    {
        $matched = array();
        foreach (self::login_backdoor_requirements() as $alternatives) {
            $found = self::first_present($contents, $alternatives);
            if ($found === '') {
                return '';
            }
            $matched[] = $found;
        }
        return implode(' + ', $matched);
    }

    private static function first_present($contents, array $alternatives)
    {
        foreach ($alternatives as $search) {
            if (strpos($contents, $search) !== false) {
                return $search;
            }
        }
        return '';
    }

    /**
     * Every group must have at least one member present in the same file.
     */
    private static function login_backdoor_requirements()
    {
        return array(
            array('wp_set_auth_cookie('),
            array('wp_insert_user(', 'wp_create_user(', 'add_cap(', 'set_role('),
            array('manage_options', 'install_plugins', 'administrator'),
            array('$_GET[', '$_REQUEST[', '$_POST['),
        );
    }

    private static function extract_structural_signals($pluginDir, array &$observations)
    {
        $structure = MSP_PG_Utils::random_payload_structure($pluginDir);

        // SP-01: concealed payload staging (random short dir + random 8-char PHP file)
        if (!empty($structure['directories']) && !empty($structure['php_files'])) {
            $dir     = reset($structure['directories']);
            $phpFile = reset($structure['php_files']);
            $observations[] = self::observation(
                'SP-01',
                'Concealed payload staging structure',
                $dir,
                'directory:' . basename($dir) . ', file:' . basename($phpFile)
            );
        }

        // SP-02: concealed asset staging (random 8-char JS under assets/)
        if (!empty($structure['asset_js'])) {
            $jsFile = reset($structure['asset_js']);
            $observations[] = self::observation(
                'SP-02',
                'Concealed asset staging',
                $jsFile,
                basename($jsFile)
            );
        }
    }

    private static function observation($signalId, $signalLabel, $file, $matchedString)
    {
        return array(
            'signal_id'      => $signalId,
            'signal_label'   => $signalLabel,
            'file'           => $file,
            'matched_string' => $matchedString,
        );
    }

    // -------------------------------------------------------------------------
    // Signal taxonomy (Spec 005 §7)
    // -------------------------------------------------------------------------

    private static function string_signal_definitions()
    {
        return array(
            // String Marker Signals (SM) — Spec 005 §7.1
            'SM-01' => array(
                'label'   => 'Known family bootstrap string (fastreactic)',
                'strings' => array('fastreactic_nanomicroserviceing'),
            ),
            'SM-02' => array(
                'label'   => 'Known family bootstrap string (tridatation)',
                'strings' => array('tridatation_quicktypescriptal'),
            ),
            'SM-03' => array(
                'label'   => 'Known C2 session identifier',
                'strings' => array('data-ph-pid'),
            ),
            'SM-04' => array(
                'label'   => 'Known C2 configuration endpoint',
                'strings' => array('/api/config/'),
            ),
            'SM-05' => array(
                'label'   => 'Known C2 event tracking endpoint',
                'strings' => array('/api/click'),
            ),
            // Function Call Signals (FC) — Spec 005 §7.2
            'FC-01' => array(
                'label'   => 'REST endpoint registration',
                'strings' => array('register_rest_route('),
            ),
            'FC-02' => array(
                'label'   => 'Outbound HTTP request',
                'strings' => array('wp_remote_get(', 'wp_remote_post(', 'wp_remote_request('),
            ),
            'FC-03' => array(
                'label'   => 'Authentication cookie creation',
                'strings' => array('wp_set_auth_cookie('),
            ),
            'FC-04' => array(
                'label'   => 'Raw cookie write',
                'strings' => array('setcookie('),
            ),
            'FC-05' => array(
                'label'   => 'Cookie read or manipulation',
                'strings' => array('$_COOKIE'),
            ),
            'FC-06' => array(
                'label'   => 'Post-authentication redirect',
                'strings' => array('wp_safe_redirect('),
            ),
            'FC-07' => array(
                'label'   => 'Script registration or inline injection',
                'strings' => array('wp_register_script(', 'wp_enqueue_script(', 'wp_add_inline_script('),
            ),
            'FC-08' => array(
                'label'   => 'AJAX handler registration',
                // Check nopriv first — more specific; wp_ajax_ also matches nopriv handlers
                'strings' => array('wp_ajax_nopriv_', 'wp_ajax_'),
            ),
            // Hook Pattern Signals (HP) — Spec 005 §7.3
            'HP-01' => array(
                'label'   => 'Plugin list filter',
                // Both quote styles, compact form only. The WordPress-style spaced form (`add_filter( 'all_plugins'`)
                // is deliberately NOT matched: calibration found 15 files in mainwp-child 4.6 using it to hide the
                // child plugin on request, so matching it would flag every WPCS-formatted plugin that filters the list.
                'strings' => array("add_filter('all_plugins'", 'add_filter("all_plugins"'),
            ),
            'HP-02' => array(
                'label'   => 'Template redirect hook',
                'strings' => array("add_action('template_redirect'"),
            ),
            // DOM Manipulation Signals (DM) — Spec 005 §7.4
            'DM-01' => array(
                'label'   => 'Dynamic JavaScript element creation',
                'strings' => array("createElement('script')", 'createElement("script")'),
            ),
            // Callback Pattern Signals (CB) — Spec 005 §7.5
            'CB-01' => array(
                'label'   => 'Unauthenticated REST access',
                'strings' => array("permission_callback' => '__return_true'"),
            ),
        );
    }
}
