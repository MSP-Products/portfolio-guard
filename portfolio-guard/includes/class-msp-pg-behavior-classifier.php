<?php

if (!defined('ABSPATH')) {
    exit;
}

class MSP_PG_BehaviorClassifier
{
    /**
     * Evaluate which behavior profiles activate for a given set of signal observations.
     *
     * Input:  observations array produced by MSP_PG_FeatureExtractor::extract()
     * Output: array of activated profile records, each containing:
     *   profile_id       — identifier from Spec 005 §6
     *   profile_label    — human-readable profile name
     *   summary          — sentence specific to the observed signals (Spec 005 §10)
     *   signals_observed — subset of input observations relevant to this profile
     *
     * This method classifies only. It does not determine Tier 2 outcomes, trigger
     * remediation, or modify any plugin state. Profile activation records are consumed
     * by the reporting layer (Milestone 3.3).
     */
    public static function classify(array $observations)
    {
        $activated = array();

        foreach (array_keys(self::profile_configs()) as $profileId) {
            if (!self::activates($profileId, $observations)) {
                continue;
            }

            $evidence = self::collect_evidence($profileId, $observations);

            $activated[] = array(
                'profile_id'       => $profileId,
                'profile_label'    => self::profile_configs()[$profileId]['label'],
                'summary'          => self::generate_summary($profileId, $evidence),
                'signals_observed' => $evidence,
            );
        }

        return $activated;
    }

    /**
     * Return true if a specific profile is activated by the given observations.
     * Activation uses a weighted scoring model: each present signal contributes
     * its weight; the profile activates when the total meets the threshold.
     * Exposed for targeted testing and classifier transparency.
     */
    public static function activates($profileId, array $observations)
    {
        $configs = self::profile_configs();
        if (!isset($configs[$profileId])) {
            return false;
        }

        $config    = $configs[$profileId];
        $threshold = $config['threshold'];
        $score     = 0;

        foreach ($config['weights'] as $signalId => $weight) {
            if (MSP_PG_FeatureExtractor::has_signal($observations, $signalId)) {
                $score += $weight;
                if ($score >= $threshold) {
                    return true;
                }
            }
        }

        return $score >= $threshold;
    }

    /**
     * Return the full signal contribution matrix for a profile against the given
     * observations. Useful for calibration, debugging, and operator transparency.
     */
    public static function explain($profileId, array $observations)
    {
        $configs = self::profile_configs();
        if (!isset($configs[$profileId])) {
            return null;
        }

        $config    = $configs[$profileId];
        $threshold = $config['threshold'];
        $score     = 0;
        $signals   = array();

        foreach ($config['weights'] as $signalId => $weight) {
            $present = MSP_PG_FeatureExtractor::has_signal($observations, $signalId);
            if ($present) {
                $score += $weight;
            }
            $signals[$signalId] = array(
                'weight'  => $weight,
                'present' => $present,
            );
        }

        return array(
            'profile_id' => $profileId,
            'label'      => $config['label'],
            'threshold'  => $threshold,
            'score'      => $score,
            'activates'  => $score >= $threshold,
            'signals'    => $signals,
        );
    }

    /**
     * Return the explain() matrix for every profile against the given observations.
     * Keyed by profile ID. Used to build the evidence snapshot stored in scan state
     * for operator review in the diagnostics page.
     */
    public static function explain_all(array $observations)
    {
        $result = array();
        foreach (array_keys(self::profile_configs()) as $profileId) {
            $result[$profileId] = self::explain($profileId, $observations);
        }
        return $result;
    }

    // -------------------------------------------------------------------------
    // Profile configs: label, activation threshold, and per-signal weights.
    // Weights reflect specificity: family-specific strings score 100 (activate
    // alone at threshold 50); generic signals require corroboration.
    // Configurable at runtime via the msp_pg_behavior_classifier_profiles filter.
    // -------------------------------------------------------------------------

    private static function profile_configs()
    {
        return apply_filters('msp_pg_behavior_classifier_profiles', array(
            'persistence' => array(
                'label'     => 'Persistence',
                'threshold' => 85, // calibrated: HP-01/HP-02 (100) activate; generic combos peak at 80
                'weights'   => array(
                    'HP-01' => 100, // removes self from plugin list — unambiguous
                    'HP-02' => 100, // hooks template_redirect pre-deactivation — unambiguous
                    'FC-08' =>  30, // cron registration — generic
                    'FC-01' =>  20, // REST endpoint — generic, insufficient alone
                    'CB-01' =>  15, // unauthenticated callback — generic
                    'SP-01' =>  15, // concealed staging structure — generic
                ),
            ),
            'command-and-control' => array(
                'label'     => 'Command & Control',
                'threshold' => 100, // calibrated: family SM/KB strings (100 each) activate; FC combos (max 95) don't
                'weights'   => array(
                    'SM-01' => 100, // known family bootstrap string — family-specific
                    'SM-02' => 100,
                    'SM-03' => 100,
                    'SM-04' => 100,
                    'SM-05' => 100,
                    'KB-02' => 100, // known family string pattern — family-specific
                    'FC-01' =>  30, // REST endpoint — generic, requires family-string corroboration
                    'FC-02' =>  25, // outbound HTTP — generic, requires family-string corroboration
                    'CB-01' =>  25, // unauthenticated callback — generic
                    'FC-08' =>  15, // cron registration — generic
                ),
            ),
            'payload-delivery' => array(
                'label'     => 'Payload Delivery',
                'threshold' => 50,
                'weights'   => array(
                    'DM-01' =>  80, // dynamic createElement in PHP output — specific
                    'SP-01' =>  20, // calibrated: weight reduced from 60; matches standard dirs (admin, class, assets)
                    'SP-02' =>  40, // secondary staging pattern — moderately specific
                    'FC-07' =>  15, // script enqueue — extremely common in clean plugins
                ),
            ),
            'operator-access' => array(
                'label'     => 'Operator Access',
                'threshold' => 65, // calibrated: FC-03+FC-04 (70) activates; FC-03 alone or with redirects (max 50) doesn't
                'weights'   => array(
                    'KB-01' => 100, // known auth impersonation pattern — family-specific
                    'LB-01' =>  70, // login cookie + account creation/elevation + privileged capability + request trigger, all in one file
                    'FC-03' =>  30, // calibrated: wp_set_auth_cookie appears in legitimate remote-management plugins
                    'FC-04' =>  40, // raw setcookie — token-write corroboration, rare in legitimate plugins
                    'FC-06' =>  10, // calibrated: wp_safe_redirect is generic (any admin form uses it)
                    'FC-05' =>  10, // calibrated: $_COOKIE common in vendor/PSR library interfaces
                ),
            ),
            'stealth' => array(
                'label'     => 'Stealth',
                'threshold' => 60, // calibrated: HP-01 (100) and HP-02 (80) activate; CB-01+FC-01 (40) doesn't
                'weights'   => array(
                    'HP-01' => 100, // self-removal from plugin list — unambiguous
                    'HP-02' =>  80, // template_redirect hook — specific
                    'CB-01' =>  20, // calibrated: public REST endpoints use __return_true legitimately
                    'FC-01' =>  20, // REST endpoint — generic
                ),
            ),
        ));
    }

    // -------------------------------------------------------------------------
    // Evidence collection
    // -------------------------------------------------------------------------

    private static function collect_evidence($profileId, array $observations)
    {
        $config   = self::profile_configs()[$profileId];
        $evidence = array();

        foreach (array_keys($config['weights']) as $signalId) {
            foreach (MSP_PG_FeatureExtractor::find_by_signal($observations, $signalId) as $obs) {
                $evidence[] = $obs;
            }
        }

        return $evidence;
    }

    // -------------------------------------------------------------------------
    // Summary generation — specific to observed signals (Spec 005 §10, criterion 4)
    // -------------------------------------------------------------------------

    private static function generate_summary($profileId, array $evidence)
    {
        // Index evidence by signal_id for targeted sentence construction
        $bySignal = array();
        foreach ($evidence as $obs) {
            $bySignal[$obs['signal_id']][] = $obs;
        }

        $parts = array();

        switch ($profileId) {
            case 'persistence':
                if (isset($bySignal['HP-01'])) {
                    $parts[] = 'removes itself from the WordPress plugin list (`'
                        . $bySignal['HP-01'][0]['matched_string'] . '` in '
                        . $bySignal['HP-01'][0]['file'] . ')';
                }
                if (isset($bySignal['HP-02'])) {
                    $parts[] = 'hooks early-execution template redirect (`'
                        . $bySignal['HP-02'][0]['matched_string'] . '` in '
                        . $bySignal['HP-02'][0]['file'] . ')';
                }
                if (isset($bySignal['FC-01'])) {
                    $parts[] = 'registers a persistent REST endpoint (`'
                        . $bySignal['FC-01'][0]['matched_string'] . '` in '
                        . $bySignal['FC-01'][0]['file'] . ')';
                }
                return 'This plugin exhibits Persistence: it ' . self::join_parts($parts) . '.';

            case 'command-and-control':
                foreach (array('SM-01', 'SM-02', 'KB-02') as $smId) {
                    if (isset($bySignal[$smId])) {
                        $parts[] = 'contains known C2 bootstrap strings (`'
                            . $bySignal[$smId][0]['matched_string'] . '` in '
                            . $bySignal[$smId][0]['file'] . ')';
                        break;
                    }
                }
                if (isset($bySignal['SM-03'])) {
                    $parts[] = 'contains known C2 session identifier (`'
                        . $bySignal['SM-03'][0]['matched_string'] . '`)';
                }
                if (isset($bySignal['SM-04'])) {
                    $parts[] = 'references a known C2 configuration endpoint (`'
                        . $bySignal['SM-04'][0]['matched_string'] . '` in '
                        . $bySignal['SM-04'][0]['file'] . ')';
                }
                if (isset($bySignal['FC-01'])) {
                    $suffix = isset($bySignal['CB-01'])
                        ? 'accessible without authentication'
                        : 'for external interaction';
                    $parts[] = 'registers a REST endpoint ' . $suffix . ' (`'
                        . $bySignal['FC-01'][0]['matched_string'] . '` in '
                        . $bySignal['FC-01'][0]['file'] . ')';
                }
                if (isset($bySignal['FC-02'])) {
                    $parts[] = 'makes outbound HTTP requests (`'
                        . $bySignal['FC-02'][0]['matched_string'] . '` in '
                        . $bySignal['FC-02'][0]['file'] . ')';
                }
                return 'This plugin exhibits Command & Control: it ' . self::join_parts($parts) . '.';

            case 'payload-delivery':
                if (isset($bySignal['DM-01'])) {
                    $parts[] = 'dynamically injects JavaScript into page output (`'
                        . $bySignal['DM-01'][0]['matched_string'] . '` in '
                        . $bySignal['DM-01'][0]['file'] . ')';
                }
                if (isset($bySignal['SP-01'])) {
                    $parts[] = 'contains a concealed payload staging structure (`'
                        . $bySignal['SP-01'][0]['matched_string'] . '`)';
                }
                if (isset($bySignal['FC-07'])) {
                    $parts[] = 'registers or enqueues scripts dynamically (`'
                        . $bySignal['FC-07'][0]['matched_string'] . '` in '
                        . $bySignal['FC-07'][0]['file'] . ')';
                }
                return 'This plugin exhibits Payload Delivery: it ' . self::join_parts($parts) . '.';

            case 'operator-access':
                if (isset($bySignal['KB-01'])) {
                    $parts[] = 'contains a known authentication impersonation pattern (`'
                        . $bySignal['KB-01'][0]['matched_string'] . '` in '
                        . $bySignal['KB-01'][0]['file'] . ')';
                }
                if (isset($bySignal['LB-01'])) {
                    $parts[] = 'combines a login cookie, a privileged account and a request-parameter trigger in one file, the shape of a login backdoor (`'
                        . $bySignal['LB-01'][0]['matched_string'] . '` in '
                        . $bySignal['LB-01'][0]['file'] . ')';
                }
                if (isset($bySignal['FC-03'])) {
                    $parts[] = 'creates WordPress authentication cookies (`'
                        . $bySignal['FC-03'][0]['matched_string'] . '` in '
                        . $bySignal['FC-03'][0]['file'] . ')';
                }
                if (isset($bySignal['FC-06'])) {
                    $parts[] = 'redirects to the admin area after session creation (`'
                        . $bySignal['FC-06'][0]['matched_string'] . '`)';
                }
                if (isset($bySignal['FC-05'])) {
                    $parts[] = 'reads or manipulates cookies for session control (`'
                        . $bySignal['FC-05'][0]['matched_string'] . '`)';
                }
                return 'This plugin exhibits Operator Access: it ' . self::join_parts($parts) . '.';

            case 'stealth':
                if (isset($bySignal['HP-01'])) {
                    $parts[] = 'removes itself from the WordPress plugin list (`'
                        . $bySignal['HP-01'][0]['matched_string'] . '` in '
                        . $bySignal['HP-01'][0]['file'] . ')';
                }
                if (isset($bySignal['CB-01'])) {
                    $parts[] = 'registers REST endpoints that require no authentication, leaving no admin trace (`'
                        . $bySignal['CB-01'][0]['matched_string'] . '` in '
                        . $bySignal['CB-01'][0]['file'] . ')';
                }
                if (isset($bySignal['HP-02'])) {
                    $parts[] = 'hooks template redirect for execution without visible admin output (`'
                        . $bySignal['HP-02'][0]['matched_string'] . '`)';
                }
                return 'This plugin exhibits Stealth: it ' . self::join_parts($parts) . '.';
        }

        return '';
    }

    private static function join_parts(array $parts)
    {
        if (empty($parts)) {
            return 'exhibits behavioral signals without further detail';
        }
        if (count($parts) === 1) {
            return $parts[0];
        }
        $last = array_pop($parts);
        return implode(', ', $parts) . ', and ' . $last;
    }
}
