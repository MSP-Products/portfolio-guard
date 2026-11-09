<?php
/**
 * Portfolio Guard Behavior Classifier Calibration Script
 *
 * Produces a full calibration report for every plugin in the clean-plugins
 * and known-malware corpora using the explain() API. Run from the validation/
 * directory:
 *
 *   php calibrate.php
 *
 * Output is written to calibration-report.txt in the same directory.
 */

$validationDir = __DIR__;
$testsDir      = dirname($validationDir) . DIRECTORY_SEPARATOR . 'portfolio-guard' . DIRECTORY_SEPARATOR . 'tests';

require_once $testsDir . DIRECTORY_SEPARATOR . 'bootstrap.php';

$cleanDir   = $validationDir . DIRECTORY_SEPARATOR . 'corpus' . DIRECTORY_SEPARATOR . 'clean-plugins';
$malwareDir = $validationDir . DIRECTORY_SEPARATOR . 'corpus' . DIRECTORY_SEPARATOR . 'known-malware';
$syntheticDir = $validationDir . DIRECTORY_SEPARATOR . 'corpus' . DIRECTORY_SEPARATOR . 'synthetic';
$profiles   = array('persistence', 'command-and-control', 'payload-delivery', 'operator-access', 'stealth');

$lines = array();

function h1($text) { return array('', str_repeat('=', 72), $text, str_repeat('=', 72)); }
function h2($text) { return array('', "--- $text ---"); }
function row($label, $value, $indent = 2) { return array(str_repeat(' ', $indent) . str_pad($label . ':', 32) . $value); }

function corpus_report($corpusDir, $corpusLabel, $profiles, $hitLabel = 'False positives') {
    $out = array();
    $out = array_merge($out, h1("CORPUS: $corpusLabel"));

    $dirs = glob($corpusDir . DIRECTORY_SEPARATOR . '*', GLOB_ONLYDIR);
    if (!$dirs) {
        $out[] = '  (empty)';
        return $out;
    }

    $falsePositives = array(); // [plugin => [profile, ...]]
    $trueMalware    = array();

    foreach ($dirs as $pluginDir) {
        $pluginName   = basename($pluginDir);
        $observations = MSP_PG_FeatureExtractor::extract($pluginDir);
        $sigCount     = count($observations);

        $out = array_merge($out, h2($pluginName));
        $out[] = "  Signals extracted: $sigCount";

        $activated = array();

        foreach ($profiles as $profileId) {
            $e = MSP_PG_BehaviorClassifier::explain($profileId, $observations);

            $status     = $e['activates'] ? '*** ACTIVATED ***' : 'not activated';
            $scoreStr   = $e['score'] . ' / ' . $e['threshold'];
            $presentSigs = array_filter($e['signals'], function ($s) { return $s['present']; });

            $out[] = '';
            $out[] = "  Profile: {$e['profile_id']} ({$e['label']})";
            $out[] = "    Score:     $scoreStr  |  $status";

            if (!empty($presentSigs)) {
                $out[] = '    Present signals:';
                foreach ($presentSigs as $signalId => $info) {
                    $out[] = "      + $signalId  (weight {$info['weight']})";
                    // Show observation details from evidence
                    foreach (MSP_PG_FeatureExtractor::find_by_signal($observations, $signalId) as $obs) {
                        $file    = $obs['file'];
                        $matched = strlen($obs['matched_string']) > 60
                            ? substr($obs['matched_string'], 0, 57) . '...'
                            : $obs['matched_string'];
                        $out[] = "          file: $file";
                        $out[] = "          matched: $matched";
                    }
                }
            } else {
                $out[] = '    Present signals: (none)';
            }

            if ($e['activates']) {
                $activated[] = $profileId;
            }
        }

        $out[] = '';
        if (!empty($activated)) {
            $out[] = "  ** ACTIVATED PROFILES: " . implode(', ', $activated) . " **";
        } else {
            $out[] = "  Result: CLEAN (no profiles activated)";
        }

        if (!empty($activated)) {
            $falsePositives[$pluginName] = $activated;
        }
    }

    $out = array_merge($out, h1("$corpusLabel SUMMARY"));
    $total = count($dirs);
    $fpCount = count($falsePositives);
    $out[] = "  Total plugins: $total";
    $out[] = "  $hitLabel: $fpCount / $total";

    if (!empty($falsePositives)) {
        $out[] = '';
        $out[] = "  $hitLabel list:";
        foreach ($falsePositives as $plugin => $profiles) {
            $out[] = "    - $plugin: " . implode(', ', $profiles);
        }
    }

    return $out;
}

$lines = array_merge($lines, array(
    'Portfolio Guard 2.0.2 — Behavior Classifier Calibration Report',
    'Generated: ' . date('Y-m-d H:i:s') . ' UTC',
    '',
    'Classifier version:    ' . MSP_PG_Config::heuristic_version(),
    'Signature version:     ' . MSP_PG_Config::signature_version(),
    '',
));

$lines = array_merge($lines, corpus_report($cleanDir,   'CLEAN PLUGINS',  $profiles));
$lines = array_merge($lines, corpus_report($malwareDir, 'KNOWN MALWARE',  $profiles));
// Fixtures that must activate a profile, so a high count here is the goal, not a problem.
$lines = array_merge($lines, corpus_report($syntheticDir, 'SYNTHETIC BEHAVIOUR FIXTURES',  $profiles, 'Fixtures caught'));

$output = implode("\n", $lines) . "\n";

$reportPath = $validationDir . DIRECTORY_SEPARATOR . 'calibration-report.txt';
file_put_contents($reportPath, $output);

echo $output;
echo "\n[Report written to $reportPath]\n";
