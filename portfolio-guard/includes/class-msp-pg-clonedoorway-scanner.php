<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Filesystem scanner for the PG-ClonedDoorway family (see
 * docs/malware-families/PG-ClonedDoorway.md and
 * class-msp-pg-clonedoorway-signatures.php for signature rationale).
 *
 * This is Portfolio Guard's second deterministic scan source. The existing
 * MSP_PG_Detector/MSP_PG_Remediator plugin loop is untouched by this file --
 * it only ever looks at wp-content/plugins/<slug> directories, which is not
 * where this family's artifacts live. This scanner instead walks the web
 * root looking specifically for this family's structural/content signatures.
 *
 * Deliberately NOT a general-purpose filesystem antivirus:
 *  - It does not classify arbitrary files; it only evaluates the specific
 *    deterministic checks in MSP_PG_ClonedDoorway_Signatures.
 *  - It does not recurse into wp-content/plugins (owned by the existing
 *    scanner), wp-content/uploads (media-heavy, no confirmed artifacts of
 *    this family were found there), or wp-content/themes (no confirmed
 *    artifacts found there either -- see family doc "Known scope boundaries"
 *    for what would justify widening this).
 *  - Content signatures are only evaluated against files inside a directory
 *    that already matched the clone-triad structural signature, or against
 *    loose PHP files directly at web root -- never against arbitrary files
 *    deep inside wp-admin/wp-includes, which are only walked to *locate*
 *    clone-triad directories (a cheap structural check, no content read).
 */
class MSP_PG_ClonedDoorway_Scanner
{
    const ARTIFACT_CLONE_DIRECTORY   = 'clone_directory';
    const ARTIFACT_LOOSE_LOADER_FILE = 'loose_loader_file';
    const ARTIFACT_MODIFIED_CORE_FILE = 'modified_core_file';

    private static $reasonWeights = array(
        'clone_directory_structure'  => 100,
        'known_htaccess_hash'        => 100,
        'cache_gate_pattern'         => 50,
        'zip_stream_stego'           => 50,
        'comment_split_obfuscation'  => 25,
        'cookie_count_eval_gate'     => 100,
        'self_dump_pattern'          => 50,
        'goto_curl_pattern'          => 100,
        'known_domain'               => 75,
    );

    /**
     * Runs the scan and returns an array of analysis records shaped
     * compatibly with MSP_PG_Detector::detect()'s return contract, so they
     * drop into MSP_PG_Remediator::run_scan()'s existing $detections[]
     * pipeline (report building, email, state storage) unchanged.
     *
     * Field names like plugin_slug/plugin_dir/protected_plugin are reused
     * as-is even though these artifacts are not plugins -- see family doc
     * "Reusable abstractions considered but not built" for why renaming
     * those fields repository-wide was judged out of scope for this task.
     */
    public static function scan()
    {
        if (!MSP_PG_ClonedDoorway_Signatures::registry_available()) {
            return array();
        }

        $root = MSP_PG_Config::cloned_doorway_scan_root();
        if ($root === '' || !is_dir($root)) {
            return array();
        }

        $analyses = array();

        foreach (self::find_clone_triad_roots($root) as $triadRoot) {
            $analyses[] = self::build_clone_directory_analysis($triadRoot, $root);
        }

        foreach (self::scan_loose_root_files($root) as $fileAnalysis) {
            $analyses[] = $fileAnalysis;
        }

        return $analyses;
    }

    // -------------------------------------------------------------------------
    // Clone-triad directory discovery
    // -------------------------------------------------------------------------

    private static function find_clone_triad_roots($root)
    {
        $roots = array();

        foreach (self::top_level_scan_dirs($root) as $startDir) {
            self::walk_for_triads($startDir, $roots);
        }

        return $roots;
    }

    /**
     * Directories to recurse into looking for clone triads: wp-admin and
     * wp-includes in full (bounded, core-owned trees), every other top-level
     * entry directly under web root except wp-content (attacker-created
     * directories like the specimen's 0d38a/, 3c8cc/, etc. are exactly this
     * shape), and wp-content's own direct children excluding plugins/
     * (existing scanner's territory), uploads/ and themes/ (see class
     * docblock).
     */
    private static function top_level_scan_dirs($root)
    {
        $dirs = array();
        $entries = @scandir($root) ?: array();

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = MSP_PG_Utils::join_paths($root, $entry);
            if (!is_dir($path)) {
                continue;
            }
            if ($entry === 'wp-content') {
                $skip = array('plugins', 'uploads', 'themes');
                foreach (@scandir($path) ?: array() as $subEntry) {
                    if ($subEntry === '.' || $subEntry === '..' || in_array($subEntry, $skip, true)) {
                        continue;
                    }
                    $subPath = MSP_PG_Utils::join_paths($path, $subEntry);
                    if (is_dir($subPath)) {
                        $dirs[] = $subPath;
                    }
                }
                continue;
            }
            $dirs[] = $path;
        }

        return $dirs;
    }

    /**
     * Iterative (non-recursive-call) directory walk that prunes descent as
     * soon as a clone-triad root is found -- the whole matched subtree is one
     * artifact, so there is no need to keep walking inside it.
     */
    private static function walk_for_triads($startDir, array &$roots)
    {
        $stack = array($startDir);

        while (!empty($stack)) {
            $dir = array_pop($stack);

            if (MSP_PG_ClonedDoorway_Signatures::is_clone_triad_directory($dir)) {
                $roots[] = $dir;
                continue; // do not descend further into a matched root
            }

            $entries = @scandir($dir) ?: array();
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $path = MSP_PG_Utils::join_paths($dir, $entry);
                if (is_dir($path)) {
                    $stack[] = $path;
                }
            }
        }
    }

    private static function build_clone_directory_analysis($triadRoot, $scanRootBase)
    {
        $relative = MSP_PG_Utils::relative_path($triadRoot, $scanRootBase);
        $files    = MSP_PG_Utils::recursive_files($triadRoot);

        $analysis = self::base_analysis(
            self::ARTIFACT_CLONE_DIRECTORY,
            'webroot:' . str_replace('\\', '/', $relative),
            $triadRoot
        );

        self::add_reason($analysis, 'clone_directory_structure', 'self-cloning directory structure (.htaccess+index.php+cache.php under a directory named the same as its parent)');
        $analysis['structural_indicators'][] = 'self_cloning_directory:' . str_replace('\\', '/', $relative);

        $htaccessPath = MSP_PG_Utils::join_paths($triadRoot, '.htaccess');
        if (is_file($htaccessPath)) {
            $htaccessHash = MSP_PG_Utils::hash_file_safe($htaccessPath);
            if ($htaccessHash !== '' && in_array($htaccessHash, MSP_PG_ClonedDoorway_Signatures::known_htaccess_hashes(), true)) {
                self::add_reason($analysis, 'known_htaccess_hash', 'matches known PG-ClonedDoorway .htaccess template hash');
            }
        }

        foreach ($files as $file) {
            $relFile = str_replace('\\', '/', MSP_PG_Utils::relative_path($file, $triadRoot));
            $analysis['files_scanned'][] = $relFile;
            $analysis['payload_hashes'][] = MSP_PG_Utils::hash_file_safe($file);

            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            if ($extension !== 'php') {
                continue;
            }
            if ((int) filesize($file) > MSP_PG_Config::max_scan_file_bytes()) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            self::apply_content_signatures($analysis, $content, $relFile);
        }

        self::finalize($analysis);

        return $analysis;
    }

    // -------------------------------------------------------------------------
    // Loose root-level file scan (filefuns.php-style loaders, replaced core
    // index.php). Non-recursive: only files directly at web root.
    // -------------------------------------------------------------------------

    private static function scan_loose_root_files($root)
    {
        $analyses = array();
        $files = glob(trailingslashit($root) . '*.php') ?: array();

        foreach ($files as $file) {
            if ((int) filesize($file) > MSP_PG_Config::max_scan_file_bytes()) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            // Detection itself (below) is always content-based. This filename
            // check only decides *remediation treatment*: a hit on a name
            // WordPress ships as a legitimate core file means some existing,
            // legitimate file was altered in place (report-only, evidence via
            // copy -- see MSP_PG_ClonedDoorway_Remediator), whereas a hit on
            // any other loose root-level filename means the file itself is
            // attacker-created (safe to quarantine like any other artifact).
            $basename = basename($file);
            $isCoreEntryFile = in_array($basename, array(
                'index.php', 'wp-blog-header.php', 'wp-load.php', 'wp-settings.php',
            ), true);

            $artifactType = $isCoreEntryFile ? self::ARTIFACT_MODIFIED_CORE_FILE : self::ARTIFACT_LOOSE_LOADER_FILE;

            $analysis = self::base_analysis($artifactType, 'webroot:' . $basename, $file);
            self::apply_content_signatures($analysis, $content, $basename);

            if (empty($analysis['exact_match_types'])) {
                continue; // no signature fired for this loose file; not a detection
            }

            $analysis['files_scanned'][] = $basename;
            $analysis['payload_hashes'][] = MSP_PG_Utils::hash_file_safe($file);

            self::finalize($analysis);
            $analyses[] = $analysis;
        }

        return $analyses;
    }

    private static function apply_content_signatures(&$analysis, $content, $relFile)
    {
        if (MSP_PG_ClonedDoorway_Signatures::has_cache_gate_pattern($content)) {
            self::add_reason($analysis, 'cache_gate_pattern', 'AES-256-CBC decrypt gate with gzinflate/base64/eval fallback (' . $relFile . ')');
        }
        if (MSP_PG_ClonedDoorway_Signatures::has_zip_stream_stego($content)) {
            self::add_reason($analysis, 'zip_stream_stego', 'zip:// stream-wrapper include used to run a payload stored inside a disguised archive (' . $relFile . ')');
        }
        if (MSP_PG_ClonedDoorway_Signatures::has_cookie_count_eval_gate($content)) {
            self::add_reason($analysis, 'cookie_count_eval_gate', 'cookie-count-gated eval() backdoor (' . $relFile . ')');
        }
        if (MSP_PG_ClonedDoorway_Signatures::has_self_dump_pattern($content)) {
            self::add_reason($analysis, 'self_dump_pattern', 'magic-parameter self-source-dump idiom (' . $relFile . ')');
        }
        if (MSP_PG_ClonedDoorway_Signatures::has_goto_curl_pattern($content)) {
            self::add_reason($analysis, 'goto_curl_pattern', 'goto-flattened control flow combined with a curl-based remote fetch (' . $relFile . ')');
        }
        if (MSP_PG_ClonedDoorway_Signatures::has_comment_split_obfuscation($content)) {
            self::add_reason($analysis, 'comment_split_obfuscation', '"garbage comment" token-splitting obfuscation style (' . $relFile . ')');
        }
        foreach (MSP_PG_ClonedDoorway_Signatures::known_domains() as $domain) {
            if (strpos($content, $domain) !== false) {
                self::add_reason($analysis, 'known_domain', 'known PG-ClonedDoorway C2/redirect domain: ' . $domain);
                $analysis['domains'][] = $domain;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Shared analysis record helpers
    // -------------------------------------------------------------------------

    private static function base_analysis($artifactType, $slug, $path)
    {
        return array(
            'family'                => MSP_PG_ClonedDoorway_Signatures::family_id(),
            'artifact_type'         => $artifactType,
            'plugin_slug'           => $slug,
            'plugin_dir'            => $path,
            'main_files'            => array(),
            'known_variant'         => '',
            'score'                 => 0,
            'reasons'               => array(),
            'hash_hits'             => array(),
            'exact_match_types'     => array(),
            'matched_indicators'    => array(),
            'matched_strings'       => array(),
            'routes'                => array(),
            'domains'               => array(),
            'backdoor_indicators'   => array(),
            'structural_indicators' => array(),
            'payload_hashes'        => array(),
            'files_scanned'         => array(),
            'tier'                  => '',
            'variant_hash'          => '',
            'detection_source'      => '',
            'protected_plugin'      => false,
            'behavior_profiles'     => array(),
        );
    }

    private static function add_reason(&$analysis, $key, $label)
    {
        if (isset($analysis['reasons'][$key])) {
            return;
        }
        $weight = isset(self::$reasonWeights[$key]) ? self::$reasonWeights[$key] : 25;
        $analysis['reasons'][$key] = array(
            'key'    => $key,
            'label'  => $label,
            'weight' => $weight,
        );
        $analysis['score'] += $weight;
        $analysis['exact_match_types'][] = $key;
        $analysis['matched_indicators'][] = $key;
    }

    private static function finalize(&$analysis)
    {
        $analysis['reasons'] = array_values($analysis['reasons']);
        usort($analysis['reasons'], function ($left, $right) {
            return $right['weight'] <=> $left['weight'];
        });

        $analysis['exact_match_types']     = MSP_PG_Utils::normalize_list($analysis['exact_match_types']);
        $analysis['matched_indicators']    = MSP_PG_Utils::normalize_list($analysis['matched_indicators']);
        $analysis['structural_indicators'] = MSP_PG_Utils::normalize_list($analysis['structural_indicators']);
        $analysis['domains']               = MSP_PG_Utils::normalize_list($analysis['domains']);
        $analysis['payload_hashes']        = MSP_PG_Utils::normalize_list($analysis['payload_hashes']);

        $analysis['tier']              = 'tier1';
        $analysis['confidence']        = 'Exact Match';
        $analysis['detection_source']  = 'Built-In Signature Registry (PG-ClonedDoorway)';
        $analysis['variant_hash']      = self::variant_hash($analysis);
    }

    public static function variant_hash($analysis)
    {
        $fingerprint = array(
            'family'                => $analysis['family'],
            'artifact_type'         => $analysis['artifact_type'],
            'slug'                  => $analysis['plugin_slug'],
            'tier'                  => $analysis['tier'],
            'score'                 => $analysis['score'],
            'exact_match_types'     => $analysis['exact_match_types'],
            'structural_indicators' => $analysis['structural_indicators'],
            'domains'               => $analysis['domains'],
            'reasons'               => array_map(function ($reason) {
                return $reason['key'];
            }, $analysis['reasons']),
        );

        return strtoupper(hash('sha256', wp_json_encode($fingerprint)));
    }
}
