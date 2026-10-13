<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Registry + deterministic content/structure signatures for the PG-ClonedDoorway
 * family (see docs/malware-families/PG-ClonedDoorway.md).
 *
 * This is a separate, additive registry from MSP_PG_Signatures/data/signatures.json
 * on purpose: that registry and its consumers (MSP_PG_Detector, MSP_PG_Remediator's
 * plugin-directory loop) are built entirely around ONE family whose artifacts are
 * always a wp-content/plugins/<slug> directory. PG-ClonedDoorway's artifacts never
 * live in wp-content/plugins/ at all, so it cannot be expressed as another "variant"
 * of that registry without corrupting its schema. Rather than reshape the existing
 * single-family registry/pipeline, this class and MSP_PG_ClonedDoorway_Scanner /
 * MSP_PG_ClonedDoorway_Remediator form a second, narrowly-scoped, additive
 * detection source that feeds the same MSP_PG_Remediator::run_scan() report.
 *
 * Unlike MSP_PG_Signatures, this registry does not currently support the signed
 * remote-update pipeline (MSP_PG_UpdateVerifier / gen-registry-manifest.php) --
 * it ships as a static bundled file only. Wiring it into that pipeline is a
 * documented future improvement (see family doc "Remaining gaps"), not required
 * for deterministic detection today.
 */
class MSP_PG_ClonedDoorway_Signatures
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
        return 'pg-cloned-doorway';
    }

    public static function family_display_name()
    {
        return 'PG-ClonedDoorway';
    }

    public static function known_htaccess_hashes()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok) {
            return array();
        }
        return array_map('strtoupper', array_merge(
            (array) self::$registry['known_htaccess_hashes_sha256'],
            (array) self::$registry['known_htaccess_hashes_md5']
        ));
    }

    public static function known_domains()
    {
        if (self::$registry === null) {
            self::load();
        }
        return self::$registry_ok ? (array) self::$registry['known_domains'] : array();
    }

    public static function clone_triad_required_files()
    {
        if (self::$registry === null) {
            self::load();
        }
        if (!self::$registry_ok || empty($self = self::$registry['structural']['clone_triad_required_files'])) {
            return array('.htaccess', 'index.php', 'cache.php');
        }
        return (array) $self;
    }

    public static function reset()
    {
        self::$registry    = null;
        self::$registry_ok = false;
    }

    private static function load()
    {
        $path = defined('MSP_PG_PLUGIN_FILE')
            ? plugin_dir_path(MSP_PG_PLUGIN_FILE) . 'data/signatures-cloned-doorway.json'
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
    // Each of these is engineered against the actual bytes of the sbkortho
    // specimen (verified by hand, not copied from the analysis report
    // uncritically -- several originally-proposed signatures were found not to
    // survive the specimen's own escaping and were dropped or reworked; see
    // docs/malware-families/PG-ClonedDoorway.md "Signature rationale"). Every
    // check below is built on PHP syntax tokens (keywords, bareword function
    // calls, magic constants) that PHP does not allow to be string-escaped, or
    // on filesystem structure -- never on filenames, paths, or the random
    // per-deployment variable names / offset constants the kit generates.
    // -------------------------------------------------------------------------

    /**
     * CD-STRUCT: a directory whose basename equals its parent directory's
     * basename, and which directly contains the clone-triad files.
     *
     * This is the primary, highest-confidence signature. It is pure filesystem
     * structure -- no file content is read to evaluate it -- so it survives
     * arbitrary obfuscation-style changes to the PHP inside the triad, and it
     * had zero false positives against every legitimate same-named nested
     * vendor directory already present in this codebase (geoip2/geoip2,
     * phpseclib/phpseclib, pimple/pimple, cmb2/cmb2) because none of those
     * also contain .htaccess+index.php+cache.php.
     */
    public static function is_clone_triad_directory($dirPath)
    {
        $base       = basename($dirPath);
        $parentBase = basename(dirname($dirPath));

        if ($base === '' || $base !== $parentBase) {
            return false;
        }

        foreach (self::clone_triad_required_files() as $required) {
            if (!is_file(MSP_PG_Utils::join_paths($dirPath, $required))) {
                return false;
            }
        }

        return true;
    }

    /**
     * CD-CACHE-GATE: an AES-256-CBC decrypt gate with a gzinflate+base64+eval
     * fallback in the same file. All four are bareword PHP function calls,
     * which cannot be string-escaped the way the kit escapes its string
     * literals -- confirmed present, unescaped, in every cache.php sampled.
     */
    public static function has_cache_gate_pattern($content)
    {
        return strpos($content, 'openssl_decrypt(') !== false
            && strpos($content, 'gzinflate(') !== false
            && strpos($content, 'base64_decode(') !== false
            && strpos($content, 'eval(') !== false;
    }

    /**
     * CD-ZIP-STEGO: a require/include of a zip:// stream-wrapper path, used to
     * execute a PHP payload stored inside a disguised .zip archive.
     *
     * The literal string "zip://" is NOT always present raw in this specimen
     * -- one loader variant hex-escapes the entire path character by character
     * (`"\x7a\x69\x70\x3a\x2f\x2f..."`). This check normalizes \xHH and \NNN
     * (octal) character escapes before testing for "zip://" -- but, unlike an
     * earlier revision, it does so ONLY within the content of actual PHP
     * string literals, never across the whole raw file.
     *
     * Earlier revision bug (fixed): decoding was applied to the entire raw
     * file and the decoded result was searched for "zip://" as one long
     * string. This produced a confirmed false positive against this
     * project's own ClonedDoorwayTest.php, which quotes the literal word
     * "zip://" in an English-language class docblock comment describing this
     * very signature -- a bare strpos() against the whole file cannot tell a
     * comment from executable code. It is also unsound more generally: \xHH
     * escapes are only meaningful inside PHP double-quoted strings/heredocs
     * (never inside single-quoted strings or comments), so decoding them
     * file-wide could in principle stitch together unrelated bytes from
     * separate, unrelated string literals or comments into a false match.
     *
     * Fixed implementation: extract_string_and_comment_segments() walks the
     * content once, classifying each span as either a string literal (single-
     * or double-quoted) or a comment (`//`, `#`, `/* ... * /`). Comment spans
     * are discarded entirely. Each string-literal span is decoded and tested
     * independently -- never concatenated with another literal or with
     * surrounding code/comments -- so a match can only come from the actual
     * content of one real PHP string literal, which is exactly what this
     * signature is meant to detect.
     */
    public static function has_zip_stream_stego($rawContent)
    {
        if (strpos($rawContent, 'require') === false && strpos($rawContent, 'include') === false) {
            return false;
        }

        foreach (self::extract_string_literal_contents($rawContent) as $literal) {
            if (strpos($literal, 'zip://') !== false) {
                return true;
            }
            if (strpos(self::decode_basic_escapes($literal), 'zip://') !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the raw (still-escaped) inner content of every single- or
     * double-quoted PHP string literal found in $content, in order,
     * skipping comment spans (`//...`, `#...`, `/* ... * /`) entirely so
     * comment text is never mistaken for string-literal content. This is a
     * lightweight lexical scan, not a full PHP parser -- it does not handle
     * heredoc/nowdoc syntax or variable interpolation -- but it is
     * sufficient to keep CD-ZIP-STEGO scoped to actual string content.
     */
    private static function extract_string_literal_contents($content)
    {
        $segments = array();

        preg_match_all(
            '/"(?:\\\\.|[^"\\\\])*"|\'(?:\\\\.|[^\'\\\\])*\'|\/\*.*?\*\/|\/\/[^\n]*|#[^\n]*/s',
            $content,
            $matches
        );

        foreach ($matches[0] as $match) {
            $first = $match[0];
            if ($first === '"' || $first === "'") {
                $segments[] = substr($match, 1, -1);
            }
            // '/*', '//', and '#' matches are comments -- intentionally discarded.
        }

        return $segments;
    }

    /**
     * CD-COOKIE-GATE: a cookie-count gate feeding eval(). $_COOKIE is a
     * superglobal token, not a string literal, so it cannot be escaped the
     * way the kit escapes its data strings.
     */
    public static function has_cookie_count_eval_gate($content)
    {
        return strpos($content, '$_COOKIE') !== false
            && strpos($content, 'eval(') !== false
            && preg_match('/count\s*\(\s*\$\w+\s*\)\s*==/', $content) === 1;
    }

    /**
     * CD-SELFDUMP: die()/exit() wrapping a call whose sole argument is the
     * __FILE__ magic constant -- a "dump my own source on a magic request
     * parameter" idiom with no legitimate-code equivalent we found anywhere
     * in this codebase's ~30 bundled plugins.
     */
    public static function has_self_dump_pattern($content)
    {
        return preg_match(
            '/(die|exit)\s*\(\s*@?\$\w+(?:\[[^\]]{0,40}\])?\s*\(\s*__FILE__\s*\)\s*\)/',
            $content
        ) === 1;
    }

    /**
     * CD-GOTO-CURL: heavy goto-based control-flow flattening combined with a
     * curl-based remote fetch in the same file. `goto` is exceedingly rare in
     * WordPress core/plugin code; combined with curl_init/curl_exec (also
     * bareword, unescapable tokens) in one file it is a strong, low-collision
     * indicator of the obfuscated backdoor variant used to replace this
     * specimen's root index.php. Threshold of 5 is deliberately conservative
     * (the observed specimen has dozens) to avoid flagging rare, legitimate
     * one-off goto usage (e.g. breaking out of nested loops).
     */
    public static function has_goto_curl_pattern($content)
    {
        $gotoCount = preg_match_all('/\bgoto\s+\w+\s*;/', $content);

        return $gotoCount >= 5
            && strpos($content, 'curl_init(') !== false
            && strpos($content, 'curl_exec(') !== false;
    }

    /**
     * CD-COMMENT-SPLIT: the kit's "garbage comment" obfuscation style, which
     * splits real PHP tokens with many `/*-...-*\/`-delimited comment blocks
     * of random filler. The `/*-` opening marker is distinctive (ordinary
     * PHPDoc/comment style uses `/**` or plain `/*`, never `/*-`), so a high
     * count of this exact marker combined with a suppressed include (`@include`,
     * used by every loader in the doorway chain to fetch its next stage) is a
     * simple, low-collision, syntax-level signature.
     */
    public static function has_comment_split_obfuscation($content)
    {
        $markerCount = preg_match_all('/\/\*-/', $content);

        return $markerCount >= 8 && strpos($content, '@include') !== false;
    }

    /**
     * Resolves \xHH (hex) and \NNN (1-3 digit octal) character escapes to
     * their raw byte, ignoring PHP string-literal boundaries. This is a
     * bounded, purely mechanical transform used only to make CD-ZIP-STEGO
     * robust against this specimen's hex-escaped path strings -- it is never
     * executed, only pattern-matched against, and it is not a PHP parser or
     * general deobfuscator (no variable resolution, no string concatenation
     * folding, no function evaluation of any kind).
     */
    public static function decode_basic_escapes($content)
    {
        $decoded = preg_replace_callback('/\\\\x([0-9A-Fa-f]{2})/', function ($m) {
            return chr(hexdec($m[1]));
        }, $content);

        $decoded = preg_replace_callback('/\\\\([0-7]{1,3})/', function ($m) {
            $code = octdec($m[1]);
            return $code <= 255 ? chr($code) : $m[0];
        }, $decoded);

        return $decoded;
    }
}
