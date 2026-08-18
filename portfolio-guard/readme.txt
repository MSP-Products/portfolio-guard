=== MSP Portfolio Guard ===
Contributors: MSP WebOps, Joshua Garza
Tags: MainWP, security, malware remediation, malware detection, wordpress
Requires at least: 5.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 2.0.9
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Family-specific WordPress malware detection and remediation with safe mode, Tier 1 signatures, and metadata-only evidence retention.

== Description ==

MSP Portfolio Guard scans the WordPress plugins directory from the filesystem and detects known fake-plugin malware families using exact signatures and controlled heuristics. It additionally scans the web root (including wp-admin/wp-includes) for the PG-ClonedDoorway family, whose artifacts never live inside wp-content/plugins.

The plugin is designed for safe operational use:

* Safe mode is enabled by default.
* Tier 1 confirmed malware can be remediated when the operator explicitly allows it.
* Metadata-only evidence retention avoids leaving executable malware copies behind in remediation storage.
* Legitimate WordPress files that have been altered (e.g. a tampered root index.php) are always reported, never modified automatically.

Current coverage includes built-in Tier 1 signatures for the known fake-plugin family set, Atlas-ecosystem coverage for `macrolayer-macroflag`, and PG-ClonedDoorway (self-replicating doorway/TDS dropper kit; see docs/malware-families/PG-ClonedDoorway.md).

Key behaviors:

* filesystem-first malware detection
* tiered malware classification
* safe mode reporting without destructive action by default
* Tier 1 malware remediation workflow
* metadata-first evidence manifests and reporting
* malware intelligence corpus-informed family tracking

== Deployment Baseline ==

Portfolio Guard 2.0.5 is the recommended starting point for all new installations. It includes the native WordPress update infrastructure introduced in 2.0.0 and stabilized through 2.0.4. Sites installed at 2.0.5 or later will receive future updates through the standard WordPress plugin update interface without requiring manual intervention.

Sites running 2.0.3 or earlier must be manually updated to 2.0.5 (bridge installation) before the native updater becomes active.

== Installation ==

1. Upload the `portfolio-guard` plugin folder to `/wp-content/plugins/`, or install it as a ZIP through the WordPress plugin uploader.
2. Activate `MSP Portfolio Guard` from the Plugins screen.
3. Confirm the site can write the MU-loader into `/wp-content/mu-plugins/`.
4. Review safe mode behavior before enabling live Tier 1 remediation.

== Frequently Asked Questions ==

= What does safe mode do? =

Safe mode keeps scanning, classification, and reporting active while preventing live deactivation, quarantine, and deletion by default.

= What can be auto-remediated? =

Only Tier 1 confirmed malware families are eligible for automatic remediation. Heuristic and uncertain findings remain report-first.

= What evidence is retained? =

The default retention mode is `metadata_only`, which stores evidence manifests and reports without retaining executable malware files in remediation storage.

= Does this plugin use a malware intelligence corpus? =

Yes. Portfolio Guard development and built-in family signatures are informed by preserved malware specimens and reverse-engineering research, including Atlas-ecosystem coverage.

== Changelog ==

= 2.0.9 =
* Added PG-ClonedDoorway family: deterministic Tier 1 detection and remediation for a self-replicating doorway/TDS dropper kit whose artifacts (self-cloning .htaccess+index.php+cache.php directories, a tampered root index.php, an optional loose cookie-gated loader) live outside wp-content/plugins. Implemented as a second, additive filesystem scan source that feeds the existing scan/report/email pipeline; the existing plugin-family scanner and remediation logic are unchanged. A tampered root index.php (or other legitimate core file) is always report-only with evidence preserved via copy — Portfolio Guard never modifies or restores WordPress core files automatically. Signature updates for this family currently ship with plugin releases, not through the independent signature-registry hot-update channel; see docs/malware-families/PG-ClonedDoorway.md for full detail and known limitations.
* Fixed: the local test/validation bootstrap was missing a required class include for the Cloud telemetry publisher added in the previous release, which made every code path that runs a full scan fatal error outside of live WordPress. No production/runtime behavior changed; this only affected the test and release-validation harness.

= 2.0.8 =
* Hotfix: corrected signature update pipeline. The MSP_PG_UPDATE_KEY secret was stored with a trailing newline, causing hex2bin() to return false and hash_hmac() to silently sign manifests with an empty key. Client verification correctly rejected all prior manifests. Fix: trim the key before use, validate it is exactly 64 hexadecimal characters, and verify hex2bin() succeeds before signing. The signing and verification algorithms are unchanged.

= 2.0.7 =
* Reduced plugin update metadata cache interval from 12 hours to 1 hour. New releases now propagate to fleet sites within one hour rather than up to 24 hours. Interval is now defined in MSP_PG_Config and filterable via msp_pg_plugin_update_check_interval.

= 2.0.6 =
* Added fleet baseline trust list: six standard MSP plugins (disable-comments, essential-addons-for-elementor-lite, seo-by-rank-math, wordfence, wp-rocket, wpmudev-updates) now suppress Tier 2 behavioral Review Required findings on healthy fleet sites. Tier 1 signature detections are unaffected.
* Signature updates now retrieve registry-manifest.json from GitHub Releases. Manifest URL is validated before download; malformed or non-HTTPS URLs fail gracefully without replacing the active registry.
* Release workflow now generates and signs registry-manifest.json using the MSP_PG_UPDATE_KEY secret, and publishes signatures.json and registry-manifest.json as release assets.

= 2.0.5 =
* Deployment baseline release. Establishes 2.0.5 as the recommended starting point for all new installations and the origin point for future native WordPress updates. No functional changes.

= 2.0.4 =
* Fixed: scheduled scan and registry update cron events not registered immediately on plugin activation.
* Fixed: activation producing "3 characters of unexpected output" warning due to UTF-8 BOM in class-msp-pg-utils.php.

= 2.0.3 =
* Added operator whitelist workflow: operators can whitelist a specific plugin slug and version from the diagnostics page.
* Added View Evidence and Remediate actions for Review Required findings.
* Added whitelist management table with per-entry removal.
* Extended telemetry schema with five additive fields: whitelist_count, last_whitelist_at, last_whitelist_plugin, last_review_action, last_review_action_timestamp.
* Added MSP_PG_Whitelist class for slug-and-version-keyed approval storage.
* Added explain_all() to MSP_PG_BehaviorClassifier to expose all five profile scores for evidence display.

= 2.0.2 =
* Recalibrated behavior classifier weights based on observed false-positive patterns in the clean plugin corpus.
* Added per-signal file evidence to explainability output.
* Expanded synthetic behavior test coverage.

= 2.0.1 =
* Stabilization release: addressed edge cases in Tier 2 scan state persistence and report formatting.
* Hardened evidence manifest generation against missing plugin header fields.

= 2.0.0 =
* Added behavior classifier with five named profiles: Persistence, Command & Control, Payload Delivery, Operator Access, and Stealth.
* Added profile-based Tier 2 classification with signal-level explainability and per-signal file evidence.
* Added native signature registry update infrastructure with HMAC-authenticated manifests and SHA-256 registry integrity verification.
* Added engineering diagnostics page for MSP operators (hidden admin page at /wp-admin/admin.php?page=msp-pg-diagnostics).
* Added native WordPress plugin update participation through the standard admin plugin update interface.
* Completed the plugin uninstall lifecycle: all msp_pg_* options, transients, scheduled events, and generated files are removed on uninstall.
* Updated plugin to production release 2.0.0.

= 1.5.6 =
* Added standard WordPress plugin `readme.txt` metadata for release consistency.
* Added Tier 1 exact-match support for `macrolayer-macroflag`.
* Reorganized the repository to separate active source, malware corpus, research, documentation, and release artifacts.

= 1.5.5 =
* Changed default evidence retention to `metadata_only`.
* Added `evidence.json` manifest generation and evidence-mode reporting.
* Added `compressed_archive` and `full_artifact_retention` evidence modes.
* Added Tier 1 signatures for `uniserviceist-multiinfrastructure`, `miniapplicationing-protypescriptic`, and `these-middleware`.

== Upgrade Notice ==

= 2.0.5 =
Deployment baseline release. Recommended starting point for all new installations. Future native WordPress updates originate from this release.

= 2.0.4 =
Critical stabilization: fixes cron scheduling not registering on activation and eliminates the activation output warning.

= 2.0.3 =
Adds operator whitelist and Review Required workflow actions. Extends telemetry additively. No schema changes required.

= 2.0.2 =
Calibration update. No database schema changes.

= 2.0.1 =
Stabilization update. No database schema changes.

= 2.0.0 =
Major release. Adds behavioral detection profiles, registry update infrastructure, MSP diagnostics, and native plugin update notifications. Complete uninstall cleanup is included.

= 1.5.6 =
This release adds `macrolayer-macroflag` coverage, standardizes WordPress plugin packaging metadata, and keeps versioning aligned for the initial Git baseline.
