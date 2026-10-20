=== MSP Portfolio Guard ===
Contributors: MSP WebOps, Joshua Garza
Tags: MainWP, security, malware remediation, malware detection, wordpress
Requires at least: 5.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 2.2.0
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

= What can be auto-remediated? =

Only Tier 1 confirmed malware is eligible, and automatic remediation is on by default. A confirmed malicious plugin is deactivated, and once its evidence has been written and verified, it is quarantined or removed. The additive families (PG-ClonedDoorway, PG-SC-MacroOptimizerCue, PG-WPLinkHelper, PG-DoorwayContentGenerator) remove their attacker-created artifacts the same way. Infected drop-ins, modified core files and wp-includes files are always report-only. Heuristic and uncertain findings remain report-first. Nothing is removed unless evidence preservation was verified first.

= How do I run detection-only, and how is that different from dry-run? =

Detection-only: filter every remediation flag to false (`msp_pg_delete_tier1_enabled`, `msp_pg_clonedoorway_delete_enabled`, `msp_pg_sc_macro_cue_delete_enabled`, `msp_pg_sc_macro_cue_wpincludes_delete_enabled`, `msp_pg_wp_link_helper_delete_enabled`, `msp_pg_doorway_content_gen_delete_enabled`). Scans, evidence, reports, email and telemetry continue. No plugin is deactivated and no live file is changed. Each eligible finding records `REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION` (and `DEACTIVATION_WITHHELD_DISABLED_BY_CONFIGURATION` for an active plugin).

Dry-run (`PORTFOLIO_GUARD_DRY_RUN` or `msp_pg_default_dry_run`) is a simulation. It makes no site changes, but it also writes no evidence and sends no email; the returned report lists the actions that would have been taken. Use detection-only, not dry-run, for monitoring or a canary.

= What do the email subjects mean? =

`CONFIRMED MALWARE REMEDIATED`: every confirmed finding from that scan was removed or quarantined. This covers that scan's findings only; it does not establish that the site is free of undetected malware. `CONFIRMED MALWARE - PARTIAL REMEDIATION`: some findings were removed and others still need manual action. `CONFIRMED MALWARE - ACTION REQUIRED`: nothing was removed (detection-only, report-only artifacts, or evidence could not be preserved). `REVIEW REQUIRED` and `CLEAN REPORT` are unchanged.

= What evidence is retained? =

The default retention mode is `metadata_only`, which stores evidence manifests and reports without retaining executable malware files in remediation storage.

= Where is evidence stored, and is it protected from HTTP access? =

Evidence may contain captured malicious code and site details, so it must not be web-reachable. By default it goes to a private directory next to the WordPress directory (`../msp-pg-evidence`, outside the document root). This is used when WordPress is served from the domain root and that location is writable; `msp_pg_artifact_base_dir` or `msp_pg_private_artifact_base_dir` can choose another location. Otherwise evidence falls back to `wp-content/uploads/.msp-remediation`. Every evidence root gets deny-all `.htaccess` and `web.config` files plus listing guards, and each scan directory name carries 128 random bits.

**nginx (including Kinsta) ignores `.htaccess`.** When the fallback location is in use on nginx, ask the host to add `location ~* /\.msp-remediation(/|$) { deny all; }`, placed before the PHP location block, or set a private `msp_pg_artifact_base_dir`. In the fallback location `full_artifact_retention` is applied as `compressed_archive`, so raw malicious PHP is never kept under the web root. If the evidence directory or its protection files cannot be created safely, that scan writes no evidence and removes nothing; detection and email still run, and the email says so.

= Does Portfolio Guard monitor uptime? =

No. It records one self-originated HTTP request to the site's home page about once a day (when WP-Cron runs) and keeps 90 days of those observations for later reporting. Because the check runs on the site itself, it cannot observe periods when the site or its host is down, and no uptime percentage is derived from it.

= Does this plugin use a malware intelligence corpus? =

Yes. Portfolio Guard development and built-in family signatures are informed by preserved malware specimens and reverse-engineering research, including Atlas-ecosystem coverage.

== Changelog ==

= 2.2.0 =
* Added: reporting to the MSP report app, so a practice's client report can show whether its site is clean and up. After each scan the site sends its security state (the existing telemetry record) and its last 35 daily availability checks. A site first enrolls: it sends its home address once to `https://reporting.mysocialpractice.com/api/portfolio_guard/enroll`; if that address belongs to a client the report app returns a key for this site alone, stored in the `msp_pg_report_app_key` option and used as a bearer key from then on. A refused enrollment (not open yet, an unknown address, an address that already enrolled) is retried at most once a day; a 401 on a later report drops the stored key so the site enrolls again. Nothing here can affect a scan or a remediation: every failure is swallowed and requests have a 3 second timeout. The wire payload is schema version 2 and adds `availability_checks`. The local telemetry record gains one additive field, `last_scan_confirmed_malware` (Tier 1 detections only; `last_scan_detections` also counts review-only findings), so a client-facing count of malware found is never inflated.
* New settings, separate from the existing ones: the filter `msp_pg_report_app_url` (defaults to the report app; return an empty string to stop a site reporting) and `msp_pg_report_app_key` (filter, or the enrolled key). The existing `msp_pg_cloud_url` and `msp_pg_cloud_api_key` filters, their empty default, their `/api/telemetry` path and their payload are unchanged, so a site already configured through them keeps working exactly as before and never enrolls with the report app because of them. Uninstalling removes the stored key, so a site reinstalled afterwards must be reset on the report app before it can enroll again.

= 2.1.0 =
* Added PG-SC-MacroOptimizerCue, PG-WPLinkHelper, and PG-DoorwayContentGenerator: Tier 1 detection and remediation for the malware toolkits recovered from the VCA Dentistry incident. Plugin-directory installs of the first two are registered in the existing signature registry; all three additionally ship additive filesystem scanners (same pattern as PG-ClonedDoorway) for artifacts the plugin-directory pipeline cannot reach: headerless mu-plugins, a hidden state directory, a randomized backup directory, and a loose web-root file. wp-content drop-ins (advanced-cache.php/db.php/object-cache.php) and wp-includes/ recovery-loader files are always report-only or guarded by independently re-validated content-signature + symlink-rejection + path-containment checks before any removal; a genuine WP_ROCKET_ADVANCED_CACHE-bearing drop-in is never flagged. Scan reports now include infection_fully_resolved/outstanding_components, surfaced to telemetry as partial_remediation, so a report-only or withheld component is never mistaken for a fully resolved infection. See docs/malware-families/PG-SC-MacroOptimizerCue.md, PG-WPLinkHelper.md, PG-DoorwayContentGenerator.md.
* Security hardening: fixed a false positive in PG-ClonedDoorway's CD-ZIP-STEGO signature that could self-trigger on unrelated source text (including this project's own regression test file) outside any real PHP string literal; detection is now scoped to actual string-literal content with comments excluded. Hardened recursive directory deletion in every remediator (main plugin loop, PG-ClonedDoorway, and the three new families) plus the shared copy_directory()/zip_directory() evidence helpers against symlink traversal — a planted symlink is never followed into or out of an artifact/evidence directory. Corrected a stale evidence-manifest status (all four additive remediators previously left the manifest's action/remediation_status field at its pre-removal placeholder after a successful removal/quarantine).
* Fixed: when a canary/low-trust deployment runs with detection enabled but a family's automatic-deletion flag disabled (sc_macro_cue_delete_enabled / wp_link_helper_delete_enabled / doorway_content_gen_delete_enabled filtered to false), an otherwise fully eligible artifact (evidence verified, sufficient confidence) previously recorded no action at all for the withheld removal. Now records REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION explicitly, so a deliberate configuration choice is never indistinguishable from an unexplained gap in the report.
* Validated end-to-end against a disposable WordPress + MariaDB environment: all three new families through the real plugin bootstrap, Tier 1 remediation under all three evidence_retention_mode settings, legitimate caching-plugin and headerless-mu-plugin coexistence, partial-remediation reporting, and continued site availability after remediation. Symlink-specific regression assertions (previously only containment-tested on Windows) independently re-verified on Linux.
* Fixed (pre-existing, unrelated to the above): any WordPress site configured with an offset-only timezone (Settings -> General -> "UTC+5:30" etc., rather than a named city) had its daily scan silently scheduled in UTC instead of the configured local time. PHP's DateTimeZone constructor rejects a "UTC+05:30"-style offset string for any offset value; the required format omits the "UTC" prefix ("+05:30"). Existing installations self-correct automatically on update -- no manual rescheduling needed. This relies on a second fix in this release: the MU-loader sync recorded the new plugin version during `plugins_loaded`, before setup could detect the upgrade on `init`, so upgrades never re-registered the scan schedule. Version-change setup now runs on the first request after updating. Scheduling regression coverage expanded to cover negative and 45-minute fractional offsets, the real-world UTC+14:00/UTC-12:00 boundary, and the US DST spring-forward date itself.
* Fixed: with `msp_pg_delete_tier1_enabled` filtered to false, the plugin-directory pipeline still deactivated active Tier 1 plugins. Deactivation now follows the same authorization as removal, so turning that flag off leaves activation records and files untouched and records DEACTIVATION_WITHHELD_DISABLED_BY_CONFIGURATION / REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION. The plugin-directory pipeline and PG-ClonedDoorway now record withheld removals explicitly, as the other families already did. Dry-run no longer predicts deactivation or removal when the matching flag is off. Normal production defaults are unchanged: Tier 1 remediation stays on.
* Fixed: the scan email subject said `CONFIRMED MALWARE REMEDIATED` whenever Tier 1 malware was found, even when nothing was removed. The subject now reflects the actual outcome (`REMEDIATED`, `- PARTIAL REMEDIATION`, or `- ACTION REQUIRED`), using the same rule as `infection_fully_resolved`. The body states removed and outstanding counts and limits any completion claim to that scan's findings.
* Security: evidence storage. Evidence now defaults to a private directory outside the web document root (`../msp-pg-evidence`) when one can be established safely. Every evidence root, including the pre-2.1.0 `uploads/.msp-remediation`, gets deny-all `.htaccess`/`web.config` and listing guards, and scan directories carry an unguessable 128-bit suffix. `full_artifact_retention` is applied as `compressed_archive` while storage is inside the web root. If evidence storage cannot be secured, the scan writes no evidence and removes nothing, and reports why. Evidence written by earlier versions is never moved or deleted. Scan reports gain an `evidence_storage` section.
* Fixed (pre-existing since 1.5.6): PHP `Undefined array key` warnings from the plugin-directory pipeline's pre-removal evidence report.
* Added: site availability observations. Once a day (WP-Cron hook `msp_pg_availability_observation`, independent of malware scans) the site makes one GET request to its own home URL. Redirects are not followed and the response body is limited and discarded. It stores the time, HTTP status, duration, outcome (`reachable` / `degraded` / `unreachable`) and a normalized error category in `{prefix}msp_pg_availability`, kept for 90 days. These are self-reported point-in-time observations, not uptime monitoring: no uptime percentage is calculated, missed checks are not backfilled, and nothing is emailed, remediated or sent to Cloud telemetry. The table is created on activation and, for upgraded sites, on the first page load after updating. Deactivation keeps the history; uninstall removes it.

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

= 2.2.0 =
Sites now report their security state and daily availability checks to the MSP report app, after enrolling once with their home address. Nothing changes for scanning or remediation, and the existing `msp_pg_cloud_url` / `msp_pg_cloud_api_key` settings are untouched. To stop a site reporting, return an empty string from the new `msp_pg_report_app_url` filter.

= 2.1.0 =
New evidence goes to `../msp-pg-evidence` (outside the web root) where possible. Evidence from earlier versions stays in `wp-content/uploads/.msp-remediation`, now behind deny-all files that nginx does not honor; move it manually or block that path at the web server. With `msp_pg_delete_tier1_enabled` set to false, malicious plugins are no longer deactivated.

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
