# 02 — Current Capabilities, Proficiencies and Limitations (2.1.0)

> **Snapshot:** 2026-10-14, working tree of `main`. "Verified" means asserted by a test in `portfolio-guard/tests/` or `validation/`, unless another source is named.

## A. Implemented capabilities

| Capability | Status | Where |
|---|---|---|
| Signature detection of fake-plugin families in `wp-content/plugins/` | Implemented | `MSP_PG_Detector`, `data/signatures.json` |
| Filesystem detection outside `plugins/` (web root, mu-plugins, drop-ins, wp-includes, hidden/backup dirs) for 4 families | Implemented, bounded scope per family | `MSP_PG_*_Scanner` |
| Tier 1 autonomous remediation (deactivate + quarantine/remove plugins; remove attacker-created files/dirs) | Implemented, on by default | `MSP_PG_Remediator`, `MSP_PG_*_Remediator` |
| Tier 2 behavioral findings, review queue, whitelist, operator-confirmed remediation | Implemented (report-only until confirmed) | `MSP_PG_BehaviorClassifier`, `MSP_PG_Whitelist`, `MSP_PG_DiagnosticsPage` |
| Evidence preservation: `metadata_only` (default), `compressed_archive`, `full_artifact_retention` | Implemented | `remediate_detection()` and family remediators |
| Quarantine | Only in `full_artifact_retention` (moved into the evidence store). Other modes delete after preservation; plugins/ uses a temp move then delete. | as above |
| Evidence retention cleanup | Deletes scan directories older than `msp_pg_artifact_retention_days` (7) in the **current** evidence root only | `cleanup_expired_artifacts()` |
| Evidence storage hardening | Private root outside web root when possible, deny files, fail-closed | `MSP_PG_Config`, `MSP_PG_Utils::prepare_evidence_directory()` |
| Scheduling | Daily 06:00 site-local via WP-Cron + admin catch-up | `MSP_PG_Plugin` |
| Operational email | One per non-dry-run scan, outcome-based subject | `send_scan_report()` |
| Telemetry | Local option always; Cloud POST only if configured | `MSP_PG_Diagnostics`, `MSP_PG_CloudPublisher` |
| Plugin updates | Native WP update flow fed by GitHub `plugin.json` | `MSP_PG_PluginUpdater` |
| Signature hot-updates | `signatures.json` only (plugins/ families), 6-hourly, HMAC + SHA-256 + schema checks | `MSP_PG_Updater` |
| Admin controls | Diagnostics, report recipient, Scan now, whitelist, confirm remediation | Settings → Portfolio Guard |
| Site availability observations (one self-originated GET per day, 90-day history, PHP retrieval API) | Implemented (v1, data collection only: no reporting, alerting or uptime %) | `MSP_PG_Availability` |
| Runtime blocking of known plugins and backdoor requests | **Not active** (class present, never booted since `ed3f9a9`) | `MSP_PG_Runtime` |
| WP-CLI / REST interface | **None** | — |
| Database inspection or remediation | **None.** No code reads or modifies `wp_options`, posts or cron entries for malware. | — |

## B. Malware-family coverage

Full rationale, IOCs and execution chains are in `docs/malware-families/*.md` (the four new-style families) and `research/` (the original plugin families). They are not repeated here.

### B.1 Plugin-directory families (`data/signatures.json`, `registry_version` 2, 10 variants)

`laravel-janet`, `framework-triappment`, `platformist-quadendpointer`, `smartrestal-serverful`, `uniserviceist-multiinfrastructure`, `miniapplicationing-protypescriptic`, `these-middleware`, `macrolayer-macroflag`, `macro-optimizer-cue`, `wp-link-helper`. The family label is `wordpress-shared-plugin-framework` (`MSP_PG_Config::family_name()`).

- **Detection:** `MSP_PG_Detector::detect()` per `plugins/<slug>`. Exact-match types:
  - plugin directory name;
  - primary plugin file name at the plugin root;
  - known relative filenames, taken from variant `ioc_strings` that look like paths;
  - file SHA-256;
  - IOC domain or REST route substring in scanned files (`php`, `js`, `json`, `txt`; ≤ 2 MB).

  Any one type → Tier 1. Content IOC strings (e.g. WLH constant names) are **not** matched by this pipeline. `exact_ioc_strings` is loaded but unused.
- **Removal:** active plugin deactivated, then the directory is quarantined or removed after verified evidence, if `known_hash` or ≥2 exact types matched (`$canDeleteOriginal`). Directory + main-file **name** alone satisfies this.
- **Report-only:** Tier 1 with a single exact type; all Tier 2.
- **Variant coverage:** three variants (`uniserviceist-…`, `miniapplicationing-…`, `these-middleware`) have no hashes, domains or routes. They are detected by name only.

### B.2 Filesystem families

| Family (`family` value) | Signature source | Locations inspected | Auto-removed (after evidence) | Report-only | Key limitations |
|---|---|---|---|---|---|
| PG-ClonedDoorway (`pg-cloned-doorway`) | `class-msp-pg-clonedoorway-signatures.php`, `data/signatures-cloned-doorway.json` | Web-root tree (skips `plugins/`, `uploads/`, `themes/`) for `.htaccess`+`index.php`+`cache.php` clone triads; loose `*.php` at web root | Clone-triad directories; loose loader files | Modified legitimate files such as root `index.php` (`REPORT_ONLY_MODIFIED_CORE_FILE`, evidence copy kept) | Not hot-updatable; uploads and themes not scanned (`PG-ClonedDoorway.md` §11) |
| PG-SC-MacroOptimizerCue (`pg-sc-macro-cue`) | `class-msp-pg-sc-signatures.php`, `data/signatures-sc-macrocue.json` | `mu-plugins/` (non-recursive); hidden `.sc_<hex>` state dir; drop-ins `advanced-cache.php`, `db.php`, `object-cache.php`; `wp-includes/` (non-recursive) | Headerless mu-plugin and state dir when hash or ≥2 signature types; wp-includes recovery loader only with a verified boundary, content signature, non-symlink, and both SC flags on | All drop-ins (always); unverified wp-includes files | No C2 domain known; option-resident payload copy not detected (`PG-SC-MacroOptimizerCue.md` §6) |
| PG-WPLinkHelper (`pg-wp-link-helper`) | `class-msp-pg-wlh-signatures.php`, `data/signatures-wp-link-helper.json` | `mu-plugins/`; `wp-content/wp-<hex>-prev/` backup dirs (name match must be corroborated by content) | Mu-plugin and backup dir when hash, IOC string or vault-derivation pattern | Lower-confidence matches (`REMOVAL_WITHHELD_INSUFFICIENT_CONFIDENCE`) | `WLH_Vault` database option neither detected nor remediated, and **not** surfaced as a manual step (the family doc's claim that it is surfaced is not implemented) |
| PG-DoorwayContentGenerator (`pg-doorway-content-gen`) | `class-msp-pg-doorwaygen-signatures.php`, `data/signatures-doorway-content-gen.json` | Loose `*.php` at web root only | Matching file (hash or bulk-upload + `$wpdb` insert + link-injection content signature) | — | Single artifact type; posts it injected into the database are not addressed |

The plugin-directory installs of `macro-optimizer-cue` and `wp-link-helper` are handled by B.1, not by these scanners.

## C. Operational proficiencies — what has been shown, and how

| Evidence level | What it covers | Source |
|---|---|---|
| Unit / harness tests (PHP CLI + stubbed WordPress, `tests/bootstrap.php`) | Every remediator path, evidence modes, symlink safety, scheduling, telemetry, whitelist/review workflow, outcome subjects, evidence storage, availability observations (in-memory `$wpdb` fake, mocked HTTP) | 19 files in `portfolio-guard/tests/` |
| Validation gate | Known-malware fixtures → expected tier; 5 clean wordpress.org plugins → no Tier 1/2; update-infrastructure, diagnostics, uninstall; 5 synthetic Tier 2 fixtures (non-blocking) | `validation/gate.php` |
| Integration in a disposable WordPress + MariaDB stack | The 3 VCA families through real WP; all retention modes; caching-plugin and headerless-mu-plugin coexistence; site still serves | 2026-10-13 run on the **pre-2.1.0-bump build** (`docs/operations/vca-families-release-validation-2.1.0.md` §1) |
| Real incidents | Signatures are derived from preserved real specimens (`malware-corpus/`, `research/case-reports/`, VCA Dentistry for the 3 newest families) | Derivation only. **The repository holds no record of PG detecting or remediating on a production site.** |
| Unverified in production | Kinsta/nginx behaviour, private evidence-root writability on real hosts, fleet-scale scan cost, any 2.1.0 correction in real WordPress | — |

Caveats:
- The gate's known-malware fixtures are name-only stubs of 45–70 bytes. They prove name matching, not hash or content detection of real payloads.
- Detection is not infection resolution. `infection_fully_resolved` covers only that scan's findings, and database-resident persistence (SC, WLH) is out of scope.

## D. Known limitations

- **Coverage:** only the families above. Anything else is caught only if a Tier 2 profile activates (report-only, `plugins/` only). Nothing is scanned in themes, uploads or the database.
- **Name-based Tier 1:** a legitimate plugin whose directory and main file share a registered family's names would be auto-removed. `msp_pg_protected_plugin_slugs` does not prevent Tier 1.
- **Report-only persistence:** SC drop-ins, modified core files and unverified wp-includes files need manual work. The email and report give operator instructions.
- **Database-resident malware:** not handled (SC option copy, WLH vault, DoorwayGen-injected posts).
- **Evidence storage:**
  - The private root depends on the parent of ABSPATH being writable and not web-served. The path check can't see web-server aliases.
  - The fallback `uploads/.msp-remediation` is unprotected on nginx without a host rule.
  - Pre-2.1.0 evidence stays in uploads.
  - Uninstall does not delete any evidence.
- **Plugin update integrity:** WordPress downloads the ZIP over HTTPS. The `sha256` in `plugin.json` is never checked, and WordPress signature verification covers wordpress.org packages only.
- **Registry integrity:** the HMAC key is embedded in every shipped plugin (`MSP_PG_Config::update_key()`), so it adds nothing beyond HTTPS and control of the GitHub repo.
- **Registry versioning:** a `signatures.json` change takes effect only if `registry_version` is raised above the last *published* value. This happened in 2.1.0 (fixed by bumping 1 → 2). The gate test does not catch a missed bump.
- **Update discovery:**
  - Plugin updates are discovered only on an admin page load (`admin_init`, hourly), so sites nobody logs into don't learn of new versions.
  - Registry checks need WP-Cron.
- **Single report recipient** per site, with a hard-coded individual fallback address. No fleet dashboard; Cloud telemetry is optional and its receiver is not in this repo.
- **No runtime protection:** `MSP_PG_Runtime` is inactive.
- **Availability observations are not uptime monitoring.**
  - They run only when WP-Cron runs. On a down site the check usually doesn't run at all, so outages appear as *missing* rows, not as `unreachable` rows.
  - Requests originate from the site itself, so they can reach the site even when outside visitors can't (and may be blocked when visitors aren't).
  - Page caches may answer the request.
  - One sample a day; no percentages; nothing leaves the site. A future integration must fetch the data via `MSP_PG_Availability::latest()` / `between()`, since no remote endpoint exists.
- **Scan time drifts with DST:** the scan schedule is a fixed `daily` WP-Cron interval. In DST zones it drifts by an hour after a DST change until the next upgrade or reactivation re-anchors it to 06:00 local. (Inferred from WP-Cron's fixed-interval rescheduling; not tested.)
- **Test-only hook in production code:** `MSP_PG_Plugin::next_6am_timestamp()` honours `$GLOBALS['msp_pg_test_current_time']`.

## E. Testing and release status

**Running:**
- Each `portfolio-guard/tests/*Test.php` is a standalone script: `php <file>`. Exit 0 means pass; failures throw with a message.
- `php validation/gate.php` aggregates the runner tests. It needs the clean corpus staged first (`validation/runner/stage-clean-corpus.ps1`, which downloads from wordpress.org).
- `validation/release-package-test.php` checks a built ZIP.

**Latest results, 2026-10-14:**

| Environment | Tree | Result |
|---|---|---|
| Windows PHP 8.5.7 | final | 19/19 test files, gate PASS |
| Linux PHP 7.4.33 | final | 19/19, gate PASS, 0 lint errors |
| Disposable WordPress (php8.2-apache) + MariaDB 11, prefix `acme7_` | final | Upgrade from published 2.0.9 on a UTC+5:30 site: scan rescheduled 06:00 → 00:30 UTC, version recorded, loader synced, no repeat reschedule; availability observations (all outcome classes, size limit, lifecycle, retention, retrieval) as expected |
| Linux PHP 8.5.11, 8.3.35 | before the `registry_version` bump | 18/18, gate PASS |
| Release package | final | 12/12 |

**Gaps:**
- No 2.1.0 correction (scheduling fix, withheld actions, deactivation gating, outcome subjects, evidence storage, registry bump) has run inside a real WordPress install.
- CI does not run the test files; it runs only the gate and the package test (doc 03).
- Real symlink assertions run only where `symlink()` works (Linux).
- The clean-corpus downloads are not hash-pinned (`sha256_zip` empty in `validation/corpus/clean-plugins/manifest.json`).
