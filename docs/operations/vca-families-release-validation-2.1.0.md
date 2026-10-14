# Portfolio Guard 2.1.0 — release validation record

Execution record for the plan in [`vca-families-disposable-wp-test-plan.md`](vca-families-disposable-wp-test-plan.md). That document is the plan; this one records what was run and what it showed. Results are copied from the session reports named below. Nothing here was re-derived.

## 1. Disposable WordPress + MariaDB integration — 2026-10-13

Source: "Release Validation Report — Portfolio Guard 2.1.0", development session of 2026-10-13 (report issued 23:22 UTC).

**Environment:** isolated Docker Compose stack (MariaDB, `wordpress:php8.2-apache`, `wp-cli`) on a dedicated bridge network. Portfolio Guard was installed and activated as a normal plugin (`wp plugin activate`). Fixtures were inert synthetic files shaped like the unit-test fixtures and written to real WordPress paths. No live malware was used. The stack was torn down afterward (`docker compose down -v`).

| Check | Reported result |
|---|---|
| Detection through the real WP runtime (`MSP_PG_Remediator::run_scan()` via `wp eval`) | PASS: 8 Tier 1 detections across PG-SC-MacroOptimizerCue, PG-WPLinkHelper, PG-DoorwayContentGenerator |
| Tier 1 remediation, all evidence modes | PASS: `metadata_only`; `compressed_archive` (archive checked with `unzip -l`); `full_artifact_retention` (quarantined file checked byte-for-byte, plus its zip). Modes were set by a throwaway mu-plugin filter. |
| Legitimate component preservation | PASS: a real WP Super Cache install and a legitimate headerless mu-plugin survived every scan; `wp-includes/functions.php` never flagged |
| Partial-remediation reporting | PASS: `infection_fully_resolved=false` with correct `outstanding_components` in every mode, while removable artifacts were removed |
| Site availability | PASS: HTTP 200 and correct page title after every remediation round, including repeat loads (no silent regeneration) |
| PHP errors | PASS: no warnings, notices or fatals in container logs for the run |
| Linux regression suite / gate (same session) | 15/16 test files (the SchedulingTest failure was pre-existing and fixed later in `76996dc`); gate PASS |

**Environment issue found and resolved during the run (not a product defect):** `wp-cli` in its own container ran as uid 82 while WordPress files were owned by uid 33. That silently blocked deletion of web-root files. Running wp-cli as uid 33, the realistic hosting model, fixed it, and the run was repeated cleanly.

**Product defect found during the run:** the three new families recorded no action when removal was withheld by `*_delete_enabled=false`. Fixed in `4edfa28` (`REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION`).

### Limitations of this run

- The **build tested was before the version bump** ("v2.0.9 pre-bump"). It did not include `4edfa28` (the withheld-removal reporting fix) or `76996dc` (the offset-timezone scheduling fix). Both are covered by unit tests, the gate and the 2026-10-14 Linux runs below, but **not** by the WordPress stack.
- Only the three new families were exercised in WordPress. The original plugin-directory pipeline and PG-ClonedDoorway were not.
- One PHP version (8.2, Apache). Not nginx and not Kinsta.
- Synthetic fixtures only. Production false-positive behaviour against a real site's content is still to be shown by the canary.
- No logs or artifacts were kept after teardown. This document is the only record.

## 2. Linux regression re-run — 2026-10-14

Committed `HEAD` (`7c9a683`) was exported with `git archive`, so no untracked specimen archives were included, and the gitignored staged clean-plugin corpus was added. The run used disposable `php:<v>-cli` containers with `ext-zip` installed.

| Runtime | Test files | Gate |
|---|---|---|
| PHP 8.5.11 / Linux | 16/16 | PASS (Known Malware 10/10, Clean Plugins 5/5, Update Infrastructure 17/17, Diagnostics 12/12, Uninstall 20/20, Synthetic 5/5) |
| PHP 8.3.35 / Linux | 16/16 | PASS (same counts) |
| PHP 8.5.7 / Windows (reference) | 16/16 | PASS (same counts) |

`symlink()` works in these containers. `DirectoryRemediationSymlinkSafetyTest`, `UtilsCopyZipSymlinkSafetyTest` and the SC wp-includes boundary test ran their real-symlink assertions (no skip notices) and passed.

Release artifact `portfolio-guard-2.1.0.zip`: SHA-256 `dd4ac658c86c86c0fdd8e2597086383080a21f07da43d9a5acb8277795ee587e`. It matches the committed `.sha256`, and its 39 entries are byte-identical to `HEAD` (only the dev `README.md` is excluded). It contains no tests, scripts, corpus or specimens.

## 3. Issues found in final review — resolved 2026-10-14

The email subject claimed remediation when nothing was removed. Deactivation ignored `msp_pg_delete_tier1_enabled`. Evidence storage had no web-access protection. The pre-removal report raised `Undefined array key` warnings. All four are fixed in the uncommitted 2.1.0 working tree; see [`evidence-storage-and-remediation-controls.md`](evidence-storage-and-remediation-controls.md). After the fixes: 18/18 test files pass and the gate passes on Windows PHP 8.5.7 and Linux PHP 8.5.11 / 8.3.35, with real symlink assertions on Linux.

## 4. Distribution checks — 2026-10-14

- **Registry version (fixed):** 2.1.0 added two plugin-directory variants (`macro-optimizer-cue`, `wp-link-helper`) to `data/signatures.json` but kept `registry_version: 1`. The live channel (GitHub `v2.0.9`) publishes registry v1, and `MSP_PG_Signatures::load()` prefers an applied registry whose version is `>=` the bundled one. So every upgraded site would have kept the old 8-variant registry, and 2.1.0 did not detect those two families. This was reproduced with the 2.1.0 code against the published `signatures.json`. The bundled registry is now `registry_version: 2`. `validation/runner/UpdateInfrastructureTest.php` now derives the bundled version instead of hard-coding 1. With v2 bundled, its lower-version case runs the upgrade path (applied v1 ignored, installed v2 used). It is **not** a regression guard: with the registry reverted to v1 the gate still passes (checked 2026-10-14), because nothing compares the bundled version with the last published one. The scenario itself was reproduced against the published `signatures.json`: new families inactive at v1, active at v2.
- **2.0.9 compatibility:** 2.0.9's own updater accepts, installs and loads the v2 registry and detects both new plugin-directory families as Tier 1. Mu-plugin, drop-in, hidden-directory, wp-includes and loose-file artifacts need the 2.1.0 scanner classes and their `signatures-*.json`; those ship only in the plugin ZIP.
- **PHP 7.4 (`Requires PHP: 7.4`):** 0 lint errors in shipped files; 18/18 tests and the gate pass on PHP 7.4.33.
- **Release metadata:** the published 2.0.9 `registry-manifest.json` verifies against the key embedded in the plugin, so the CI signing secret equals the shipped key.
- **2.0.9 rollback artifact:** the published 2.0.9 package is `portfolio-guard-2.0.9.zip`, SHA-256 `0ef58d5c79980cf02720a2c14e3b2cbf9a0d3e58f7ea60ff78edb84e9aa59ef5`. Provenance:
  - GitHub release `v2.0.9`, published 2026-08-18T20:53:24Z by `github-actions[bot]`.
  - Built by release workflow run `32184695411`, triggered by pushing the annotated tag `v2.0.9`, which points at commit `d522c10`.
  - The asset matches GitHub's server-side digest, the published `.sha256` and `plugin.json`.
  - All 24 entries match the `v2.0.9` tree except for line endings (CI checks out CRLF).

  An authenticated copy of all five release assets was retrieved read-only to `_release_validation/published-v2.0.9/` (gitignored). The local `releases/portfolio-guard/portfolio-guard-2.0.9.zip` (`ff3d0984…`, dated 2026-08-31) is a later local build of the same commit: 17 entries CRLF, 7 LF, matching this workstation's checkout, with no content differences. It is not the published artifact. Roll back with the published asset.
