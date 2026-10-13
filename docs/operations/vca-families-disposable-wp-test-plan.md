# Disposable WordPress Integration-Test Plan — SC, WP Link Helper, Doorway-Generator Families

**Purpose:** validate PG-SC-MacroOptimizerCue, PG-WPLinkHelper, and PG-DoorwayContentGenerator against a real WordPress install before canary deployment. Everything in this plan runs against a throwaway environment that is destroyed afterward — never a production or customer site.

## 1. Environment

- A disposable Linux container or VM (Docker `wordpress:latest` + `mysql`/`mariadb`, or a local `wp-env`/`wp-cli scaffold` install) running a clean WordPress core + the real `portfolio-guard` plugin installed as a normal plugin.
- **Linux, not this Windows sandbox, is specifically preferred here**: `symlink()` works without elevated privileges on Linux, which lifts the one category of assertion this session could not execute live (see §5). Confirmed in this session via both PHP's `symlink()` and PowerShell's `New-Item -ItemType SymbolicLink` that this sandbox requires admin privileges neither grants.
- Fresh database, default theme, no other plugins active besides Portfolio Guard, to keep signal-to-noise high for first-pass validation.
- Destroy and recreate the container/VM between test rounds rather than cleaning it in place — cheaper and removes any doubt about leftover state.

## 2. Fixture placement (real filesystem, real WordPress bootstrap)

Reuse the exact fixture shapes already proven in `SCMacroOptimizerCueTest.php` / `WPLinkHelperTest.php` / `DoorwayContentGeneratorTest.php`, but written to the real paths a live site would use instead of a reflection-targeted test root:

| Family | Path | Content |
|---|---|---|
| SC | `wp-content/mu-plugins/<name>.php` | SC-VER-STAMP + SC-HELPER-SET fixture |
| SC | `.sc_<hex>/` at web root | Hidden-dir + `own_<hex>.php` beacon fixture |
| SC | `wp-content/advanced-cache.php` | SC-DROPIN-MARKER fixture (plus a synthetic "legitimate tail" to exercise mixed-content preservation) |
| SC | `wp-includes/.g_<hex>.php` + `.gl_<hex>` | Recovery-loader + empty-marker fixture |
| WLH | `wp-content/mu-plugins/<name>.php` | WLH-VAULT-DERIVATION + WLH-IOC fixture, no `Plugin Name:` header |
| WLH | `wp-content/wp-<hex>-prev/` | Backup-dir fixture, content-signature-bearing |
| Doorway-gen | `page.php` at web root | DG-BULK-UPLOAD-INJECT fixture |

## 3. Scenarios to run (via a real WP-Cron-triggered or WP-CLI-triggered scan, not a unit test)

1. **Clean baseline scan** — confirm zero detections on an unmodified install (false-positive check against real core files, especially `wp-includes/`, and against a real caching plugin's genuine `advanced-cache.php` if one is installed, e.g. install WP Rocket or a Redis object-cache drop-in and confirm `WP_ROCKET_ADVANCED_CACHE`-style content is never flagged).
2. **Each fixture individually** — plant one fixture at a time, trigger a scan, confirm detection + the documented remediation outcome (removed / quarantined / report-only) exactly matches what the unit/integration tests already proved.
3. **All fixtures simultaneously** — plant every fixture from §2 in one pass, trigger one scan, confirm the aggregate `infection_fully_resolved`/`outstanding_components` reporting matches expectations (removable artifacts gone, drop-in and wp-includes-without-content-signature cases still outstanding).
4. **Evidence modes** — repeat scenario 3 with `evidence_retention_mode` filtered to each of `metadata_only`, `compressed_archive`, `full_artifact_retention` (a real `add_filter` in a tiny throwaway mu-plugin on the disposable site, not a config change shipped anywhere). Confirm quarantine directories, zip archives, and manifests are created where expected and are readable/openable from outside PHP (e.g., `unzip -l`, `cat evidence.json | jq`).
5. **Regeneration simulation** — for SC specifically, after remediation, manually re-trigger a page load (the mechanism documented in `docs/malware-families/PG-SC-MacroOptimizerCue.md` §2) to confirm the *fixture* does not silently reappear on its own (it shouldn't — these are synthetic fixtures with no real self-heal logic, so this is really a sanity check that Portfolio Guard's own scan isn't the thing "regenerating" anything).
6. **Live caching plugin coexistence** — install a real caching plugin (WP Rocket free alternative or a Redis-backed object-cache drop-in) alongside an SC `advanced-cache.php` fixture that wraps a genuine caching-plugin tail, confirm the caching plugin continues to function (cache actually populates) and Portfolio Guard's report-only path never touches the file.
7. **mu-plugin coexistence** — install a real, headerless, legitimate mu-plugin (e.g., a trivial "force HTTPS" snippet with no `Plugin Name:` docblock, mirroring how some hosts ship mu-plugins) alongside the WLH mu-plugin fixture; confirm only the fixture is flagged.

## 4. What to capture per run

- Full scan report (`report.json`/`report.md`) and the operational email body (point `MSP_PG_Config::report_recipient()` at a local mail-catcher like MailHog/Mailpit for the disposable environment).
- `wp-content/.msp-remediation/` (or configured artifact base dir) contents, to inspect real evidence manifests/archives.
- WordPress's own `debug.log` for any PHP warnings/notices the unit-test stubs might have masked (the test harness stubs every WP function; a real WP core/MySQL stack can surface behavior the stubs can't — e.g., real `wp_mail()` transport issues, real `WP_Filesystem` interactions if any are later added, real plugin-API timing around `deactivate_plugins()`).

## 5. Symlink handling — specifically deferred to this environment

This session's sandbox cannot create symlinks (`symlink()` returns `Permission denied`; confirmed independently via PowerShell). Every symlink-safety unit test (`DirectoryRemediationSymlinkSafetyTest.php`, `UtilsCopyZipSymlinkSafetyTest.php`, the SC wp-includes boundary test) printed an explicit skip note for the true-symlink assertion and relied on a non-symlink containment check instead — **this is not equivalent to a verified symlink defense.** On the disposable Linux environment, re-run those three test files directly (`php portfolio-guard/tests/*.php` — they're self-contained, no WordPress bootstrap needed) and confirm the previously-skipped assertions now execute and pass. This is the one item from this round's validation request that remains genuinely unverified until it runs somewhere `symlink()` works.

## 6. Exit criteria before canary

- All scenarios in §3 produce the expected detection/remediation outcome with no unexpected false positive against real core/plugin files.
- The three symlink-safety test files' true-symlink assertions pass (not skipped) on the Linux disposable environment.
- No PHP warnings/errors in `debug.log` beyond the ones already understood (the deliberately-forced preservation-failure case, if re-run there).
- Evidence archives/manifests are independently readable with standard tools (`unzip`, `jq`), not just from within PHP.
