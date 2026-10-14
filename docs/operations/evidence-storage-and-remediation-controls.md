# Remediation controls and evidence storage (2.1.0)

## Operating modes

| | Production (default) | Detection-only | Dry-run |
|---|---|---|---|
| How | nothing to set | filter all six `*_delete_enabled` flags to `false` (below) | `PORTFOLIO_GUARD_DRY_RUN` / `msp_pg_default_dry_run`, or `run_scan($t, ['dry_run' => true])` |
| Detection / classification | yes | yes | yes |
| Plugin deactivation | Tier 1, active plugins | **no** (`DEACTIVATION_WITHHELD_DISABLED_BY_CONFIGURATION`) | no (`WOULD_PLUGIN_DEACTIVATE` only if the flag is on) |
| Quarantine / removal | Tier 1, after verified evidence | **no** (`REMOVAL_WITHHELD_DISABLED_BY_CONFIGURATION`) | no (`WOULD_*_REMOVE` only if the flag is on) |
| Evidence, scan report files | yes | yes | **no** |
| Email | yes | yes | **no** |
| Telemetry | yes | yes | yes |

Detection-only flags: `msp_pg_delete_tier1_enabled` (plugin-directory pipeline: deactivation and removal), `msp_pg_clonedoorway_delete_enabled`, `msp_pg_sc_macro_cue_delete_enabled`, `msp_pg_sc_macro_cue_wpincludes_delete_enabled`, `msp_pg_wp_link_helper_delete_enabled`, `msp_pg_doorway_content_gen_delete_enabled`. No new control was added. Deactivation now uses the existing `msp_pg_delete_tier1_enabled`.

In detection-only mode Portfolio Guard still writes its own options (`msp_pg_state`, `msp_pg_telemetry`) and its evidence store. It modifies nothing else on the site.

In production mode, deactivation still happens *before* evidence preservation, as it always has. It is reversible and leaves the files that evidence is taken from in place. Quarantine and removal still require verified evidence.

## Remediation outcome terms

The outcome is derived from recorded actions, using the same rule as `infection_fully_resolved`. A finding counts as resolved only if `LIVE_PLUGIN_REMOVED`, `LIVE_ARTIFACT_REMOVED` or `QUARANTINE_COMPLETED` was recorded, which happens only on success.

| Subject | Meaning | `partial_remediation` telemetry |
|---|---|---|
| `CONFIRMED MALWARE REMEDIATED` | every Tier 1 finding from this scan removed/quarantined (not a claim that no other malware exists) | false |
| `CONFIRMED MALWARE - PARTIAL REMEDIATION` | some removed, some outstanding | true |
| `CONFIRMED MALWARE - ACTION REQUIRED` | none removed: detection-only, report-only drop-in/core file, evidence not preserved, or removal failed | true |
| `REVIEW REQUIRED` / `CLEAN REPORT` | unchanged | false |

## Evidence storage

Root resolution: `msp_pg_artifact_base_dir`, then `msp_pg_private_artifact_base_dir`, then `wp-content/uploads/.msp-remediation`.

The private default is `dirname(ABSPATH)/msp-pg-evidence`. It is only used when WordPress is served at the domain root, the location is writable and not a symlink, and it lies outside ABSPATH, `WP_CONTENT_DIR`, the uploads base and `DOCUMENT_ROOT`. Path containment cannot detect web-server aliases. Where a host serves the parent of ABSPATH (for example a cPanel addon domain nested in another site's `public_html`), set `msp_pg_artifact_base_dir` explicitly.

Every scan:

- creates `<root>/<site>/<timestamp>-<128-bit hex>/`
- writes deny-all `.htaccess` (Apache 2.2/2.4, LiteSpeed) and `web.config` (IIS) into the root, plus `index.html` listing guards in the root, site and scan directories
- refuses a symlinked root, site or scan directory, a symlinked or unwritable protection file, or a scan directory that resolves outside the root. When any of these happens, evidence writes are blocked for the scan. Preservation then cannot be verified, so nothing is removed. Detection, email (`Evidence Storage: NOT SECURED`) and telemetry continue.
- inside the web root, applies `full_artifact_retention` as `compressed_archive` (raw PHP copies never land under the web root) and reports it in `evidence_storage`
- adds the same deny files to a pre-2.1.0 `uploads/.msp-remediation` that still exists. That evidence is never moved or deleted. Retention cleanup does not touch it once a private root is in use, and it never scrubs historical snapshots because of the fallback.

### HTTP verification (2026-10-14, disposable containers, synthetic evidence)

The evidence tree was built by the plugin's own `prepare_evidence_directory()`, and the files were requested without credentials:

| Request | nginx 1.27 (autoindex on) | Apache 2.4 (AllowOverride All) | nginx + host rule |
|---|---|---|---|
| private root, direct or any traversal form | 404 / 400, no content | 404 / 400, no content | n/a |
| `uploads/.msp-remediation/…/evidence.json`, `.zip`, `.php` | **200, content returned** | 403 | 403 |
| `uploads/.msp-remediation/` listing | 200, empty (`index.html`), no names | 403 | 403 |
| bypass variants (`%2e`, `//`, `/./`, case) | n/a | n/a | 403 |

On nginx, the web-root fallback depends only on the unguessable directory name unless the host adds:

```nginx
location ~* /\.msp-remediation(/|$) { deny all; }   # before the PHP location block
```

A prefix rule (`location ^~ /wp-content/uploads/.msp-remediation/`) was bypassed by a case variant on a case-insensitive filesystem. Use the case-insensitive regex above.

## Kinsta

Kinsta runs nginx. If `~/msp-pg-evidence` (a sibling of `~/public`) is writable, evidence is private and nothing more is needed. Each scan report's `evidence_storage.scope` shows which root was used: `private` or `web_root`. If it shows `web_root`, ask Kinsta support to add the rule above, or set `msp_pg_artifact_base_dir` to a non-public directory. Evidence outside `~/public` may not be included in Kinsta's site backups; retrieve it over SFTP/SSH.

## Remaining risks (not addressed in this pass)

- Fallback storage on nginx without the host rule: evidence can be read by anyone who obtains a full evidence path. Paths are not in emails, but they appear in the on-disk reports and could leak through any other path disclosure.
- Evidence from earlier versions under `uploads/.msp-remediation` (raw PHP if `full_artifact_retention` was used) stays web-reachable on nginx until it is moved or blocked.
- The private-root check cannot see web-server aliases (see above).
- `MSP_PG_Config::update_key()` is an HMAC key embedded in the shipped plugin and used to verify signature-registry updates. Anyone with the plugin source can compute valid HMACs, so registry integrity rests on the HTTPS update channel. Asymmetric signatures would fix this; out of scope here.
