# 03 — Version Control, CI/CD and Portability (2.1.0)

> **Snapshot:** 2026-10-14. Remote facts were read with the `gh` CLI (read-only) on that date. Local `main` was 9 commits ahead of `origin/main` (`d522c10`), with uncommitted 2.1.0 corrections. 2.1.0 is **not** tagged or published.

## A. Version-control structure

**Remote:** `github.com/joshualee791/portfolio-guard`.
- **Public** repository, so the tracked malware corpus is publicly readable.
- Default branch `main`, with **no branch protection, no rulesets, no webhooks, no deploy keys, no environments**.
- Actions enabled (all actions allowed); default workflow token read-only (`release.yml` raises it to `contents: write`).
- One Actions secret, `MSP_PG_UPDATE_KEY`. No Actions variables.

| Path | Contents | Tracked |
|---|---|---|
| `portfolio-guard/` | Plugin source (`portfolio-guard.php`, `includes/`, `data/`, `readme.txt`), `tests/`, `scripts/`, dev `README.md` | yes |
| `validation/` | `gate.php`, `runner/*.php`, `release-package-test.php`, `calibrate.php`, `corpus/` (known-malware stubs, synthetic Tier 2 fixtures, clean-plugin manifest) | yes; staged clean plugins ignored |
| `releases/portfolio-guard/` | `.sha256` for 2.0.0–2.0.3 and 2.1.0; ZIPs (ignored) | sha256 only |
| `docs/` | Family write-ups, operations, product/spec docs (many from June 2026; see discrepancies in §G) | yes |
| `specs/`, `research/` | Specs 001/002/005/009; case reports and malware intel | yes |
| `malware-corpus/` | `specimens/` (353 files, including 109 `.php`), `neutralized-artifacts/` | yes, except raw `*.tar.gz.sample` inbox files (untracked but **not ignored**), `site-artifacts/`, `sbkortho/` |
| `.github/workflows/release.yml` | The only workflow | yes |
| `_release_validation/` | Local release-validation workspaces, canary material, distribution previews, authenticated copy of published 2.0.9 assets | ignored |
| `archive/`, `signatures/`, `tooling/`, `portfolio-guard;C/` | Local leftovers (`archive/inventories/*` ignored; the others empty) | no |

**Branches:** `main` is the only release branch. Feature branches (`feature/3.4-…` through `feature/4.4-…`, telemetry, test-harness) are historical; two exist on the remote. There is no develop branch and no PR workflow.

**Tags:**
- `v1.5.6`, `v1.5.6-baseline`: initial import.
- `v2.0.0-m1.1a` … `v2.0.0-m4.3`, `v2.0.0-pc1`: milestone tags, which predate the workflow.
- `v2.0.4` … `v2.0.9`: releases, each published by `release.yml`.

All are on the remote.

**Versioning:**

| Identifier | Location | Enforcement |
|---|---|---|
| Plugin version `X.Y.Z` | Header `Version:`, `MSP_PG_VERSION` (`portfolio-guard.php`), `Stable tag:` and a `= X.Y.Z =` changelog heading (`readme.txt`) | Must equal the tag without its `v`. Enforced by `build-release.ps1` Step 2 and `release-package-test.php`. The upgrade notice is **not** checked. |
| `registry_version` (int) | `data/signatures.json` | Must exceed the last **published** value for hot-update and for upgraded sites to use it (doc 01 §C.5). **Not enforced** by any tool. |
| `signature_version` / `heuristic_version` | `MSP_PG_Config` defaults | Labels in reports and telemetry only. Not enforced. |

**Malware handling:**
- Treat `malware-corpus/` as untrusted, and use static analysis only.
- `.gitignore` excludes live site trees (`malware-corpus/site-artifacts/`, `**/wp-admin/`, `**/wp-includes/`).
- `malware-corpus/README.md` tells contributors to drop raw `*.tar.gz.sample` files into `specimens/`, which is **not** ignored, so `git add -A` would commit them. Neutralization (`return;` prefix) is a convention; no tool verifies it.

## B. Build and validation

Requirements:
- PHP CLI ≥ 7.4 with `ext-zip`.
- Windows PowerShell 5.1+ or pwsh for the `.ps1` scripts. They are written with Windows paths, and CI uses `windows-latest`. They are untested on Linux pwsh.
- Network access to `downloads.wordpress.org` for corpus staging.
- `gh` CLI only for release inspection.

Commands below were run successfully on 2026-10-14 unless marked.

| Purpose | Command (repo root) | Fails when |
|---|---|---|
| Stage clean corpus (once) | `powershell -File validation/runner/stage-clean-corpus.ps1` *(used by CI; not re-run in this review)* | download or pinned-hash mismatch (all `sha256_zip` are empty, so nothing is pinned) |
| One test file | `php portfolio-guard/tests/<Name>Test.php` | non-zero exit, with the failing assertion message |
| All test files | `for f in portfolio-guard/tests/*Test.php; do php "$f" \|\| echo "FAIL $f"; done` | any failure |
| Validation gate | `php validation/gate.php` | any blocking category fails (Synthetic is non-blocking); corpus not staged |
| Release build | `powershell -ExecutionPolicy Bypass -File portfolio-guard/scripts/build-release.ps1 -Version 2.1.0 [-PhpPath <php.exe>]` | Step 0: no PHP or ZipArchive. Step 1: gate. Step 2: version mismatch. Step 3: zip. Step 4: package test. |
| Package test (also run in Step 4) | `php validation/release-package-test.php --zip releases/portfolio-guard/portfolio-guard-2.1.0.zip --version 2.1.0` | missing core files, tests/scripts/README present, version mismatch, `.tmp` files, more than one top-level directory |
| Verify checksum | `sha256sum releases/portfolio-guard/portfolio-guard-X.Y.Z.zip` and compare with `releases/portfolio-guard/portfolio-guard-X.Y.Z.sha256` (format `<hash> *<zip>`, ASCII, no newline) | — |
| Registry manifest | `MSP_PG_UPDATE_KEY=<64 hex> php portfolio-guard/scripts/gen-registry-manifest.php <signatures.json> <public URL>` | key missing or malformed; `registry_version` absent |
| Tests on Linux | `docker run --rm -v <repo>:/app php:<7.4\|8.3\|8.5>-cli` with `docker-php-ext-install zip`, then the commands above | — |

Build caveats:
- `build-wordpress-plugin-zip.ps1` zips the **working directory** `portfolio-guard/` minus `tests/`, `scripts/` and `README.md`, not a git export. Stray untracked files there would ship.
- Local and CI builds differ in line endings, so their hashes differ. The published asset (CI) is authoritative. Example: the local 2.0.9 ZIP is `ff3d0984…` while the published one is `0ef58d5c…`.

## C. CI/CD — `.github/workflows/release.yml` (the only workflow)

| Aspect | Detail |
|---|---|
| Trigger | `push` of tags matching `v*`. No branch, PR, schedule or manual triggers. |
| Runner | `windows-latest`; `actions/checkout@v4`, `shivammathur/setup-php@v2` (PHP 8.1, `ext-zip`). Actions are pinned to major tags, not SHAs. |
| Permissions | `contents: write` (create releases); `GITHUB_TOKEN` passed to `gh` as `GH_TOKEN`. |
| Secret | `MSP_PG_UPDATE_KEY`, the 64-hex HMAC key. Its value **must equal** `MSP_PG_Config::update_key()` in the installed fleet's code; otherwise every site rejects the manifest. Never print it. |
| Steps | 1. Derive version from the tag. 2. `stage-clean-corpus.ps1`. 3. `build-release.ps1 -Version <v>` (gate, version check, ZIP, package test, `.sha256`). 4. Write `releases/portfolio-guard/plugin.json` from `readme.txt` headers and the `.sha256`. 5. Copy `data/signatures.json` and run `gen-registry-manifest.php`, producing `registry-manifest.json` for `releases/download/<tag>/signatures.json`. 6. `gh release create <tag>` with 5 assets: ZIP, `.sha256`, `plugin.json`, `signatures.json`, `registry-manifest.json`; `--latest` unless the tag contains `-` (then `--prerelease`). |
| Not run | The 19 `portfolio-guard/tests/*Test.php` files. CI runs only the gate and the package test. |
| Failure modes | Gate or version check fails → no release. Missing secret → step 5 fails → no release (the ZIP was already built on the runner, but nothing is published). Re-running on a tag that already has a release fails at `gh release create`. An invalid workflow YAML produces failed runs on ordinary pushes, as happened on 2026-07-01 before `dd09a5a`. |
| Outputs | Only the GitHub Release. Nothing is committed back; the CI `.sha256` and `plugin.json` are not in git. |

## D. Publication triggers and fleet consequences

Installed sites read **only** the release GitHub currently marks *latest*:
- `releases/latest/download/plugin.json`, checked hourly on `admin_init`;
- `releases/latest/download/registry-manifest.json`, checked every 6 h by WP-Cron.

The URLs are hard-coded in `MSP_PG_Config::plugin_update_url()` and `update_manifest_url()`.

| Action | What happens | Reaches production sites? |
|---|---|---|
| Push a commit / merge to `main` | Nothing (no workflow) | **No** |
| Push tag `vX.Y.Z` (no hyphen) | CI builds and publishes a release marked *latest*. | **Yes, fleet-wide, two ways:** (1) every site sees the plugin update on its next admin visit and installs it when an admin clicks update, or automatically if WP auto-updates are on for the plugin. (2) If `registry_version` rose, every site installs the new `signatures.json` within ~6 h **without any plugin update**, so new plugin-directory signatures start triggering automatic Tier 1 deactivation and removal immediately (delete defaults on). |
| Push tag with a hyphen (`v2.2.0-rc.1`) | Published as a prerelease, not *latest*. **But** Step 2 requires every version field to equal `2.2.0-rc.1`, so it only builds if the source carries that suffix. | No (not *latest*) |
| Push a non-release `v*` tag (milestone style) | Workflow runs and fails at the version check | No |
| Publish or edit a release manually in the GitHub UI, or mark another release *latest* | No CI; whatever assets the *latest* release holds are served as-is | **Yes, immediately**, if *latest* changes or its `plugin.json` / `signatures.json` / `registry-manifest.json` are replaced. Marking an older release latest does **not** roll sites back: WordPress offers no downgrades, and a lower `registry_version` is ignored. A *latest* release missing the JSON assets causes registry check failures; after 3 in a row, **each site emails every 6 h**. |
| Edit `data/signatures.json` / family JSON in git | Nothing until a tagged release | Only via the next release. Family JSON (`signatures-*.json`) reaches sites only through a plugin update. |
| Change Config defaults (e.g. a delete flag) | Only via plugin update | Yes, after release and update |

**To roll back a bad signature release, publish a new release with a higher `registry_version`.** Reverting the file or the release does nothing on sites that already applied it.

## E. Portability and ownership transfer

**Hard couplings in shipped code**, which every installed copy carries:
- `MSP_PG_Config::plugin_update_url()` and `update_manifest_url()`: GitHub URLs for `joshualee791/portfolio-guard`, not filterable.
- `MSP_PG_Config::update_key()`: the HMAC key that must match the CI secret.
- `MSP_PG_Config::report_recipient()`: a hard-coded individual email fallback.

Docs also reference the account: `docs/Release_Automation.md`, `docs/operations/*`, family docs.

| Item | Portable as-is? | Action on migration |
|---|---|---|
| Git history, tags, branches | Yes (`git clone --mirror` / push) | — |
| GitHub Releases and assets | Move with a GitHub *transfer*; not with a new repo | For a new repo, re-publish at least the current release's 5 assets |
| `release.yml` | GitHub-only (`GITHUB_REF_NAME`, `GITHUB_OUTPUT`, `gh release create`, `windows-latest`) | Rewrite for any other CI. Keep steps 3–6 semantics. |
| Secret `MSP_PG_UPDATE_KEY` | Re-create it wherever CI runs, with the **same value** the fleet ships. Treat it as sensitive even though it is derivable. | Confirm it exists after any transfer. Rotating it requires shipping a plugin release with the new key first; sites that haven't updated will then reject manifests. |
| Workflow permissions | Per-repo setting | Re-grant `contents: write` (the workflow requests it explicitly) |
| Update endpoints used by installed sites | **No.** Hard-coded. | See the ordering rule below |
| Report recipient fallback | n/a | Set `msp_pg_report_recipient` per site and/or change the default in code |
| Cloud telemetry (legacy) | Unchanged: off unless `msp_pg_cloud_url` is filtered per site | Inventory per-site MU-plugin overrides |
| Report-app reporting | On by default (2.2.0): `msp_pg_report_app_url` defaults to the MSP report app; a site enrolls itself and stores its key in `msp_pg_report_app_key`. A per-site filter returning '' turns it off | Keep the report app's address stable, or ship a release with the new one (same ordering rule as the update URLs) |
| Webhooks, deploy keys, environments, rulesets | None exist | — |

**Ordering rule for any endpoint change:** the fleet can only learn a new URL from a plugin release served at the **old** URL.
1. Publish, from the current location, a release whose `plugin_update_url()` / `update_manifest_url()` point to the new location.
2. Wait until every site has installed it. Discovery needs an admin page load, so check the fleet's actual versions; there is no fleet inventory in this repo.
3. Keep serving the old *latest* assets until then.

Sites still on old versions keep polling the old URLs indefinitely.

- **GitHub transfer to a new owner or organization:** GitHub redirects the old repository URL after a transfer or rename. Whether `releases/latest/download/<asset>` redirects reliably was **not verified** here, and any redirect breaks if a repository is later created at the old name. Test the asset URLs from a site, or follow the ordering rule anyway.
- **New account or repo (no transfer):** new URLs, so the ordering rule is mandatory.
- **Non-GitHub host:** any HTTPS host with stable URLs for a "current" `plugin.json` and `registry-manifest.json` works. `download_url` and `registry_url` inside them can point anywhere over HTTPS. Then port CI.

**Migration checklist:**
- [ ] Inventory installed sites and their PG versions; confirm all are on a version that contains the new URLs before retiring the old endpoint.
- [ ] Inventory per-site configuration overrides (filters in MU-plugins, `msp_pg_report_recipient`).
- [ ] Create the destination repo or org; push the mirror including tags; re-publish or transfer releases.
- [ ] Re-create `MSP_PG_UPDATE_KEY` (same value); confirm the workflow write permission; enable Actions.
- [ ] Ship a release that updates `MSP_PG_Config` URLs (and the recipient default if needed) from the **old** location.
- [ ] Verify from one site: the update offer, registry install (`msp_pg_last_update_applied`), no failure emails.
- [ ] Update docs that reference the old account.
- [ ] Only then archive the old repo, keeping its *latest* release assets online for stragglers.

## F. Developer onboarding

1. **Get the repo:** `git clone https://github.com/joshualee791/portfolio-guard.git`. Do not run anything under `malware-corpus/`.
2. **Environment:** PHP ≥ 7.4 with `ext-zip`; PowerShell on Windows, or Docker `php:*-cli` images on Linux; `gh` (optional). No Composer or npm.
3. **Tests:** §B "All test files". All 19 must pass. Symlink assertions run for real only on Linux.
4. **Gate:** stage the corpus once, then `php validation/gate.php`. Must print `RESULT: PASS`.
5. **Build:** bump the four version fields and add a changelog heading, then `build-release.ps1 -Version X.Y.Z`.
6. **Integrity:** compare the computed SHA-256 with the `.sha256`; list the ZIP entries (single `portfolio-guard/` root, no tests or scripts).
7. **Signature update:**
   1. Edit `data/signatures.json` (plugin-directory families).
   2. Set `registry_version` to one more than the published value. Check it with `gh release download --repo <repo> --pattern signatures.json`.
   3. Add or adjust `validation/corpus/known-malware` fixtures and run the gate.
   4. Ship it as a plugin release; the workflow always publishes both together.

   Family scanners (`signatures-*.json`, `*_Signatures` classes) change only with a plugin release.
8. **Release readiness:** gate PASS; all test files (19 as of 2.1.0) pass on Windows and Linux; package test 12/12; version fields aligned; `registry_version` above the published value if signatures changed; review §D consequences.
9. **Publish (authorized only):** commit, push `main`, then `git tag vX.Y.Z && git push origin vX.Y.Z`. Watch the Actions run. Confirm the 5 assets and that *latest* points to it (`gh release view`).
10. **Diagnose:**
    - **Workflow failures:** Actions log; step names match §C.
    - **Site-side update problems:** options `msp_pg_plugin_update_cache` / `msp_pg_plugin_update_last_checked` (plugin updates); `msp_pg_last_update_checked`, `msp_pg_last_update_applied`, `msp_pg_max_registry_version`, `msp_pg_update_consecutive_failures` (registry); PHP `error_log` lines prefixed `MSP Portfolio Guard:`; the Settings → Portfolio Guard diagnostics page.

**Cannot be reproduced from the repository alone:**
- the fleet inventory and per-site configuration;
- the HMAC key's custody (beyond the source constant);
- the receiving end of Cloud reporting (the MSP report app, a separate repository);
- hosting access (e.g. Kinsta) and WordPress admin credentials;
- who monitors the report mailbox;
- the off-repo forensic specimen store referenced in `.gitignore`;
- the status of the planned VCA Dentistry canary (local, gitignored `_release_validation/canary-vca-dentistry/`).

## G. Documentation discrepancies found

| Document | Claim | Actual (2.1.0) |
|---|---|---|
| `docs/architecture/PORTFOLIO_GUARD_PROJECT_STATE.md` (Jun 2026) | MU-loader blocks known entrypoints and hides known plugins at runtime | `MSP_PG_Runtime` is never booted (caller deleted in `ed3f9a9`) |
| `docs/Release_Automation.md` | Three release assets; "no secrets need to be configured"; upgrade notice verified | Five assets; `MSP_PG_UPDATE_KEY` required; upgrade notice not checked |
| `docs/Release_Automation.md` | Hyphenated tags publish prereleases | Only if every version field carries the suffix |
| Root `README.md` | `portfolio-guard/` contains "boot files"; build with `build-wordpress-plugin-zip.ps1`; release notes in `docs/releases/` | No boot dir; `build-release.ps1` is the release entry point; release notes live in `readme.txt` (`docs/releases/` stops at 1.5.6) |
| `portfolio-guard/README.md` (dev) | "Configuration hooks" lists `msp_pg_scan_interval` and `msp_pg_report_recipient` | No `msp_pg_scan_interval` filter exists; `msp_pg_report_recipient` is an option, not a filter; many current filters are missing (see doc 01 §D) |
| `docs/malware-families/PG-WPLinkHelper.md` §4 | `WLH_Vault` option "surfaced as an outstanding manual step" | No code reports it |
| `malware-corpus/README.md` vs `.gitignore` comment | Raw specimens dropped into `specimens/` vs "must live outside the repository" | Contradictory, and not enforced |
