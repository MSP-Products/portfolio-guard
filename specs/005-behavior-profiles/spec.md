# Specification 005 — Behavior Profile Specification

**Status:** Approved  
**Covers:** Phase 3 vocabulary, signal taxonomy, and profile definitions  
**Depends on:** Spec 001 (approved), Spec 003 (approved), Spec 004 (approved)  
**Does not cover:** Feature extraction implementation (Milestone 3.1), classification
algorithm (Milestone 3.2), detector code changes, scoring weights or thresholds

---

## 1. Purpose

This specification establishes the vocabulary, structure, and explainability model for
Portfolio Guard's behavioral detection system. It defines what Behavior Profiles are,
which profiles exist in PC1, which observable signals contribute to each profile, and
what evidence each profile must produce when it activates.

It does not define how profiles are activated (classifier algorithm, signal thresholds,
or weighting). Those decisions belong to the implementation milestones that follow this
spec. A profile that activates without producing the evidence defined here is
incorrectly implemented.

---

## 2. Objectives

1. Replace the phrase "heuristic finding" with a precise, explainable behavioral model
   that MSP engineers can understand and act on.
2. Define five named profiles corresponding to the five malicious capabilities
   identified in the PSOT and roadmap.
3. Establish a complete observable signal taxonomy rooted in signals already present
   in the codebase.
4. Define what constitutes sufficient evidence for a profile to be considered active.
5. Define the explainability output that every Review Required report must produce.

---

## 3. Scope

- Definition of Behavior Profile as a concept
- The five PC1 profiles: Persistence, Command & Control, Payload Delivery, Operator
  Access, Stealth
- The complete observable signal taxonomy
- Profile-to-signal mapping (which signals contribute to which profiles)
- Evidence requirements per profile
- Explainability output format
- Integration with the Review Required report and `evidence.json`
- Acceptance criteria for Phase 3 correctness

---

## 4. Non-Goals

- Scoring algorithms, threshold values, or weighting (Milestone 3.2 / 3.3)
- Feature extraction implementation (Milestone 3.1)
- Any changes to `MSP_PG_Detector` in this spec
- Modification of Tier 1 detection in any way
- Automatic remediation of Tier 2 findings (never allowed — Spec 001 §3.2)
- Reputation scoring or cross-site intelligence (PC2)
- Machine learning or probabilistic models
- Detection of malware families not in the `wordpress-shared-plugin-framework`
  ecosystem

---

## 5. Behavior Profile Philosophy

### 5.1 What a Behavior Profile Is

A **Behavior Profile** is a named, human-readable description of a specific malicious
capability that a plugin may possess. A profile groups related observable signals
together under a concept that an MSP engineer can immediately understand.

A profile does not describe what a plugin *is*. It describes what a plugin *can do*.

A plugin that activates the Command & Control profile has demonstrated the capability
to receive instructions from an external operator. Whether it is actively being used
for that purpose is a question for the MSP engineer, not the scanner. The scanner's
role is to surface the evidence; the operator's role is to investigate.

### 5.2 Why Profiles Replace Additive Scoring

The current additive scoring system assigns numeric weights to individual signals and
classifies a plugin as Tier 2 when the total score crosses a threshold. This produces
"score: 105" in an evidence manifest, which an MSP engineer cannot interpret without
understanding the weight table.

Profile-based classification produces "Command & Control activated:
`register_rest_route` found in core.php, `wp_remote_get` found in vendor/client.php."
An MSP engineer understands this without any knowledge of the detection engine.

Profiles provide explainability by construction, not as an afterthought.

### 5.3 The Profile Activation Model

A profile is either **active** or **inactive** for a given plugin. Activation is
determined by the classifier (defined in Milestone 3.2 / 3.3). This specification
does not define the classifier — it defines:

1. What signals exist and how they are observed.
2. Which signals contribute to which profiles.
3. What evidence a profile produces when it activates.

The implementation milestone will define the specific activation logic (e.g., minimum
required signals, required signal combinations). This separation is intentional: the
vocabulary is stable; the sensitivity tuning is iterative.

### 5.4 Profiles and the Review Required Outcome

Behavior Profiles provide the explainability model for Tier 2 (Review Required)
outcomes. When a plugin is classified as Review Required, the activated profiles and
their signal evidence constitute the explanation that operators receive — the *why*
behind the classification decision.

The decision of when sufficient profile evidence exists to produce a Review Required
outcome belongs to the classifier implementation in Milestone 3.3. This specification
does not define that decision. It defines what profiles are, which signals they
observe, and what evidence they produce. The classifier consumes that evidence and
applies its own logic to determine whether a Review Required classification is
warranted.

Tier 1 detection is entirely unchanged. Tier 1 fires on exact matches against the
signature registry. Tier 1 does not use profiles.

### 5.5 Multi-Profile Activation

A plugin may activate multiple profiles simultaneously. This is expected and common.
The malware families in the known corpus activate multiple profiles concurrently: a
plugin that hides itself (Stealth) typically also has a remote control channel
(Command & Control) and an authentication bypass (Operator Access).

When multiple profiles activate, all are reported. The MSP engineer's review scope is
informed by which profiles are active.

### 5.6 Signal Overlap Across Profiles

Some signals contribute to multiple profiles. `register_rest_route(` is both a
Command & Control signal (control endpoint) and a Persistence signal (execution
pathway that survives restarts). `add_filter('all_plugins'` is both a Stealth signal
(hiding from admin) and a Persistence signal (ensures continued operation).

Signal overlap does not create conflicting classifications. It means the signal
provides evidence for multiple aspects of the plugin's behavior.

---

## 6. Profile Definitions

### 6.1 Persistence

**ID:** `persistence`  
**Label:** Persistence

**What it means:** The plugin has mechanisms that allow it to continue executing or
remain installed even when an administrator takes action to remove or deactivate it.
This includes hiding from admin interfaces, registering execution hooks that survive
plugin deactivation attempts, and maintaining execution pathways through WordPress
core mechanisms.

**Why it matters to operators:** A plugin with Persistence capability is harder to
fully remove. Deactivating it through the WP Admin plugin list may not stop its
execution if it has hidden its entry or registered early-loading hooks. MSP engineers
investigating a Persistence finding should verify that the plugin has been fully
removed from both the active plugin list and the MU-plugin directory, and that no
associated hooks remain.

**Operator question answered:** "Will this plugin keep running if I deactivate it
through the admin interface?"

---

### 6.2 Command & Control

**ID:** `command-and-control`  
**Label:** Command & Control

**What it means:** The plugin has mechanisms to receive instructions from an external
operator or automated controller. This includes registering custom REST endpoints that
respond to external requests, making outbound HTTP connections to retrieve
configuration or commands, and using known C2 infrastructure patterns observed in the
known-family corpus.

**Why it matters to operators:** A plugin with Command & Control capability is
actively participating in an external infrastructure. Removing the plugin breaks the
control channel, but the external infrastructure may already have received data from
this site. MSP engineers investigating a Command & Control finding should check site
logs for outbound connections and assess what data may have been exfiltrated.

**Operator question answered:** "Is this plugin reporting to or receiving orders from
someone outside this site?"

---

### 6.3 Payload Delivery

**ID:** `payload-delivery`  
**Label:** Payload Delivery

**What it means:** The plugin has mechanisms to introduce, stage, or execute code
beyond what is contained in its static plugin files. This includes injecting
JavaScript dynamically into page output, loading scripts from remote sources, and the
structural pattern of concealed PHP payload files in randomly named subdirectories.

**Why it matters to operators:** A plugin with Payload Delivery capability may be
serving malicious code to site visitors, or may be staging a secondary payload that is
not visible in a simple filesystem scan. MSP engineers investigating a Payload
Delivery finding should examine browser-facing output on the site for injected scripts
and inspect any randomly named subdirectories for PHP files.

**Operator question answered:** "Is this plugin loading additional code that isn't in
its own plugin files?"

---

### 6.4 Operator Access

**ID:** `operator-access`  
**Label:** Operator Access

**What it means:** The plugin has mechanisms to authenticate or impersonate a
legitimate WordPress user, bypassing normal authentication requirements. This includes
creating and reading authentication cookies, redirecting to the WordPress admin area,
and the known backdoor parameter triplet that impersonates authenticated requests.

**Why it matters to operators:** A plugin with Operator Access capability may have
already allowed unauthorized access to the WordPress admin. MSP engineers
investigating an Operator Access finding should review recent admin activity logs,
check for unauthorized admin accounts, and reset all administrator passwords as a
precaution.

**Operator question answered:** "Has this plugin given someone unauthenticated access
to this site's admin area?"

---

### 6.5 Stealth

**ID:** `stealth`  
**Label:** Stealth

**What it means:** The plugin takes active measures to conceal its presence or
activity from WordPress administrators. This includes filtering itself out of the
active plugin list displayed in WP Admin, registering REST routes without
authentication requirements (leaving no admin-visible trace), and hooking early
execution points without producing any visible admin output.

**Why it matters to operators:** A plugin with Stealth capability has been
deliberately designed to avoid detection. Its absence from the WP Admin plugin list
does not mean it is not installed and running. MSP engineers investigating a Stealth
finding should inspect the filesystem directly rather than relying on admin interface
listings.

**Operator question answered:** "Is this plugin hiding itself from normal
administrative visibility?"

---

## 7. Observable Signal Taxonomy

A **signal** is a specific, observable characteristic of a plugin's code or filesystem
structure that can be detected by scanning plugin files without executing any code.
All signals in this taxonomy are detectable by substring search, pattern matching
against file contents, or filesystem structure analysis within the scan extensions and
size limits defined in `MSP_PG_Config`.

Signals are grouped into classes by their detection method.

### 7.1 String Marker Signals (SM)

Presence of a specific literal string in any scanned file's contents.

| Signal ID | Observable string | Source registry |
|---|---|---|
| SM-01 | `fastreactic_nanomicroserviceing` | `heuristic_markers()['shared']` |
| SM-02 | `tridatation_quicktypescriptal` | `heuristic_markers()['shared']` |
| SM-03 | `data-ph-pid` | `heuristic_markers()['network']` |
| SM-04 | `/api/config/` | `heuristic_markers()['network']` |
| SM-05 | `/api/click` | `heuristic_markers()['network']` |

SM-01 and SM-02 are obfuscated identifiers observed across multiple family specimens.
SM-03, SM-04, SM-05 are network and control-plane markers observed in the known-family
network layer. All five are present in real captured specimens in
`malware-corpus/specimens/`.

### 7.2 Function Call Signals (FC)

Presence of a specific PHP function call string in any scanned file's contents.

| Signal ID | Observable string(s) | Behavioral meaning |
|---|---|---|
| FC-01 | `register_rest_route(` | REST endpoint registration |
| FC-02 | `wp_remote_get(`, `wp_remote_post(`, `wp_remote_request(` | Outbound HTTP request |
| FC-03 | `wp_set_auth_cookie(` | WordPress authentication cookie creation |
| FC-04 | `setcookie(` | Raw PHP cookie write |
| FC-05 | `$_COOKIE` | Cookie read or manipulation |
| FC-06 | `wp_safe_redirect(` | Post-authentication redirect |
| FC-07 | `wp_register_script(`, `wp_enqueue_script(`, `wp_add_inline_script(` | Script registration or inline injection |
| FC-08 | `wp_ajax_`, `wp_ajax_nopriv_` | AJAX handler registration |

FC-02 through FC-06 are individually common in legitimate plugins. Their significance
rises when observed in combination with other signals within the same plugin. FC-08
(`wp_ajax_nopriv_`) is more specific than `wp_ajax_` — nopriv handlers respond to
unauthenticated AJAX requests.

### 7.3 Hook Pattern Signals (HP)

Presence of a specific WordPress action or filter hook registration.

| Signal ID | Observable string | Behavioral meaning |
|---|---|---|
| HP-01 | `add_filter('all_plugins'` or `add_filter("all_plugins"` | Removes plugin from admin plugin list |
| HP-02 | `add_action('template_redirect'` | Early execution hook before any output |

HP-01 matches the compact form with either quote style. The WordPress-style spaced form
(`add_filter( 'all_plugins'`) is deliberately not matched: calibration found it in 15 files of
mainwp-child 4.6, which hides its own entry on request, so matching it would flag every
plugin formatted to WordPress standards. Malware written in the spaced form is therefore
not seen by HP-01.

HP-01 is the primary stealth mechanism observed in the known-family corpus. HP-02
provides early execution that survives normal plugin deactivation because it fires
before WordPress checks whether a plugin is active.

### 7.4 DOM Manipulation Signals (DM)

Presence of JavaScript DOM manipulation strings in any scanned file.

| Signal ID | Observable string(s) | Behavioral meaning |
|---|---|---|
| DM-01 | `createElement('script')`, `createElement("script")` | Dynamic JavaScript element creation and injection |

DM-01 is observed in PHP files that output JavaScript designed to inject additional
script elements into the page DOM at runtime. Both single and double quote variants
are matched.

### 7.5 Callback Pattern Signals (CB)

Presence of a specific callback configuration pattern.

| Signal ID | Observable string | Behavioral meaning |
|---|---|---|
| CB-01 | `permission_callback' => '__return_true'` | REST route registered without authentication |

CB-01 indicates a REST endpoint that any HTTP client can call without authentication.
Combined with FC-01, this creates an anonymous, unauthenticated control interface
accessible to anyone who knows the route.

### 7.6 Structural Pattern Signals (SP)

Observable filesystem structure patterns assessed against the plugin directory as a
whole.

| Signal ID | Pattern description | Behavioral meaning |
|---|---|---|
| SP-01 | A 5–6 character alphanumeric subdirectory containing at least one 8-character alphanumeric PHP filename | Concealed payload staging structure |
| SP-02 | An 8-character alphanumeric JavaScript file directly under `assets/` | Concealed asset staging |

SP-01 and SP-02 are structural markers derived from analysis of the known-family
corpus. The random naming convention is a deliberate obfuscation technique to prevent
signature matching on filenames. Detection is implemented in
`MSP_PG_Utils::random_payload_structure()`.

### 7.7 Compound Behavioral Signals (KB)

Signals that require the co-presence of multiple observable strings to fire. These
are assessed per-file.

| Signal ID | Co-presence requirement | Behavioral meaning |
|---|---|---|
| KB-01 | All three present in one file: the backdoor `id_param`, the backdoor `token_param`, and the backdoor `token_value` from any registered backdoor pair | Known authentication impersonation triplet |
| KB-02 | Any of: SM-01, SM-02, or SM-03 present | Known family bootstrap pattern |
| LB-01 | One PHP file contains all four: `wp_set_auth_cookie(`; one of `wp_insert_user(`, `wp_create_user(`, `add_cap(`, `set_role(`; one of `manage_options`, `install_plugins`, `administrator`; and one of `$_GET[`, `$_REQUEST[`, `$_POST[` | Login backdoor: a request parameter triggers creation or elevation of a privileged account and logs it in |

KB-01 is the existing `known_auth_cookie_impersonation_pattern` signal. It is not an
exact match type (it does not identify a specific family variant), but it is a strong
behavioral indicator. Each registered backdoor pair in
`MSP_PG_Signatures::backdoor_pairs()` defines one testable triplet.

LB-01 comes from incident report MSP-WO-IR-2026-001 (Levine Eye Care). Each part alone is
common in legitimate code (remote-management plugins set auth cookies), so the signal needs all
four in a single file; a plugin-wide score cannot express "same file", which is why it is a
signal of its own. It is read from `.php` files only. It does not detect a backdoor that logs
in an existing account without creating or elevating one, and string matching does not see
obfuscated code. `matched_string` lists the four strings that matched.

KB-02 consolidates the existing `known_family_bootstrap_pattern` into the signal
taxonomy. Its constituent strings (SM-01, SM-02, SM-03) are listed individually above
but recognized together as a bootstrap marker.

---

## 8. Profile-to-Signal Mapping

Each profile has a defined set of signals. Signals are categorized as **primary**
(strongly indicative of this profile's specific capability) or **contextual**
(commonly observed alongside this profile's capability, contributing supporting
evidence).

This categorization informs the evidence report structure (§10) but does not prescribe
which signals must be present to activate a profile — that belongs to the classifier
implementation in Milestone 3.3.

### 8.1 Persistence

| Signal | Category | Rationale |
|---|---|---|
| HP-01 `add_filter('all_plugins'` | Primary | Directly enables plugin to hide and persist through admin action |
| HP-02 `add_action('template_redirect'` | Primary | Provides execution pathway that fires before plugin active-list checks |
| FC-01 `register_rest_route(` | Primary | Maintains a control endpoint that persists through WP restarts |
| FC-08 `wp_ajax_`/`wp_ajax_nopriv_` | Primary | AJAX pathway that persists independently of plugin list state |
| CB-01 `permission_callback '__return_true'` | Contextual | Anonymous access to the persisted endpoint |
| SP-01 (structural) | Contextual | Payload staged in obfuscated location survives simple plugin removal |

### 8.2 Command & Control

| Signal | Category | Rationale |
|---|---|---|
| FC-01 `register_rest_route(` | Primary | Creates the inbound control endpoint |
| FC-02 `wp_remote_*` | Primary | Makes outbound contact with external infrastructure |
| CB-01 `permission_callback '__return_true'` | Primary | Control endpoint accessible without authentication |
| SM-04 `/api/config/` | Primary | Known C2 configuration endpoint pattern |
| SM-05 `/api/click` | Primary | Known C2 event tracking pattern |
| KB-02 (bootstrap pattern) | Primary | Family-specific C2 initialization strings |
| SM-03 `data-ph-pid` | Primary | Known C2 session/tracking identifier |
| FC-08 `wp_ajax_nopriv_` | Contextual | Unauthenticated AJAX as secondary control interface |

### 8.3 Payload Delivery

| Signal | Category | Rationale |
|---|---|---|
| DM-01 `createElement('script')` | Primary | Runtime JavaScript payload injection into page DOM |
| SP-01 (structural) | Primary | Presence of concealed PHP payload staging structure |
| FC-07 `wp_register_script/enqueue/inline` | Contextual | Script loading via WordPress API (can deliver payloads) |
| SP-02 (structural) | Contextual | Concealed JavaScript asset in assets directory |

### 8.4 Operator Access

| Signal | Category | Rationale |
|---|---|---|
| KB-01 (backdoor triplet) | Primary | Known authentication impersonation pattern |
| LB-01 (login backdoor combination) | Primary | Auth cookie, account creation or elevation, privileged capability and request trigger in one file |
| FC-03 `wp_set_auth_cookie(` | Primary | Directly creates WordPress authentication session |
| FC-05 `$_COOKIE` | Contextual | Cookie read used in session validation logic |
| FC-04 `setcookie(` | Contextual | Raw cookie write (may create or extend auth session) |
| FC-06 `wp_safe_redirect(` | Contextual | Post-authentication redirect to admin area |

### 8.5 Stealth

| Signal | Category | Rationale |
|---|---|---|
| HP-01 `add_filter('all_plugins'` | Primary | Directly removes plugin from admin plugin list |
| CB-01 `permission_callback '__return_true'` | Primary | REST access leaves no authentication trace in logs |
| HP-02 `add_action('template_redirect'` | Contextual | Executes before any visible page output |
| KB-02 (bootstrap pattern) | Contextual | Obfuscated strings reduce static analysis effectiveness |

---

## 9. Signal Evidence Requirements

When a signal is observed, its contribution to a profile's evidence must be recorded
with sufficient detail for an MSP engineer to locate and verify it independently.

Each observed signal instance must record:

| Field | Description |
|---|---|
| `signal_id` | The signal identifier from §7 (e.g., `FC-01`, `HP-01`, `KB-01`) |
| `signal_label` | Human-readable signal description (e.g., "REST endpoint registration") |
| `file` | The relative file path within the plugin directory where this signal was observed |
| `matched_string` | The exact substring or pattern that triggered this signal, as it appears in the file |

For compound signals (KB-01, KB-02, SP-01, SP-02), each component observation is
recorded individually, and the compound signal ID is noted as the binding concept.

**Signal-level evidence is the atomic unit.** A profile activation without per-signal
file evidence is not explainable and does not satisfy this specification.

---

## 10. Profile Activation Evidence

When a profile activates, it produces a **profile activation record** that is attached
to the Review Required report. A profile activation record contains:

| Field | Description |
|---|---|
| `profile_id` | The profile identifier from §6 (e.g., `command-and-control`) |
| `profile_label` | Human-readable profile name (e.g., "Command & Control") |
| `signals_observed` | Array of signal evidence records (per §9), one entry per observed signal instance |
| `summary` | A single human-readable sentence explaining what was found and what it means for this plugin |

The `summary` field is the sentence that an MSP engineer reads first. It must be
specific to the observed signals — not a generic template. Acceptable: "This plugin
registers a REST endpoint (`register_rest_route`) accessible without authentication
and makes outbound HTTP requests (`wp_remote_get`) during initialization."
Unacceptable: "Behavioral signals consistent with Command & Control were detected."

**A profile that activates without producing a summary and at least one signal
evidence record is non-conforming.**

---

## 11. Explainability Requirements

These requirements apply to every Review Required detection. They are not aspirational
— they are correctness criteria.

### 11.1 Every conclusion must trace to evidence

If a plugin is classified as Review Required, every profile that contributed to that
classification must appear in the report. If a profile activated but produced no
evidence records, the classification is unsupported and must not be presented to the
operator.

### 11.2 Evidence must be independently verifiable

An MSP engineer must be able to open the referenced file at the referenced path,
search for the matched string, and confirm that it is present. If the signal is a
structural pattern, the engineer must be able to navigate to the referenced directory
and confirm the structure.

### 11.3 No raw scores in operator output

The evidence manifest and all operator-facing reports must not expose numeric heuristic
scores. The classification is "Review Required" because specific profiles activated
based on specific observable signals — not because a number crossed a threshold. The
implementation milestone may use scores internally during classification, but scores
must not appear in `evidence.json`, `report.md`, `report.txt`, or the HTML email.

### 11.4 Operator summary must be actionable

Each profile's summary must tell the MSP engineer what to do next, not just what was
found. The PSOT states that Tier 2 findings enable "Human investigation" — the profile
summary is the starting point for that investigation.

### 11.5 Confidence label is preserved

The `confidence` field in the manifest continues to read "Strong Heuristic" for Tier 2
detections. This is set by `MSP_PG_Detector` and is not changed by Phase 3 (per Spec
003 §3 deferred items). Profile activation provides the explanation beneath that label.

---

## 12. Report Integration

Profile activation data is added to the existing report structure. This is an
extension, not a redesign.

### 12.1 Evidence manifest (`evidence.json`)

A new top-level field is added to the manifest for Tier 2 detections:

```json
"behavior_profiles": [
  {
    "profile_id": "command-and-control",
    "profile_label": "Command & Control",
    "summary": "This plugin registers a REST endpoint accessible without authentication and makes outbound HTTP requests during initialization.",
    "signals_observed": [
      {
        "signal_id": "FC-01",
        "signal_label": "REST endpoint registration",
        "file": "framework-triappment.php",
        "matched_string": "register_rest_route("
      },
      {
        "signal_id": "FC-02",
        "signal_label": "Outbound HTTP request",
        "file": "vendor/rusty/client.php",
        "matched_string": "wp_remote_get("
      },
      {
        "signal_id": "CB-01",
        "signal_label": "Unauthenticated REST access",
        "file": "framework-triappment.php",
        "matched_string": "permission_callback' => '__return_true'"
      }
    ]
  }
]
```

For Tier 1 detections, `behavior_profiles` is an empty array. Profiles are Tier 2
only.

### 12.2 Markdown and plaintext reports

Per-detection report sections for Tier 2 include a "Behavior Profiles" block listing
activated profiles and their summaries. Signal-level detail is available in
`evidence.json`; the text reports present the summary and a count of observed signals
per profile.

### 12.3 HTML email

The Review Required section in the HTML email is extended with activated profile names
and their summaries per detection. Signal-level detail is not included in the email
body — it is available in the evidence manifest.

### 12.4 Existing fields are unchanged

All existing manifest fields defined in Spec 003 §5 remain. No existing fields are
removed, renamed, or reordered. `behavior_profiles` is an additive extension.

---

## 13. Synthetic Corpus Alignment

The five synthetic plugins in `validation/corpus/synthetic/` (defined in Spec 004)
map directly to the five profiles. This alignment is precise and intentional:

| Synthetic plugin | Target profile | Primary signals it emits |
|---|---|---|
| `synthetic-c2-channel` | Command & Control | FC-01, FC-02, CB-01 |
| `synthetic-payload-delivery` | Payload Delivery | DM-01, FC-07 |
| `synthetic-operator-access` | Operator Access | FC-03, FC-04, FC-05, FC-06 |
| `synthetic-login-backdoor` | Operator Access | LB-01 (inert: the function is never hooked) |
| `synthetic-persistence` | Persistence | HP-01, FC-01, FC-08, FC-02 |
| `synthetic-stealth` | Stealth | HP-01, CB-01, FC-01, FC-07 |

When Phase 3 implementation is complete, each synthetic plugin must activate its
target profile and produce a conforming activation record. This is what makes the
synthetic corpus blocking (per Spec 004 §9.4, `gate_blocking` transitions from
`false` to `true` per profile).

---

## 14. Acceptance Criteria

Phase 3 is complete when all of the following are true:

1. Every Review Required detection in `evidence.json` contains a `behavior_profiles`
   array with at least one entry.
2. Every entry in `behavior_profiles` contains a non-empty `profile_id`,
   `profile_label`, `summary`, and at least one `signals_observed` entry.
3. Every signal evidence entry contains a `signal_id` from the taxonomy in §7, a
   `file` field referencing a file that existed in the plugin directory at scan time,
   and a `matched_string`.
4. The `summary` field for each activated profile contains a sentence specific to the
   observed signals — not a generic template.
5. No numeric heuristic score appears in `evidence.json`, `report.md`, `report.txt`,
   or the HTML email body for Tier 2 detections.
6. The `synthetic-c2-channel` plugin activates the `command-and-control` profile and
   produces a conforming activation record.
7. The `synthetic-payload-delivery` plugin activates the `payload-delivery` profile and
   produces a conforming activation record.
8. The `synthetic-operator-access` plugin activates the `operator-access` profile and
   produces a conforming activation record.
9. The `synthetic-persistence` plugin activates the `persistence` profile and produces
   a conforming activation record.
10. The `synthetic-stealth` plugin activates the `stealth` profile and produces a
    conforming activation record.
11. `php validation/gate.php` passes with all synthetic corpus entries blocking
    (`gate_blocking: true` for all five profiles after Phase 3 merge).
12. Tier 1 detection is unchanged — no registered family's detection behavior changes
    as a result of Phase 3 work.
13. `SignatureRegistryTest.php` passes without modification.

---

## 15. Risks

**Risk 1 — Profile activation threshold tuning may require iteration.**
This spec defines signal membership per profile but defers the activation threshold
to Milestone 3.3. The implementation team may discover that the initial threshold
produces too many false positives (profile fires on clean plugins) or too few true
positives (profile fails to fire on known-family variants). The synthetic corpus
provides a reference for true positives; the clean corpus provides a reference for
false positives. Both must be checked before any threshold is considered stable.

**Risk 2 — Signal overlap across profiles may amplify one-signal detections.**
A single signal like `register_rest_route(` contributes to both Command & Control and
Persistence. The classifier must be designed to require corroborating evidence, not
activate a profile on a single common signal alone. This is a classifier design
requirement that belongs to Milestone 3.3, not a change to profile definitions.

**Risk 3 — `behavior_profiles` output field must not appear for Tier 1.**
The implementation must ensure that `behavior_profiles` is only populated for Tier 2
detections. If a Tier 1 detection accidentally includes profile data, it creates the
impression that Tier 1 detections are behavioral rather than exact-match, which
contradicts the two-tier model. This must be explicitly tested.

**Risk 4 — Summary generation.**
The `summary` field must be specific to the signals observed, not a generic template.
This requires either template-with-variable substitution (where signal labels and
files are injected into a phrase structure) or a more sophisticated generation
approach. A template-based approach is acceptable for PC1. The implementation must
define a summary generation strategy that satisfies criterion 4 above.

**Risk 5 — Scan perimeter limits signal coverage.**
The scanner reads only `.php`, `.js`, `.json`, and `.txt` files up to 2 MB. Signals
embedded in files outside these types or size limits will not be detected. This is a
known limitation of the existing scan perimeter. Profile definitions assume signals
are within scanned files; if malware evolves to place signals outside the scan
perimeter, the perimeter must be re-evaluated separately.

---

## 16. Future Extensibility

**Adding a new signal:** Define it in the taxonomy (§7) with an ID, observable string,
and detection method. Update the affected profile mappings (§8). If it introduces a
new detection class, add a new class section under §7. No profile definition changes
are required unless the signal represents a new behavioral capability.

**Adding a new profile (PC2 or beyond):** Define it following the template in §6 —
purpose, operator question, and behavioral meaning. Assign signals from the existing
taxonomy. Create a synthetic plugin in the validation corpus. Set `gate_blocking:
false` until the profile is validated by the classifier.

**Extending evidence richness:** Future implementation milestones may add line numbers,
character offsets, or file checksums to signal evidence records. These are additive
extensions to the `signals_observed` array.

**Tightening or loosening activation thresholds:** The activation model (Milestone
3.3) may be tuned independently of profile definitions. This spec defines what
profiles are and what they observe; it does not lock activation sensitivity. Threshold
changes flow through the classifier implementation, not this specification.
