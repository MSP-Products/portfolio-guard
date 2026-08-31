# Telemetry Contract v1

Status: **Canonical — Schema Version 1**
Scope: Portfolio Guard Agent → Portfolio Guard Cloud outbound telemetry
Canonical contract: this document
Reference implementation: `MSP_PG_Diagnostics::build_telemetry()` (`portfolio-guard/includes/class-msp-pg-diagnostics.php`), published via `MSP_PG_CloudPublisher::publish()` (`portfolio-guard/includes/class-msp-pg-cloud-publisher.php`)

This document is the canonical specification of the telemetry contract between Portfolio Guard Agent and Portfolio Guard Cloud. It was derived from a direct audit of the shipping implementation, but once approved, this document — not the code — is authoritative: the reference implementation MUST conform to this contract, not the other way around. Where the implementation and this document disagree, the implementation is in error and MUST be brought back into compliance, or this document MUST be revised as a deliberate, versioned change (see §4 and §8).

---

## Normative Language

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as follows:

- **MUST** indicates a mandatory requirement.
- **MUST NOT** indicates a prohibited behavior.
- **SHOULD** indicates a strong recommendation.
- **SHOULD NOT** indicates behavior discouraged except under exceptional circumstances.
- **MAY** indicates optional behavior.

---

## 1. Purpose

Telemetry is a periodic, best-effort snapshot of what the Agent already knows about the security state of a single site, sent to Portfolio Guard Cloud for storage and visualization. It is not a control channel, not a configuration channel, and not a mechanism Cloud uses to influence the Agent.

**The Agent is authoritative** because it is the only party with direct access to the filesystem, the WordPress installation, the signature registry, and the operator's review actions. Every fact in the telemetry payload is produced by a scan, a registry update, or an operator interacting with the Agent's own admin UI — Cloud has no independent way to observe or verify any of it.

**Cloud is a passive consumer** by design: it MUST store and visualize whatever the Agent publishes, and it MUST NOT influence scan, detection, or remediation behavior. The reference implementation enforces this structurally, not just by convention — `MSP_PG_CloudPublisher::publish()` is fire-and-forget, has no return value consumed by any caller, and every failure mode (missing config, network error, non-2xx response, thrown exception) is swallowed silently and logged locally. A Cloud outage, misconfiguration, or rejection MUST have zero effect on scanning, remediation, or reporting.

---

## 2. Contract Philosophy

- **Agent owns facts.** Every field in the payload originates from Agent-side state: scan results, registry metadata, report-delivery timestamps, or operator review actions recorded through the Agent's own admin handlers.
- **Cloud stores facts.** Cloud's role is to persist published snapshots as a historical record.
- **Cloud derives analytics.** Trends, dashboards, and fleet-level views are computed *from* published telemetry by Cloud; the Agent does not pre-aggregate or interpret data on Cloud's behalf beyond what's naturally required to answer its own local admin UI.
- **Cloud never modifies telemetry.** A published record MUST be treated as immutable once received. Cloud MUST NOT write back to the Agent, and the Agent MUST NOT accept telemetry-derived instructions from Cloud. If Cloud disagrees with a state (e.g., it thinks a scan should have run), it MUST wait for the next Agent-initiated publish rather than inject a corrected value.

---

## 3. Payload Specification

All fields are always present in a v1 payload (enforced by `TelemetryTest::test_telemetry_has_all_required_fields()`); "optional" below means the value may be `null`, not that the key may be absent. There are no optional-and-absent keys in schema version 1.

| Field | Type | Presence | Description | Ownership | Mutability |
|---|---|---|---|---|---|
| `telemetry_schema_version` | int | required | Contract version this payload conforms to. Always `1` under this document. | Agent | Immutable once set |
| `plugin_version` | string | required | Installed Portfolio Guard Agent version. | Agent | Changes on Agent upgrade |
| `signature_version` | string | required | Version identifier of the signature registry in effect. | Agent | Changes on registry update |
| `heuristic_version` | string | required | Version identifier of the behavioral heuristic ruleset in effect. | Agent | Changes on Agent release |
| `site_url` | string | required | Canonical site URL (`home_url('/')`). | Agent | Changes only if site is reconfigured |
| `site_slug` | string | required | Stable slug derived from site host, used as the primary identity key by Cloud. | Agent | Changes only if site host changes |
| `current_security_state` | string enum: `healthy`, `review_required`, `confirmed_malware`, `scan_failed` | required | The most recently determined security state. | Agent | Overwritten by each subsequent publish; not amendable in place |
| `last_scan_at` | string (ISO 8601) or `null` | required (nullable) | Timestamp of the most recent scan. | Agent | Updated every scan |
| `last_scan_trigger` | string or `null` | required (nullable) | What initiated the most recent scan (e.g. `cron`, manual). | Agent | Updated every scan |
| `last_scan_detections` | int | required | Count of detections from the most recent scan. | Agent | Updated every scan |
| `scan_in_progress` | bool | required | Whether a scan is currently holding the scan lock. | Agent | Transient — true only for the scan's duration |
| `next_scan_at` | int (Unix timestamp) or `null` | required (nullable) | When the next scheduled scan is due. | Agent | Updated by WP cron rescheduling |
| `registry_version` | mixed or `null` | required (nullable) | Version of the currently applied signature registry. | Agent | Updated on registry update |
| `registry_source` | string or `null` | required (nullable) | Where the applied registry came from. | Agent | Updated on registry update |
| `registry_consecutive_failures` | int | required | Consecutive failed registry update attempts. | Agent | Increments on failure, resets on success |
| `last_update_checked` | mixed | required | When the registry was last checked for updates. | Agent | Updated on every update check |
| `report_recipient_configured` | bool | required | Whether an email report recipient is configured locally. | Agent | Changes on admin config edit |
| `last_clean_report_sent` | string (ISO 8601) or `null` | required (nullable) | Timestamp of the last "CLEAN REPORT" email. | Agent | Set only on clean-outcome scans; otherwise preserved as-is |
| `last_review_report_sent` | string (ISO 8601) or `null` | required (nullable) | Timestamp of the last "REVIEW REQUIRED" email. | Agent | Set only on review-required outcomes; otherwise preserved |
| `last_malware_report_sent` | string (ISO 8601) or `null` | required (nullable) | Timestamp of the last "CONFIRMED MALWARE" email. | Agent | Set only on malware-confirmed outcomes; otherwise preserved |
| `last_failed_report_sent` | string (ISO 8601) or `null` | required (nullable) | Timestamp of the last "SCAN FAILED" email. | Agent | Set only when the registry is unavailable at scan start; otherwise preserved |
| `whitelist_count` | int | required | Current number of whitelisted plugin entries. | Agent | Reflects live count at time of publish |
| `last_whitelist_at` | string (ISO 8601) or `null` | required (nullable) | Timestamp of the most recent whitelist addition. | Agent | Set by operator whitelist action |
| `last_whitelist_plugin` | string or `null` | required (nullable) | Slug of the most recently whitelisted plugin. | Agent | Set by operator whitelist action |
| `last_review_action` | string enum: `whitelist`, `whitelist_remove`, `remediate`, or `null` | required (nullable) | The most recent operator review-workflow action. | Agent | Set by the corresponding admin handler |
| `last_review_action_timestamp` | string (ISO 8601) or `null` | required (nullable) | Timestamp of `last_review_action`. | Agent | Set alongside `last_review_action` |
| `telemetry_recorded_at` | string (ISO 8601) | required | When this specific record was assembled. | Agent | **Recomputed on every write** — the one field never preserved from the prior record |

No field in this payload is Cloud-owned, and Cloud MUST NOT set or alter any of them. Fields marked "preserved" retain their last-known value across writes that don't touch them — see §6 for why this matters.

---

## 4. Versioning Policy

- `telemetry_schema_version` is a single integer, currently `1`.
- **Additive changes** (new fields) do **not** require a version bump. Precedent: the whitelist/review-workflow field group was added to the payload without incrementing the schema version, on the basis that existing consumers reading known fields are unaffected by the presence of new, unrecognized ones.
- **Breaking changes** — renaming a field, changing a field's type, changing the meaning of an existing field's value, or removing a field — require incrementing `telemetry_schema_version`. Cloud must be able to key its parsing behavior off this field.
- There is currently no dual-write or payload-translation layer: `MSP_PG_CloudPublisher::build_payload()` passes the internal telemetry record through unchanged. The code carries an explicit note that this translation point exists so that a divergence between Agent's internal shape and Cloud's wire schema can be introduced later without relocating the call site. Until that divergence is needed, the internal contract and the wire contract are identical by choice, not by structural necessity.
- No field has yet been deprecated or removed under this contract; the compatibility path for that scenario is intentionally undefined until it's needed (see §8).

---

## 5. Compatibility

- Consumers MUST ignore unknown fields present in a payload.
- The presence of an unrecognized field MUST NOT be treated as a contract violation.
- A new additive field MUST NOT break existing consumers — introducing one MUST NOT require any consumer to change in order to keep functioning correctly.
- Consumers MUST validate only the fields required by the schema version they implement; a consumer built against v1 MUST NOT require fields introduced in a later, additive revision.
- Future schema versions MAY introduce additional fields while remaining wire-compatible with v1 consumers, provided those additions are additive per §4.
- This compatibility guarantee covers additive evolution only. A breaking change, as defined in §4, is by definition not covered by these guarantees and requires the schema version increment described there.

---

## 6. Publication Lifecycle

```
Scan
  ↓
Telemetry assembled     (MSP_PG_Diagnostics::build_telemetry())
  ↓
Telemetry persisted locally   (WP option: msp_pg_telemetry)
  ↓
Telemetry published    (MSP_PG_CloudPublisher::publish(), on successful scan completion only)
```

**Contract**, independent of implementation: a published telemetry record MUST reflect a complete, internally consistent snapshot as of the end of the most recently completed scan. Consumers MAY rely on this guarantee. Consumers MUST NOT rely on any particular internal mechanism producing that guarantee — the mechanism described below is how the reference implementation currently satisfies it, and MAY change as the Agent evolves, provided the guarantee itself is preserved.

**Reference implementation**, as it exists today: telemetry is **assembled and locally persisted** on every call to `record_telemetry()` — this happens at multiple points: scan completion, scan-failure (registry unavailable), each of the three report-delivery outcomes, registry updates, and operator review-workflow actions (whitelist add/remove, remediate). Every one of these calls rebuilds the record from current state and merges in caller-supplied updates, so the locally-stored `msp_pg_telemetry` option is always current.

Publication to Cloud, however, happens at exactly one point in the reference implementation: immediately after `current_security_state` is finalized at the end of a successful `run_scan()` call — after detections have been classified, the scan report has been written and emailed, and the corresponding `last_*_report_sent` timestamp has already been stamped into the record by that email-send step. This is the only moment in the Agent's current execution where scan outcome, report-delivery status, and security state are all simultaneously final and internally consistent within a single call frame.

**Why publication happens only after successful scan completion, and not on every local telemetry write:**

- It guarantees Cloud only ever receives *complete, self-consistent* snapshots — never a security-state update without its supporting scan metadata, and never a partial write mid-scan.
- It keeps the publish call co-located with code that is already structured to tolerate failure without affecting the operator-facing outcome (dry-run guards, quarantine handling, and mail delivery are all already best-effort in this same code path).
- The registry-failure branch of `run_scan()` deliberately does not publish — a failed scan (registry unavailable) has no confirmed security state to report, so there is nothing yet worth Cloud persisting as a data point.
- Operator review actions and registry updates are lower-frequency, locally-persisted immediately, and will be reflected in Cloud on the next scan-triggered publish. This is a known lag, not an oversight — see the note at the end of this document.

---

## 7. Stability Requirements

Consumers of this contract (i.e., Portfolio Guard Cloud) MAY rely on the following:

- **Field names are stable within a schema version.** A field present in schema version 1 MUST NOT be renamed without a version increment.
- **Field meanings are stable within a schema version.** The semantics of a field (what triggers it to change, what its enum values mean) MUST NOT be silently redefined.
- **Additive fields do not require a version bump.** New fields MAY appear in future payloads without `telemetry_schema_version` changing. Consumers MUST tolerate and ignore unrecognized fields (see §5).
- **Breaking changes require a schema version increment.** Any rename, type change, meaning change, or removal is a breaking change and MUST be accompanied by incrementing `telemetry_schema_version`.
- **Absence of a field is not a valid v1 payload.** All fields listed in §3 MUST always be present (possibly `null`); a consumer encountering a v1 payload missing a listed key MUST treat that as a contract violation, not as "field temporarily unavailable."
- **Publication frequency is not part of the contract.** Consumers MUST NOT assume telemetry is published on a fixed cadence, or that every local Agent state change results in a publish. Consumers MAY assume only that a new publish reflects a superset of information as of the last completed scan.
- **`telemetry_recorded_at` reflects assembly time, not publish time or scan time.** It SHOULD be used to reason about record freshness, and SHOULD NOT be conflated with `last_scan_at`.

---

## 8. Future Extensions

To introduce a new field without breaking existing consumers:

1. The field MUST be added to `build_telemetry()`'s returned array with a sensible default/null for records that predate the field's introduction (matching the precedent set by the whitelist/review-workflow field group).
2. `telemetry_schema_version` MUST NOT be incremented for a purely additive field.
3. The new field MUST be documented in this contract (§3) as part of the same change, including ownership and mutability, before or alongside the implementation change that introduces it.
4. Cloud-side parsing MUST already treat unrecognized fields as ignorable and MUST NOT require a field's presence unless it is listed in the current version of this document.

To make a breaking change (rename, retype, redefine, or remove a field):

1. `telemetry_schema_version` MUST be incremented.
2. This document MUST be updated as part of the same change — the version number in this document's header and the enum/table entries MUST move together with the implementation.
3. Whether Cloud needs a translation/compatibility path for records published under the prior schema version that are already stored SHOULD be considered; this contract does not currently define one, since no breaking change has occurred yet. That gap SHOULD be closed the first time a breaking change is actually proposed, not preemptively.

---

*This document reflects the payload and lifecycle audited directly from `main` (commit `d522c10` and its ancestor `6f4850c`, the merge that introduced `MSP_PG_CloudPublisher`). It supersedes no prior document — this is the first Telemetry Contract for Portfolio Guard Agent.*
