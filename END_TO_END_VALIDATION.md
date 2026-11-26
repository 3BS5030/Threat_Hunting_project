# VM Threat Hunting Dashboard — End-to-End Integration Validation

Validation date: 2026-11-25  
Validation mode: real network, real GUI, real configuration, synthetic events where explicitly required, and injected transport where real SSH was unavailable.  
Application functionality was **not modified** during validation. Only this report and temporary validation artifacts outside the workspace were created.

## Executive conclusion

The application is **not proven as a fully working real end-to-end system**.

Two real integration blockers were found:

1. The live MITRE CTI dataset downloads successfully and is valid, but the application STIX parser rejects the current official bundle with `ValueError: STIX data: no Enterprise techniques or tactics found`. Root cause: current `x-mitre-tactic` objects expose `x_mitre_shortname` and no longer contain `kill_chain_phases`; the parser requires `kill_chain_phases`.
2. The configured Linux lab target cannot be reached through the application because `fabric` is not installed: `RuntimeError: fabric is required for SSH: No module named 'fabric'`.

Downstream integration works when using synthetic events and the application's injected-transport path: collection → normalization → rules/correlation → baseline → findings → MITRE enrichment from the static fallback catalog → Navigator layer all passed stage-handoff checks.

Status legend: **PASS**, **FAIL**, **BLOCKED**.

---

## 1. Real integration tests

### R1 — Official MITRE HTTP response validation

- **Test name:** Official MITRE CTI HTTP HEAD validation
- **Expected:** HTTP 200 responses from the official STIX and release endpoints.
- **Actual:** STIX HEAD returned 200 with `Content-Length: 49257997`, `ETag: "42c56af7faa364b19086b4d09ae43c8b7e46ea89efee4a33b566ffe9343ff306"`. Release API returned 200 via Python `urllib`; Windows `curl.exe -I` failed locally with a revocation-check error.
- **Result:** **PASS**
- **Evidence:** `mitre_real_integration.json`; Python release API response `tag_name = ATT&CK-v20.1`, `published_at = 2026-11-05T16:33:52Z`.
- **Error messages:** `curl: (35) schannel: next InitializeSecurityContext failed: CRYPT_E_REVOCATION_OFFLINE (0x80092013)` — local `curl.exe` TLS revocation check only; Python `urllib` succeeded.
- **Remaining issues:** None for application path; local `curl.exe` requires `--ssl-no-revoke` if used manually.

### R2 — Real Enterprise ATT&CK STIX download

- **Test name:** Real MITRE CTI bundle download
- **Expected:** Download the complete official Enterprise ATT&CK STIX bundle.
- **Actual:** Complete file downloaded to a temporary artifact after resuming a interrupted transfer with HTTP Range. Final size exactly `49,257,997` bytes; bundle type `bundle`; `26,698` STIX objects.
- **Result:** **PASS**
- **Evidence:** `C:\Users\hp\AppData\Local\Temp\opencode\enterprise-attack-real.json`; resume output: `total_bytes = 49257997`, `final_bytes = 49257997`.
- **Error messages:** Initial inspection attempt was interrupted at `14,680,064` bytes; Range resume completed the file.
- **Remaining issues:** Application's own download is slow; first full sync took `249.43s`.

### R3 — Real downloaded STIX data validation

- **Test name:** Independent validation of real STIX object content
- **Expected:** Valid tactics, techniques, sub-techniques, references, and no orphaned sub-techniques.
- **Actual:** `15` tactics, `867` attack-pattern objects, `867` parsed techniques, `370` top-level techniques, `497` sub-techniques, `149` revoked, `12` deprecated, `0` missing names, `0` missing tactics, `0` orphan sub-techniques.
- **Result:** **PASS**
- **Evidence:** `cti_data_real_validation.json`; sample verified IDs: `T1001`, `T1003.001`, `T1001.001`. Confirmed `T1110 = Brute Force`, `T1685 = Disable or Modify Tools`.
- **Error messages:** None.
- **Remaining issues:** This validation used independent parsing because the application parser failed R4.

### R4 — Application parsing of real STIX bundle

- **Test name:** `mitre.attack.parse_stix_bundle` against the real bundle
- **Expected:** Application parses the official bundle into techniques and tactics.
- **Actual:** Application sync returned `status = unavailable` and fell back to `hunting/attack.json`. No cache was written.
- **Result:** **FAIL**
- **Evidence:** `mitre_real_integration.json`: `sync_error = "ValueError: STIX data: no Enterprise techniques or tactics found"`. Real tactic sample: `name = Credential Access`, `x_mitre_shortname = credential-access`, `kill_chain_phases = None`.
- **Error messages:** `ValueError: STIX data: no Enterprise techniques or tactics found`.
- **Remaining issues:** Parser compatibility defect in `mitre/attack.py:99`; current CTI tactic objects use `x_mitre_shortname` instead of `kill_chain_phases`.

### R5 — Dataset version verification

- **Test name:** Real ATT&CK dataset version validation
- **Expected:** Release and dataset versions can be determined.
- **Actual:** Release tag `ATT&CK-v20.1`; real dataset maximum modified timestamp `2026-11-04T14:59:51.172Z`; `T1110` modified `2026-11-03T21:47:10.515Z`; `T1685` modified `2026-09-11T19:52:16.657Z`.
- **Result:** **PASS**
- **Evidence:** Python release API response; `cti_data_real_validation.json`.
- **Error messages:** None.
- **Remaining issues:** Application reports empty `source_version`/`version` because R4 aborts before version assignment.

### R6 — MITRE cache creation and update

- **Test name:** Application cache lifecycle
- **Expected:** `mitre/attack_cache.json` created after successful sync and updated on subsequent sync.
- **Actual:** Cache file absent after first and second forced sync. Application remained on static migration catalog with `15` techniques.
- **Result:** **FAIL**
- **Evidence:** `mitre_real_integration.json`: `cache_after_first.exists = false`, `cache_after_second.exists = false`; direct check: `cache_exists = False`.
- **Error messages:** Same as R4.
- **Remaining issues:** Static fallback catalog is parseable (`4571` bytes, SHA-256 prefix `872df2e8526ef924`), but it is not a live cache.

### R7 — Duplicate notification prevention with real live data

- **Test name:** Real live-sync deduplication
- **Expected:** First live sync reports new/changed techniques; second forced sync reports zero duplicate notifications.
- **Actual:** Both syncs failed before producing live datasets. The observed zero notification count is not evidence of deduplication.
- **Result:** **BLOCKED**
- **Evidence:** `mitre_real_integration.json`: first `notification_count = 0`, second `notification_count = 0`, both with `status = unavailable`.
- **Error messages:** Same as R4.
- **Remaining issues:** Cannot validate real dedupe until R4 is fixed and a live cache exists.

### R8 — Authorized Linux lab SSH connection

- **Test name:** Real SSH transport connection to configured Linux lab VM
- **Expected:** Application connects to the configured Linux lab target over SSH.
- **Actual:** `SSHTransport.connect()` failed before any network connection was attempted. Credentials were not printed.
- **Result:** **BLOCKED**
- **Evidence:** `linux_lab_integration.json`: `target_name = linux-lab-01`, `target_os = linux`, `transport_connect = FAIL`.
- **Error messages:** `RuntimeError: fabric is required for SSH: No module named 'fabric'`.
- **Remaining issues:** `requirements.txt` lists Fabric, but the validation Python environment does not have it installed.

### R9 — Real Linux distribution detection and authentication-log collection

- **Test name:** Real collection through application transport
- **Expected:** Detect distribution, select `/var/log/secure` or `/var/log/auth.log`, collect and normalize auth events plus processes/services/users/scheduled tasks.
- **Actual:** Not executed; SSH transport unavailable.
- **Result:** **BLOCKED**
- **Evidence:** `linux_lab_integration.json`: `hunt_vm = FAIL`.
- **Error messages:** `RuntimeError: fabric is required for SSH: No module named 'fabric'`.
- **Remaining issues:** Real evidence preservation and collection-error behavior remain unproven against the lab host.

### R10 — GUI application startup

- **Test name:** Real Tk GUI startup
- **Expected:** Application window starts with VM cards and ATT&CK refresh button.
- **Actual:** Window title `VM Threat Hunter`, `3` VM cards, refresh button present and enabled, initial status `Ready`.
- **Result:** **PASS**
- **Evidence:** `gui_integration.json` → `startup`.
- **Error messages:** None during startup.
- **Remaining issues:** None.

### R11 — GUI background synchronization and responsiveness

- **Test name:** Real ATT&CK refresh button and non-blocking UI
- **Expected:** Clicking refresh disables the button, starts a background thread, and keeps the UI responsive.
- **Actual:** Status became `Refreshing ATT&CK...`, button became `disabled`, thread count increased from `2` to `3`. UI event loop pumped `9,393` times during sync with maximum gap `0.329s`.
- **Result:** **PASS** for non-blocking behavior
- **Evidence:** `gui_integration.json` → `refresh_button`.
- **Error messages:** Harness shutdown emitted `invalid command name "...poll_queue"` after `root.destroy()`; this occurred after validation and did not affect startup or responsiveness.
- **Remaining issues:** Button never re-enabled because sync did not finish in `480s` (see R12).

### R12 — GUI refresh completion and real notification display

- **Test name:** Real GUI sync completion
- **Expected:** Sync completes, button re-enables, status shows ATT&CK version and change count.
- **Actual:** Status remained `Refreshing ATT&CK...` and button remained disabled for the full `480s` observation window. No real notifications appeared.
- **Result:** **FAIL**
- **Evidence:** `gui_integration.json`: `status_after_background_sync = Refreshing ATT&CK...`, `state_after_background_sync = disabled`.
- **Error messages:** No exception surfaced to the GUI.
- **Remaining issues:** Slow/failing live sync is not surfaced to the user; button can remain disabled.

### R13 — GUI real error display

- **Test name:** Real synchronization error visibility
- **Expected:** A failed sync error is displayed in the GUI.
- **Actual:** `sync_attack_data()` catches errors into `dataset["sync_error"]`, but `gui/app.py:137` only shows queued `error` events. The real sync failure from R4/R12 was not displayed.
- **Result:** **FAIL**
- **Evidence:** `mitre_real_integration.json` contains `sync_error`; `gui_integration.json` status after sync contains no error text.
- **Error messages:** `ValueError: STIX data: no Enterprise techniques or tactics found` existed in the dataset but was not displayed.
- **Remaining issues:** Real sync errors are not propagated to the GUI event queue.

### R14 — Last successful synchronization visibility

- **Test name:** Last successful sync timestamp display
- **Expected:** GUI displays the last successful synchronization timestamp.
- **Actual:** No widget or status text shows a synchronization timestamp. Status logic uses version/status only.
- **Result:** **FAIL**
- **Evidence:** `gui_integration.json`: `last_successful_sync_visible.visible = false`.
- **Error messages:** None.
- **Remaining issues:** Requirement not implemented in `gui/app.py`.

---

## 2. Synthetic integration tests

These tests used synthetic events or the application's injected transport. They are integration-level because they execute the real collection, normalization, rule, baseline, enrichment, report, and Navigator code paths.

### S1 — Linux collection and normalization through injected transport

- **Test name:** CentOS collection handoff using injected transport
- **Expected:** Distribution detection selects CentOS auth log and produces normalized auth events.
- **Actual:** Distribution `centos`; `secure_log` count `12`; event types: `account_created`, `failed_password`, `group_membership_change`, `successful_login`, `sudo_auth_failure`; collection errors `[]`.
- **Result:** **PASS**
- **Evidence:** `pipeline_integration.json` → `stage_collection`.
- **Error messages:** None.
- **Remaining issues:** Real SSH path remains blocked by R8.

### S2 — Authentication-log path selection

- **Test name:** `authentication_log_path()` distribution mapping
- **Expected:** RHEL-family → `/var/log/secure`; Debian-family → `/var/log/auth.log`.
- **Actual:** CentOS/RHEL mapped to `/var/log/secure`; Ubuntu/Debian mapped to `/var/log/auth.log`; unknown returned `None`.
- **Result:** **PASS**
- **Evidence:** `tests/test_collection.py`; `test_authentication_log_paths_match_distribution`.
- **Error messages:** None.
- **Remaining issues:** None.

### S3 — Detection engine required detections

- **Test name:** Synthetic detection coverage for eight required behaviors
- **Expected:** SSH brute force, successful login after failures, sudo activity, user creation, privileged group modification, suspicious cron, suspicious systemd service, and repeated downloads all produce findings.
- **Actual:** All eight positive checks returned `true`; engine errors `[]`.
- **Result:** **PASS**
- **Evidence:** `detection_engine_integration.json` → `positive_checks`. Detected rules include `LNX-AUTH-001`, `LNX-AUTH-002`, `LNX-SUDO-001`, `LNX-USER-001`, `LNX-USER-002`, `LINUX_CRONTAB_PERSISTENCE`, `LINUX_SYSTEMD_SUSPICIOUS_UNIT`, `LINUX_REPEATED_SUSPICIOUS_COMMAND`.
- **Error messages:** None.
- **Remaining issues:** Precision issue noted in S5.

### S4 — Threshold, sequence, and window negative behavior

- **Test name:** Negative threshold/sequence/time-window checks
- **Expected:** Below-threshold and outside-window inputs do not create findings.
- **Actual:** `5` failures against threshold `6` produced `0` brute-force findings; accepted login with no prior failures produced `0` sequence findings; downloads at minutes `0,2,20` outside a `5`-minute window produced `0` findings.
- **Result:** **PASS**
- **Evidence:** `detection_engine_integration.json` → `threshold_negative`, `sequence_negative`, `time_window_negative`.
- **Error messages:** None.
- **Remaining issues:** None.

### S5 — Privileged group rule precision

- **Test name:** `LNX-USER-002` false-positive check
- **Expected:** Only privileged group modifications produce `LNX-USER-002`.
- **Actual:** The rule detected the real group-change event but also produced findings for unrelated events classified as unauthorized (`failed_password`, `sudo_auth_failure`, `account_created`), for `4` total findings in one synthetic sequence.
- **Result:** **FAIL** for precision
- **Evidence:** `detection_engine_integration.json` → `findings_by_rule["LNX-USER-002"]`.
- **Error messages:** None.
- **Remaining issues:** `baseline_comparison` rule logic treats any unauthorized event as a match; it should be constrained to group-membership events.

### S6 — Full pipeline stage handoff

- **Test name:** Complete hunting operation with injected transport
- **Expected:** SSH/collection → normalization → rules → correlation → baseline → MITRE enrichment → findings → report → Navigator each pass output correctly.
- **Actual:** All eight handoff checks returned `true`. Final report had `17` findings, `9` technique IDs, `0` errors, and Navigator layer had `9` technique entries.
- **Result:** **PASS** with synthetic transport and fallback MITRE catalog
- **Evidence:** `pipeline_integration.json` → `handoff_checks`, `stage_report`, `stage_navigator`.
- **Error messages:** None.
- **Remaining issues:** SSH stage is not real (R8); MITRE enrichment used `static_migration`, not live CTI (R4).

### S7 — Multi-technique enrichment

- **Test name:** Multi-technique findings in report
- **Expected:** Findings carry multiple MITRE technique IDs and metadata.
- **Actual:** `5` multi-technique findings in rule stage; report techniques included `T1110`, `T1548.003`, `T1098`, `T1098.007`, `T1136.001`, `T1053.003`, `T1543.002`, `T1543.003`, `T1071.001`.
- **Result:** **PASS**
- **Evidence:** `pipeline_integration.json` → `stage_rules.multi_technique_finding_count`, `stage_report.techniques`.
- **Error messages:** None.
- **Remaining issues:** Metadata came from static fallback catalog; live enrichment blocked by R4.

### S8 — Navigator export from report

- **Test name:** ATT&CK Navigator layer generation
- **Expected:** Export all valid technique IDs from findings.
- **Actual:** Layer contained all `9` valid technique IDs; metadata recorded `mitre_status = static_migration`; attack version fell back to `14` because live/fallback version is empty.
- **Result:** **PASS** for export; **FAIL** for live version provenance
- **Evidence:** `pipeline_integration.json` → `stage_navigator`.
- **Error messages:** None.
- **Remaining issues:** Version should come from live dataset after R4 is fixed.

### S9 — GUI notification and error event paths

- **Test name:** Synthetic GUI event rendering
- **Expected:** Queued MITRE notifications and error events render in status.
- **Actual:** Notification event rendered `ATT&CK 20.1: 1 change(s) (T9999.001 new_technique)`; error event rendered `MITRE: ERROR_DISPLAY_PROBE`.
- **Result:** **PASS** for UI rendering path only
- **Evidence:** `gui_integration.json` → `notification_display_synthetic_event`, `error_display`.
- **Error messages:** None.
- **Remaining issues:** Real sync does not generate these events correctly (R7/R12/R13).

---

## 3. Mocked and simulated tests

These are explicitly not real integration proof.

### M1 — 31 automated unit tests

- **Test name:** Python 3.11 pytest suite
- **Expected:** All automated tests pass.
- **Actual:** `31 passed in 0.10s`.
- **Result:** **PASS**
- **Evidence:** Command: `python.exe -B -m pytest -p no:cacheprovider -q`.
- **Error messages:** None.
- **Remaining issues:** Unit success does not prove real network/SSH/GUI integration.

### M2 — Offline fallback simulation

- **Test name:** Simulated network failure after cache state
- **Expected:** `status = offline_cache` with cached techniques.
- **Actual:** Because no live cache was ever created, simulated opener failure returned `status = unavailable` with static catalog `15` techniques.
- **Result:** **FAIL**
- **Evidence:** `mitre_real_integration.json` → `offline_fallback`: `status = unavailable`, `sync_error = OSError: simulated offline: network unavailable`, `technique_count = 15`.
- **Error messages:** `OSError: simulated offline: network unavailable`.
- **Remaining issues:** Offline-cache fallback cannot be proven until R4/R6 pass.

### M3 — Permission and missing auth-log collection tests

- **Test name:** Simulated `/var/log/secure` and `/var/log/auth.log` errors
- **Expected:** Missing and permission-denied logs are reported as collection errors.
- **Actual:** Tests pass; errors are appended to report errors.
- **Result:** **PASS** as mocked test
- **Evidence:** `tests/test_collection.py`.
- **Error messages:** Simulated only: `permission denied: /var/log/secure`, `missing: /var/log/auth.log`.
- **Remaining issues:** Real target errors not observed due R8.

---

## 4. Security validation

### SEC1 — Plaintext passwords in `vms.json`

- **Test name:** Credential storage inspection
- **Expected:** VM credentials should not be plaintext.
- **Actual:** `3 of 3` VMs contain a plaintext `password` field; `0` VMs use key-based authentication. No credential values are reported in this document.
- **Result:** **FAIL**
- **Evidence:** `security_validation.json` → `credential_storage`; `vms.json` inspected programmatically without printing values.
- **Error messages:** None.
- **Remaining issues:** Move credentials to a secret store or SSH agent/key-based authentication.

### SEC2 — SSH credential handling

- **Test name:** `transport/ssh.py` credential flow
- **Expected:** Credentials are used for authentication only and never logged.
- **Actual:** Password is passed through Fabric `connect_kwargs`; key filename is supported as an alternative. No `print`, `logging`, or logger calls were found in `transport/ssh.py`.
- **Result:** **PASS** for handling; **FAIL** for storage combined with SEC1
- **Evidence:** `transport/ssh.py:23-37`; grep results.
- **Error messages:** None.
- **Remaining issues:** Plaintext source remains a risk.

### SEC3 — Secret leakage in validation outputs

- **Test name:** Credential-value scan of generated evidence
- **Expected:** No credential values appear in validation outputs.
- **Actual:** `7` validation output JSON files scanned; `0` credential-value hits.
- **Result:** **PASS**
- **Evidence:** Secret-scan command output: `credential_value_hits: []`.
- **Error messages:** None.
- **Remaining issues:** None for this report.

### SEC4 — Broad source scan for credential substrings

- **Test name:** Workspace and temp source scan
- **Expected:** No credential values outside `vms.json`.
- **Actual:** `41` files scanned; `9` exact-substring hits in `rules.json`, `test_rules.py`, and a temporary GUI helper. The configured credential values are common substrings, so the scan produced false-positive-style collisions. No values are printed.
- **Result:** **FAIL** for credential quality / mixed PASS for output hygiene
- **Evidence:** `security_validation.json` → `credential_leak_scan`; filename-only follow-up scan.
- **Error messages:** None.
- **Remaining issues:** Replace weak/common passwords regardless of the substring-collision nature of these hits.

### SEC5 — Temporary log storage

- **Test name:** Application log-write inspection
- **Expected:** Collected auth logs are not persisted to temporary files.
- **Actual:** No application log writes or `tempfile` usage found in `hunting/*.py`. Collected log lines stayed in memory. `navigator.py` can write a Navigator layer only when `save_layer()` is called.
- **Result:** **PASS**
- **Evidence:** Grep results; `security_validation.json` → `temporary_log_storage`.
- **Error messages:** None.
- **Remaining issues:** None.

### SEC6 — Cache integrity

- **Test name:** MITRE cache and static catalog integrity
- **Expected:** Live cache created and parseable; fallback catalog parseable.
- **Actual:** Live cache absent. Static fallback catalog is parseable, `4,571` bytes, SHA-256 prefix `872df2e8526ef924`.
- **Result:** **FAIL** for live cache; **PASS** for fallback catalog
- **Evidence:** Direct cache check; `security_validation.json` → `cache_integrity`.
- **Error messages:** Same as R4.
- **Remaining issues:** Cache creation blocked by parser incompatibility.

### SEC7 — Untrusted log content handling

- **Test name:** Malicious auth-log payload
- **Expected:** Untrusted log content is not executed, remains JSON-serializable, and evidence is bounded.
- **Actual:** Six malicious failed-login lines with `<script>alert(1)</script>` produced one brute-force finding; engine errors `[]`; evidence length `126` and bounded to `500`; JSON serialization succeeded; no shell execution was triggered.
- **Result:** **PASS**
- **Evidence:** `security_validation.json` → `untrusted_log_handling`.
- **Error messages:** None.
- **Remaining issues:** None.

---

## 5. Remaining issues summary

1. **MITRE parser incompatible with current official CTI** — `mitre/attack.py:99` depends on tactic `kill_chain_phases`; real CTI uses `x_mitre_shortname`. This blocks live cache, live version, real notifications, dedupe proof, and live GUI completion.
2. **Real SSH collection blocked** — Fabric is not installed in the validation environment, producing `RuntimeError: fabric is required for SSH: No module named 'fabric'`.
3. **GUI sync UX** — refresh button can remain disabled; real sync errors are not displayed; last successful synchronization timestamp is not visible.
4. **`LNX-USER-002` over-triggers** — baseline comparison currently flags any unauthorized event, not only privileged group modifications.
5. **Plaintext/weak credentials** — all configured VMs use plaintext password fields; no key-based auth.
6. **Offline cache fallback unproven** — no live cache exists because R4 fails.
7. **Live ATT&CK Navigator provenance unavailable** — layer falls back to version `14` and `static_migration` status.

## 6. Evidence artifacts

All evidence artifacts were written outside the workspace under:

`C:\Users\hp\AppData\Local\Temp\opencode\`

Key artifacts:

- `mitre_real_integration.json`
- `enterprise-attack-real.json`
- `cti_data_real_validation.json`
- `cti_structure_inspection.json`
- `linux_lab_integration.json`
- `detection_engine_integration.json`
- `pipeline_integration.json`
- `gui_integration.json`
- `security_validation.json`

No application functionality was changed during this validation.
