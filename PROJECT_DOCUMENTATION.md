# VM Threat Hunting Dashboard — Project Work Documentation

Scope note: this document intentionally excludes the final standalone GUI test-harness step. It covers the application work, validation, integration of the colleague-provided log collection/rule engine code, commands run, errors encountered, and the current state immediately before that excluded GUI step.

---

## 1. Purpose of the project

The project is a local VM threat-hunting dashboard that:

1. Reads configured VMs from `vms.json`.
2. Connects to a VM over SSH or accepts an injected transport for testing.
3. Collects host evidence:
   - processes
   - services
   - scheduled tasks
   - startup commands
   - users
   - listening ports
   - Linux authentication and operational logs
4. Normalizes and evaluates collected evidence with:
   - the original detection rule engine
   - the colleague-provided advanced rule engine
   - baseline deviation checks
5. Enriches findings with MITRE ATT&CK metadata.
6. Produces a report suitable for the report panel and ATT&CK Navigator export.

The main GUI entry point is still `main.py`; the existing GUI files were not reworked during the colleague-integration phase.

---

## 2. Environment and commands

### Python

Used Python 3.11 at:

```powershell
C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe
```

### Dependencies

`requirements.txt` contains:

```text
fabric>=3.2.2
pytest>=8.0.0
```

Important: `fabric` is declared but was not installed in the validation environment. Real SSH collection was therefore blocked and had to be validated with injected transports.

### Standard test command

Used throughout validation and after integration:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'; & "C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe" -B -m pytest -p no:cacheprovider -q
```

Results at key points:

- Initial unit/mocked suite: `31 passed in 0.10s`
- After colleague collector + rule engine integration: `49 passed in 0.30s`

The bytecode/cache flags were used to avoid polluting the workspace with `__pycache__` and `.pytest_cache` artifacts.

### Test collection diagnostic

When the colleague files first appeared, normal pytest collection failed:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'; & "C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe" -B -m pytest -p no:cacheprovider --collect-only -q
```

Error:

```text
ERROR log collection/test_rule_engine.py
E   ModuleNotFoundError: No module named 'hunting.collector'
```

This showed that the colleague test expected `hunting.collector`, but the source file was under the space-containing folder `log collection`.

### Repository status command

Used repeatedly to verify changed/untracked files:

```powershell
git status --short
```

### Launch command for the main application

```powershell
& "C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe" main.py
```

`main.py` creates `tk.Tk()`, instantiates `gui.app.App`, and starts `mainloop()`.

---

## 3. Project structure

### Entry and configuration

- `main.py` — launches the main Tk GUI.
- `vms.json` — VM connection metadata. Contains plaintext passwords; values were never printed during validation.
- `baseline.json` — expected-good host policy and profile data.
- `requirements.txt` — Fabric and pytest dependencies.

### GUI

- `gui/app.py` — main GUI shell, VM cards, hunt dispatch, ATT&CK refresh, background event queue.
- `gui/vm_card.py` — per-VM status and hunt button.
- `gui/report_panel.py` — displays reports.
- `gui/ai_panel.py` — AI assistant panel.

### Hunting pipeline

- `hunting/checks.py`
  - command selection for Windows/Linux
  - Linux distribution detection
  - integrated log collection through the colleague collector
  - auth-log normalization
  - baseline comparison
- `hunting/rule_engine.py`
  - original rule pack loader/validator
  - regex/threshold/time-window/sequence/baseline detection
  - compatibility layer for colleague rule engine functions
  - translation of advanced engine hits into report findings
- `hunting/engine.py`
  - `hunt_vm()` orchestration
  - runs original rules, advanced rules, baseline checks
  - dedupe/sort findings
  - MITRE status in report
- `hunting/navigator.py`
  - ATT&CK Navigator layer export
- `hunting/attack.json`
  - static fallback MITRE catalog
- `hunting/rules.json`
  - original rule pack

### Integrated colleague code

- `log collection/collector.py` — colleague-provided collector source.
- `log collection/rule_engine.py` — colleague-provided advanced rule engine source.
- `log collection/rules.json` — colleague-provided 23-rule pack.
- `log collection/test_rule_engine.py` — colleague tests.
- `hunting/collector.py` — import wrapper that exposes `hunting.collector` using `importlib` because the source folder name contains a space.
- `hunting/colleague_rule_engine.py` — import wrapper that exposes the colleague rule engine functions under a normal Python module path.

### MITRE

- `mitre/attack.py`
  - live STIX fetch
  - STIX parsing
  - cache read/write
  - dataset comparison and notifications
  - offline fallback
- `mitre/attack_cache.json`
  - expected live cache file; not created during validation because live STIX parsing failed.

### Transport

- `transport/ssh.py`
  - Fabric-backed `SSHTransport`
  - `connect()`, `run()`, `fetch()`, `close()`
  - added `run_result()` returning `{ok, stdout, stderr, exit_code, error}` so the colleague collector’s command-runner contract is supported.

### Tests and fixtures

- `tests/test_collection.py`
- `tests/test_mitre.py`
- `tests/test_navigator.py`
- `tests/test_rules.py`
- `tests/sample_logs/centos-lab/`
- `tests/sample_logs/clean/`

---

## 4. Original implementation work completed before colleague integration

### Collection and normalization

Implemented in `hunting/checks.py`:

- `secure_log` collection for Linux
- Linux distribution detection from `/etc/os-release`
- auth path selection:
  - RHEL family → `/var/log/secure`
  - Debian family → `/var/log/auth.log`
- auth event normalization with fields such as:
  - `event_type`
  - `username`
  - `source_ip`
  - `command_user`
  - `target_user`
  - `groupname`
- collection error markers such as `__COLLECT_ERROR__ permission denied: ...`

### Detection rules

Implemented or expanded in `hunting/rule_engine.py` and `hunting/rules.json`:

- advanced detection types:
  - `regex`
  - `threshold`
  - `time_window`
  - `sequence_correlation`
  - `baseline_comparison`
- multi-technique findings
- MITRE metadata enrichment
- rule validation
- baseline-aware severity

### MITRE ATT&CK integration

Implemented in `mitre/attack.py`:

- live official CTI fetch
- STIX parsing
- cache file management
- dataset version tracking
- change notifications
- offline fallback to `hunting/attack.json`

A real bug was later discovered: current official CTI tactic objects use `x_mitre_shortname` and no longer include `kill_chain_phases`, while the parser expected `kill_chain_phases`.

### Navigator and AI

- `hunting/navigator.py`
  - exports every valid technique ID from findings
  - handles unknown technique IDs without exporting them
  - uses dynamic ATT&CK version when available
- `ai/tools.py`
  - summaries support multi-technique findings

### Existing GUI

- `gui/app.py`
  - VM cards
  - ATT&CK refresh button
  - background MITRE sync
  - event-queue-based UI updates

---

## 5. Validation performed

### 5.1 Unit and mocked tests

Command:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'; & "C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe" -B -m pytest -p no:cacheprovider -q
```

Initial result:

```text
31 passed in 0.10s
```

These covered:

- rule pack validation
- original rule engine behavior
- baseline checks
- `hunt_vm()` with fake transports
- MITRE sync/notification logic
- Navigator export behavior
- collection path selection and auth normalization

### 5.2 Real MITRE CTI validation

Official endpoints checked:

```text
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
https://api.github.com/repos/mitre/cti/releases/latest
```

Observed:

- STIX HEAD: HTTP `200`
- `Content-Length: 49257997`
- `ETag: "42c56af7faa364b19086b4d09ae43c8b7e46ea89efee4a33b566ffe9343ff306"`
- GitHub release via Python `urllib`: HTTP `200`
- Release tag: `ATT&CK-v20.1`
- Published: `2026-11-05T16:33:52Z`

Issue:

```text
curl: (35) schannel: next InitializeSecurityContext failed: CRYPT_E_REVOCATION_OFFLINE (0x80092013)
```

This was a local Windows `curl.exe` revocation problem only. Python `urllib` succeeded.

Download:

- complete file size: `49,257,997` bytes
- first transfer was interrupted at `14,680,064` bytes
- resumed with HTTP Range
- final bundle type: `bundle`
- object count: `26,698`

Independent real-data parse result:

- `15` tactics
- `867` attack-pattern objects
- `867` parsed techniques
- `370` top-level techniques
- `497` sub-techniques
- `149` revoked
- `12` deprecated
- `0` missing names
- `0` missing tactics
- `0` orphan sub-techniques
- dataset max modified: `2026-11-04T14:59:51.172Z`

Application live sync result:

```text
first_sync_seconds: 249.43
status: unavailable
sync_error: ValueError: STIX data: no Enterprise techniques or tactics found
cache_after_first.exists: false
```

Root cause:

- real tactic object example:
  - `name: Credential Access`
  - `x_mitre_shortname: credential-access`
  - `kill_chain_phases: None`
- parser required `kill_chain_phases`

Consequences:

- no live cache created
- live version not propagated into reports/Navigator
- real notification deduplication could not be validated
- offline-cache fallback could not be validated through the app

### 5.3 Linux lab collection

Attempted through `SSHTransport.connect()` and `hunt_vm()` against the configured Linux lab VM.

Error:

```text
RuntimeError: fabric is required for SSH: No module named 'fabric'
```

Result:

- real SSH collection: BLOCKED
- real distribution detection over SSH: BLOCKED
- real `/var/log/secure` collection: BLOCKED

Because of this, collection and pipeline tests used injected transports.

### 5.4 Detection engine integration

Used synthetic events through the real detection engine and real rule pack.

Positive checks passed:

- `LNX-AUTH-001`
- `LNX-AUTH-002`
- `LNX-SUDO-001`
- `LNX-USER-001`
- `LNX-USER-002`
- `LINUX_CRONTAB_PERSISTENCE`
- `LINUX_SYSTEMD_SUSPICIOUS_UNIT`
- `LINUX_REPEATED_SUSPICIOUS_COMMAND`

Negative checks passed:

- below-threshold failures produced no brute-force finding
- accepted login without prior failures produced no sequence finding
- events outside the time window produced no repeated-command finding

Known issue found:

- `LNX-USER-002` also fired on unrelated unauthorized events, producing false positives.

### 5.5 Full pipeline validation

Used an injected `LabTransport` so downstream stages could be exercised despite missing Fabric.

Observed:

- collection errors: `[]`
- normalized event types included:
  - `failed_password`
  - `successful_login`
  - `sudo_auth_failure`
  - `account_created`
  - `group_membership_change`
- original rule findings included multi-technique findings
- baseline findings were produced
- final report had:
  - `17` findings
  - `9` technique IDs
  - `0` report errors
- MITRE status was `static_migration` because live cache failed

### 5.6 Existing GUI validation

Validated earlier GUI behavior, not the final excluded GUI harness step.

Observed:

- title: `VM Threat Hunter`
- VM cards: `3`
- refresh button present and initially enabled
- background MITRE thread started
- click disabled the refresh button
- UI remained responsive during sync:
  - event-loop pumps: `9,393`
  - maximum UI gap: `0.329s`
- synthetic queued error event displayed correctly
- synthetic notification event displayed correctly

Problems observed:

- real sync did not complete within `480s`
- status stayed `Refreshing ATT&CK...`
- button stayed disabled
- real sync error from `dataset["sync_error"]` was not displayed
- no last-successful-sync timestamp was visible

### 5.7 Security validation

Credential storage:

- VMs scanned: `3`
- VMs with plaintext password field: `3`
- VMs using key-based authentication: `0`
- no credential values printed

Credential leakage scan:

- validation output JSON files scanned: `7`
- credential-value hits in validation outputs: `0`
- broad source scan produced `9` exact-substring hits in unrelated files because configured values were common words; no values were printed

Temporary storage:

- no application log writes found
- no `tempfile` use for collected auth logs
- Navigator layer writer exists but only writes layers when called
- live MITRE cache absent

Cache integrity:

- static catalog size: `4,571` bytes
- SHA-256 prefix: `872df2e8526ef924`
- static catalog parseable

Untrusted log handling:

- malicious payload lines with `<script>` content produced no engine errors
- evidence bounded to `500` chars
- findings remained JSON-serializable
- no shell execution triggered

Evidence artifacts were written under:

```text
C:\Users\hp\AppData\Local\Temp\opencode\
```

Key evidence files:

- `mitre_real_integration.json`
- `enterprise-attack-real.json`
- `cti_data_real_validation.json`
- `cti_structure_inspection.json`
- `linux_lab_integration.json`
- `detection_engine_integration.json`
- `pipeline_integration.json`
- `gui_integration.json`
- `security_validation.json`
- `post_integration_pipeline.json`

---

## 6. Colleague log collection and rule engine integration

### 6.1 Discovery

The colleague work was found in:

```text
log collection\
  collector.py
  rule_engine.py
  rules.json
  test_rule_engine.py
  export_logs.sh
  __init__.py
  README.md
```

Findings:

- `collector.py` expected a structured `run_cmd(command, timeout=30)` returning a dict.
- `SSHTransport.run()` only returned stdout text.
- the folder name `log collection` contains a space and cannot be imported normally.
- `hunting.collector` did not exist, causing pytest collection failure.
- colleague rule engine schema differed from the original project rule schema.

### 6.2 Import wrappers

Created:

- `hunting/collector.py`
  - loads `log collection/collector.py` using `importlib.util`
  - exposes:
    - `LOG_SOURCES`
    - `ALL_LOG_TYPES`
    - `resolve_log_paths`
    - `family_from_os_release`
    - `collect_log`
    - `collect_all`
    - `get_lines`
    - `save_logs_to_dir`
    - `load_logs_from_dir`
    - `generate_sudoers_snippet`

- `hunting/colleague_rule_engine.py`
  - loads `log collection/rule_engine.py`
  - exposes:
    - `VALID_LOG_TYPES`
    - `VALID_SEVERITIES`
    - `load_rules`
    - `parse_timestamp`
    - `apply_rule`
    - `group_and_window`
    - `evaluate_rule`
    - `evaluate_all`
    - `get_rules_for_check`
    - `get_rule`
    - `run_rule_tests`
    - `validate_mitre_ids`
    - `coverage_summary`
    - `_is_ip_internal`

### 6.3 Transport contract

`transport/ssh.py` gained:

```python
run_result(command, timeout=60) -> dict[str, Any]
```

Returns:

```python
{
    "ok": bool,
    "stdout": str,
    "stderr": str,
    "exit_code": int | None,
    "error": str | None,
}
```

`run()` now delegates to `run_result()` and returns stdout, preserving the old interface.

### 6.4 Collection integration

`hunting/checks.py` was changed so Linux collection uses the colleague collector.

New constants:

- `COLLECTOR_LOG_KEYS`
- expanded `DATA_KEYS`
- expanded `POLICY_KEYS`

New helpers:

- `_coerce_run_result`
- `_marker_message`
- `_structured_runner`
- `_linux_family`

Behavior:

1. Detect Linux distribution.
2. Map distribution to `rhel` or `debian`.
3. Call `collect_all()` with a structured runner.
4. Store raw collected lines in:
   - `auth`
   - `syslog`
   - `audit`
   - `cron`
   - `package`
   - `history`
   - `web_access`
   - `web_error`
5. Convert `auth` lines into `secure_log` normalized events.
6. Preserve collection errors in report errors.
7. Keep original process/service/user/task/port collection unchanged.

### 6.5 Rule engine integration

`hunting/rule_engine.py` gained:

- `ADVANCED_RULES_PATH` pointing to `log collection/rules.json`
- `_colleague_load_rules()`
- dual-mode `load_rules()`:
  - no `path` and no `include_disabled` → original rule pack list
  - explicit path or `include_disabled=True` → colleague rule pack dict
- compatibility re-exports for colleague rule-engine functions
- hybrid `run_rule_tests()` supporting both test schemas
- `advanced_rule_findings()`

`advanced_rule_findings()`:

1. Loads the colleague 23-rule pack.
2. Skips rule IDs already emitted by the original engine.
3. Runs `evaluate_all()` against raw collected logs.
4. Converts colleague hits into the existing finding shape:
   - `rule`
   - `description`
   - `severity`
   - `techniques`
   - `technique_metadata`
   - `target`
   - `evidence`
   - `groups`
   - `event_timestamp`
   - `source: advanced_rule_engine`

### 6.6 Pipeline integration

`hunting/engine.py` now:

1. Runs original `run_rules()`.
2. Builds `existing_rule_ids`.
3. Runs `advanced_rule_findings()` with those IDs skipped.
4. Adds advanced findings.
5. Adds baseline findings.
6. Dedupes and sorts all findings.

This prevents duplicate `LNX-AUTH-001` / `LNX-AUTH-002` findings from both engines while still allowing the advanced engine to add its extra log-source coverage.

### 6.7 Baseline updates

Added empty policy sections to `baseline.json` for new raw log keys:

- `syslog`
- `audit`
- `cron`
- `package`
- `history`
- `web_access`
- `web_error`

This fixed:

```text
AssertionError: set(DATA_KEYS).issubset(baseline)
```

### 6.8 Sample fixtures

Created:

```text
tests/sample_logs/centos-lab/
tests/sample_logs/clean/
```

Each contains:

- `auth.log`
- `syslog.log`
- `audit.log`
- `cron.log`
- `package.log`
- `history.log`
- `web_access.log`
- `web_error.log`
- `metadata.json`

Purpose:

- `centos-lab` triggers expected malicious checks from the colleague tests.
- `clean` provides false-positive control data.

### 6.9 Tests added/updated

Added or updated:

- `tests/test_collection.py`
  - integrated collector behavior
  - structured transport behavior
  - `SSHTransport.run_result()` behavior
- `tests/test_rules.py`
  - advanced rule engine findings through `hunt_vm` components
- colleague tests in `log collection/test_rule_engine.py` now collect and pass because `hunting.collector` and compatible `hunting.rule_engine` symbols exist.

Final result before the excluded final GUI harness step:

```text
49 passed in 0.30s
```

### 6.10 Post-integration synthetic pipeline proof

A temporary validation script used an injected structured transport and produced:

```json
{
  "errors": [],
  "finding_count": 19,
  "findings_by_source": {
    "advanced_rule_engine": 12,
    "rule": 7
  }
}
```

Collected summary included:

```text
processes: 2
services: 2
scheduled_tasks: 1
startup_commands: 1
users: 1
listening_ports: 1
secure_log: 10
syslog: 1
audit: 2
cron: 1
package: 1
history: 3
web_access: 1
web_error: 1
distribution: 1
auth: 10
```

This proved the non-GUI integration path end to end using sample data.

---

## 7. Data flow after integration

```text
main.py / external caller
        |
        v
hunt_vm(vm, transport=None, attack=None)
        |
        +-- SSHTransport.connect() if no transport injected
        |
        +-- detect_linux_distribution()
        |
        +-- collect_data()
        |      +-- original process/service/user/task/port commands
        |      +-- colleague collect_all()
        |             +-- auth -> secure_log normalized events
        |             +-- syslog/audit/cron/package/history/web logs -> raw lists
        |
        +-- run_rules()                 original rule pack
        |
        +-- advanced_rule_findings()    colleague 23-rule pack
        |
        +-- baseline_checks()
        |
        +-- dedupe + sort
        |
        +-- report with MITRE status
        |
        +-- Navigator / report panel / AI tools
```

---

## 8. Problems faced and what was done

| Problem | Impact | Action taken / current status |
|---|---|---|
| Fabric not installed | Real SSH collection blocked | Used injected transports; documented exact error |
| Real CTI tactic objects changed shape | App STIX parser failed | Documented root cause; no functional change requested for this issue |
| Live MITRE cache never created | Offline cache and real notifications unproven | Static fallback used; documented limitation |
| Windows `curl.exe` revocation offline | `curl -I` failed | Used Python `urllib`; documented exact error |
| GUI ATT&CK sync did not finish | Button stayed disabled, no real notification | Documented as failure in validation report |
| Real sync errors not shown in GUI | User would not see failure | Documented; `sync_error` was not queued to GUI |
| `LNX-USER-002` false positives | Noisy findings | Documented as remaining detection issue |
| Plaintext passwords in `vms.json` | Security risk | Documented; values never printed; recommended key/secret store |
| `hunting.collector` missing | pytest collection error | Created wrapper module |
| `log collection` folder has a space | Cannot import normally | Used `importlib.util` wrappers |
| Rule schema mismatch | Colleague tests could not use original engine | Added compatibility loader and advanced-rule adapter |
| Missing sample fixtures | Colleague sample tests would fail | Created `centos-lab` and `clean` fixtures |
| Baseline missing new keys | `DATA_KEYS` subset assertion failed | Added empty baseline sections |

---

## 9. Current state before the excluded GUI step

- Application functionality had been extended with:
  - integrated colleague collector
  - structured SSH runner
  - colleague rule engine compatibility
  - advanced rule findings in reports
  - sample log fixtures
- Non-GUI full pipeline worked with injected transports.
- Real SSH remained blocked because Fabric was missing.
- Live MITRE parsing remained broken against current official CTI.
- Existing main GUI had known ATT&CK refresh limitations.
- Test suite state: `49 passed in 0.30s`.
- No lint/typecheck configuration was found; pytest was the available verification command.

---

## 10. Recommended next steps

1. Fix `mitre/attack.py` parsing to support `x_mitre_shortname` for current CTI tactic objects.
2. Install Fabric in the runtime environment:

   ```powershell
   & "C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe" -m pip install -r requirements.txt
   ```

3. Re-run real Linux lab collection after Fabric is installed.
4. Propagate real MITRE `sync_error` into the GUI event queue.
5. Show last successful synchronization timestamp in the GUI.
6. Tighten `LNX-USER-002` so it only matches privileged group modifications.
7. Move VM passwords out of plaintext `vms.json` into key-based auth or a secret store.
8. Re-validate live MITRE notifications and dedupe after the CTI parser fix.
