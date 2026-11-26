from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_SOURCE = Path(__file__).resolve().parent.parent / "log collection" / "rule_engine.py"
_SPEC = spec_from_file_location("hunting._colleague_rule_engine", _SOURCE)
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

VALID_LOG_TYPES = _MODULE.VALID_LOG_TYPES
VALID_SEVERITIES = _MODULE.VALID_SEVERITIES
load_rules = _MODULE.load_rules
parse_timestamp = _MODULE.parse_timestamp
apply_rule = _MODULE.apply_rule
group_and_window = _MODULE.group_and_window
evaluate_rule = _MODULE.evaluate_rule
evaluate_all = _MODULE.evaluate_all
get_rules_for_check = _MODULE.get_rules_for_check
get_rule = _MODULE.get_rule
run_rule_tests = _MODULE.run_rule_tests
validate_mitre_ids = _MODULE.validate_mitre_ids
coverage_summary = _MODULE.coverage_summary
_is_ip_internal = _MODULE._is_ip_internal
