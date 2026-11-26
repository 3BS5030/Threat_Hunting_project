from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_SOURCE = Path(__file__).resolve().parent.parent / "log collection" / "collector.py"
_SPEC = spec_from_file_location("hunting._colleague_collector", _SOURCE)
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

LOG_SOURCES = _MODULE.LOG_SOURCES
ALL_LOG_TYPES = _MODULE.ALL_LOG_TYPES
resolve_log_paths = _MODULE.resolve_log_paths
family_from_os_release = _MODULE.family_from_os_release
collect_log = _MODULE.collect_log
collect_all = _MODULE.collect_all
get_lines = _MODULE.get_lines
save_logs_to_dir = _MODULE.save_logs_to_dir
load_logs_from_dir = _MODULE.load_logs_from_dir
generate_sudoers_snippet = _MODULE.generate_sudoers_snippet
