"""Compare each version independently with a documented external oracle."""
import base64
import json
import re

from .contracts import validate_oracle
from .store import checked_path


def json_equal(actual, expected):
    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual is expected
    if isinstance(actual, dict) and isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(json_equal(actual[key], expected[key]) for key in actual)
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(json_equal(a, b) for a, b in zip(actual, expected))
    return actual == expected


def evaluate_oracle(run, oracle, root):
    if oracle is None or not oracle['provenance']['independent']:
        return {'status': 'unknown', 'reason': 'no independent oracle'}
    validate_oracle(oracle)
    if (run.get('runner_error') or run.get('timeout') or run.get('output_truncated')
            or run.get('resource_status', 'ok') != 'ok'):
        return {'status': 'unknown', 'reason': 'incomplete execution or resource termination'}
    checks = {'exit_code': run.get('exit_code') == oracle['exit_code'] and run.get('signal') is None}
    for field in ('stdout', 'stderr'):
        comparator = oracle.get(field)
        if comparator is None:
            continue
        data = checked_path(root, run[field]).read_bytes()
        try:
            if comparator['mode'] == 'exact':
                checks[field] = data == base64.b64decode(comparator['base64'], validate=True)
            elif comparator['mode'] == 'regex':
                checks[field] = re.fullmatch(comparator['pattern'], data.decode('utf-8')) is not None
            else:
                checks[field] = json_equal(json.loads(data), comparator['value'])
        except (UnicodeDecodeError, ValueError):
            checks[field] = False
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'source': oracle['provenance']['source']}
