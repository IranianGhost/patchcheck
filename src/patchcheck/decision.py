"""Pure exit-code precedence and independent functional comparison."""


def decide(axes):
    if axes.get('technical_error'):
        return 30
    if axes.get('confirmed_security_issue'):
        return 10
    if axes.get('functional_regression'):
        return 20
    if (axes.get('incomplete') or not axes.get('baseline_reproduced', False)
            or axes.get('hardening_degraded')):
        return 40
    return 0


def functional_pair(base, candidate, category):
    if 'unknown' in (base, candidate):
        return 'unknown'
    if base == 'pass' and candidate == 'fail':
        return 'regression' if category in ('valid', 'boundary') else 'invalid_behavior_changed'
    if base == candidate == 'fail':
        return 'both_fail'
    if base == 'fail':
        return 'baseline_fail'
    return 'preserved'
