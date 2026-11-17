"""Line-coverage evidence for functional-regression correlation (gcov).

A functional regression has no crash stack, so the earlier correlation reported it
as `unknown`. To give the correlation execution-path evidence, the pipeline can run
the failing functional test on a separate `--coverage` (gcov) diagnostic build and
feed the covered lines back here. `parse_gcov` turns gcov text into a file -> set
of executed line numbers, and `covered_changes` maps that back onto the changed
lines of each diff hunk.
"""


def parse_gcov(text):
    """Parse gcov text into ``{file: set(executed_line_numbers)}``.

    Accepts both the annotated ``*.gcov`` file format (a ``Source:<file>`` header
    followed by ``count:lineno:source`` records) and gcov's stdout ``File '<file>'``
    header. ``count`` is a non-negative integer (times executed), ``#####`` (never
    executed) or ``-`` (not instrumented); only lines with a positive count are
    returned as covered.
    """
    covered = {}
    current = None
    for raw in text.splitlines():
        if raw.startswith('File '):
            current = raw[len('File '):].strip().strip("'")
            covered.setdefault(current, set())
            continue
        if ':' not in raw:
            continue
        count, lineno, source = raw.split(':', 2)
        count, lineno, source = count.strip(), lineno.strip(), source.strip()
        if source.startswith('Source:'):
            current = source[len('Source:'):].strip()
            covered.setdefault(current, set())
            continue
        if current is not None and count.isdigit() and int(count) > 0 and lineno.isdigit():
            covered[current].add(int(lineno))
    return covered


def covered_changes(hunks, covered, version='candidate'):
    """Hunks whose changed lines are covered (executed) in the given coverage map.

    ``covered`` is ``{file: set(line_numbers)}`` (as returned by ``parse_gcov``).
    For the candidate side the added lines are checked, for the base side the
    removed lines. Returns one entry per hunk with at least one covered changed
    line, carrying the concrete covered lines and the mapped functions.
    """
    out = []
    for hunk in hunks:
        file = hunk.get('file' if version == 'candidate' else 'old_file')
        side = hunk.get('added' if version == 'candidate' else 'removed', [])
        hits = [line for line in side if line in covered.get(file, set())]
        functions = [c['function'] for c in hunk.get('functions', []) if c['version'] == version]
        if hits:
            out.append({'hunk_id': hunk['id'], 'file': file, 'covered_lines': sorted(hits),
                        'functions': sorted(set(functions))})
    return out
