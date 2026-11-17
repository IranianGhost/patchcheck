"""Public schema contracts and semantic configuration checks."""
import base64
import json
import re
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator


class ConfigError(Exception):
    """Configuration, environment or tool failure (CLI exit 30)."""


def validate_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}', value):
        raise ConfigError(f'invalid artifact identifier: {value!r}')


def validate(kind, value):
    try:
        schema = json.loads(files('patchcheck').joinpath(f'schemas/{kind}.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(e.path))
        if errors:
            error = errors[0]
            field = '.'.join(map(str, error.absolute_path)) or '<root>'
            raise ConfigError(f'{kind}.{field}: {error.message}')
    except (OSError, ValueError) as exc:
        raise ConfigError(f'Cannot validate {kind}: {exc}') from exc


def validate_oracle(oracle):
    validate('Oracle', oracle)
    for field in ('stdout', 'stderr'):
        comparator = oracle.get(field)
        if not comparator:
            continue
        try:
            if comparator['mode'] == 'exact':
                base64.b64decode(comparator['base64'], validate=True)
            elif comparator['mode'] == 'regex':
                re.compile(comparator['pattern'])
        except (ValueError, re.error) as exc:
            raise ConfigError(f'oracle.{field}: {exc}') from exc


def relative_path(value, name):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or value in ('', '.'):
        raise ConfigError(f'{name}: expected a nonempty relative path without ..')
    return path


# Tools the pipeline needs even when no build declares them as a compiler; a
# missing entry here must fail configuration, not crash mid-build with KeyError.
MANDATORY_TOOLS = ('git', 'python3', 'readelf')


def load_config(path):
    from .store import read_json
    path = Path(path).resolve()
    config = read_json(path)
    validate('TargetConfig', config)
    root = path.parent
    for tool in MANDATORY_TOOLS:
        if tool not in config['tools']:
            raise ConfigError(f'{tool} is a required tool and must be declared in tools')
    repo = (root / config['source']['repo']).resolve()
    if not repo.is_dir():
        raise ConfigError(f'source.repo does not exist: {repo}')
    if config['source'].get('diff') and not (root / config['source']['diff']).is_file():
        raise ConfigError('source.diff does not exist')
    if config['source'].get('dirty') and not (root / config['source']['dirty']['path']).is_dir():
        raise ConfigError('source.dirty.path does not exist')
    ids = set()
    for test in config['tests']:
        if test['id'] in ids:
            raise ConfigError(f'duplicate test id: {test["id"]}')
        ids.add(test['id'])
        input_path = (root / test['input']).resolve()
        if not input_path.is_file():
            raise ConfigError(f'tests.{test["id"]}.input does not exist: {input_path}')
        if test.get('sha256'):
            from .store import digest
            if digest(input_path) != test['sha256']:
                raise ConfigError(f'tests.{test["id"]}.sha256 mismatch')
        if test['oracle'] is not None:
            validate_oracle(read_json(root / test['oracle']))
        mode = test.get('input_mode', config['input']['mode'])
        if mode == 'argv':
            data = input_path.read_bytes()
            try:
                data.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise ConfigError(f'argv input must be UTF-8: {test["id"]}') from exc
            if b'\0' in data or len(data) > 32768:
                raise ConfigError(f'argv input contains NUL or exceeds 32768 bytes: {test["id"]}')
    args = config['input']['argv']
    if args[0] != '{binary}':
        raise ConfigError('input.argv[0] must be {binary}')
    for arg in args:
        scrubbed = arg.replace('{binary}', '').replace('{input}', '')
        if '{' in scrubbed or '}' in scrubbed or '\0' in arg:
            raise ConfigError(f'unsupported argument placeholder or NUL: {arg!r}')
    cwd = config['input']['cwd']
    if cwd != '.':
        relative_path(cwd, 'input.cwd')
    for mode in ('release', 'sanitized'):
        spec = config['builds'][mode]
        if spec['compiler'] not in config['tools']:
            raise ConfigError(f'builds.{mode}.compiler must be declared in tools')
        relative_path(spec['binary'], f'builds.{mode}.binary')
        if '{compiler}' not in spec['command'] or '{flags}' not in spec['command']:
            raise ConfigError(f'builds.{mode}.command must contain standalone {{compiler}} and {{flags}}')
        if any('\0' in x for x in spec['command'] + spec['flags']):
            raise ConfigError('NUL in build command')
        for marker in spec.get('instrumentation', []):
            if not isinstance(marker, str) or not marker:
                raise ConfigError(f'builds.{mode}.instrumentation entries must be non-empty strings')
    if config['builds']['release'] == config['builds']['sanitized']:
        raise ConfigError('release and sanitized build specs must differ; the sanitized build '
                          'must actually enable instrumentation (e.g. -fsanitize) and declare it')
    variables = config['environment']['variables']
    for tool, pattern in config['tools'].items():
        if not re.fullmatch(r'[A-Za-z0-9_+.-]+', tool):
            raise ConfigError(f'invalid required tool name: {tool}')
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f'invalid version pattern for {tool}: {exc}') from exc
    for key, value in variables.items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key) or '\0' in value:
            raise ConfigError(f'invalid environment variable {key!r}')
    if 'fixture-marker' in config['analyzers'] and not config['fixture']:
        raise ConfigError('fixture-marker analyzer is restricted to explicitly labeled fixtures')
    return config
