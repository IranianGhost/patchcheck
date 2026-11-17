"""ELF evidence extraction, protection interpretation and base/candidate comparison.

Indicators come from `readelf -W -h -l -d -s` (raw output is kept per build):
  NX      PT_GNU_STACK flags (RW = non-executable stack, RWE = executable)
  PIE     ELF type DYN plus DT_FLAGS_1 PIE (EXEC = fixed address)
  RELRO   PT_GNU_RELRO segment, plus BIND_NOW for full RELRO
  canary  __stack_chk_fail import          (indicator only)
  FORTIFY __*_chk imports, e.g. __memcpy_chk (indicator only)
Canary and FORTIFY symbols only appear when the compiler had something to
protect, so their absence is never proof that the protection is off.
"""
import re
import struct
from pathlib import Path

from .contracts import ConfigError


def check_elf(binary):
    header = Path(binary).read_bytes()[:64]
    if len(header) < 64 or header[:4] != b'\x7fELF' or header[4:6] != b'\x02\x01':
        raise ConfigError('build output must be a 64-bit little-endian ELF executable')
    kind, machine = struct.unpack_from('<HH', header, 16)
    if machine != 62 or kind not in (2, 3):
        raise ConfigError(f'ELF must be x86_64 EXEC/DYN, got machine={machine} type={kind}')
    return {'architecture': 'x86_64', 'file_type': 'ELF', 'elf_type': 'EXEC' if kind == 2 else 'DYN'}


def raw_hardening(readelf_output):
    stack = next((line.strip() for line in readelf_output.splitlines() if 'GNU_STACK' in line), None)
    stack_flags = re.search(r'\s([RWE][RWE ]*)\s+0x[0-9a-f]+$', stack) if stack else None
    symbols = sorted(set(re.findall(r'\b__stack_chk_(?:fail|guard)(?:@\S+)?', readelf_output)))
    return {'extraction_complete': True, 'interpretation': 'unknown',
            'gnu_stack_header': stack, 'nx_indicator': 'unknown' if stack_flags is None else
            'executable_stack' if 'E' in stack_flags[1] else 'non_executable_stack',
            'pie_indicator': 'DYN' if re.search(r'Type:\s+DYN', readelf_output) else 'EXEC',
            'gnu_relro_segment': 'GNU_RELRO' in readelf_output,
            'bind_now_indicator': bool(re.search(r'BIND_NOW|FLAGS[^\n]*\bNOW\b', readelf_output)),
            'relro_indicator': ('full' if re.search(r'BIND_NOW|FLAGS[^\n]*\bNOW\b', readelf_output) else 'partial')
                               if 'GNU_RELRO' in readelf_output else 'none',
            'stack_canary_symbols': symbols,
            'pie_flag': bool(re.search(r'FLAGS_1\)[^\n]*\bPIE\b', readelf_output)),
            'fortify_symbols': sorted(set(re.findall(r'\b__(?!stack_chk)\w+_chk(?=@|\s|$)', readelf_output))),
            'stack_canary_note': 'symbol presence is an indicator; absence does not establish missing protection'}


# Sanitizer runtimes link stable entry symbols into the binary; their presence in
# the symbol table is evidence that the sanitized build was actually instrumented.
SANITIZER_MARKERS = ('__asan_init', '__ubsan_handle_', '__tsan_init', '__msan_init')


def instrumentation_markers(readelf_symbol_output):
    """Sanitizer runtime symbols present in a binary's symbol table.

    `readelf_symbol_output` is the raw text of `readelf -W -h -l -d -s`. Returns
    `{asan, ubsan, tsan, msan, symbols}`; `symbols` lists the concrete matches so
    the build record carries the evidence, not just the boolean.
    """
    found = {}
    for marker in SANITIZER_MARKERS:
        found[marker] = sorted(set(re.findall(re.escape(marker) + r'\w*', readelf_symbol_output)))
    return {'asan': bool(found['__asan_init']), 'ubsan': bool(found['__ubsan_handle_']),
            'tsan': bool(found['__tsan_init']), 'msan': bool(found['__msan_init']),
            'symbols': sorted({s for matches in found.values() for s in matches})}


# Ordered from weakest to strongest; indicator-only protections are not ordered.
LEVELS = {'nx': ['disabled', 'enabled'], 'pie': ['disabled', 'enabled'], 'relro': ['none', 'partial', 'full']}
INDICATORS = ('stack_canary', 'fortify_source')


def interpret(hardening):
    """{protection: value} for one Release binary; 'unknown' when the evidence does not decide."""
    if not hardening or not hardening.get('extraction_complete'):
        return {name: 'unknown' for name in (*LEVELS, *INDICATORS)}
    nx = {'non_executable_stack': 'enabled', 'executable_stack': 'disabled'}.get(hardening.get('nx_indicator'), 'unknown')
    if hardening.get('pie_indicator') == 'EXEC':
        pie = 'disabled'
    elif hardening.get('pie_indicator') == 'DYN':
        # Older reports lack pie_flag; DYN alone could also be a shared library.
        pie = 'enabled' if hardening.get('pie_flag', True) else 'unknown'
    else:
        pie = 'unknown'
    relro = hardening.get('relro_indicator', 'unknown')
    return {'nx': nx, 'pie': pie, 'relro': relro if relro in LEVELS['relro'] else 'unknown',
            'stack_canary': 'present' if hardening.get('stack_canary_symbols') else 'not-observed',
            'fortify_source': 'present' if hardening.get('fortify_symbols') else
                              'unknown' if 'fortify_symbols' not in hardening else 'not-observed'}


def change(name, before, after):
    if 'unknown' in (before, after):
        return 'unknown'
    if before == after:
        return 'same'
    if name in LEVELS:
        order = LEVELS[name]
        return 'degraded' if order.index(after) < order.index(before) else 'improved'
    return 'indicator-lost' if before == 'present' else 'indicator-gained'


def compare_hardening(base_build, candidate_build):
    """Compare the two Release binaries. Degradation of NX/PIE/RELRO blocks PASS (exit 40)."""
    if not base_build or not candidate_build:
        return {'interpretation': 'unknown', 'comparison': 'missing-release-build', 'degraded': [], 'warnings': [],
                'unknown': ['release build missing'], 'base': {}, 'candidate': {}, 'changes': {}, 'evidence': []}
    before, after = interpret(base_build.get('hardening')), interpret(candidate_build.get('hardening'))
    changes = {name: change(name, before[name], after[name]) for name in before}
    degraded = [f'{name}: {before[name]} -> {after[name]}' for name, c in changes.items() if c == 'degraded']
    warnings = [f'{name}: symbol evidence {before[name]} -> {after[name]} (absence is not proof; check the build)'
                for name, c in changes.items() if c == 'indicator-lost']
    unknown = [f'{name}: base={before[name]} candidate={after[name]}' for name in LEVELS if changes[name] == 'unknown']
    same_flags = (base_build.get('flags'), base_build.get('command')) == \
                 (candidate_build.get('flags'), candidate_build.get('command'))
    if not same_flags:
        warnings.append('release build flags or command differ between base and candidate')
    return {'interpretation': 'unknown' if unknown else 'complete', 'comparison': 'compared',
            'base': before, 'candidate': after, 'changes': changes, 'degraded': degraded,
            'warnings': warnings, 'unknown': unknown, 'flags_equal': same_flags,
            'policy': 'NX/PIE/RELRO degradation prevents PASS (exit 40); canary/FORTIFY symbol loss is a warning',
            'evidence': [b['hardening'].get('raw') for b in (base_build, candidate_build) if b['hardening'].get('raw')]}
