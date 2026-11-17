"""Generate giflib (gif2rgb) test inputs and independent oracles.

Every GIF here is built byte by byte from the GIF89a specification, and every
expected result is computed from the specification in `expected_rgb` / the error
tables below -- never by running gif2rgb. The GIF LZW encoder mirrors giflib's
decoder (lib/dgif_lib.c DGifDecompressInput) only so the files decode; the oracle
values do not come from giflib.

Target: the CVE-2016-3977 heap-buffer-overflow in util/gif2rgb.c DumpScreen2RGB,
where the background-color index is used to read the colormap with no range check.

Run: python3 tools/gen_giflib_corpus.py
"""
import base64
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_SIGNATURE = {'error_type': 'heap-buffer-overflow',
                    'location': 'util/gif2rgb.c:DumpScreen2RGB', 'key': 'READ'}

# A fixed 4-entry global color table shared by every test GIF.
PALETTE = [(0, 0, 0), (255, 0, 0), (0, 255, 0), (0, 0, 255)]   # black, red, green, blue


def min_code_size(colors):
    bits = max(1, (len(colors) - 1).bit_length())
    return max(2, bits)   # GIF requires a minimum LZW code size of 2


def lzw_encode(indices, mcs):
    """GIF LZW. Code widths follow giflib's decoder: after each emitted code the
    running code count rises and the width grows when it passes the current max."""
    clear, eoi = 1 << mcs, (1 << mcs) + 1
    out, bits, nbits = bytearray(), 0, 0

    def emit(code, width):
        nonlocal bits, nbits
        bits |= code << nbits
        nbits += width
        while nbits >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8

    def reset():
        return {bytes([i]): i for i in range(clear)}, eoi + 1, mcs + 1, 1 << (mcs + 1)

    emit(clear, mcs + 1)
    table, running_code, running_bits, max_code1 = reset()
    w = b''
    for index in indices:
        c = bytes([index])
        if w + c in table:
            w += c
            continue
        emit(table[w], running_bits)
        if running_code < (1 << 12) + 1:
            table[w + c] = running_code
            running_code += 1
            if running_code > max_code1 and running_bits < 12:
                max_code1 <<= 1
                running_bits += 1
        else:
            emit(clear, running_bits)
            table, running_code, running_bits, max_code1 = reset()
        w = c
    emit(table[w], running_bits)
    emit(eoi, running_bits)
    if nbits:
        out.append(bits & 0xFF)
    return bytes([mcs]) + sub_blocks(out) + b'\x00'


def sub_blocks(data):
    out = bytearray()
    for i in range(0, len(data), 255):
        chunk = data[i:i + 255]
        out.append(len(chunk))
        out += chunk
    return bytes(out)


def gif(screen, palette, background, image=None, aspect=0):
    """A one-image (or image-less) GIF89a with a global color table."""
    sw, sh = screen
    gct_bits = min_code_size(palette) if len(palette) > 4 else 2  # table size field
    size_field = max(0, (len(palette) - 1).bit_length() - 1)
    data = bytearray(b'GIF89a')
    packed = 0x80 | (size_field << 4) | size_field   # GCT present, color res, GCT size
    data += struct.pack('<HHBBB', sw, sh, packed, background, aspect)
    for r, g, b in palette + [(0, 0, 0)] * ((1 << (size_field + 1)) - len(palette)):
        data += bytes((r, g, b))
    if image is not None:
        left, top, iw, ih, pixels = image
        data.append(0x2C)
        data += struct.pack('<HHHHB', left, top, iw, ih, 0)   # no local table, no interlace
        data += lzw_encode(pixels, min_code_size(palette))
    data.append(0x3B)
    return bytes(data)


def expected_rgb(screen, palette, background, image):
    """gif2rgb -1 output: logical screen filled with the background index, the
    image overlaid, every pixel mapped through the global palette (row-major RGB)."""
    sw, sh = screen
    cells = [[background] * sw for _ in range(sh)]
    if image is not None:
        left, top, iw, ih, pixels = image
        for r in range(ih):
            for c in range(iw):
                cells[top + r][left + c] = pixels[r * iw + c]
    out = bytearray()
    for row in cells:
        for index in row:
            out += bytes(palette[index])
    return bytes(out)


def grid(iw, ih, fn):
    return [fn(r, c) for r in range(ih) for c in range(iw)]


def ok(stdout):
    return 0, stdout, b''


def fail(stderr):
    return 1, b'', stderr


# (id, category, gif bytes, (exit, stdout, stderr), signature, spec section)
def build_cases():
    cases = []

    # valid: image fills the whole screen, background never shows.
    img = (0, 0, 4, 4, grid(4, 4, lambda r, c: (r + c) % 4))
    cases.append(('valid-fill', 'valid', gif((4, 4), PALETTE, 0, img),
                  ok(expected_rgb((4, 4), PALETTE, 0, img)), None, 'Rendering'))

    # valid: a 3x3 image inside a 5x5 screen with a blue (index 3) background margin.
    img = (1, 1, 3, 3, grid(3, 3, lambda r, c: (r * 3 + c) % 4))
    cases.append(('valid-margin', 'valid', gif((5, 5), PALETTE, 3, img),
                  ok(expected_rgb((5, 5), PALETTE, 3, img)), None, 'Rendering'))

    # boundary: background index 3 is the largest valid index for a 4-color table.
    img = (1, 1, 2, 2, grid(2, 2, lambda r, c: 1))
    cases.append(('boundary-bg-max', 'boundary', gif((4, 4), PALETTE, 3, img),
                  ok(expected_rgb((4, 4), PALETTE, 3, img)), None, 'Rendering'))

    # invalid: an image that is not confined to the logical screen.
    img = (3, 0, 3, 3, grid(3, 3, lambda r, c: 1))
    cases.append(('invalid-oversize', 'invalid', gif((4, 4), PALETTE, 0, img),
                  fail(b'Image 1 is not confined to screen dimension, aborted.\n'), None, 'Errors'))

    # invalid: a logical screen with zero height.
    cases.append(('invalid-zero-dim', 'invalid', gif((4, 0), PALETTE, 0, None),
                  fail(b'Image of width or height 0\n'), None, 'Errors'))

    # security: background index 20 is out of range for the 4-color table. A
    # correct program rejects it; the vulnerable one reads past the colormap.
    img = (1, 1, 3, 3, grid(3, 3, lambda r, c: (r + c) % 4))
    cases.append(('poc-bg-oob', 'original', gif((5, 5), PALETTE, 20, img),
                  fail(b'Background color out of range for colormap\n'), TARGET_SIGNATURE, 'Security property'))

    # security variant: a larger out-of-range index in a wider margin.
    img = (2, 2, 2, 2, grid(2, 2, lambda r, c: 2))
    cases.append(('poc-bg-far', 'original', gif((6, 6), PALETTE, 37, img),
                  fail(b'Background color out of range for colormap\n'), TARGET_SIGNATURE, 'Security property'))

    return cases


def oracle(section, exit_code, stdout, stderr):
    def comparator(data):
        return {'mode': 'exact', 'base64': base64.b64encode(data).decode()}
    return {'schema_version': '1.0',
            'provenance': {'source': f'oracles/giflib/SPEC.md#{section}', 'independent': True},
            'exit_code': exit_code, 'stdout': comparator(stdout), 'stderr': comparator(stderr)}


def config_tests(cases):
    tests = []
    for test_id, category, _input, _expected, signature, _section in cases:
        tests.append({'id': test_id, 'category': category,
                      'input': f'../corpus/giflib/inputs/{test_id}.gif',
                      'oracle': f'../oracles/giflib/{test_id}.json', 'signature': signature})
    return tests


def main():
    cases = build_cases()
    inputs = ROOT / 'corpus' / 'giflib' / 'inputs'
    oracles = ROOT / 'oracles' / 'giflib'
    inputs.mkdir(parents=True, exist_ok=True)
    oracles.mkdir(parents=True, exist_ok=True)
    for test_id, _category, data, (exit_code, stdout, stderr), _signature, section in cases:
        (inputs / f'{test_id}.gif').write_bytes(data)
        (oracles / f'{test_id}.json').write_text(json.dumps(oracle(section, exit_code, stdout, stderr), indent=2) + '\n')
    config_path = ROOT / 'configs' / 'giflib-file.json'
    config = json.loads(config_path.read_text())
    config['tests'] = config_tests(cases)
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    print(f'Wrote {len(cases)} giflib inputs and oracles, and updated {config_path.name}.')


if __name__ == '__main__':
    main()
