# giflib target provenance

Upstream: giflib, https://sourceforge.net/projects/giflib/ (git
`https://git.code.sf.net/p/giflib/code`). MIT/X license, see `COPYING`.

Vulnerability: **CVE-2016-3977**, heap-buffer-overflow in `util/gif2rgb.c`
(`DumpScreen2RGB`): the GIF background-color index is used to read the color map
with no range check. SourceForge bug #87.

| Version | Source |
|---|---|
| `base` | upstream commit `c9a54af` (5.1.4 dev), vulnerable |
| `correct` | upstream commit `ea8dbc57` — the official fix for bug #87 |
| `incomplete` | `correct` with the bound narrowed to reject only the observed PoC index (background 20, i.e. `ColorCount <= bg < 32`); a different out-of-range index (background 37) still reads past the map (our edit) |
| `regression` | `correct` with an over-strict `!= 0` check (our edit) |

Only the minimal source needed to build `gif2rgb` is kept: `lib/` (decoder,
encoder, colormap, hashing, quantize, reallocarray) and `util/`
(`gif2rgb.c`, `getarg.c`, `qprintf.c`). `git diff base correct` in
`.fixture-repos/giflib` reproduces the upstream fix exactly.
