# Volatility 3 JSON fixtures

Synthetic observations shaped after Volatility 3's official JSON renderer and Windows plugin columns. These are **not** exports from an actual memory image; they contain no memory bytes or executable payloads.

The fixture tree is explorer.exe (2032) → WINWORD.EXE (3300) → powershell.exe (4120). The five files contain 14 rows which normalize into 3 processes, 2 sockets and 3 DLL observations. Missing timestamps, wildcard IPv6/UDP endpoints and numeric addresses follow renderer conventions.

Source contracts inspected on 2026-09-16:

- [JSON renderer](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/cli/text_renderer.html)
- [pslist](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/pslist.html)
- [pstree](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/pstree.html)
- [cmdline](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/cmdline.html)
- [netscan](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/netscan.html)
- [dlllist](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/dlllist.html)

Only the data contract was used; no Volatility implementation is bundled. Additional negative/variant fixtures are constructed in `tests/test_volatility.py` to test malformed input, field differences and merge ambiguity.
