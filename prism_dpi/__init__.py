"""Prism DPI: no-MITM transport classification and causal flow analysis.

Each supported technology lives under ``modules/`` and uses the shared
signature types from ``signatures/``. Active policies may block precisely classified
traffic, while shadow policies count observations. ``flowgraph`` adds a
metadata-only stateful observer; it has no firewall mutation capability.

See README.md. No decryption and no certificates.
"""

__version__ = "0.2.0"
