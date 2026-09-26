"""Scanner adapters. One module per scanner, each exposing ``run`` and ``parse``.

Adding a scanner (Syft, Dockle, …) means: an adapter here, a
:class:`~rotsy_runner.tools.specs.ToolSpec` for its binary (and database, if
it has one), and an entry in the Rotsy server's tool catalogue
(``backend/app/core/tools.py``). The executor dispatches by scanner name.
"""
