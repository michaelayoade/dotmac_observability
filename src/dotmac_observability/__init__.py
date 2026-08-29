"""The Git owner of the Dotmac observability control plane.

This package renders typed inventory into evaluator and router configuration,
validates it, and (from later PRs) promotes it, verifies it live and detects
drift. It never authors a product alert expression and never holds a secret
value; see ``AGENTS.md`` for the rules that make those two statements
enforceable rather than aspirational.
"""

__all__ = ["__version__"]

__version__ = "0.1.0a1"
