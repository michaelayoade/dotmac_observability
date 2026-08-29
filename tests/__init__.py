"""Test package.

`__init__.py` files are present so `from tests.conftest import ...` resolves
identically under pytest, mypy and a bare interpreter. Without them the import
works only when the runner happens to have inserted the repository root on
`sys.path`, which differs between `pytest` and `python -m pytest`.
"""
