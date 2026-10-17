"""Automatically register one CLI module per command."""

from importlib import import_module
from pkgutil import iter_modules

import typer

app = typer.Typer(no_args_is_help=True)
for module in sorted(iter_modules(__path__), key=lambda item: item.name):
    if not module.name.startswith("_"):
        import_module(f"{__name__}.{module.name}").register(app)
