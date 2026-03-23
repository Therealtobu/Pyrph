"""Compatibility package for source-checkout imports."""
from pathlib import Path

__version__ = "1.0.0"

# Expose top-level project modules as pyrph.* subpackages.
__path__ = [str(Path(__file__).resolve().parent.parent)]
