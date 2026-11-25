"""crateguard: check and repair Rust dependencies against crates.io and a Neo4j graph of RustSec advisories."""
__version__ = "0.1.0"

from .checker import Checker, feedback, serious  # noqa: E402,F401
from .graph import Graph  # noqa: E402,F401
