"""CrateShield TaintFlow: Data-Flow & Taint-Guided Context Selection Engine."""

from .sources_sinks import SOURCES, SINKS, is_source_call, is_sink_call
from .ast_parser import RustASTParser, FunctionDef, FileASTInfo
from .callgraph import CrateCallGraph
from .taint_engine import TaintEngine, TaintPath
from .extractor import extract_taint_context

__all__ = [
    "SOURCES",
    "SINKS",
    "is_source_call",
    "is_sink_call",
    "RustASTParser",
    "FunctionDef",
    "FileASTInfo",
    "CrateCallGraph",
    "TaintEngine",
    "TaintPath",
    "extract_taint_context",
]
