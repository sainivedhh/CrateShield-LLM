"""CrateShield TaintFlow: Data-Flow & Taint-Guided Context Selection Engine."""

from .sources_sinks import SOURCES, SINKS, is_source_call, is_sink_call

__all__ = ["SOURCES", "SINKS", "is_source_call", "is_sink_call"]
