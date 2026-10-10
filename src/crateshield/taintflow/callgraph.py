"""Intra-crate call graph construction with conservative name resolution."""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from typing import Optional

from .ast_parser import FunctionDef, FileASTInfo


@dataclass
class CrateCallGraph:
    nodes: dict[str, FunctionDef] = field(default_factory=dict)
    files: dict[str, FileASTInfo] = field(default_factory=dict)
    # Forward edges: caller_id -> list of callee_ids
    forward_edges: dict[str, set[str]] = field(default_factory=lambda: collections.defaultdict(set))
    # Reverse edges: callee_id -> list of caller_ids
    reverse_edges: dict[str, set[str]] = field(default_factory=lambda: collections.defaultdict(set))
    # Lookup by function simple name
    by_name: dict[str, list[str]] = field(default_factory=lambda: collections.defaultdict(list))

    def add_file(self, file_info: FileASTInfo) -> None:
        self.files[file_info.rel_path] = file_info
        for fn in file_info.functions:
            self.nodes[fn.id] = fn
            self.by_name[fn.name].append(fn.id)

    def build_edges(self) -> None:
        """Resolves callee names to candidate function node IDs across the crate."""
        for fn_id, fn in self.nodes.items():
            for callee in fn.callee_names:
                # Conservative resolution: match candidate function definitions
                candidates = self.by_name.get(callee, [])
                if not candidates and "::" in callee:
                    short_name = callee.split("::")[-1]
                    candidates = self.by_name.get(short_name, [])

                for target_id in candidates:
                    if target_id != fn_id:
                        self.forward_edges[fn_id].add(target_id)
                        self.reverse_edges[target_id].add(fn_id)

    def get_source_nodes(self) -> list[FunctionDef]:
        """Returns all functions containing direct taint sources or build.rs entry points."""
        sources = []
        for fn in self.nodes.values():
            if fn.direct_sources:
                sources.append(fn)
            elif fn.rel_path.endswith("build.rs") and fn.name == "main":
                # build.rs main is treated as an active execution source
                sources.append(fn)
        return sources

    def get_sink_nodes(self) -> list[FunctionDef]:
        """Returns all functions containing direct taint sinks."""
        return [fn for fn in self.nodes.values() if fn.direct_sinks]
