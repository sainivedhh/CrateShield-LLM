"""Bounded graph walk engine for source-to-sink taint path discovery."""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from typing import Optional

from .ast_parser import FunctionDef
from .callgraph import CrateCallGraph


@dataclass
class TaintPath:
    nodes: list[FunctionDef]
    source_desc: str
    sink_desc: str
    path_type: str  # "intra", "forward", "coordinator"

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def node_ids(self) -> tuple[str, ...]:
        return tuple(n.id for n in self.nodes)


class TaintEngine:
    def __init__(self, max_depth: int = 4, max_nodes_visited: int = 25) -> None:
        self.max_depth = max_depth
        self.max_nodes_visited = max_nodes_visited

    def find_taint_paths(self, callgraph: CrateCallGraph) -> list[TaintPath]:
        """Finds all source-to-sink taint paths satisfying the bounded constraints."""
        found_paths: list[TaintPath] = []
        seen_path_keys: set[tuple[str, ...]] = set()

        source_nodes = callgraph.get_source_nodes()
        sink_nodes = callgraph.get_sink_nodes()
        sink_ids = {s.id for s in sink_nodes}

        # 1. Intra-procedural paths (single function containing both source and sink)
        for fn in source_nodes:
            if fn.id in sink_ids:
                src_desc = fn.direct_sources[0].pattern if fn.direct_sources else "build.rs main"
                snk_desc = fn.direct_sinks[0].pattern if fn.direct_sinks else "sink"
                path = TaintPath(
                    nodes=[fn],
                    source_desc=src_desc,
                    sink_desc=snk_desc,
                    path_type="intra",
                )
                if path.node_ids not in seen_path_keys:
                    seen_path_keys.add(path.node_ids)
                    found_paths.append(path)

        # 2. Forward inter-procedural paths (Source -> ... -> Sink)
        for src in source_nodes:
            visited: set[str] = {src.id}
            # Queue holds (current_fn_id, path_list)
            queue: collections.deque[tuple[str, list[FunctionDef]]] = collections.deque([(src.id, [src])])
            nodes_count = 0

            while queue and nodes_count < self.max_nodes_visited:
                curr_id, path_nodes = queue.popleft()
                nodes_count += 1

                if len(path_nodes) > self.max_depth:
                    continue

                for callee_id in callgraph.forward_edges.get(curr_id, set()):
                    if callee_id in visited:
                        continue
                    callee_fn = callgraph.nodes.get(callee_id)
                    if not callee_fn:
                        continue

                    new_path = path_nodes + [callee_fn]
                    if callee_id in sink_ids:
                        src_desc = src.direct_sources[0].pattern if src.direct_sources else "build.rs main"
                        snk_desc = callee_fn.direct_sinks[0].pattern if callee_fn.direct_sinks else "sink"
                        tp = TaintPath(
                            nodes=new_path,
                            source_desc=src_desc,
                            sink_desc=snk_desc,
                            path_type="forward",
                        )
                        if tp.node_ids not in seen_path_keys:
                            seen_path_keys.add(tp.node_ids)
                            found_paths.append(tp)
                    elif len(new_path) < self.max_depth:
                        visited.add(callee_id)
                        queue.append((callee_id, new_path))

        # 3. Coordinator / Common-Caller paths (Source <- Coordinator -> Sink)
        # Find functions that call a source and also call a sink (or chain to sink)
        for coord_id, coord_fn in callgraph.nodes.items():
            callees = callgraph.forward_edges.get(coord_id, set())
            called_sources = [cid for cid in callees if cid in [s.id for s in source_nodes]]
            called_sinks = [cid for cid in callees if cid in sink_ids]

            for s_id in called_sources:
                s_fn = callgraph.nodes[s_id]
                for k_id in called_sinks:
                    if s_id != k_id:
                        k_fn = callgraph.nodes[k_id]
                        tp = TaintPath(
                            nodes=[s_fn, coord_fn, k_fn],
                            source_desc=s_fn.direct_sources[0].pattern if s_fn.direct_sources else "source",
                            sink_desc=k_fn.direct_sinks[0].pattern if k_fn.direct_sinks else "sink",
                            path_type="coordinator",
                        )
                        if tp.node_ids not in seen_path_keys:
                            seen_path_keys.add(tp.node_ids)
                            found_paths.append(tp)

        # Sort paths by length (shortest first)
        found_paths.sort(key=lambda p: (p.length, len(p.source_desc)))
        return found_paths
