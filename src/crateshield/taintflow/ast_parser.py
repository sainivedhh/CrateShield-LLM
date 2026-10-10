"""Tree-sitter AST parser for Rust source code.

Extracts functions, intra-crate calls, imports, impl blocks, and direct taint sources/sinks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import tree_sitter
import tree_sitter_rust

from .sources_sinks import SourceDef, SinkDef, is_source_call, is_sink_call


@dataclass
class FunctionDef:
    name: str
    rel_path: str
    start_line: int
    end_line: int
    code: str
    impl_type: Optional[str] = None
    direct_sources: list[SourceDef] = field(default_factory=list)
    direct_sinks: list[SinkDef] = field(default_factory=list)
    callee_names: set[str] = field(default_factory=set)

    @property
    def id(self) -> str:
        return f"{self.rel_path}:{self.name}:{self.start_line}"


@dataclass
class FileASTInfo:
    rel_path: str
    imports: list[str] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)


class RustASTParser:
    def __init__(self) -> None:
        self.language = tree_sitter.Language(tree_sitter_rust.language())
        self.parser = tree_sitter.Parser(self.language)

    def parse_file(self, rel_path: str, source_text: str) -> FileASTInfo:
        """Parses a single Rust source file into FileASTInfo."""
        info = FileASTInfo(rel_path=rel_path)
        if not source_text or not source_text.strip():
            return info

        source_bytes = source_text.encode("utf-8", errors="ignore")
        tree = self.parser.parse(source_bytes)
        root = tree.root_node

        # 1. Extract imports (use_declaration)
        for child in root.children:
            if child.type == "use_declaration":
                text = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
                info.imports.append(text.strip())

        # 2. Extract functions (standalone and inside impl/mod blocks)
        self._find_functions(root, rel_path, source_bytes, info, current_impl=None)
        return info

    def _find_functions(
        self,
        node: tree_sitter.Node,
        rel_path: str,
        source_bytes: bytes,
        info: FileASTInfo,
        current_impl: Optional[str] = None,
    ) -> None:
        if node.type == "impl_item":
            # Extract type name from impl block
            type_node = node.child_by_field_name("type")
            if type_node:
                current_impl = source_bytes[type_node.start_byte:type_node.end_byte].decode("utf-8", errors="ignore").strip()

        if node.type == "function_item":
            name_node = node.child_by_field_name("name")
            fn_name = (
                source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore").strip()
                if name_node
                else "anonymous"
            )

            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            code = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

            fn_def = FunctionDef(
                name=fn_name,
                rel_path=rel_path,
                start_line=start_line,
                end_line=end_line,
                code=code,
                impl_type=current_impl,
            )

            # Analyze function body for calls, macros, sources, sinks
            self._analyze_function_calls(node, source_bytes, fn_def)
            info.functions.append(fn_def)
            return

        for child in node.children:
            self._find_functions(child, rel_path, source_bytes, info, current_impl)

    def _analyze_function_calls(
        self,
        fn_node: tree_sitter.Node,
        source_bytes: bytes,
        fn_def: FunctionDef,
    ) -> None:
        """Walks the function AST to collect calls, macro invocations, sources, and sinks."""
        def visit(node: tree_sitter.Node) -> None:
            if node.type == "call_expression":
                fn_child = node.child_by_field_name("function")
                if fn_child:
                    call_text = source_bytes[fn_child.start_byte:fn_child.end_byte].decode("utf-8", errors="ignore").strip()
                    full_call_expr = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore").strip()
                    
                    # Extract callee name
                    if fn_child.type == "field_expression":
                        field_child = fn_child.child_by_field_name("field")
                        if field_child:
                            m_name = source_bytes[field_child.start_byte:field_child.end_byte].decode("utf-8", errors="ignore").strip()
                            fn_def.callee_names.add(m_name)
                    else:
                        base_name = call_text.split("::")[-1]
                        fn_def.callee_names.add(base_name)
                        if "::" in call_text:
                            fn_def.callee_names.add(call_text)

                    # Check taint sources and sinks
                    src = is_source_call(call_text) or is_source_call(full_call_expr)
                    if src and src not in fn_def.direct_sources:
                        fn_def.direct_sources.append(src)

                    snk = is_sink_call(call_text) or is_sink_call(full_call_expr)
                    if snk and snk not in fn_def.direct_sinks:
                        fn_def.direct_sinks.append(snk)

            elif node.type == "macro_invocation":
                macro_child = node.child_by_field_name("macro")
                if macro_child:
                    m_text = source_bytes[macro_child.start_byte:macro_child.end_byte].decode("utf-8", errors="ignore").strip()
                    full_m = f"{m_text}!"
                    fn_def.callee_names.add(full_m)
                    
                    src = is_source_call(full_m) or is_source_call(m_text)
                    if src and src not in fn_def.direct_sources:
                        fn_def.direct_sources.append(src)

                    snk = is_sink_call(full_m) or is_sink_call(m_text)
                    if snk and snk not in fn_def.direct_sinks:
                        fn_def.direct_sinks.append(snk)

            for child in node.children:
                visit(child)

        visit(fn_node)
