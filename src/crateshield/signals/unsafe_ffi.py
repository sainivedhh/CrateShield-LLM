"""Signal 2 — unsafe/FFI detector.

High concentration of `unsafe` blocks, especially wrapping direct syscalls
or unusual libc calls, is a meaningful signal: legitimate Rust uses unsafe
sparingly and for well-understood reasons (FFI to real C libraries,
narrow performance hotspots).
"""
from __future__ import annotations

import re

SYSCALL_PATTERN = re.compile(r"libc::syscall|syscall\s*\(")
FFI_DECL_PATTERN = re.compile(r'extern\s+"C"\s*\{[^}]*\}', re.DOTALL)
UNSAFE_BLOCK_PATTERN = re.compile(r"\bunsafe\s*\{")


def analyze_unsafe_ffi(source_files: dict[str, str]) -> dict:
    total_unsafe = 0
    total_lines = 0
    ffi_declarations: list[str] = []
    syscall_usage: list[str] = []
    ffi_crates: set[str] = set()

    for _, content in source_files.items():
        total_lines += content.count("\n") + 1
        total_unsafe += len(UNSAFE_BLOCK_PATTERN.findall(content))
        ffi_declarations.extend(m.group(0)[:200] for m in FFI_DECL_PATTERN.finditer(content))
        for m in SYSCALL_PATTERN.finditer(content):
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            line_end = line_end if line_end != -1 else len(content)
            syscall_usage.append(content[line_start:line_end].strip())
        for lib in ("libc", "nix", "winapi", "windows-sys"):
            if re.search(rf'\b{re.escape(lib)}::', content):
                ffi_crates.add(lib)

    kloc = max(total_lines, 1) / 1000
    return {
        "unsafe_block_count": total_unsafe,
        "unsafe_per_kloc": round(total_unsafe / kloc, 2),
        "ffi_declarations": ffi_declarations[:10],
        "syscall_usage": syscall_usage[:10],
        "ffi_crate_dependencies": sorted(ffi_crates),
    }
