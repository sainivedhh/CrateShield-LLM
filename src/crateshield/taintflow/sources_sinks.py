"""Independence Firewall: Taint Source and Sink Specifications.

These definitions are derived strictly from:
1. data/bench_v3/taxonomy.yaml (Families F1-F8: credential_exfil, reverse_shell_rce,
   build_download_exec, persistence, supply_chain_dep, typosquat_payload, conditional_gated,
   data_destructive_wallet).
2. General Rust stdlib (std::env, std::fs, std::process, std::net) and standard network/process
   ecosystem libraries (reqwest, ureq, hyper, curl, libloading).

CRITICAL FIREWALL RULE:
This specification was created prior to inspecting individual v3 payload files.
"""

from typing import NamedTuple, Optional


class SourceDef(NamedTuple):
    category: str
    pattern: str
    description: str


class SinkDef(NamedTuple):
    category: str
    pattern: str
    description: str


# Formal Sources (F1 credential_exfil, F7 conditional_gated, F8 data_destructive_wallet)
SOURCES: list[SourceDef] = [
    # Environment variable extraction / CI environment gate detection
    SourceDef("env", "std::env::var", "Reading environment variable (e.g. credentials, tokens, CI flags)"),
    SourceDef("env", "std::env::var_os", "Reading environment variable OsString"),
    SourceDef("env", "std::env::vars", "Iterating all environment variables"),
    SourceDef("env", "std::env::vars_os", "Iterating all environment variables OsString"),
    SourceDef("env", "env::var", "Reading environment variable"),
    SourceDef("env", "env::var_os", "Reading environment variable OsString"),
    SourceDef("env", "env::vars", "Iterating all environment variables"),
    SourceDef("env", "env::vars_os", "Iterating all environment variables OsString"),
    SourceDef("env", "std::env::args", "Reading command-line arguments"),
    SourceDef("env", "std::env::args_os", "Reading command-line arguments OsString"),
    SourceDef("env", "env::args", "Reading command-line arguments"),
    SourceDef("env", "env::args_os", "Reading command-line arguments OsString"),

    # Filesystem credential harvesting / arbitrary file reads
    SourceDef("fs_read", "std::fs::read", "Reading file bytes from disk"),
    SourceDef("fs_read", "std::fs::read_to_string", "Reading file string from disk"),
    SourceDef("fs_read", "std::fs::File::open", "Opening file on disk"),
    SourceDef("fs_read", "std::fs::read_link", "Reading symlink target"),
    SourceDef("fs_read", "std::fs::read_dir", "Listing directory contents"),
    SourceDef("fs_read", "fs::read", "Reading file bytes from disk"),
    SourceDef("fs_read", "fs::read_to_string", "Reading file string from disk"),
    SourceDef("fs_read", "fs::File::open", "Opening file on disk"),
    SourceDef("fs_read", "File::open", "Opening file on disk"),
    SourceDef("fs_read", "fs::read_link", "Reading symlink target"),
    SourceDef("fs_read", "fs::read_dir", "Listing directory contents"),

    # Sensitive path resolution
    SourceDef("path", "dirs::home_dir", "Resolving user home directory (SSH/AWS keys)"),
    SourceDef("path", "dirs::config_dir", "Resolving user configuration directory"),
    SourceDef("path", "dirs::data_dir", "Resolving user data directory"),
    SourceDef("path", "dirs::cache_dir", "Resolving cache directory"),
    SourceDef("path", "home::home_dir", "Resolving user home directory"),

    # OUT_DIR code generation includes
    SourceDef("macro_include", "include!", "Including arbitrary Rust source code"),
    SourceDef("macro_include", "include_str!", "Including external file string"),
    SourceDef("macro_include", "include_bytes!", "Including external file bytes"),
]


# Formal Sinks (F1 credential_exfil, F2 reverse_shell_rce, F3 build_download_exec,
# F4 persistence, F8 data_destructive_wallet)
SINKS: list[SinkDef] = [
    # Command execution / reverse shell spawn
    SinkDef("process", "std::process::Command::new", "Spawning child process / shell command"),
    SinkDef("process", "std::process::Command", "Process Command invocation"),
    SinkDef("process", "Command::new", "Spawning child process / shell command"),
    SinkDef("process", "Command", "Process Command invocation"),

    # Raw network sockets (reverse shells, direct TCP exfiltration)
    SinkDef("net_socket", "std::net::TcpStream::connect", "Opening outbound TCP connection"),
    SinkDef("net_socket", "std::net::TcpStream::connect_timeout", "Opening outbound TCP connection with timeout"),
    SinkDef("net_socket", "std::net::UdpSocket::bind", "Binding UDP socket"),
    SinkDef("net_socket", "std::net::UdpSocket::connect", "Connecting UDP socket"),
    SinkDef("net_socket", "std::net::TcpListener::bind", "Binding TCP listening socket (inbound reverse shell)"),
    SinkDef("net_socket", "TcpStream::connect", "Opening outbound TCP connection"),
    SinkDef("net_socket", "TcpStream::connect_timeout", "Opening outbound TCP connection with timeout"),
    SinkDef("net_socket", "UdpSocket::bind", "Binding UDP socket"),
    SinkDef("net_socket", "UdpSocket::connect", "Connecting UDP socket"),

    # HTTP / HTTPS network clients (webhook / exfiltration / payload dropper)
    SinkDef("http_client", "reqwest::get", "Sending outbound HTTP GET request"),
    SinkDef("http_client", "reqwest::post", "Sending outbound HTTP POST request"),
    SinkDef("http_client", "reqwest::Client::new", "Constructing HTTP client"),
    SinkDef("http_client", "reqwest::blocking::Client::new", "Constructing blocking HTTP client"),
    SinkDef("http_client", "reqwest::blocking::get", "Sending blocking HTTP GET request"),
    SinkDef("http_client", "ureq::get", "Sending ureq HTTP GET request"),
    SinkDef("http_client", "ureq::post", "Sending ureq HTTP POST request"),
    SinkDef("http_client", "ureq::put", "Sending ureq HTTP PUT request"),
    SinkDef("http_client", "hyper::Client::new", "Constructing hyper HTTP client"),
    SinkDef("http_client", "curl::easy::Easy::new", "Constructing libcurl client"),

    # Filesystem mutations / persistence / destructive deletion
    SinkDef("fs_write", "std::fs::write", "Writing data to filesystem"),
    SinkDef("fs_write", "std::fs::File::create", "Creating file on filesystem"),
    SinkDef("fs_write", "std::fs::OpenOptions::new", "Opening file with write/create options"),
    SinkDef("fs_write", "std::fs::copy", "Copying file to persistence target"),
    SinkDef("fs_write", "std::fs::rename", "Renaming file on filesystem"),
    SinkDef("fs_write", "std::fs::remove_file", "Deleting file from filesystem"),
    SinkDef("fs_write", "std::fs::remove_dir", "Deleting directory"),
    SinkDef("fs_write", "std::fs::remove_dir_all", "Recursively deleting directory tree"),
    SinkDef("fs_write", "fs::write", "Writing data to filesystem"),
    SinkDef("fs_write", "fs::File::create", "Creating file on filesystem"),
    SinkDef("fs_write", "File::create", "Creating file on filesystem"),
    SinkDef("fs_write", "OpenOptions::new", "Opening file with write/create options"),
    SinkDef("fs_write", "fs::copy", "Copying file to filesystem"),
    SinkDef("fs_write", "fs::rename", "Renaming file"),
    SinkDef("fs_write", "fs::remove_file", "Deleting file from filesystem"),
    SinkDef("fs_write", "fs::remove_dir", "Deleting directory"),
    SinkDef("fs_write", "fs::remove_dir_all", "Recursively deleting directory tree"),

    # Dynamic library loading / native payload execution
    SinkDef("dynamic_load", "libloading::Library::new", "Dynamically loading native shared library"),
    SinkDef("dynamic_load", "libloading::Symbol", "Resolving symbol in dynamically loaded library"),
    SinkDef("dynamic_load", "loading::Library::new", "Dynamically loading shared library"),
]


SOURCE_PATTERNS = [s.pattern for s in SOURCES]
SINK_PATTERNS = [s.pattern for s in SINKS]


def is_source_call(call_expr: str) -> Optional[SourceDef]:
    """Check if a call expression matches any defined taint source."""
    call_expr = call_expr.strip()
    for src in SOURCES:
        if call_expr == src.pattern or call_expr.endswith("::" + src.pattern) or (src.pattern in call_expr and not call_expr.startswith("//")):
            return src
    return None


def is_sink_call(call_expr: str) -> Optional[SinkDef]:
    """Check if a call expression matches any defined taint sink."""
    call_expr = call_expr.strip()
    for snk in SINKS:
        if call_expr == snk.pattern or call_expr.endswith("::" + snk.pattern) or (snk.pattern in call_expr and not call_expr.startswith("//")):
            return snk
    return None
