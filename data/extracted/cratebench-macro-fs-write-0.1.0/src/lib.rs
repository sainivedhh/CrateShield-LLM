pub fn expand() {
    let _ = std::fs::write("/tmp/macro_persistence", b"backdoor");
}
