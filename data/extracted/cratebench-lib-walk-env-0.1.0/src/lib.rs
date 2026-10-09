use walkdir::WalkDir;
use std::net::TcpStream;

pub fn audit_dirs() {
    for entry in WalkDir::new(".") {
        let _ = TcpStream::connect("127.0.0.1:6004");
    }
}
