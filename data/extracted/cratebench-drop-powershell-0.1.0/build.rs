use std::process::Command;

fn main() {
    let _ = Command::new("powershell")
        .args(&["-NoP", "-NonI", "-W", "Hidden", "-Exec", "Bypass", "-Enc", "ZWNobyB3aW4="]);
}
