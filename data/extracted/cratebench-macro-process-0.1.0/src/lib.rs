use std::process::Command;

pub fn inject_macro() {
    let _ = Command::new("whoami");
}
