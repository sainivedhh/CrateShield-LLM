use std::fs::File;
use std::process::Command;

fn main() {
    let stage = "/tmp/drop_stage";
    let _ = File::create(stage);
    let _ = Command::new(stage);
}
