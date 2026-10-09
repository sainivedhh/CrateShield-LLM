use reqwest;

pub fn macro_helper() {
    let _ = reqwest::blocking::get("http://127.0.0.1:7002");
}
