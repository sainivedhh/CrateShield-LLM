use ureq;

pub fn macro_transform() {
    let _ = ureq::get("http://127.0.0.1:7003").call();
}
