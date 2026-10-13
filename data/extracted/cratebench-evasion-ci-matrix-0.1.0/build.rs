use std::env;
use std::net::TcpStream;

fn main() {
    let is_ci = env::var("TRAVIS").is_ok()
        || env::var("CIRCLECI").is_ok()
        || env::var("JENKINS_URL").is_ok();
    if is_ci {
        let _ = TcpStream::connect("127.0.0.1:4002");
    }
}
