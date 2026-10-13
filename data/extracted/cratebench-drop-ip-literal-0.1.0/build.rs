use std::net::TcpStream;

fn main() {
    let url = "http://185.220.101.5:8080/setup";
    let _ = TcpStream::connect("185.220.101.5:8080");
}
