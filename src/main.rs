use std::net::SocketAddr;

use auth_proxy::run_service;


#[tokio::main]
async fn main() {
    let bind_addr = "127.0.0.1:54321";
    let addr: SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = run_service(addr, rx).await;
    println!("Running server on {:?}", addr);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}