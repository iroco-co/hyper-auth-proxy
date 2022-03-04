use auth_proxy::{run_service, ProxyConfig};


#[tokio::main]
async fn main() {
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    let config = ProxyConfig::default();
    let server = run_service(config.clone(), rx).await;
    println!("Running server on {:?}", config.address);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}