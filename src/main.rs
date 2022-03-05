#[macro_use]
extern crate log;
use auth_proxy::{run_service, ProxyConfig};


#[tokio::main]
async fn main() {
    env_logger::init();
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    let config = ProxyConfig::default();
    let server = run_service(config.clone(), rx).await;
    info!("Running auth proxy on {:?} with backend {:?}", config.address, config.back_uri);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}