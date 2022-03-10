
pub fn b64_decode(credentials: &str, _k: &str) -> Result<String, AuthProxyError> {
    Ok(String::from_utf8_lossy(&base64::decode(&credentials)?).to_string())
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    let config = ProxyConfig::default();
    let server = run_service_with_decoder(config.clone(), rx, b64_decode).await;
    info!("Running auth proxy on {:?} with backend {:?}", config.address, config.back_uri);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}