#[macro_use]
extern crate log;

use structopt::StructOpt;
use hyper_auth_proxy::{ProxyConfig, run_service_with_decoder};
use crate::aes::aes_decode;

/// simple auth proxy
#[derive(StructOpt, Debug)]
#[structopt(name = "auth-proxy")]
struct Args {
    /// back uri
    back_uri: String,
    /// JWT decode key
    jwt_key: String,
    #[structopt(long)]
    /// credentials decode key
    credentials_key: Option<String>,
    // redis url on the form redis://host
    #[structopt(long)]
    /// Redis url, redis://redis if not present
    redis_uri: Option<String>,
    #[structopt(long)]
    /// Listen port, 3000 if not present
    port: Option<u32>,
}

impl Args {
    fn to_config(self) -> ProxyConfig {
        ProxyConfig {
            jwt_key: self.jwt_key,
            credentials_key: match self.credentials_key {
                Some(cred_key) => cred_key,
                None => String::new()
            },
            back_uri: self.back_uri,
            redis_uri: match self.redis_uri {
                Some(redisuri) => redisuri,
                None => "redis://redis".to_string()
            },
            address: match self.port {
                Some(port) => format!("127.0.0.1:{}", port).parse().unwrap(),
                None => "127.0.0.1:3000".parse().unwrap()
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = Args::from_args();

    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    let config = opt.to_config();
    let server = run_service(config.clone(), rx).await;
    info!("Running auth proxy on {:?} with backend {:?}", config.address, config.back_uri);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}