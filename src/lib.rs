use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use base64::decode;
use hmac::Hmac;
use hyper::{Body, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use jwt::{Header, Token, VerifyWithKey};
use sha2::digest::KeyInit;
use sha2::Sha512;
use tokio::sync::oneshot::Receiver;

mod cookies;
pub mod redis_session;

use crate::redis_session::RedisSessionStore;
use std::borrow::Borrow;
use std::sync::Arc;

static DOUBLE_QUOTES: &str = "\"";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    pub key: String,
    pub back_uri : String,
    pub redis_uri: String,
    pub address: SocketAddr
}

impl ProxyConfig {
    pub fn from_address(address_str: &str) -> ProxyConfig {
        let Self {key, back_uri, redis_uri, address: _ } = ProxyConfig::default();
        Self {key, back_uri, redis_uri, address: address_str.parse().unwrap()}
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            key: "testsecretpourlestests".to_string(),
            back_uri: "http://127.0.0.1:5000".to_string(),
            redis_uri: "redis://redis".to_string(),
            address: "127.0.0.1:3000".parse().unwrap()
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SessionToken {
    pub sub: String,
    pub sid: String,
    pub iat: i64,
    pub exp: i64
}

async fn handle(client_ip: IpAddr, mut req: Request<Body>, store: Arc<RedisSessionStore>, config: Arc<ProxyConfig>) -> Result<Response<Body>, Infallible> {
    if let Some(cookie_header) = req.headers().get("Cookies") {
        if let Ok(cookie_header_str) = cookie_header.to_str() {
            if let Some(auth_cookie) = cookies::find_from_header(cookie_header_str, "Authorization") {
                let token_str_base64 = auth_cookie.value();
                if let Ok(token) = &decode(token_str_base64) {
                    let token_str = String::from_utf8_lossy(token).to_string();
                    let stripped = match token_str.starts_with("\"") {
                        true => token_str.strip_prefix(DOUBLE_QUOTES).unwrap().strip_suffix(DOUBLE_QUOTES).unwrap(),
                        false => token_str.borrow()
                    };
                    let key: Hmac<Sha512> = Hmac::new_from_slice(config.key.as_bytes()).unwrap();
                    if let Ok(token_checked) = VerifyWithKey::verify_with_key(stripped, &key) {
                        let token: Token<Header, SessionToken, _> = token_checked;
                        if let Ok(Some(session)) = store.get(token.claims().sid.to_string()).await {
                            req.headers_mut().insert("Authorization", format!("Basic {}", session.credentials).parse().unwrap());
                            return match hyper_reverse_proxy::call(client_ip, config.back_uri.as_str(), req).await {
                                Ok(response) => { Ok(response) }
                                Err(_error) => {
                                    Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::empty()).unwrap())
                                }
                            };
                        }
                    }
                }
            }
        }
    }
    Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap())
}

pub async fn run_service(config: ProxyConfig, rx: Receiver<()>) -> impl Future<Output = Result<(), hyper::Error>> {
    let cloned_config = config.clone();
    let shared_config = Arc::new(config);
    let shared_store = Arc::new(RedisSessionStore::new(shared_config.redis_uri.to_owned()).unwrap());
    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let config_capture = shared_config.clone();
        let store_capture = shared_store.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle(remote_addr, req, store_capture.clone(), config_capture.clone())))
        }
    });
    Server::bind(&cloned_config.address).serve(make_svc).with_graceful_shutdown(async {rx.await.ok();})
}

#[cfg(test)]
mod test {
    use crate::ProxyConfig;

    #[test]
    fn build_from_uri() {
        let config = ProxyConfig::from_address("127.0.0.1:12345");
        assert_eq!(config.address, "127.0.0.1:12345".parse().unwrap())
    }
}