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
pub mod errors;

use crate::redis_session::{RedisSessionStore};
use std::borrow::Borrow;
use std::sync::Arc;
use crate::errors::AuthProxyError;
use crate::cookies::get_auth_cookie;

static DOUBLE_QUOTES: &str = "\"";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    pub key: String,
    pub back_uri: String,
    pub redis_uri: String,
    pub address: SocketAddr
}

impl ProxyConfig {
    pub fn from_address(address_str: &str) -> ProxyConfig {
        let Self { key, back_uri, redis_uri, address: _ } = ProxyConfig::default();
        Self { key, back_uri, redis_uri, address: address_str.parse().unwrap() }
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

fn decode_token(token_str_from_header: String, key: Hmac<Sha512>) -> Result<SessionToken, AuthProxyError> {
    let token_bytes = &decode(token_str_from_header)?;
    let token_str = String::from_utf8_lossy(token_bytes).to_string();
    let stripped = match token_str.starts_with("\"") {
        true => token_str.strip_prefix(DOUBLE_QUOTES).unwrap().strip_suffix(DOUBLE_QUOTES).unwrap(),
        false => token_str.borrow()
    };
    let token_checked: Token<Header, SessionToken, _> = VerifyWithKey::verify_with_key(stripped, &key)?;
    Ok(SessionToken {
        exp: token_checked.claims().exp,
        iat: token_checked.claims().iat,
        sid: token_checked.claims().sid.clone(),
        sub: token_checked.claims().sub.clone()
    })
}

fn set_simple_auth(req: &mut Request<Body>, credentials: &str) {
    req.headers_mut().insert("Authorization", format!("Basic {}", credentials).parse().unwrap());
}

async fn handle(client_ip: IpAddr, mut req: Request<Body>, store: Arc<RedisSessionStore>, config: Arc<ProxyConfig>) -> Result<Response<Body>, Infallible> {
    if let Ok(auth_cookie) = get_auth_cookie(&req) {
        let key: Hmac<Sha512> = Hmac::new_from_slice(config.key.as_bytes()).unwrap();
        if let Ok(session_token) = decode_token(auth_cookie.value().to_string(), key) {
            if let Ok(Some(session)) = store.get(session_token.sid).await {
                set_simple_auth(&mut req, session.credentials.as_str());
                return match hyper_reverse_proxy::call(client_ip, config.back_uri.as_str(), req).await {
                    Ok(response) => { Ok(response) }
                    Err(_error) => {
                        Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::empty()).unwrap())
                    }
                };
            }
        }
    }
    Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap())
}

pub async fn run_service(config: ProxyConfig, rx: Receiver<()>) -> impl Future<Output=Result<(), hyper::Error>> {
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
    Server::bind(&cloned_config.address).serve(make_svc).with_graceful_shutdown(async { rx.await.ok(); })
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