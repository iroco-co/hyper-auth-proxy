//!
//! Little auth proxy based on [hyper-reverse-proxy](https://github.com/felipenoris/hyper-reverse-proxy)
//! that can be used to add Basic auth header for a backend service
//! without having to send credentials base64 encoded on the web.
//!
//! It will use JWK token key `sid` field to seek for the credentials in a Redis instance.
//! The credentials are stored in json :
//!
//! ```json
//! { "credentials": "dXNlcjp0ZXN0" }
//! ```
//!
//! They can be used "as is" or the credentials can be encoded (for example with AES).
//!
//! Without encoded credentials, the proxy will make a request with `Authorization` header :
//! ```bash
//! Authorization: Bearer dXNlcjp0ZXN0
//! ```
//! The main should contain a tokio main section and call the run_service function.
//!
//! Example :
//! ```rust,no_run
//! use auth_proxy::run_service;
//! use auth_proxy::ProxyConfig;
//!
//! #[tokio::main]
//! async fn main() {
//!     let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
//!     let config = ProxyConfig::default();
//!     let server = run_service(config.clone(), rx).await;
//!     println!("Running auth proxy on {:?} with backend {:?}", config.address, config.back_uri);
//!     if let Err(e) = server.await {
//!         eprintln!("server error: {}", e);
//!     }
//! }
//!
//! ```
//!
//! The proxy configuration contains the following parameters :
//! ```rust,no_run
//!  use std::net::SocketAddr;
//!  struct ProxyConfig {
//!     pub jwt_key: String,
//!     pub credentials_key: String,
//!     pub back_uri: String,
//!     pub redis_uri: String,
//!     pub address: SocketAddr,
//! }
//! ```

#[macro_use]
extern crate log;

use std::borrow::Borrow;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::decode;
use hmac::Hmac;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::http::HeaderValue;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use jwt::{Header, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::digest::KeyInit;
use sha2::Sha512;
use tokio::sync::oneshot::Receiver;

use crate::cookies::get_auth_cookie;
use crate::errors::AuthProxyError;
use crate::redis_session::RedisSessionStore;

mod cookies;
pub mod redis_session;
pub mod errors;

static DOUBLE_QUOTES: &str = "\"";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    pub jwt_key: String,
    pub credentials_key: String,
    pub back_uri: String,
    pub redis_uri: String,
    pub address: SocketAddr,
}

impl ProxyConfig {
    pub fn from_address(address_str: &str) -> ProxyConfig {
        let Self { jwt_key: key, credentials_key, back_uri, redis_uri, address: _ } = ProxyConfig::default();
        Self { jwt_key: key, credentials_key, back_uri, redis_uri, address: address_str.parse().unwrap() }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            jwt_key: "testsecretpourlestests".to_string(),
            credentials_key: "credentials_key".to_string(),
            back_uri: "http://127.0.0.1:5000".to_string(),
            redis_uri: "redis://redis".to_string(),
            address: "127.0.0.1:3000".parse().unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SessionToken {
    pub sub: String,
    pub sid: String,
    pub iat: i64,
    pub exp: i64,
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
        sub: token_checked.claims().sub.clone(),
    })
}

fn set_basic_auth(req: &mut Request<Body>, credentials: &str) {
    let mut header_value: String = "Basic ".to_owned() + credentials;
    if header_value.ends_with("\n") {
        header_value.pop();
    }
    req.headers_mut().insert("Authorization", HeaderValue::from_str(header_value.as_str()).unwrap());
}

async fn handle(client_ip: IpAddr, mut req: Request<Body>, store: Arc<RedisSessionStore>,
                config: Arc<ProxyConfig>, decode_credentials: fn(&str, &str) -> Result<String, AuthProxyError>) -> Result<Response<Body>, Infallible> {
    match get_auth_cookie(&req) {
        Ok(auth_cookie) => {
            let key: Hmac<Sha512> = Hmac::new_from_slice(config.jwt_key.as_bytes()).unwrap();
            match decode_token(auth_cookie.value().to_string(), key) {
                Ok(session_token) => {
                    match store.get(session_token.sid.as_str()).await {
                        Ok(Some(session)) => {
                            match decode_credentials(session.credentials.as_str(), config.credentials_key.as_str()) {
                                Ok(credentials) => {
                                    set_basic_auth(&mut req, credentials.as_str());
                                    match hyper_reverse_proxy::call(client_ip, config.back_uri.as_str(), req).await {
                                        Ok(response) => { Ok(response) }
                                        Err(_error) => {
                                            Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::empty()).unwrap())
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("credentials decode error {} for sid={}", e, session_token.sid);
                                    Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::empty()).unwrap())
                                }
                            }
                        }
                        Ok(None) => {
                            debug!("no session {} found", session_token.sid);
                            Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap())
                        }
                        Err(e) => {
                            debug!("err getting session from redis: {}", e);
                            Ok(Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::empty()).unwrap())
                        }
                    }
                }
                Err(e) => {
                    debug!("cannot decode jwt token: {}", e);
                    Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap())
                }
            }
        }
        Err(e) => {
            debug!("cannot find auth cookie: {}", e);
            Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap())
        }
    }
}

fn identity_fn_credentials(credentials: &str, _key_str: &str) -> Result<String, AuthProxyError> {
    Ok(String::from(credentials))
}

/// Runs the proxy without credential decoder. The string in Redis credential field is used
///  as `Authorization` header
pub async fn run_service(config: ProxyConfig, rx: Receiver<()>) -> impl Future<Output=Result<(), hyper::Error>> {
    run_service_with_decoder(config, rx, identity_fn_credentials).await
}

/// Runs the proxy with a credential decoder function. It should be with the signature :
/// ```rust,no_run
/// use auth_proxy::errors::AuthProxyError;
/// type F = fn(&str, &str) -> Result<String, AuthProxyError>;
/// ```
///
pub async fn run_service_with_decoder(config: ProxyConfig, rx: Receiver<()>, decode_credentials: fn(&str, &str) -> Result<String, AuthProxyError>) -> impl Future<Output=Result<(), hyper::Error>> {
    let cloned_config = config.clone();
    let shared_config = Arc::new(config);
    let shared_store = Arc::new(RedisSessionStore::new(shared_config.redis_uri.to_owned()).unwrap());
    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let config_capture = shared_config.clone();
        let store_capture = shared_store.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle(remote_addr, req, store_capture.clone(), config_capture.clone(), decode_credentials)))
        }
    });
    Server::bind(&cloned_config.address).serve(make_svc).with_graceful_shutdown(async { rx.await.ok(); })
}

#[cfg(test)]
mod test {
    use crate::{ProxyConfig};

    #[test]
    fn build_from_uri() {
        let config = ProxyConfig::from_address("127.0.0.1:12345");
        assert_eq!(config.address, "127.0.0.1:12345".parse().unwrap())
    }
}