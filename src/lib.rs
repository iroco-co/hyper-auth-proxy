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
mod redis_session;

use crate::redis_session::RedisSessionStore;

static DOUBLE_QUOTES: &str = "\"";

#[derive(Serialize, Deserialize)]
pub struct SessionToken {
    pub sub: String,
    pub sid: String,
    pub iat: i64,
    pub exp: i64
}

async fn handle(client_ip: IpAddr, req: Request<Body>, store: RedisSessionStore, key: Hmac<Sha512>) -> Result<Response<Body>, Infallible> {
    if let Some(cookie_header) = req.headers().get("Cookies") {
        if let Ok(cookie_header_str) = cookie_header.to_str() {
            if let Some(auth_cookie) = cookies::find_from_header(cookie_header_str, "Authorization") {
                let token_str_base64 = auth_cookie.value();
                if let Ok(token) = &decode(token_str_base64) {
                    let token_str = String::from_utf8_lossy(token).to_string();
                    let stripped = token_str.strip_prefix(DOUBLE_QUOTES).unwrap().strip_suffix(DOUBLE_QUOTES).unwrap();
                    let token: Token<Header, SessionToken, _> = VerifyWithKey::verify_with_key(stripped, &key).unwrap();
                    if let Ok(Some(session)) = store.get(token.claims().sid.to_string()).await {
                        println!("{}", session.credentials);
                        return match hyper_reverse_proxy::call(client_ip, "http://127.0.0.1:5000", req).await {
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
    Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap())
}

pub async fn run_service(addr: SocketAddr, rx: Receiver<()>) -> impl Future<Output = Result<(), hyper::Error>> {
    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let key: Hmac<Sha512> = Hmac::new_from_slice(b"testsecretpourlestests").unwrap();
        let store = RedisSessionStore::new("redis://redis").unwrap();
        let remote_addr = conn.remote_addr().ip();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle(remote_addr, req, store.clone(), key.clone())))
        }
    });

    Server::bind(&addr).serve(make_svc).with_graceful_shutdown(async {rx.await.ok();})
}