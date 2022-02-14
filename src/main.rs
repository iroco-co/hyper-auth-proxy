use std::{convert::Infallible, net::SocketAddr};
use std::net::IpAddr;

use base64::decode;
use hmac::Hmac;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use jwt::{Header, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha2::digest::KeyInit;

use crate::redis_session::RedisSessionStore;

mod cookies;
mod redis_session;

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

#[tokio::main]
async fn main() {
    let bind_addr = "127.0.0.1:8000";
    let addr: SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let key: Hmac<Sha512> = Hmac::new_from_slice(b"testsecretpourlestests").unwrap();
        let store = RedisSessionStore::new("redis://redis").unwrap();
        let remote_addr = conn.remote_addr().ip();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle(remote_addr, req, store.clone(), key.clone())))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Running server on {:?}", addr);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}