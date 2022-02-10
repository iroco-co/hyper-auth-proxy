mod cookies;
mod redis_session;

use hyper::server::conn::AddrStream;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{service_fn, make_service_fn};
use std::{convert::Infallible, net::SocketAddr};
use std::collections::BTreeMap;
use std::net::IpAddr;
use base64::decode;
use hmac::Hmac;
use jwt::VerifyWithKey;
use sha2::digest::KeyInit;
use sha2::Sha256;
use crate::redis_session::RedisSessionStore;


async fn handle(client_ip: IpAddr, req: Request<Body>, store: RedisSessionStore, key: Hmac<Sha256>) -> Result<Response<Body>, Infallible> {
    if let Some(cookie_header) = req.headers().get("Cookies") {
        if let Ok(cookie_header_str) = cookie_header.to_str() {
            if let Some(auth_cookie) = cookies::find_from_header(cookie_header_str, "Authorization") {
                let token_str_base64 = auth_cookie.value();
                println!("{}", token_str_base64);
                if let Ok(token) = &decode(token_str_base64) {
                    let token_str = String::from_utf8_lossy(token).to_string();
                    println!("{}", token_str);
                    if let Ok(claims) = token_str.verify_with_key(&key) {
                        let c: BTreeMap<String, String> = claims;
                        if let Some(sid) = c.get("sid") {
                            if let Ok(Some(session)) = store.get(String::from(sid)).await {
                                println!("{}", session.credentials);
                                return match hyper_reverse_proxy::call(client_ip, "http://127.0.0.1:13901", req).await {
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
    }
    Ok(Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap())
}

#[tokio::main]
async fn main() {
    let bind_addr = "127.0.0.1:8000";
    let addr: SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
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