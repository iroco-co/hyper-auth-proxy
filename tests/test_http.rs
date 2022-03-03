use std::collections::BTreeMap;
use std::net::SocketAddr;
use base64::encode;
use chrono::{Duration, Utc};
use hmac::Hmac;
use tokio::sync::oneshot::Sender;
use hyper::{Body, Client, Method, Request, Uri};
use jwt::{AlgorithmType, SignWithKey, Token};
use jwt::header::PrecomputedAlgorithmOnlyHeader;
use test_context::{AsyncTestContext, test_context};
use tokio::task::JoinHandle;
use auth_proxy::{run_service, SessionToken};
use serial_test::serial;
use sha2::digest::KeyInit;
use sha2::{Sha256, Sha512};

struct ProxyTestContext {
    sender: Sender<()>,
    proxy_handler: JoinHandle<Result<(), hyper::Error>>,
}

#[async_trait::async_trait]
impl AsyncTestContext for ProxyTestContext {
    async fn setup() -> ProxyTestContext {
        let addr: SocketAddr = "127.0.0.1:54321".parse().expect("Could not parse ip:port.");
        let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
        let proxy_handler = tokio::spawn(run_service(addr, receiver).await);
        ProxyTestContext {
            sender,
            proxy_handler
        }
    }
    async fn teardown(self) {
        let _ = self.sender.send(()).unwrap();
        let _ = tokio::join!(self.proxy_handler);
    }
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_without_cookie_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");
    let resp = Client::new().get(proxy_uri).await.unwrap();
    assert_eq!(401, resp.status());
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_without_auth_cookie_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header("foo", "bar")
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(401, resp.status());
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_with_auth_cookie_not_base64_encoded_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header("Authorization", "not_base64")
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(401, resp.status());
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_with_auth_cookie_not_jwt_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header("Authorization", encode("foo:bar"))
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(401, resp.status());
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_with_auth_cookie_with_malformed_jwt_token_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");
    let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("sub", "someone");
    let token_str = claims.sign_with_key(&key).unwrap();

    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header("Authorization", base64::encode(token_str))
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(401, resp.status());
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_with_auth_cookie_with_jwt_token_with_wrong_signature_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");

    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header("Authorization", create_jwt("sid", b"bad secret"))
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(401, resp.status());
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_with_auth_cookie_with_jwt_token_without_redis_session_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");

    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header("Authorization", create_jwt("sid", b"testsecretpourlestests"))
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(401, resp.status());
}

fn create_jwt(sid: &str, secret: &[u8]) -> String {
    let sub = "sub".to_string();
    let sid = sid.to_string();
    let iat = Utc::now().timestamp();
    let exp = Utc::now().checked_add_signed(Duration::seconds(5)).unwrap().timestamp();
    let key: Hmac<Sha512> = Hmac::new_from_slice(secret).unwrap();
    let my_claims = SessionToken { iat, exp, sub, sid };
    let token = Token::new(PrecomputedAlgorithmOnlyHeader(AlgorithmType::Hs512), my_claims);
    let token_str:String = token.sign_with_key(&key).unwrap().into();
    base64::encode(token_str)
}
