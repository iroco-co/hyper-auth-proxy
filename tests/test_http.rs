use std::collections::BTreeMap;

use base64::encode;
use chrono::{Duration, Utc};
use hmac::Hmac;
use hyper::{Body, Client, HeaderMap, Method, Request, StatusCode, Uri};
use jwt::{AlgorithmType, SignWithKey, Token};
use jwt::header::PrecomputedAlgorithmOnlyHeader;
use serial_test::serial;
use sha2::{Sha256, Sha512};
use sha2::digest::KeyInit;
use test_context::{AsyncTestContext, test_context};
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokiotest_httpserver::handler::HandlerBuilder;
use tokiotest_httpserver::HttpTestContext;

use auth_proxy::{ProxyConfig, run_service, SessionToken};
use auth_proxy::redis_session::{RedisSessionStore, Session};


struct ProxyTestContext {
    sender: Sender<()>,
    proxy_handler: JoinHandle<Result<(), hyper::Error>>,
    http_back: HttpTestContext,
    redis: RedisSessionStore
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
        .header("Cookies", "foo:bar")
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
        .header("Cookies", "Authorization=not_base64")
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
        .header("Cookies", format!("Authorization={}", encode("foo:bar")))
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
        .header("Cookies", format!("Authorization={}", encode(token_str)))
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
        .header("Cookies", format!("Authorization={}", create_jwt("sid", b"bad secret")))
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
        .header("Cookies", format!("Authorization={}", create_jwt("sid", b"testsecretpourlestests")))
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(401, resp.status());
}

#[test_context(ProxyTestContext)]
#[tokio::test]
#[serial]
async fn test_get_with_auth_cookie_with_jwt_token_and_redis_session_sends_request_to_back(ctx: &mut ProxyTestContext) {
    let b64credentials = base64::encode("foo:bar").to_string();
    let mut headers = HeaderMap::new();
    headers.append("Authorization", format!("Basic {}", b64credentials).parse().unwrap());
    ctx.http_back.add(HandlerBuilder::new("/back").headers(headers).status_code(StatusCode::OK).build());
    ctx.redis.set("sid", Session { credentials: b64credentials.clone() }).await.unwrap();

    let req = Request::builder()
        .method(Method::GET)
        .uri(Uri::from_static("http://127.0.0.1:54321/back"))
        .header("Cookies", format!("Authorization={}", create_jwt("sid", b"testsecretpourlestests")))
        .body(Body::empty()).unwrap();
    let resp = Client::new().request(req).await.unwrap();
    assert_eq!(200, resp.status());
}


#[async_trait::async_trait]
impl AsyncTestContext for ProxyTestContext {
    async fn setup() -> ProxyTestContext {
        let http_back: HttpTestContext = AsyncTestContext::setup().await;
        let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
        let ProxyConfig { jwt_key, credentials_key, redis_uri: _, back_uri: _, address} = ProxyConfig::from_address("127.0.0.1:54321");
        let redis_uri = "redis://redis/1";
        let config = ProxyConfig { jwt_key, credentials_key, redis_uri: redis_uri.to_string(), back_uri: format!("http://127.0.0.1:{}", http_back.port), address };
        let proxy_handler = tokio::spawn(run_service(config,receiver).await);
        ProxyTestContext {
            sender,
            proxy_handler,
            http_back,
            redis: RedisSessionStore::new(redis_uri).unwrap()
        }
    }
    async fn teardown(self) {
        self.redis.clear_store(&["sid"]).await.unwrap();
        let _ = AsyncTestContext::teardown(self.http_back);
        let _ = self.sender.send(()).unwrap();
        let _ = tokio::join!(self.proxy_handler);
    }
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
