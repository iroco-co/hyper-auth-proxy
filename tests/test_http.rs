use std::net::SocketAddr;
use tokio::sync::oneshot::Sender;
use hyper::{Client, Uri};
use test_context::{AsyncTestContext, test_context};
use tokio::task::JoinHandle;
use auth_proxy::run_service;
use serial_test::serial;

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
async fn test_get_without_credentials_returns_401(proxy: &mut ProxyTestContext) {
    let proxy_uri = Uri::from_static("http://127.0.0.1:54321");
    let resp = Client::new().get(proxy_uri).await.unwrap();
    assert_eq!(401, resp.status());
}
