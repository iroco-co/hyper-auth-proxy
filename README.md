# hyper-auth-proxy [![CircleCI](https://circleci.com/gh/iroco-co/hyper-auth-proxy/tree/main.svg?style=svg&circle-token=d38df9072668f34203a01f0cc07763d7ca025db5)](https://circleci.com/gh/iroco-co/auth-proxy/tree/main)

A proxy to do http basic auth from a JWT token and redis session credentials


![schema](doc/auth_token.drawio.png)


 Little auth proxy based on [hyper-reverse-proxy](https://github.com/felipenoris/hyper-reverse-proxy)
 that can be used to add Basic auth header for a backend service
 without having to send credentials base64 encoded on the web.

 It will use JWK token key `sid` field to seek for the credentials in a Redis instance.
 The credentials are stored in json :

 ```json
 { "credentials": "dXNlcjp0ZXN0" }
 ```

 They can be used "as is" or the credentials can be encoded (for example with AES).

 Without encoded credentials, the proxy will make a request with `Authorization` header :
 ```bash
 Authorization: Basic dXNlcjp0ZXN0
 ```
 The main should contain a tokio main section and call the run_service function.

 Example :
 ```rust,no_run
 use auth_proxy::run_service;
 use auth_proxy::ProxyConfig;

 #[tokio::main]
 async fn main() {
     let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
     let config = ProxyConfig::default();
     let server = run_service(config.clone(), rx).await;
     println!("Running auth proxy on {:?} with backend {:?}", config.address, config.back_uri);
     if let Err(e) = server.await {
         eprintln!("server error: {}", e);
     }
 }

 ```

 The proxy configuration contains the following parameters :
 ```rust,no_run
  use std::net::SocketAddr;
  struct ProxyConfig {
     pub jwt_key: String,
     pub credentials_key: String,
     pub back_uri: String,
     pub redis_uri: String,
     pub address: SocketAddr,
 }
 ```