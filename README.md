# hyper-auth-proxy [![CircleCI](https://circleci.com/gh/iroco-co/hyper-auth-proxy/tree/main.svg?style=svg&circle-token=d38df9072668f34203a01f0cc07763d7ca025db5)](https://circleci.com/gh/iroco-co/hyper-auth-proxy/tree/main)

A proxy to do http basic auth from a JWT token and redis session credentials


![schema](doc/auth_token.drawio.png)

## usage

 Little auth proxy based on [hyper-reverse-proxy](https://github.com/felipenoris/hyper-reverse-proxy)
 that can be used to add Basic auth header for a backend service
 without having to send credentials base64 encoded on the web.

 It will use JWK token key `sid` field to seek for the credentials in a Redis instance. The JWT token is read from `Authorization`
cookie. The credentials are stored in json :

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
 use hyper_auth_proxy::{run_service, ProxyConfig};

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

## logging && debugging

It uses log API so [for example](example/main_with_config.rs) with [env_logger](https://docs.rs/env_logger) it can be launched with 

```shell
$ RUST_LOG=debug hyper-auth-proxy
```

And you should have logs like : 

```shell
[2022-03-16T12:51:26Z INFO  my_auth_proxy] Running auth proxy on 127.0.0.1:3000 with backend "http://backend"
[2022-03-16T12:51:33Z DEBUG hyper_auth_proxy] cannot find auth cookie: no cookies header
[2022-03-16T12:53:21Z DEBUG hyper_auth_proxy] cannot find auth cookie: no auth cookie
[2022-03-16T12:53:35Z DEBUG hyper_auth_proxy] cannot decode jwt token: cannot decode jwt token (No claims component found in token string)
```