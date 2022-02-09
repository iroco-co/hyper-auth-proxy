use hyper::server::conn::AddrStream;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{service_fn, make_service_fn};
use std::{convert::Infallible, net::SocketAddr};
use std::net::IpAddr;

async fn handle(client_ip: IpAddr, req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match hyper_reverse_proxy::call(client_ip, "http://127.0.0.1:13901", req).await {
        Ok(response) => {Ok(response)}
        Err(_error) => {Ok(Response::builder()
                              .status(StatusCode::INTERNAL_SERVER_ERROR)
                              .body(Body::empty())
                              .unwrap())}
    }
}

#[tokio::main]
async fn main() {
    let bind_addr = "127.0.0.1:8000";
    let addr:SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle(remote_addr, req)))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Running server on {:?}", addr);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}