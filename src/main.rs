use axum::{Router, response::Html, routing::get};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // routes
    let app = Router::new().route("/", get(home_handler));

    // run app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// handler for the home page
async fn home_handler() -> Html<&'static str> {
    Html("<h1>Hello Axum!</h1><p>Our server is running!</p>")
}
