use askama::Template;
use axum::{
    Router,
    extract::Form,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use serde::Deserialize;
use std::net::SocketAddr;

// Template structs - these match our HTML templates
#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate {
    logged_in: bool,
    username: String,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    logged_in: bool,
    error: String,
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupTemplate {
    logged_in: bool,
    error: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    logged_in: bool,
    username: String,
    user_id: u32,
    login_time: String,
}

// Form data structures
#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct SignupForm {
    username: String,
    password: String,
    confirm_password: String,
}

#[tokio::main]
async fn main() {
    // Build our application with routes
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_page).post(login_handler))
        .route("/signup", get(signup_page).post(signup_handler))
        .route("/dashboard", get(dashboard_handler))
        .route("/logout", get(logout_handler));

    // Run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Handler for the home page
async fn home_handler() -> impl IntoResponse {
    let template = HomeTemplate {
        logged_in: false,        // We'll implement session checking later
        username: String::new(), // Empty string instead of None
    };
    Html(template.render().unwrap())
}

// Show login page
async fn login_page() -> impl IntoResponse {
    let template = LoginTemplate {
        logged_in: false,
        error: String::new(),
    };
    Html(template.render().unwrap())
}

// Handle login form submission
async fn login_handler(Form(form): Form<LoginForm>) -> impl IntoResponse {
    // TODO: Implement actual authentication
    println!("Login attempt: username={}", form.username);

    // For now, just show error
    let template = LoginTemplate {
        logged_in: false,
        error: "Authentication not implemented yet".to_string(),
    };
    Html(template.render().unwrap())
}

// Show signup page
async fn signup_page() -> impl IntoResponse {
    let template = SignupTemplate {
        logged_in: false,
        error: String::new(),
    };
    Html(template.render().unwrap())
}

// Handle signup form submission
async fn signup_handler(Form(form): Form<SignupForm>) -> impl IntoResponse {
    // TODO: Implement user registration
    println!("Signup attempt: username={}", form.username);

    let template = SignupTemplate {
        logged_in: false,
        error: "Registration not implemented yet".to_string(),
    };
    Html(template.render().unwrap())
}

// Protected dashboard page
async fn dashboard_handler() -> impl IntoResponse {
    // TODO: Check if user is logged in
    let template = DashboardTemplate {
        logged_in: true,
        username: "demo_user".to_string(),
        user_id: 1,
        login_time: "Just now".to_string(),
    };
    Html(template.render().unwrap())
}

// Handle logout
async fn logout_handler() -> impl IntoResponse {
    // TODO: Clear session
    Redirect::to("/")
}
