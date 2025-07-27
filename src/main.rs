use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use chrono;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer, cookie::time::Duration};

// Helper function to hash passwords
fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

// Helper function to verify passwords
fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

// Helper function to get current user from session
async fn get_current_user(session: &Session, state: &AppState) -> Option<User> {
    if let Ok(Some(user_session)) = session.get::<UserSession>("user").await {
        let users = state.users.read().await;
        users
            .values()
            .find(|u| u.id == user_session.user_id)
            .cloned()
    } else {
        None
    }
}

// User data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: u32,
    username: String,
    password_hash: String,
    created_at: String,
}

// Application state that will be shared across handlers
#[derive(Clone)]
struct AppState {
    users: Arc<RwLock<HashMap<String, User>>>, // username -> User
    next_user_id: Arc<RwLock<u32>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            next_user_id: Arc::new(RwLock::new(1)),
        }
    }
}

// Session data structure
#[derive(Debug, Serialize, Deserialize)]
struct UserSession {
    user_id: u32,
    username: String,
    login_time: String,
}

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
    // Create application state
    let app_state = AppState::new();

    // Set up session store (in-memory for this demo)
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // set to true in prod for https
        .with_expiry(Expiry::OnInactivity(Duration::seconds(3600))); // 1 hour

    // Build our application with routes
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_page).post(login_handler))
        .route("/signup", get(signup_page).post(signup_handler))
        .route("/dashboard", get(dashboard_handler))
        .route("/logout", get(logout_handler))
        .layer(session_layer) // Add session middleware
        .with_state(app_state); // Add application state

    // Run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Handler for the home page
async fn home_handler(session: Session, State(state): State<AppState>) -> impl IntoResponse {
    let (logged_in, username) = if let Some(user) = get_current_user(&session, &state).await {
        (true, user.username)
    } else {
        (false, String::new())
    };

    let template = HomeTemplate {
        logged_in,
        username,
    };
    Html(template.render().unwrap())
}

// Show login page
async fn login_page(session: Session, State(state): State<AppState>) -> impl IntoResponse {
    // Redirect if already logged in
    if get_current_user(&session, &state).await.is_some() {
        return Redirect::to("/dashboard").into_response();
    }

    let template = LoginTemplate {
        logged_in: false,
        error: String::new(),
    };
    Html(template.render().unwrap()).into_response()
}

// Handle login form submission
async fn login_handler(
    session: Session,
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    println!("Login attempt: username={}", form.username);

    // Check if user exists and password is correct
    let users = state.users.read().await;
    if let Some(user) = users.get(&form.username) {
        match verify_password(&form.password, &user.password_hash) {
            Ok(true) => {
                // Password is correct, create session
                let user_session = UserSession {
                    user_id: user.id,
                    username: user.username.clone(),
                    login_time: chrono::Utc::now()
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string(),
                };

                if let Err(e) = session.insert("user", user_session).await {
                    eprintln!("Failed to create session: {}", e);
                    let template = LoginTemplate {
                        logged_in: false,
                        error: "Login failed. Please try again".to_string(),
                    };

                    return Html(template.render().unwrap()).into_response();
                }

                // Redirect to dashboard
                return Redirect::to("/dashboard").into_response();
            }
            Ok(false) => {
                // Invalid password
                let template = LoginTemplate {
                    logged_in: false,
                    error: "Invalid username or password".to_string(),
                };
                return Html(template.render().unwrap()).into_response();
            }
            Err(e) => {
                eprintln!("Password verification error: {}", e);
                let template = LoginTemplate {
                    logged_in: false,
                    error: "Login failed. Please try again".to_string(),
                };
                return Html(template.render().unwrap()).into_response();
            }
        }
    } else {
        // User doesn't exist
        let template = LoginTemplate {
            logged_in: false,
            error: "Login failed. Please try again.".to_string(),
        };
        return Html(template.render().unwrap()).into_response();
    }
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
async fn signup_handler(
    session: Session,
    State(state): State<AppState>,
    Form(form): Form<SignupForm>,
) -> impl IntoResponse {
    println!("Signup attempt: username={}", form.username);

    // Validate form data
    if form.username.len() < 3 || form.username.len() > 20 {
        let template = SignupTemplate {
            logged_in: false,
            error: "Username must be between 3 and 20 characters.".to_string(),
        };
        return Html(template.render().unwrap()).into_response();
    }

    if form.password.len() < 6 {
        let template = SignupTemplate {
            logged_in: false,
            error: "Password must be at least 6 characters".to_string(),
        };
        return Html(template.render().unwrap()).into_response();
    }

    if form.password != form.confirm_password {
        let template = SignupTemplate {
            logged_in: false,
            error: "Passwords do not match".to_string(),
        };
        return Html(template.render().unwrap()).into_response();
    }

    // Check if username already exists
    {
        let users = state.users.read().await;
        if users.contains_key(&form.username) {
            let template = SignupTemplate {
                logged_in: false,
                error: "Username already exists".to_string(),
            };
            return Html(template.render().unwrap()).into_response();
        }
    }

    // Hash password
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Password hashing error: {}", e);
            let template = SignupTemplate {
                logged_in: false,
                error: "Registration failed. Please try again.".to_string(),
            };
            return Html(template.render().unwrap()).into_response();
        }
    };

    // Create new user
    let user_id = {
        let mut next_id = state.next_user_id.write().await;
        let id = *next_id;
        *next_id += 1;
        id
    };

    let user = User {
        id: user_id,
        username: form.username.clone(),
        password_hash,
        created_at: chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
    };

    // Store user
    {
        let mut users = state.users.write().await;
        users.insert(form.username.clone(), user.clone());
    }

    // Create session for the new user
    let user_session = UserSession {
        user_id: user.id,
        username: user.username.clone(),
        login_time: chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
    };

    if let Err(e) = session.insert("user", user_session).await {
        eprintln!("Failed to create session: {}", e);
        let template = SignupTemplate {
            logged_in: false,
            error: "Registration successful but login failed. Please try logging in.".to_string(),
        };
        return Html(template.render().unwrap()).into_response();
    }

    // Redirect to dashboard
    Redirect::to("/dashboard").into_response()
}

// Protected dashboard page
async fn dashboard_handler(session: Session, State(state): State<AppState>) -> impl IntoResponse {
    // Check if user is logged in
    if let Some(user) = get_current_user(&session, &state).await {
        if let Ok(Some(user_session)) = session.get::<UserSession>("user").await {
            let template = DashboardTemplate {
                logged_in: true,
                username: user.username,
                user_id: user.id,
                login_time: user_session.login_time,
            };
            Html(template.render().unwrap()).into_response()
        } else {
            // Session exists but couldn't get session data
            Redirect::to("/login").into_response()
        }
    } else {
        // Not logged in, redirect to login
        Redirect::to("/login").into_response()
    }
}

// Handle logout
async fn logout_handler(session: Session) -> impl IntoResponse {
    // Clear session
    if let Err(e) = session.delete().await {
        eprintln!("Failed to delete session: {}", e);
    }
    Redirect::to("/")
}

// Helper function to create the app (for testing)
fn create_app() -> Router {
    let app_state = AppState::new();

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(3600)));

    Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_page).post(login_handler))
        .route("/signup", get(signup_page).post(signup_handler))
        .route("/dashboard", get(dashboard_handler))
        .route("/logout", get(logout_handler))
        .layer(session_layer)
        .with_state(app_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use http::StatusCode;

    // Helper function to create a test server
    fn test_server() -> TestServer {
        TestServer::new(create_app()).unwrap()
    }

    #[tokio::test]
    async fn test_signup_page_loads() {
        let server = test_server();

        let response = server.get("/signup").await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let text = response.text();
        assert!(text.contains("Sign Up"));
        assert!(text.contains("Username:"));
        assert!(text.contains("Password:"));
        assert!(text.contains("Confirm Password:"));
    }

    #[tokio::test]
    async fn test_login_page_loads() {
        let server = test_server();

        let response = server.get("/login").await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let text = response.text();
        assert!(text.contains("Login"));
        assert!(text.contains("Username:"));
        assert!(text.contains("Password:"));
    }

    #[tokio::test]
    async fn test_dashboard_redirects_when_not_logged_in() {
        let server = test_server();

        let response = server.get("/dashboard").await;

        // Should redirect to login
        assert_eq!(response.status_code(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], "/login");
    }

    #[tokio::test]
    async fn test_successful_signup() {
        let server = test_server();

        let form_data = [
            ("username", "testuser"),
            ("password", "password123"),
            ("confirm_password", "password123"),
        ];

        let response = server.post("/signup").form(&form_data).await;

        // Should redirect to dashboard after successful signup
        assert_eq!(response.status_code(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], "/dashboard");
    }

    #[tokio::test]
    async fn test_signup_validation_short_username() {
        let server = test_server();

        let form_data = [
            ("username", "ab"), // Too short
            ("password", "password123"),
            ("confirm_password", "password123"),
        ];

        let response = server.post("/signup").form(&form_data).await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let text = response.text();
        assert!(text.contains("Username must be between 3 and 20 characters"));
    }

    #[tokio::test]
    async fn test_signup_validation_short_password() {
        let server = test_server();

        let form_data = [
            ("username", "testuser"),
            ("password", "123"), // Too short
            ("confirm_password", "123"),
        ];

        let response = server.post("/signup").form(&form_data).await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let text = response.text();
        assert!(text.contains("Password must be at least 6 characters"));
    }

    #[tokio::test]
    async fn test_signup_validation_password_mismatch() {
        let server = test_server();

        let form_data = [
            ("username", "testuser"),
            ("password", "password123"),
            ("confirm_password", "different456"),
        ];

        let response = server.post("/signup").form(&form_data).await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let text = response.text();
        assert!(text.contains("Passwords do not match"));
    }

    #[tokio::test]
    async fn test_login_with_existing_user() {
        let server = test_server();

        // First create a user
        let signup_form = [
            ("username", "logintest"),
            ("password", "password123"),
            ("confirm_password", "password123"),
        ];

        server.post("/signup").form(&signup_form).await;

        // Now try to login with the same credentials
        let login_form = [("username", "logintest"), ("password", "password123")];

        let login_response = server.post("/login").form(&login_form).await;

        // Should redirect to dashboard
        assert_eq!(login_response.status_code(), StatusCode::SEE_OTHER);
        assert_eq!(login_response.headers()["location"], "/dashboard");
    }

    #[tokio::test]
    async fn test_login_with_wrong_password() {
        let server = test_server();

        // First create a user
        let signup_form = [
            ("username", "wrongpasstest"),
            ("password", "password123"),
            ("confirm_password", "password123"),
        ];

        server.post("/signup").form(&signup_form).await;

        // Try to login with wrong password
        let login_form = [("username", "wrongpasstest"), ("password", "wrongpassword")];

        let login_response = server.post("/login").form(&login_form).await;

        assert_eq!(login_response.status_code(), StatusCode::OK);
        let text = login_response.text();
        assert!(text.contains("Invalid username or password"));
    }

    #[tokio::test]
    async fn test_duplicate_username_signup() {
        let server = test_server();

        // Create first user
        let form_data = [
            ("username", "duplicate"),
            ("password", "password123"),
            ("confirm_password", "password123"),
        ];

        let first_signup = server.post("/signup").form(&form_data).await;

        assert_eq!(first_signup.status_code(), StatusCode::SEE_OTHER);

        // Try to create second user with same username
        let second_signup = server.post("/signup").form(&form_data).await;

        assert_eq!(second_signup.status_code(), StatusCode::OK);
        let text = second_signup.text();
        assert!(text.contains("Username already exists"));
    }

    // Test helper functions
    #[tokio::test]
    async fn test_password_hashing() {
        let password = "test_password_123";

        // Hash the password
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Same password should produce different hashes (due to salt)
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());

        // Wrong password should not verify
        assert!(!verify_password("wrong_password", &hash1).unwrap());
    }
}
