# Axum Session Server

A demonstration project for session-based authentication using [Axum](https://github.com/tokio-rs/axum), Rust’s ergonomic web framework. This project showcases secure user registration, login, session management, and protected routes using in-memory storage and modern password hashing.

---

## Features

- 🔐 **User Registration & Login**
  Secure signup and login forms with validation.

- 🍪 **Session-Based Authentication**
  Uses cookies and `tower-sessions` for session management.

- 🔒 **Protected Routes**
  Dashboard and other pages require authentication.

- 🛡️ **Password Hashing**
  Passwords are hashed using Argon2 for security.

- 🧩 **Templated HTML**
  Uses [Askama](https://github.com/askama-rs/askama) for compile-time HTML templates.

---

## Flow Graph

```mermaid
graph TD
    A[Home Page] -->|Signup| B(Signup Page)
    A -->|Login| C(Login Page)
    B -->|Submit Valid Form| D{Username Exists?}
    D -- Yes --> B
    D -- No --> E[Create User & Session]
    E --> F[Redirect to Dashboard]
    C -->|Submit Valid Form| G{Credentials Valid?}
    G -- No --> C
    G -- Yes --> H[Create Session]
    H --> F
    F --> I[Dashboard (Protected)]
    I -->|Logout| J[Clear Session]
    J --> A
    A --> I
```

---

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (edition 2021+)
- [cargo](https://doc.rust-lang.org/cargo/)

### Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/sebastianiv21/axum-session-server.git
    cd axum-session-server
    ```

2. **Install dependencies:**
    ```sh
    cargo build
    ```

3. **Run the server:**
    ```sh
    cargo run
    ```

4. **Visit in your browser:**
   [http://localhost:3000](http://localhost:3000)

---

## Project Structure

```
axum-session-server/
├── src/
│   └── main.rs           # Main application logic
├── templates/            # Askama HTML templates
│   ├── base.html
│   ├── home.html
│   ├── login.html
│   ├── signup.html
│   └── dashboard.html
├── Cargo.toml            # Rust dependencies
└── README.md
```

---

## How It Works

- **Home Page:**
  Offers links to login or signup. If logged in, shows username and dashboard link.

- **Signup:**
  Validates username and password, checks for duplicates, hashes password, creates user and session, redirects to dashboard.

- **Login:**
  Validates credentials, creates session, redirects to dashboard.

- **Dashboard:**
  Protected route. Only accessible if logged in. Shows user info and session details.

- **Logout:**
  Clears session and redirects to home.

---

## Security Notes

- **Session Storage:**
  Uses in-memory storage for demonstration. For production, use a persistent store (Redis, database, etc).

- **HTTPS:**
  The demo disables secure cookies for local testing. Enable `.with_secure(true)` in production.

- **Password Hashing:**
  Uses Argon2 for strong password security.
