//! Management authentication boundary.
//!
//! The first release has one locally configured administrator. The password hash is
//! bootstrapped into SQLite on first start, while sessions remain in memory so a
//! process restart invalidates every browser session.

use argon2::{
        Argon2,
        password_hash::{
                PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
        },
};
use axum::{
        Json,
        body::Body,
        extract::State,
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
        middleware::Next,
        response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use std::{
        collections::HashMap,
        fmt,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
};

use crate::{state::AppState, storage::SqliteRepository};

pub const SESSION_COOKIE_NAME: &str = "routescope_session";
pub const CSRF_COOKIE_NAME: &str = "routescope_csrf";
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
pub const LOGIN_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(15 * 60);
pub const LOGIN_RATE_LIMIT_FAILURES: u32 = 5;

#[derive(Debug)]
pub enum AuthInitError {
        Storage(rusqlite::Error),
        InvalidConfig(&'static str),
        InvalidPasswordHash,
}

impl fmt::Display for AuthInitError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                        Self::Storage(error) => {
                                write!(formatter, "authentication storage error: {error}")
                        }
                        Self::InvalidConfig(message) => {
                                write!(formatter, "invalid authentication config: {message}")
                        }
                        Self::InvalidPasswordHash => {
                                write!(
                                        formatter,
                                        "configured password hash is not a valid Argon2 PHC string"
                                )
                        }
                }
        }
}

impl std::error::Error for AuthInitError {}

impl From<rusqlite::Error> for AuthInitError {
        fn from(error: rusqlite::Error) -> Self {
                Self::Storage(error)
        }
}

#[derive(Clone)]
pub struct AuthService {
        account: Arc<Option<LocalAccount>>,
        sessions: Arc<Mutex<HashMap<[u8; 32], Session>>>,
        login_attempts: Arc<Mutex<HashMap<String, LoginAttempt>>>,
}

#[derive(Clone)]
struct LocalAccount {
        username: String,
        password_hash: String,
}

struct Session {
        csrf_digest: [u8; 32],
        expires_at: Instant,
}

struct LoginAttempt {
        window_started: Instant,
        failures: u32,
}

#[derive(Debug, Clone)]
pub struct SessionCredentials {
        pub session_token: String,
        pub csrf_token: String,
}

impl AuthService {
        /// Loads the persisted account, bootstrapping it from the configured PHC hash once.
        pub fn from_repository(
                repository: Arc<SqliteRepository>,
                configured_username: String,
                configured_password_hash: Option<String>,
        ) -> Result<Self, AuthInitError> {
                validate_username(&configured_username)?;

                let account = if let Some((username, password_hash)) =
                        repository.first_local_account()?
                {
                        validate_username(&username)?;
                        validate_password_hash(&password_hash)?;
                        Some(LocalAccount {
                                username,
                                password_hash,
                        })
                } else if let Some(password_hash) = configured_password_hash {
                        validate_password_hash(&password_hash)?;
                        repository.insert_local_account_if_missing(
                                &configured_username,
                                &password_hash,
                        )?;
                        Some(LocalAccount {
                                username: configured_username,
                                password_hash,
                        })
                } else {
                        None
                };

                Ok(Self::from_account(account))
        }

        /// Creates an in-memory account for unit/integration tests.
        #[cfg(test)]
        pub fn from_password(username: &str, password: &str) -> Result<Self, AuthInitError> {
                validate_username(username)?;
                validate_password(password)?;
                let password_hash = Self::hash_password(password)
                        .map_err(|_| AuthInitError::InvalidPasswordHash)?;
                Ok(Self::from_account(Some(LocalAccount {
                        username: username.to_owned(),
                        password_hash,
                })))
        }

        /// Generates an Argon2id PHC password hash for deployment configuration.
        pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
                let salt = SaltString::generate(&mut OsRng);
                Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .map(|password_hash| password_hash.to_string())
        }

        fn from_account(account: Option<LocalAccount>) -> Self {
                Self {
                        account: Arc::new(account),
                        sessions: Arc::new(Mutex::new(HashMap::new())),
                        login_attempts: Arc::new(Mutex::new(HashMap::new())),
                }
        }

        /// Returns whether a local account is ready to accept logins.
        pub fn is_configured(&self) -> bool {
                self.account.is_some()
        }

        /// Checks the per-source login limiter before doing expensive password work.
        pub fn retry_after_secs(&self, source: &str) -> Option<u64> {
                let now = Instant::now();
                let mut attempts = self
                        .login_attempts
                        .lock()
                        .expect("login attempt mutex poisoned");
                attempts.retain(|_, attempt| {
                        now.duration_since(attempt.window_started) < LOGIN_RATE_LIMIT_WINDOW
                });

                let attempt = attempts.get(source)?;
                if attempt.failures < LOGIN_RATE_LIMIT_FAILURES {
                        return None;
                }

                Some(LOGIN_RATE_LIMIT_WINDOW
                        .saturating_sub(now.duration_since(attempt.window_started))
                        .as_secs()
                        .max(1))
        }

        /// Verifies credentials without mutating the rate limiter.
        pub fn verify_credentials(&self, username: &str, password: &str) -> bool {
                if username.len() > 128 || password.len() > 1_024 {
                        return false;
                }

                let Some(account) = self.account.as_ref() else {
                        return false;
                };
                if username != account.username {
                        return false;
                }

                let Ok(parsed_hash) = PasswordHash::new(&account.password_hash) else {
                        return false;
                };
                Argon2::default()
                        .verify_password(password.as_bytes(), &parsed_hash)
                        .is_ok()
        }

        /// Records a failed login attempt for the source address.
        pub fn record_login_failure(&self, source: &str) {
                let now = Instant::now();
                let mut attempts = self
                        .login_attempts
                        .lock()
                        .expect("login attempt mutex poisoned");
                let attempt = attempts.entry(source.to_owned()).or_insert(LoginAttempt {
                        window_started: now,
                        failures: 0,
                });

                if now.duration_since(attempt.window_started) >= LOGIN_RATE_LIMIT_WINDOW {
                        attempt.window_started = now;
                        attempt.failures = 0;
                }
                attempt.failures = attempt.failures.saturating_add(1);
        }

        /// Clears the source limiter after a successful login.
        pub fn record_login_success(&self, source: &str) {
                self.login_attempts
                        .lock()
                        .expect("login attempt mutex poisoned")
                        .remove(source);
        }

        /// Creates a fresh in-memory session and its CSRF token.
        pub fn create_session(&self) -> SessionCredentials {
                let session_token = generate_token();
                let csrf_token = generate_token();
                let session = Session {
                        csrf_digest: digest(&csrf_token),
                        expires_at: Instant::now() + SESSION_TTL,
                };

                let mut sessions = self.sessions.lock().expect("session mutex poisoned");
                sessions.retain(|_, session| session.expires_at > Instant::now());
                sessions.insert(digest(&session_token), session);

                SessionCredentials {
                        session_token,
                        csrf_token,
                }
        }

        /// Checks whether a session token is present and not expired.
        pub fn is_session_valid(&self, session_token: &str) -> bool {
                let mut sessions = self.sessions.lock().expect("session mutex poisoned");
                let now = Instant::now();
                sessions.retain(|_, session| session.expires_at > now);
                sessions.contains_key(&digest(session_token))
        }

        /// Checks a CSRF token against the session that issued it.
        pub fn is_csrf_valid(&self, session_token: &str, csrf_token: &str) -> bool {
                let mut sessions = self.sessions.lock().expect("session mutex poisoned");
                let now = Instant::now();
                sessions.retain(|_, session| session.expires_at > now);
                let Some(session) = sessions.get(&digest(session_token)) else {
                        return false;
                };
                constant_time_equal(&session.csrf_digest, &digest(csrf_token))
        }

        /// Invalidates a session, including on logout.
        pub fn invalidate_session(&self, session_token: &str) {
                self.sessions
                        .lock()
                        .expect("session mutex poisoned")
                        .remove(&digest(session_token));
        }
}

/// Management route authentication middleware.
pub async fn require_admin(
        State(state): State<AppState>,
        request: Request<Body>,
        next: Next,
) -> Response {
        if state.dev_bypass_auth {
                return next.run(request).await;
        }

        let session_token = cookie_value(request.headers(), SESSION_COOKIE_NAME);
        if session_token
                .as_deref()
                .is_some_and(|token| state.auth.is_session_valid(token))
        {
                return next.run(request).await;
        }

        if request.uri().path().starts_with("/api/") {
                return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({
                            "error": "authentication_required",
                            "message": "A valid management session is required."
                        })),
                )
                        .into_response();
        }

        let mut response = (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, HeaderValue::from_static("/login"))],
        )
                .into_response();
        append_cookie(
                &mut response,
                SESSION_COOKIE_NAME,
                "",
                0,
                true,
                state.secure_cookies,
        );
        response
}

/// Extracts one value from the Cookie request header.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
        headers.get(header::COOKIE)?
                .to_str()
                .ok()?
                .split(';')
                .filter_map(|part| part.trim().split_once('='))
                .find_map(|(cookie_name, value)| {
                        let value = value.trim().trim_matches('"');
                        (cookie_name.trim() == name && is_token_safe(value))
                                .then(|| value.to_owned())
                })
}

/// Validate a CSRF token for a browser form or management API request.
pub(crate) fn csrf_request_is_valid(
        state: &AppState,
        headers: &HeaderMap,
        submitted_token: &str,
) -> bool {
        if submitted_token.is_empty() {
                return false;
        }

        if state.dev_bypass_auth {
                return cookie_value(headers, CSRF_COOKIE_NAME).as_deref() == Some(submitted_token);
        }

        cookie_value(headers, SESSION_COOKIE_NAME)
                .as_deref()
                .is_some_and(|session| state.auth.is_csrf_valid(session, submitted_token))
}

/// Adds a Set-Cookie header with the attributes used by management cookies.
pub(crate) fn append_cookie(
        response: &mut Response,
        name: &str,
        value: &str,
        max_age_secs: i64,
        http_only: bool,
        secure: bool,
) {
        let mut cookie = format!("{name}={value}; Path=/; SameSite=Lax; Max-Age={max_age_secs}");
        if http_only {
                cookie.push_str("; HttpOnly");
        }
        if secure {
                cookie.push_str("; Secure");
        }
        response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie).expect("generated cookie value must be valid"),
        );
}

/// Generates a cryptographically random cookie token.
pub(crate) fn generate_csrf_token() -> String {
        generate_token()
}

fn is_token_safe(value: &str) -> bool {
        !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                })
}

fn generate_token() -> String {
        // SaltString uses PHC's B64 alphabet; make the token URL/form safe before
        // placing it in cookies and hidden form fields.
        SaltString::generate(&mut OsRng)
                .as_str()
                .replace('+', "-")
                .replace('/', "_")
}

fn digest(value: &str) -> [u8; 32] {
        let hash = Sha256::digest(value.as_bytes());
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hash);
        digest
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
        left.iter()
                .zip(right)
                .fold(0u8, |difference, (left, right)| difference | (left ^ right))
                == 0
}

fn validate_username(username: &str) -> Result<(), AuthInitError> {
        if username.is_empty() || username.len() > 128 || username.chars().any(char::is_control) {
                return Err(AuthInitError::InvalidConfig(
                        "administrator username must be 1-128 non-control characters",
                ));
        }
        Ok(())
}

#[cfg(test)]
fn validate_password(password: &str) -> Result<(), AuthInitError> {
        if password.is_empty() || password.len() > 1_024 {
                return Err(AuthInitError::InvalidConfig(
                        "administrator password must be 1-1024 bytes",
                ));
        }
        Ok(())
}

fn validate_password_hash(password_hash: &str) -> Result<(), AuthInitError> {
        PasswordHash::new(password_hash)
                .map(|_| ())
                .map_err(|_| AuthInitError::InvalidPasswordHash)
}

#[cfg(test)]
mod tests {
        use super::*;

        #[test]
        fn password_hash_verifies_and_session_requires_csrf() {
                let auth = AuthService::from_password("admin", "correct horse").unwrap();

                assert!(auth.verify_credentials("admin", "correct horse"));
                assert!(!auth.verify_credentials("admin", "wrong horse"));

                let session = auth.create_session();
                assert!(auth.is_session_valid(&session.session_token));
                assert!(!auth.is_csrf_valid(&session.session_token, "wrong"));
                assert!(auth.is_csrf_valid(&session.session_token, &session.csrf_token));

                auth.invalidate_session(&session.session_token);
                assert!(!auth.is_session_valid(&session.session_token));
        }

        #[test]
        fn failed_logins_are_limited_per_source() {
                let auth = AuthService::from_password("admin", "secret").unwrap();

                for _ in 0..LOGIN_RATE_LIMIT_FAILURES {
                        auth.record_login_failure("192.0.2.10");
                }

                assert!(auth.retry_after_secs("192.0.2.10").is_some());
                assert!(auth.retry_after_secs("192.0.2.11").is_none());
                auth.record_login_success("192.0.2.10");
                assert!(auth.retry_after_secs("192.0.2.10").is_none());
        }

        #[test]
        fn repository_bootstraps_only_when_no_account_exists() {
                let repository = Arc::new(SqliteRepository::open_in_memory().unwrap());
                let first_hash = AuthService::hash_password("first password").unwrap();
                let auth = AuthService::from_repository(
                        Arc::clone(&repository),
                        "admin".to_owned(),
                        Some(first_hash),
                )
                .unwrap();
                assert!(auth.verify_credentials("admin", "first password"));

                let replacement_hash = AuthService::hash_password("replacement password").unwrap();
                let auth = AuthService::from_repository(
                        repository,
                        "admin".to_owned(),
                        Some(replacement_hash),
                )
                .unwrap();
                assert!(auth.verify_credentials("admin", "first password"));
                assert!(!auth.verify_credentials("admin", "replacement password"));
        }
}
