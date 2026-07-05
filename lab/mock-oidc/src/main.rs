use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CLIENT_ID: &str = "openbao-lab";
const CLIENT_SECRET: &str = "openbao-lab-secret";
const TEST_SUBJECT: &str = "alice-id";
const TEST_EMAIL: &str = "alice@example.test";

#[derive(Clone)]
struct AppState {
    issuer: String,
    encoding_key: Arc<EncodingKey>,
    modulus: String,
    exponent: String,
    codes: Arc<Mutex<HashMap<String, AuthorizationCode>>>,
}

#[derive(Clone)]
struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    nonce: String,
    code_challenge: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizationQuery {
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
    response_type: String,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
    nonce: &'a str,
    email: &'a str,
    email_verified: bool,
    preferred_username: &'a str,
    groups: [&'a str; 1],
}

#[tokio::main]
async fn main() {
    let address = std::env::var("MOCK_OIDC_ADDR").unwrap_or_else(|_| "127.0.0.1:19090".into());
    let issuer = std::env::var("MOCK_OIDC_ISSUER")
        .unwrap_or_else(|_| format!("http://{address}"))
        .trim_end_matches('/')
        .to_owned();

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("generate test RSA key");
    let public_key = private_key.to_public_key();
    let private_der = private_key.to_pkcs1_der().expect("encode test RSA key");
    let state = AppState {
        issuer,
        encoding_key: Arc::new(EncodingKey::from_rsa_der(private_der.as_bytes())),
        modulus: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
        exponent: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        codes: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/jwks", get(jwks))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("bind mock OIDC listener");
    eprintln!("mock OIDC listening at http://{address} for {TEST_EMAIL}");
    axum::serve(listener, app).await.expect("serve mock OIDC");
}

async fn discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "userinfo_endpoint": format!("{}/userinfo", state.issuer),
        "jwks_uri": format!("{}/jwks", state.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "claims_supported": ["sub", "email", "preferred_username", "groups", "nonce"]
    }))
}

async fn userinfo(headers: HeaderMap) -> impl IntoResponse {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "Bearer lab-access-token");
    if !authorized {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    Json(json!({
        "sub": TEST_SUBJECT,
        "email": TEST_EMAIL,
        "email_verified": true,
        "preferred_username": "alice",
        "groups": ["certificate_users"]
    }))
    .into_response()
}

async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(json!({"keys": [{
        "kty": "RSA", "use": "sig", "kid": "lab-key", "alg": "RS256",
        "n": state.modulus, "e": state.exponent
    }]}))
}

async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizationQuery>,
) -> impl IntoResponse {
    if query.client_id != CLIENT_ID
        || query.response_type != "code"
        || query.code_challenge_method != "S256"
        || !query
            .redirect_uri
            .starts_with("http://127.0.0.1:18200/v1/auth/oidc/oidc/callback")
    {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    }
    let code = uuid::Uuid::new_v4().simple().to_string();
    state.codes.lock().expect("code lock").insert(
        code.clone(),
        AuthorizationCode {
            client_id: query.client_id,
            redirect_uri: query.redirect_uri.clone(),
            nonce: query.nonce,
            code_challenge: query.code_challenge,
        },
    );
    let mut redirect = url::Url::parse(&query.redirect_uri).expect("validated redirect URL");
    redirect
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &query.state);
    Redirect::temporary(redirect.as_str()).into_response()
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> impl IntoResponse {
    let credentials = basic_credentials(&headers).or_else(|| {
        form.client_id
            .clone()
            .zip(form.client_secret.clone())
            .map(|(client_id, secret)| StringPair(client_id, secret))
    });
    if credentials.as_ref().map(StringPair::as_refs) != Some((CLIENT_ID, CLIENT_SECRET))
        || form.grant_type != "authorization_code"
    {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let Some(code) = state.codes.lock().expect("code lock").remove(&form.code) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(form.code_verifier.as_bytes()));
    if code.client_id != CLIENT_ID
        || code.redirect_uri != form.redirect_uri
        || challenge != code.code_challenge
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let claims = IdTokenClaims {
        iss: &state.issuer,
        sub: TEST_SUBJECT,
        aud: CLIENT_ID,
        exp: now + 300,
        iat: now,
        nonce: &code.nonce,
        email: TEST_EMAIL,
        email_verified: true,
        preferred_username: "alice",
        groups: ["certificate_users"],
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("lab-key".into());
    let id_token =
        jsonwebtoken::encode(&header, &claims, &state.encoding_key).expect("sign test ID token");
    Json(json!({
        "access_token": "lab-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token
    }))
    .into_response()
}

struct StringPair(String, String);

impl StringPair {
    fn as_refs(&self) -> (&str, &str) {
        (&self.0, &self.1)
    }
}

fn basic_credentials(headers: &HeaderMap) -> Option<StringPair> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (client_id, secret) = decoded.split_once(':')?;
    Some(StringPair(client_id.into(), secret.into()))
}

fn oauth_error(status: StatusCode, error: &'static str) -> axum::response::Response {
    (status, Json(json!({"error": error}))).into_response()
}
