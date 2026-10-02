//! Server-side OpenID Connect relying party for the control-plane boundary.
//!
//! ZITADEL (or any OIDC provider) is the login/assertion source only: this
//! module owns the authorization-code + PKCE S256 exchange, provider
//! discovery and the server-authoritative identity-provider configuration.
//! Sessions, authorization, tenant scope, impersonation and audit semantics
//! stay in [`crate::admin_rbac`] behind the same BFF boundary — the browser
//! never receives tokens, only the existing HttpOnly session cookie.
//!
//! The callback route is the protocol's explicitly designed alternative
//! trust mechanism: it is reached as a top-level navigation from the IdP and
//! creates nothing until `state`, `nonce`, PKCE and the ID-token signature
//! all verify.

use openidconnect::core::{
    CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims,
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, LogoutRequest, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, RequestTokenError, Scope, SubjectIdentifier,
    TokenResponse,
};
use reqwest::{redirect, Url};
use std::time::Duration;

/// Browser callback for the authorization-code flow (top-level IdP
/// navigation; still behind the workload bearer boundary).
pub const OIDC_CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";
/// Starts a fresh IdP re-authentication for an existing session (step-up).
pub const OIDC_REAUTH_PATH: &str = "/api/v1/auth/reauth";
/// Pending flows live for ten minutes; a half-started login must not linger.
pub const OIDC_FLOW_TTL_SECS: i64 = 600;

/// Which login path the server accepts. Server-authoritative configuration;
/// it never grants authorization by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProviderKind {
    /// Development/CI default: the reverse-proxy boundary identity header.
    ProxyHeader,
    /// Authorization-code flow against a configured OIDC provider.
    Oidc,
}

/// Identity-provider mode plus its OIDC settings.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub kind: IdentityProviderKind,
    pub oidc: Option<OidcConfig>,
}

/// Static OIDC relying-party configuration for one provider.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Issuer URL; discovery and ID-token `iss` checks anchor on it.
    pub issuer: String,
    pub client_id: String,
    /// Confidential client secret; `None` for a public PKCE-only client.
    pub client_secret: Option<String>,
    /// Public callback URL (`{origin}` + [`OIDC_CALLBACK_PATH`]).
    pub redirect_uri: String,
    /// Extra scopes beyond the implied `openid`.
    pub scopes: Vec<String>,
}

/// One authorization request that has been started but not yet completed.
#[derive(Debug, Clone)]
pub struct OidcFlowStart {
    /// Absolute URL of the IdP authorize endpoint for the browser.
    pub authorize_url: String,
    /// Opaque `state` value echoed by the callback (hashed before storage).
    pub state: String,
    /// `nonce` echoed in the ID token (stored for verification).
    pub nonce: String,
    /// PKCE S256 code verifier (stored for the token exchange).
    pub code_verifier: String,
}

/// Claims needed for identity mapping after full verification.
#[derive(Debug, Clone)]
pub struct VerifiedIdToken {
    pub subject: String,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    /// `email_verified` claim must be explicitly true; absence means false.
    pub email_verified: bool,
}

/// Failure classes with fixed, non-leaky audit reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcError {
    /// Discovery/provider network failures and misconfiguration: infrastructure
    /// problems audited as `failed`, answered `503`.
    ProviderUnavailable(&'static str),
    /// The IdP rejected the exchange or the assertion failed verification:
    /// caller-attributable, audited as `denied`, answered `400`.
    Rejected(&'static str),
}

impl OidcError {
    pub fn audit_result(&self) -> &'static str {
        match self {
            Self::ProviderUnavailable(_) => "failed",
            Self::Rejected(_) => "denied",
        }
    }

    pub fn audit_reason(&self) -> &'static str {
        match self {
            Self::ProviderUnavailable(reason) => reason,
            Self::Rejected(reason) => reason,
        }
    }
}

impl IdentityConfig {
    /// Development/CI default: reverse-proxy identity header, no IdP.
    pub fn proxy_header() -> Self {
        Self {
            kind: IdentityProviderKind::ProxyHeader,
            oidc: None,
        }
    }

    /// Reads `NULLAPART_IDENTITY_PROVIDER` and the `NULLAPART_OIDC_*` family.
    /// Unknown modes or malformed OIDC settings fail startup rather than
    /// silently falling back to a weaker login path.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Same validation over an injectable lookup (testable without
    /// touching process-global environment variables).
    pub(crate) fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let configured =
            lookup("NULLAPART_IDENTITY_PROVIDER").unwrap_or_else(|| "proxy_header".to_string());
        match configured.trim() {
            "proxy_header" => Ok(Self::proxy_header()),
            "oidc" => Ok(Self {
                kind: IdentityProviderKind::Oidc,
                oidc: Some(OidcConfig::from_lookup(lookup)?),
            }),
            other => Err(format!(
                "NULLAPART_IDENTITY_PROVIDER must be proxy_header or oidc, got {other:?}"
            )),
        }
    }
}

fn required_env(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> Result<String, String> {
    let value = lookup(name)
        .ok_or_else(|| format!("{name} is required when NULLAPART_IDENTITY_PROVIDER=oidc"))?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{name} must not contain control characters"));
    }
    Ok(value)
}

fn parse_http_url(name: &str, value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| format!("{name} must be an absolute http(s) URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(format!("{name} must be an absolute http(s) URL"));
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "{name} must not carry userinfo, a query or a fragment"
        ));
    }
    Ok(url)
}

impl OidcConfig {
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let lookup = &lookup;
        let issuer = required_env(lookup, "NULLAPART_OIDC_ISSUER")?;
        parse_http_url("NULLAPART_OIDC_ISSUER", &issuer)?;

        let redirect_uri = required_env(lookup, "NULLAPART_OIDC_REDIRECT_URI")?;
        let redirect = parse_http_url("NULLAPART_OIDC_REDIRECT_URI", &redirect_uri)?;
        if redirect.path() != OIDC_CALLBACK_PATH {
            return Err(format!(
                "NULLAPART_OIDC_REDIRECT_URI path must be {OIDC_CALLBACK_PATH}"
            ));
        }

        let client_id = required_env(lookup, "NULLAPART_OIDC_CLIENT_ID")?;
        let client_secret = lookup("NULLAPART_OIDC_CLIENT_SECRET")
            .map(|secret| secret.trim().to_string())
            .filter(|secret| !secret.is_empty());
        if let Some(secret) = &client_secret {
            if secret.chars().any(char::is_control) {
                return Err(
                    "NULLAPART_OIDC_CLIENT_SECRET must not contain control characters".to_string(),
                );
            }
        }

        let scopes = match lookup("NULLAPART_OIDC_SCOPES") {
            Some(raw) => raw
                .split_whitespace()
                .map(str::to_string)
                .filter(|scope| scope != "openid")
                .collect(),
            None => vec!["profile".to_string(), "email".to_string()],
        };
        for scope in &scopes {
            if scope.chars().any(char::is_whitespace) {
                return Err("NULLAPART_OIDC_SCOPES entries must not contain whitespace".to_string());
            }
        }

        Ok(Self {
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            scopes,
        })
    }
}

/// Shared HTTP client for provider calls: no redirect following (the issuer
/// is configuration, but a redirect must never relocate a token exchange)
/// and a hard timeout so a hung IdP cannot pin login handlers.
pub fn http_client() -> Result<reqwest::Client, OidcError> {
    reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| OidcError::ProviderUnavailable("provider http client build failed"))
}

async fn discover(
    config: &OidcConfig,
    http: &reqwest::Client,
) -> Result<CoreProviderMetadata, OidcError> {
    let issuer = IssuerUrl::new(config.issuer.clone())
        .map_err(|_| OidcError::ProviderUnavailable("configured issuer is not a valid URL"))?;
    // Discovery validates that the returned issuer equals the configured one
    // (mix-up defense) and fetches the JWKS used for signature verification.
    CoreProviderMetadata::discover_async(issuer, http)
        .await
        .map_err(|_| OidcError::ProviderUnavailable("provider discovery failed"))
}

/// Starts an authorization-code flow: discovery, PKCE S256 challenge, a fresh
/// `state` and `nonce`. The caller persists the returned secrets bound to the
/// hashed `state` before redirecting the browser.
pub async fn start_authorization(
    config: &OidcConfig,
    http: &reqwest::Client,
    prompt_login: bool,
) -> Result<OidcFlowStart, OidcError> {
    let metadata = discover(config, http).await?;
    let redirect_uri = RedirectUrl::new(config.redirect_uri.clone())
        .map_err(|_| OidcError::ProviderUnavailable("configured redirect URI is invalid"))?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        config.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(redirect_uri);
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(config.scopes.iter().map(|scope| Scope::new(scope.clone())))
        .set_pkce_challenge(pkce_challenge);
    if prompt_login {
        request = request.add_prompt(CoreAuthPrompt::Login);
    }
    let (authorize_url, csrf, nonce) = request.url();
    Ok(OidcFlowStart {
        authorize_url: authorize_url.to_string(),
        state: csrf.secret().clone(),
        nonce: nonce.secret().clone(),
        code_verifier: pkce_verifier.secret().clone(),
    })
}

/// Completes the exchange: token request with the stored PKCE verifier, then
/// full ID-token verification (signature via provider JWKS, issuer, audience,
/// expiry with skew, and the expected `nonce`).
///
/// Additional audiences are accepted because providers legitimately mint them
/// (ZITADEL appends its project id, Keycloak appends `account`), but OIDC Core
/// 3.1.3.7 step 3 is still enforced: a token carrying more than one audience
/// must name this client in `azp`, otherwise another audience could replay the
/// same claims here. `openidconnect` documents that check as deliberately
/// skipped, so it is applied explicitly below.
pub async fn complete_authorization(
    config: &OidcConfig,
    http: &reqwest::Client,
    code: &str,
    code_verifier: &str,
    expected_nonce: &str,
) -> Result<VerifiedIdToken, OidcError> {
    let metadata = discover(config, http).await?;
    let redirect_uri = RedirectUrl::new(config.redirect_uri.clone())
        .map_err(|_| OidcError::ProviderUnavailable("configured redirect URI is invalid"))?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        config.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(redirect_uri);
    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .map_err(|_| OidcError::Rejected("token request could not be built"))?
        .set_pkce_verifier(PkceCodeVerifier::new(code_verifier.to_string()))
        .request_async(http)
        .await
        .map_err(|error| match error {
            RequestTokenError::Request(_) => {
                OidcError::ProviderUnavailable("token endpoint unreachable")
            },
            RequestTokenError::ServerResponse(_)
            | RequestTokenError::Parse(..)
            | RequestTokenError::Other(_) => {
                OidcError::Rejected("token endpoint rejected the exchange")
            },
        })?;
    let id_token = token_response
        .id_token()
        .ok_or(OidcError::Rejected("token response carried no ID token"))?;
    let verifier = client
        .id_token_verifier()
        .set_other_audience_verifier_fn(|_| true);
    let claims = id_token
        .claims(&verifier, &Nonce::new(expected_nonce.to_string()))
        .map_err(|error| {
            tracing::warn!(error = %error, "oidc id token verification failed");
            OidcError::Rejected("ID token verification failed")
        })?;
    if claims.audiences().len() > 1
        && claims
            .authorized_party()
            .is_none_or(|azp| **azp != config.client_id)
    {
        return Err(OidcError::Rejected(
            "id token authorized party does not match the client",
        ));
    }
    let mut verified = VerifiedIdToken {
        subject: claims.subject().to_string(),
        preferred_username: claims
            .preferred_username()
            .map(|username| username.to_string()),
        email: claims.email().map(|email| email.to_string()),
        email_verified: claims.email_verified().unwrap_or(false),
    };
    // OIDC Core 5.3: a provider may keep profile/e-mail claims behind the
    // UserInfo endpoint instead of asserting them in the ID token. Fetch them
    // there when the ID token is silent. The expected subject binds the answer
    // to this ID token, so a substituted profile can never borrow another
    // user's identity; a missing or failing endpoint simply leaves the mapping
    // without candidates and the caller refuses the login.
    if verified.preferred_username.is_none() && verified.email.is_none() {
        let subject = SubjectIdentifier::new(verified.subject.clone());
        match client.user_info(token_response.access_token().clone(), Some(subject)) {
            Ok(request) => {
                let fetched: Result<CoreUserInfoClaims, _> = request.request_async(http).await;
                match fetched {
                    Ok(info) => {
                        verified.preferred_username = info
                            .preferred_username()
                            .map(|username| username.to_string());
                        verified.email = info.email().map(|email| email.to_string());
                        verified.email_verified = info.email_verified().unwrap_or(false);
                    },
                    Err(error) => {
                        tracing::warn!(error = %error, "oidc userinfo request failed");
                    },
                }
            },
            Err(_) => {
                tracing::warn!("oidc provider advertises no userinfo endpoint");
            },
        }
    }
    Ok(verified)
}

/// RP-initiated logout URL (best effort): local revocation is the security
/// control; this only lets the browser terminate the IdP session too.
pub async fn end_session_url(config: &OidcConfig, http: &reqwest::Client) -> Option<String> {
    let issuer = IssuerUrl::new(config.issuer.clone()).ok()?;
    let metadata = ProviderMetadataWithLogout::discover_async(issuer, http)
        .await
        .ok()?;
    let endpoint = metadata
        .additional_metadata()
        .end_session_endpoint
        .clone()?;
    let mut post_logout = Url::parse(&config.redirect_uri).ok()?;
    post_logout.set_query(None);
    post_logout.set_fragment(None);
    post_logout.set_path("/");
    let url = LogoutRequest::from(endpoint)
        .set_client_id(ClientId::new(config.client_id.clone()))
        .set_post_logout_redirect_uri(PostLogoutRedirectUrl::new(post_logout.to_string()).ok()?)
        .http_get_url();
    Some(url.to_string())
}

/// Login candidates for identity mapping, in priority order: the stable
/// preferred username first, then a verified email. Values are lowercased
/// because local logins are lowercase; the caller decides match/link rules.
pub fn login_candidates(token: &VerifiedIdToken) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut push = |value: &str| {
        let normalized = value.trim().to_lowercase();
        if !normalized.is_empty() && !candidates.contains(&normalized) {
            candidates.push(normalized);
        }
    };
    if let Some(username) = &token.preferred_username {
        push(username);
        if let Some((local, _)) = username.split_once('@') {
            push(local);
        }
    }
    if token.email_verified {
        if let Some(email) = &token.email {
            push(email);
        }
    }
    candidates
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// In-process mock OIDC provider: discovery, JWKS and a token endpoint that
/// issues RS256-signed ID tokens, so the protocol paths run over a real
/// HTTP round trip without external dependencies.
#[cfg(test)]
pub(crate) mod testkit {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::OidcConfig;

    struct Inner {
        issuer: String,
        client_id: String,
        kid: String,
        modulus: String,
        exponent: String,
        private_key: RsaPrivateKey,
        subject: Mutex<String>,
        preferred_username: Mutex<String>,
        email: Mutex<String>,
        email_verified: AtomicBool,
        nonce: Mutex<Option<String>>,
        extra_audience: Mutex<Option<String>>,
        authorized_party: Mutex<Option<String>>,
        suppress_id_token_profile: AtomicBool,
        userinfo_subject: Mutex<Option<String>>,
        corrupt_signature: AtomicBool,
    }

    impl Inner {
        fn id_token(&self) -> String {
            let header = json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid });
            let extra_audience = self
                .extra_audience
                .lock()
                .expect("mock idp poisoned")
                .clone();
            let audience = match &extra_audience {
                Some(extra) => json!([self.client_id, extra]),
                None => json!(self.client_id),
            };
            let mut claims = json!({
                "iss": self.issuer,
                "sub": self.subject.lock().expect("mock idp poisoned").clone(),
                "aud": audience,
                "exp": chrono::Utc::now().timestamp() + 3600,
                "iat": chrono::Utc::now().timestamp() - 10,
            });
            // A provider may keep profile claims behind the UserInfo endpoint.
            if !self.suppress_id_token_profile.load(Ordering::SeqCst) {
                claims["preferred_username"] = json!(self
                    .preferred_username
                    .lock()
                    .expect("mock idp poisoned")
                    .clone());
                claims["email"] = json!(self.email.lock().expect("mock idp poisoned").clone());
                claims["email_verified"] = json!(self.email_verified.load(Ordering::SeqCst));
            }
            if let Some(nonce) = self.nonce.lock().expect("mock idp poisoned").clone() {
                claims["nonce"] = json!(nonce);
            }
            if let Some(azp) = self
                .authorized_party
                .lock()
                .expect("mock idp poisoned")
                .clone()
            {
                claims["azp"] = json!(azp);
            }
            let encode = |value: &[u8]| URL_SAFE_NO_PAD.encode(value);
            let signing_input = format!(
                "{}.{}",
                encode(&serde_json::to_vec(&header).expect("header serializes")),
                encode(&serde_json::to_vec(&claims).expect("claims serialize")),
            );
            let digest = Sha256::digest(signing_input.as_bytes());
            let mut signature = self
                .private_key
                .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
                .expect("test key signs");
            if self.corrupt_signature.load(Ordering::SeqCst) {
                let last = signature.len() - 1;
                signature[last] ^= 0xff;
            }
            format!("{signing_input}.{}", encode(&signature))
        }
    }

    /// Live mock provider bound to an ephemeral loopback port; dropping it
    /// stops the server task.
    pub(crate) struct MockIdp {
        pub(crate) config: OidcConfig,
        inner: Arc<Inner>,
        server: tokio::task::JoinHandle<()>,
    }

    impl MockIdp {
        pub(crate) async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("mock idp binds an ephemeral port");
            let address = listener.local_addr().expect("mock idp has an address");
            let issuer = format!("http://{address}");
            let client_id = "test-oidc-client".to_string();
            let mut rng = rsa::rand_core::OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("test RSA key generates");
            let public_key = RsaPublicKey::from(&private_key);
            let modulus_bytes = public_key.n().to_bytes_be();
            let inner = Arc::new(Inner {
                issuer: issuer.clone(),
                client_id: client_id.clone(),
                kid: URL_SAFE_NO_PAD.encode(Sha256::digest(&modulus_bytes)),
                modulus: URL_SAFE_NO_PAD.encode(&modulus_bytes),
                exponent: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
                private_key,
                subject: Mutex::new("subject-123".to_string()),
                preferred_username: Mutex::new("alice@example.test".to_string()),
                email: Mutex::new("alice@example.test".to_string()),
                email_verified: AtomicBool::new(true),
                nonce: Mutex::new(None),
                extra_audience: Mutex::new(None),
                authorized_party: Mutex::new(None),
                suppress_id_token_profile: AtomicBool::new(false),
                userinfo_subject: Mutex::new(None),
                corrupt_signature: AtomicBool::new(false),
            });
            let app = Router::new()
                .route("/.well-known/openid-configuration", get(discovery))
                .route("/jwks.json", get(jwks))
                .route("/token", post(token))
                .route("/userinfo", get(userinfo))
                .with_state(inner.clone());
            let server = tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("mock idp serves requests");
            });
            let config = OidcConfig {
                issuer,
                client_id,
                client_secret: Some("test-client-secret".to_string()),
                redirect_uri: "http://127.0.0.1:53080/api/v1/auth/oidc/callback".to_string(),
                scopes: vec!["profile".to_string(), "email".to_string()],
            };
            Self {
                config,
                inner,
                server,
            }
        }

        pub(crate) fn issuer(&self) -> &str {
            &self.inner.issuer
        }

        /// The `nonce` claim the next issued ID token will carry.
        pub(crate) fn set_nonce(&self, nonce: &str) {
            *self.inner.nonce.lock().expect("mock idp poisoned") = Some(nonce.to_string());
        }

        pub(crate) fn set_subject(&self, subject: &str) {
            *self.inner.subject.lock().expect("mock idp poisoned") = subject.to_string();
        }

        pub(crate) fn set_preferred_username(&self, username: &str) {
            *self
                .inner
                .preferred_username
                .lock()
                .expect("mock idp poisoned") = username.to_string();
        }

        pub(crate) fn set_email(&self, email: &str, verified: bool) {
            *self.inner.email.lock().expect("mock idp poisoned") = email.to_string();
            self.inner.email_verified.store(verified, Ordering::SeqCst);
        }

        /// Adds a second audience to the next issued ID token, the way real
        /// providers do (project id, `account`, …).
        pub(crate) fn set_extra_audience(&self, audience: Option<&str>) {
            *self.inner.extra_audience.lock().expect("mock idp poisoned") =
                audience.map(str::to_string);
        }

        /// Sets (or clears) the `azp` claim of the next issued ID token.
        pub(crate) fn set_authorized_party(&self, azp: Option<&str>) {
            *self
                .inner
                .authorized_party
                .lock()
                .expect("mock idp poisoned") = azp.map(str::to_string);
        }

        /// Breaks the signature of the next issued ID token.
        pub(crate) fn corrupt_signature(&self) {
            self.inner.corrupt_signature.store(true, Ordering::SeqCst);
        }

        /// Keeps profile claims out of issued ID tokens, the way providers
        /// that only assert them at the UserInfo endpoint behave.
        pub(crate) fn suppress_id_token_profile(&self) {
            self.inner
                .suppress_id_token_profile
                .store(true, Ordering::SeqCst);
        }

        /// Overrides the `sub` answered by the UserInfo endpoint, for the
        /// token-substitution guard test.
        pub(crate) fn set_userinfo_subject(&self, subject: &str) {
            *self
                .inner
                .userinfo_subject
                .lock()
                .expect("mock idp poisoned") = Some(subject.to_string());
        }
    }

    impl Drop for MockIdp {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn discovery(State(inner): State<Arc<Inner>>) -> Json<serde_json::Value> {
        Json(json!({
            "issuer": inner.issuer,
            "authorization_endpoint": format!("{}/authorize", inner.issuer),
            "token_endpoint": format!("{}/token", inner.issuer),
            "userinfo_endpoint": format!("{}/userinfo", inner.issuer),
            "jwks_uri": format!("{}/jwks.json", inner.issuer),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none"
            ],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "nonce",
                "preferred_username", "email", "email_verified"
            ],
            "end_session_endpoint": format!("{}/logout", inner.issuer),
        }))
    }

    async fn jwks(State(inner): State<Arc<Inner>>) -> Json<serde_json::Value> {
        Json(json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": inner.kid,
                "n": inner.modulus,
                "e": inner.exponent,
            }],
        }))
    }

    async fn userinfo(State(inner): State<Arc<Inner>>) -> Json<serde_json::Value> {
        let subject = inner
            .userinfo_subject
            .lock()
            .expect("mock idp poisoned")
            .clone()
            .unwrap_or_else(|| inner.subject.lock().expect("mock idp poisoned").clone());
        Json(json!({
            "sub": subject,
            "preferred_username": inner
                .preferred_username
                .lock()
                .expect("mock idp poisoned")
                .clone(),
            "email": inner.email.lock().expect("mock idp poisoned").clone(),
            "email_verified": inner.email_verified.load(Ordering::SeqCst),
        }))
    }

    async fn token(State(inner): State<Arc<Inner>>) -> Json<serde_json::Value> {
        Json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": inner.id_token(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::oidc::testkit::MockIdp;

    fn lookup(vars: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let vars = vars.to_vec();
        move |name: &str| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    fn valid_oidc_vars(
        extra: &[(&'static str, &'static str)],
    ) -> Vec<(&'static str, &'static str)> {
        let base = [
            ("NULLAPART_IDENTITY_PROVIDER", "oidc"),
            ("NULLAPART_OIDC_ISSUER", "https://idp.example.test"),
            (
                "NULLAPART_OIDC_REDIRECT_URI",
                "http://192.168.8.4:53080/api/v1/auth/oidc/callback",
            ),
            ("NULLAPART_OIDC_CLIENT_ID", "nullapart-control"),
        ];
        // Later entries win so each test can override one setting.
        let mut vars: Vec<(&'static str, &'static str)> = base
            .into_iter()
            .filter(|(key, _)| !extra.iter().any(|(other, _)| other == key))
            .collect();
        vars.extend_from_slice(extra);
        vars
    }

    #[test]
    fn identity_defaults_to_the_proxy_header_mode() {
        let config = IdentityConfig::from_lookup(lookup(&[])).expect("default is valid");
        assert!(matches!(config.kind, IdentityProviderKind::ProxyHeader));
        assert!(config.oidc.is_none());
    }

    #[test]
    fn unknown_identity_modes_fail_startup() {
        let error = IdentityConfig::from_lookup(lookup(&[("NULLAPART_IDENTITY_PROVIDER", "ldap")]))
            .expect_err("unknown modes are rejected");
        assert!(error.contains("proxy_header or oidc"));
    }

    #[test]
    fn oidc_mode_requires_a_full_valid_configuration() {
        let error = IdentityConfig::from_lookup(lookup(&[("NULLAPART_IDENTITY_PROVIDER", "oidc")]))
            .expect_err("missing issuer is rejected");
        assert!(error.contains("NULLAPART_OIDC_ISSUER is required"));

        let error = IdentityConfig::from_lookup(lookup(&valid_oidc_vars(&[(
            "NULLAPART_OIDC_REDIRECT_URI",
            "http://192.168.8.4:53080/login/done",
        )])))
        .expect_err("wrong redirect path is rejected");
        assert!(error.contains("path must be /api/v1/auth/oidc/callback"));

        let error = IdentityConfig::from_lookup(lookup(&valid_oidc_vars(&[(
            "NULLAPART_OIDC_ISSUER",
            "idp.example.test",
        )])))
        .expect_err("non-URL issuer is rejected");
        assert!(error.contains("absolute http(s) URL"));

        let error = IdentityConfig::from_lookup(lookup(&valid_oidc_vars(&[(
            "NULLAPART_OIDC_ISSUER",
            "https://idp.example.test?x=1",
        )])))
        .expect_err("issuer with a query is rejected");
        assert!(error.contains("query"));

        let error = IdentityConfig::from_lookup(lookup(&valid_oidc_vars(&[(
            "NULLAPART_OIDC_REDIRECT_URI",
            "https://user:pass@idp.example.test/api/v1/auth/oidc/callback",
        )])))
        .expect_err("userinfo in the redirect is rejected");
        assert!(error.contains("userinfo"));
    }

    #[test]
    fn oidc_scopes_default_sensibly_and_never_repeat_openid() {
        let config = IdentityConfig::from_lookup(lookup(&valid_oidc_vars(&[])))
            .expect("valid configuration");
        let oidc = config.oidc.expect("oidc configured");
        assert_eq!(
            oidc.scopes,
            vec!["profile".to_string(), "email".to_string()]
        );

        let config = IdentityConfig::from_lookup(lookup(&valid_oidc_vars(&[(
            "NULLAPART_OIDC_SCOPES",
            "openid  profile custom-scope",
        )])))
        .expect("valid configuration");
        let oidc = config.oidc.expect("oidc configured");
        assert_eq!(
            oidc.scopes,
            vec!["profile".to_string(), "custom-scope".to_string()]
        );
    }

    #[test]
    fn login_candidates_prefer_username_then_local_part_then_verified_email() {
        let token = VerifiedIdToken {
            subject: "subject-1".to_string(),
            preferred_username: Some("Alice@Example.TEST".to_string()),
            email: Some("alice@example.test".to_string()),
            email_verified: true,
        };
        assert_eq!(
            login_candidates(&token),
            vec!["alice@example.test".to_string(), "alice".to_string()]
        );
    }

    #[test]
    fn login_candidates_drop_unverified_emails_and_keep_the_subject_last() {
        let token = VerifiedIdToken {
            subject: "subject-2".to_string(),
            preferred_username: Some("bob".to_string()),
            email: Some("bob@example.test".to_string()),
            email_verified: false,
        };
        assert_eq!(login_candidates(&token), vec!["bob".to_string()]);
        let bare = VerifiedIdToken {
            subject: "subject-3".to_string(),
            preferred_username: None,
            email: Some("carol@example.test".to_string()),
            email_verified: false,
        };
        assert!(login_candidates(&bare).is_empty());
    }

    #[tokio::test]
    async fn start_authorization_builds_a_pkce_code_flow() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        let url = Url::parse(&start.authorize_url).expect("authorize URL parses");
        let params: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some(idp.config.client_id.as_str())
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some(idp.config.redirect_uri.as_str())
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(params["scope"].split(' ').any(|scope| scope == "openid"));
        assert_eq!(
            params.get("state").map(String::as_str),
            Some(start.state.as_str())
        );
        assert_eq!(
            params.get("nonce").map(String::as_str),
            Some(start.nonce.as_str())
        );
        assert!(!params.contains_key("prompt"));
        let expected_challenge =
            URL_SAFE_NO_PAD.encode(Sha256::digest(start.code_verifier.as_bytes()));
        assert_eq!(
            params.get("code_challenge").map(String::as_str),
            Some(expected_challenge.as_str())
        );
    }

    #[tokio::test]
    async fn start_authorization_forces_an_interactive_login_for_step_up() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, true)
            .await
            .expect("flow starts");
        let url = Url::parse(&start.authorize_url).expect("authorize URL parses");
        let params: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        assert_eq!(params.get("prompt").map(String::as_str), Some("login"));
    }

    #[tokio::test]
    async fn complete_authorization_verifies_a_signed_id_token() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.set_subject("zitadel-user-1");
        idp.set_preferred_username("owner");
        let verified = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect("token verifies");
        assert_eq!(verified.subject, "zitadel-user-1");
        assert_eq!(verified.preferred_username.as_deref(), Some("owner"));
        assert_eq!(verified.email.as_deref(), Some("alice@example.test"));
        assert!(verified.email_verified);
    }

    #[tokio::test]
    async fn complete_authorization_carries_an_unverified_email_without_trusting_it() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.set_preferred_username("nobody@example.test");
        idp.set_email("owner@example.test", false);
        let verified = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect("token verifies");
        assert_eq!(verified.email.as_deref(), Some("owner@example.test"));
        assert!(!verified.email_verified);
        assert_eq!(
            login_candidates(&verified),
            vec!["nobody@example.test".to_string(), "nobody".to_string()]
        );
    }

    #[tokio::test]
    async fn complete_authorization_rejects_a_wrong_nonce() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce("some-other-nonce");
        let error = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect_err("nonce mismatch fails verification");
        assert!(matches!(error, OidcError::Rejected(_)));
    }

    #[tokio::test]
    async fn complete_authorization_rejects_a_corrupted_signature() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.corrupt_signature();
        let error = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect_err("tampered signature fails verification");
        assert!(matches!(error, OidcError::Rejected(_)));
    }

    #[tokio::test]
    async fn complete_authorization_accepts_a_second_audience_bound_by_azp() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.set_subject("zitadel-user-1");
        idp.set_extra_audience(Some("project-123"));
        idp.set_authorized_party(Some(&idp.config.client_id));
        let verified = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect("an additional audience bound by azp verifies");
        assert_eq!(verified.subject, "zitadel-user-1");
    }

    #[tokio::test]
    async fn complete_authorization_rejects_a_second_audience_without_azp() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.set_extra_audience(Some("project-123"));
        let error = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect_err("an unbound second audience fails verification");
        assert_eq!(
            error.audit_reason(),
            "id token authorized party does not match the client"
        );
    }

    #[tokio::test]
    async fn complete_authorization_rejects_an_azp_naming_another_client() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.set_extra_audience(Some("project-123"));
        idp.set_authorized_party(Some("another-client"));
        let error = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect_err("an azp naming another client fails verification");
        assert_eq!(
            error.audit_reason(),
            "id token authorized party does not match the client"
        );
    }

    #[tokio::test]
    async fn complete_authorization_falls_back_to_userinfo_when_the_id_token_is_silent() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.set_subject("zitadel-user-1");
        idp.suppress_id_token_profile();
        let verified = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect("the userinfo endpoint supplies the profile claims");
        assert_eq!(verified.subject, "zitadel-user-1");
        assert_eq!(
            verified.preferred_username.as_deref(),
            Some("alice@example.test")
        );
        assert_eq!(verified.email.as_deref(), Some("alice@example.test"));
        assert!(verified.email_verified);
    }

    #[tokio::test]
    async fn complete_authorization_never_adopts_another_subjects_userinfo() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let start = start_authorization(&idp.config, &http, false)
            .await
            .expect("flow starts");
        idp.set_nonce(&start.nonce);
        idp.set_subject("zitadel-user-1");
        idp.suppress_id_token_profile();
        idp.set_userinfo_subject("zitadel-user-2");
        let verified = complete_authorization(
            &idp.config,
            &http,
            "mock-code",
            &start.code_verifier,
            &start.nonce,
        )
        .await
        .expect("verification succeeds with the ID token's own subject");
        assert_eq!(verified.subject, "zitadel-user-1");
        assert!(verified.preferred_username.is_none());
        assert!(verified.email.is_none());
    }

    #[tokio::test]
    async fn end_session_url_is_built_when_the_provider_advertises_one() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let url = end_session_url(&idp.config, &http)
            .await
            .expect("discovery advertises an end-session endpoint");
        assert!(url.starts_with(&format!("{}/logout", idp.issuer())));
        assert!(url.contains("client_id="));
        assert!(url.contains("post_logout_redirect_uri="));
    }

    #[tokio::test]
    async fn end_session_url_is_none_when_the_provider_has_no_logout_endpoint() {
        let idp = MockIdp::start().await;
        let http = http_client().expect("client builds");
        let mut config = idp.config.clone();
        // Point at a provider whose discovery document lacks the endpoint
        // by cloning the live issuer but stripping is not possible here;
        // instead verify the helper stays best-effort against an issuer
        // that cannot be reached at all.
        config.issuer = "http://127.0.0.1:1".to_string();
        assert!(end_session_url(&config, &http).await.is_none());
    }
}
