//! Async client for the relay's /api/v1 (same wire types as the CLI's api.rs).
//!
//! TLS trust is per server (SPEC "Production certificate mode"):
//! - a server on a domain is checked against the public web roots (webpki
//!   roots, as browsers do), so a Let's Encrypt certificate just works;
//! - a test server (a bare IP address, or a root pasted under Advanced) has
//!   its own root certificate pinned in the identity, after the person
//!   confirmed its SHA-256 fingerprint. Then that root and nothing else is
//!   trusted, and a server presenting anything else is refused.
//!
//! Verification is never turned off, except to download a test server's root
//! certificate for that confirmation (`fetch_root`), which trusts nothing it
//! fetches until the person has compared the fingerprint.

use anyhow::{bail, Context, Result};
use reqwest::{Client, RequestBuilder};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Clone)]
pub struct Api {
    http: Client,
    base: String,
    token: Option<String>,
    /// Fingerprint of the pinned root, for a test server.
    pinned: Option<String>,
}

/// Normalise a server address. HTTPS only, except plain HTTP to this computer
/// (a relay under development).
pub fn normalize_server(url: &str) -> Result<String> {
    let mut s = url.trim().to_string();
    if !s.contains("://") {
        s = format!("https://{s}");
    }
    let u = reqwest::Url::parse(&s).context("that isn't a valid server address")?;
    let loopback = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    match u.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => bail!("the server address must start with https://"),
    }
    if u.query().is_some() || u.fragment().is_some() {
        bail!("the server address shouldn't have ? or # in it");
    }
    if u.path() != "/" {
        bail!("the server address is just the name or IP address, with nothing after it");
    }
    Ok(u.as_str().trim_end_matches('/').to_string())
}

/// A bare IP address can't have a public certificate, so it's a test server.
pub fn is_ip_server(server: &str) -> bool {
    reqwest::Url::parse(server)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok()))
        .unwrap_or(false)
}

pub fn is_https(server: &str) -> bool {
    server.starts_with("https://")
}

/// The single certificate in `pem`, DER-encoded.
fn one_cert(pem: &str) -> Result<CertificateDer<'static>> {
    let mut certs = CertificateDer::pem_slice_iter(pem.as_bytes());
    let first = certs
        .next()
        .context("that isn't a certificate (expected -----BEGIN CERTIFICATE-----)")?
        .context("reading the certificate")?;
    if certs.next().is_some() {
        bail!("expected one root certificate, found several");
    }
    Ok(first)
}

/// SHA-256 of the certificate, as `openssl x509 -fingerprint -sha256` prints
/// it (and so install.sh): `AB:CD:...`, 32 bytes.
pub fn fingerprint(pem: &str) -> Result<String> {
    let der = one_cert(pem)?;
    Ok(Sha256::digest(der.as_ref()).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

/// Fingerprints compare ignoring case, spaces and colons.
pub fn same_fingerprint(a: &str, b: &str) -> bool {
    let n = |s: &str| -> String { s.chars().filter(|c| c.is_ascii_hexdigit()).map(|c| c.to_ascii_uppercase()).collect() };
    n(a).len() == 64 && n(a) == n(b)
}

/// Download a test server's root certificate (Caddy serves it at
/// `/sidetray-root.crt`). The connection is NOT verified: what comes back is
/// only shown as a fingerprint for the person to compare with what the
/// server's installer printed. It also checks that the server's own
/// certificate chains to that root, so the fingerprint describes this server.
pub async fn fetch_root(server: &str) -> Result<String> {
    if !is_https(server) {
        bail!("only an https:// server has a certificate to check");
    }
    let http = Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent(concat!("sidetray-app/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("setting up HTTPS")?;
    let resp = http
        .get(format!("{}/sidetray-root.crt", server.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| describe_send_error(e, None))?;
    if !resp.status().is_success() {
        bail!(
            "this server doesn't offer its root certificate (it answered {}). A test server set up \
             before Side Tray 0.6.2 needs install.sh run again; or paste its root certificate under Advanced.",
            resp.status()
        );
    }
    let body = resp.bytes().await.context("downloading the root certificate")?;
    if body.len() > 16 * 1024 {
        bail!("the server's root certificate is suspiciously large");
    }
    let pem = String::from_utf8(body.to_vec()).context("the server's root certificate isn't text")?;
    check_pinned(server, &pem).await?;
    Ok(pem.trim().to_string() + "\n")
}

/// Connect with exactly `pem` trusted, to check the server's chain ends there.
pub async fn check_pinned(server: &str, pem: &str) -> Result<()> {
    fingerprint(pem)?;
    let r: Result<serde_json::Value> = Api::new(server, Some(pem), None)?.get("/health").await;
    match r {
        Ok(_) => Ok(()),
        Err(e) if is_cert_error(&e) => {
            bail!("the server's certificate isn't issued by that root certificate, so it isn't this server's root")
        }
        Err(e) => Err(e),
    }
}

/// rustls config for the push socket, trusting exactly what `Api` trusts:
/// the pinned root for a test server, else the public web roots.
pub fn tls_config(ca_pem: Option<&str>) -> Result<std::sync::Arc<rustls::ClientConfig>> {
    let mut store = rustls::RootCertStore::empty();
    match ca_pem.filter(|p| !p.trim().is_empty()) {
        None => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        Some(pem) => store.add(one_cert(pem)?).context("adding the pinned root certificate")?,
    }
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .context("setting up TLS")?
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(std::sync::Arc::new(config))
}

/// `https://host` -> `wss://host/api/v1/ws` (and http -> ws for a local relay).
pub fn ws_url(server: &str) -> Result<String> {
    let s = server.trim_end_matches('/');
    let rest = if let Some(r) = s.strip_prefix("https://") {
        format!("wss://{r}")
    } else if let Some(r) = s.strip_prefix("http://") {
        format!("ws://{r}")
    } else {
        bail!("unexpected server address {s}");
    };
    Ok(format!("{rest}/api/v1/ws"))
}

impl Api {
    /// `ca_pem`: the pinned root of a test server, or None for the public web roots.
    pub fn new(server: &str, ca_pem: Option<&str>, token: Option<&str>) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("sidetray-app/", env!("CARGO_PKG_VERSION")));
        let mut pinned = None;
        if let Some(pem) = ca_pem.filter(|p| !p.trim().is_empty()) {
            let cert = reqwest::Certificate::from_der(one_cert(pem)?.as_ref()).context("reading the pinned root certificate")?;
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(cert);
            pinned = Some(fingerprint(pem)?);
        }
        Ok(Api {
            http: builder.build().context("setting up HTTPS")?,
            base: format!("{}/api/v1", server.trim_end_matches('/')),
            token: token.map(str::to_string),
            pinned,
        })
    }

    fn auth(&self, req: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn checked(&self, req: RequestBuilder) -> Result<reqwest::Response> {
        let resp = req.send().await.map_err(|e| describe_send_error(e, self.pinned.as_deref()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("detail").map(|d| d.as_str().map(str::to_string).unwrap_or_else(|| d.to_string())))
            .unwrap_or(body);
        Err(HttpError { status: status.as_u16(), detail }.into())
    }

    async fn json<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T> {
        let resp = self.checked(req).await?;
        let body = resp.text().await.context("reading response")?;
        serde_json::from_str(&body).with_context(|| format!("unexpected response: {body}"))
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.json(self.auth(self.http.get(format!("{}{path}", self.base)))).await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.json(self.auth(self.http.post(format!("{}{path}", self.base)).json(body))).await
    }

    /// Upload an encrypted blob; returns its media id.
    pub async fn upload_media(&self, blob: Vec<u8>) -> Result<String> {
        let req = self
            .http
            .post(format!("{}/media", self.base))
            .header("content-type", "application/octet-stream")
            .timeout(Duration::from_secs(300))
            .body(blob);
        let r: MediaResp = self.json(self.auth(req)).await?;
        Ok(r.id)
    }

    pub async fn download_media(&self, id: &str) -> Result<Vec<u8>> {
        let req = self.http.get(format!("{}/media/{id}", self.base)).timeout(Duration::from_secs(300));
        let resp = self.checked(self.auth(req)).await?;
        Ok(resp.bytes().await.context("downloading media")?.to_vec())
    }
}

/// The relay answered with an error status.
#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub detail: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server said {}: {}", self.status, self.detail)
    }
}

impl std::error::Error for HttpError {}

/// Whether `e` (anywhere in its chain) is the relay answering `status`.
pub fn is_status(e: &anyhow::Error, status: u16) -> bool {
    e.chain().any(|c| c.downcast_ref::<HttpError>().is_some_and(|h| h.status == status))
}

/// The relay refused an event because a newer group key exists (POST /events -> 409).
pub fn is_stale_key(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<HttpError>().is_some_and(|h| h.status == 409 && h.detail.contains("out of date")))
}

/// The server's certificate wasn't accepted.
#[derive(Debug)]
pub struct CertError {
    /// The fingerprint of the root this app pinned for a test server, if any.
    pub pinned: Option<String>,
    pub detail: String,
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.pinned {
            Some(fp) => write!(
                f,
                "This server's certificate has changed: it isn't issued by the root certificate you confirmed \
                 (SHA-256 {fp}), so Side Tray refused to connect. Either the server was set up again, or \
                 someone is intercepting the connection. Ask whoever runs the server before trusting it again.\n({})",
                self.detail
            ),
            None => write!(
                f,
                "The server's HTTPS certificate isn't valid or isn't publicly trusted, so Side Tray refused \
                 to connect. A test server's root certificate can be pasted under Advanced.\n({})",
                self.detail
            ),
        }
    }
}

impl std::error::Error for CertError {}

/// Whether `e` is a refused certificate.
pub fn is_cert_error(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<CertError>().is_some())
}

/// Whether an error message is about the certificate.
fn mentions_certificate(text: &str) -> bool {
    text.contains("certificate") || text.contains("UnknownIssuer") || text.contains("BadSignature")
}

fn describe_send_error(e: reqwest::Error, pinned: Option<&str>) -> anyhow::Error {
    // Walk the source chain: certificate problems are buried a few levels down.
    let mut chain = String::new();
    let mut src: Option<&dyn std::error::Error> = Some(&e);
    while let Some(s) = src {
        chain.push_str(&format!(" {s}"));
        src = s.source();
    }
    if mentions_certificate(&chain) {
        CertError { pinned: pinned.map(str::to_string), detail: chain.trim().to_string() }.into()
    } else if e.is_timeout() {
        anyhow::anyhow!("the server didn't answer in time")
    } else if e.is_connect() {
        anyhow::anyhow!("couldn't reach the server ({})", chain.trim())
    } else {
        anyhow::anyhow!("contacting server:{chain}")
    }
}

#[derive(Deserialize)]
struct MediaResp {
    id: String,
}

#[derive(Deserialize, Serialize)]
pub struct GroupInfo {
    pub exists: bool,
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct JoinReq<'a> {
    pub group_name: &'a str,
    pub display_name: &'a str,
    pub email: &'a str,
    pub enc_pubkey: String,
    pub sign_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<&'a str>,
}

#[derive(Deserialize)]
pub struct JoinResp {
    pub group_id: String,
    pub group_name: String,
    pub member_id: String,
    pub device_id: String,
    pub token: String,
    pub status: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct JoinStatus {
    pub status: String,
    pub role: Option<String>,
    #[serde(default)]
    pub sealed_keys: Vec<SealedKey>,
    pub approved_by: Option<String>,
    #[serde(default)]
    pub anchors: Vec<AnchorJson>,
    #[serde(default)]
    pub anchors_signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AnchorJson {
    pub device_id: String,
    pub sign_pubkey: String,
}

#[derive(Deserialize, Clone)]
pub struct SealedKey {
    pub key_version: u32,
    pub sealed_blob: String,
    pub signature: String,
    pub signer_device_id: Option<String>,
    pub signer_sign_pubkey: String,
    pub signer_enc_pubkey: String,
    pub signer_name: Option<String>,
}

#[derive(Deserialize)]
pub struct KeysResp {
    #[serde(default)]
    pub sealed_keys: Vec<SealedKey>,
    pub key_version: u32,
    #[serde(default)]
    pub rotation_pending: bool,
}

#[derive(Serialize)]
pub struct GrantUpload {
    pub device_id: String,
    pub sealed_blob: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct RotateReq {
    pub key_version: u32,
    pub sealed_keys: Vec<GrantUpload>,
}

#[derive(Serialize)]
pub struct RoleReq {
    pub role: &'static str,
    pub certs: Vec<CertUpload>,
}

#[derive(Deserialize)]
pub struct PendingList {
    pub pending: Vec<Pending>,
}

#[derive(Deserialize)]
pub struct Pending {
    pub device_id: String,
    pub member_id: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub existing_member: bool,
    pub enc_pubkey: String,
    pub sign_pubkey: String,
}

#[derive(Serialize)]
pub struct SealedKeyUpload {
    pub key_version: u32,
    pub sealed_blob: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct ApproveReq {
    pub sealed_keys: Vec<SealedKeyUpload>,
    pub cert: CertUpload,
    pub anchors: Vec<AnchorJson>,
    pub anchors_signature: String,
}

#[derive(Serialize)]
pub struct CertUpload {
    pub device_id: String,
    pub role: String,
    pub display_name: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct CertsReq {
    pub certs: Vec<CertUpload>,
}

#[derive(Deserialize)]
pub struct Roster {
    pub members: Vec<Member>,
    /// Removed members and revoked devices that may still have events on the relay.
    #[serde(default)]
    pub former: Vec<Member>,
}

/// The server's view of a member. Its name and role are only shown for
/// devices that don't verify (flagged as such); verified ones use certificates.
#[derive(Deserialize)]
pub struct Member {
    pub id: String,
    #[serde(default)]
    pub display_name: String,
    pub devices: Vec<MemberDevice>,
}

#[derive(Deserialize)]
pub struct MemberDevice {
    pub id: String,
    pub enc_pubkey: String,
    pub sign_pubkey: String,
    #[serde(default)]
    pub certs: Vec<CertJson>,
    /// Only sent to Key Masters.
    pub last_seen: Option<i64>,
    pub joined_at: Option<i64>,
    /// Former devices: the last event seq before they were cut off.
    pub revoked_seq: Option<i64>,
    /// Former devices: the last direct message seq before they were cut off.
    #[serde(default)]
    pub revoked_dm_seq: Option<i64>,
}

#[derive(Deserialize)]
pub struct CertJson {
    pub issuer_device_id: String,
    pub role: String,
    pub display_name: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct EventReq<'a> {
    pub kind: &'a str,
    pub key_version: u32,
    pub ciphertext: String,
    pub signature: String,
    pub media_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub last_seq: i64,
    pub has_more: bool,
    /// Highest seq the relay has pruned. A cursor below it missed events.
    #[serde(default)]
    pub pruned_through: i64,
    #[serde(default)]
    pub retention_days: f64,
    /// The group's current key version.
    #[serde(default)]
    pub key_version: u32,
}

/// A direct message, as `GET /dms` returns it (Phase 5b).
#[derive(Deserialize)]
pub struct Dm {
    pub seq: i64,
    pub conversation_id: String,
    pub sender_device_id: String,
    pub sender_member_id: String,
    pub recipient_member_id: String,
    pub ciphertext: String,
    pub signature: String,
    pub created_at: i64,
    #[serde(default)]
    pub sealed_keys: Vec<DmKey>,
}

#[derive(Deserialize, Serialize)]
pub struct DmKey {
    pub device_id: String,
    pub sealed_key: String,
}

#[derive(Deserialize)]
pub struct DmPage {
    pub messages: Vec<Dm>,
    pub last_seq: i64,
    pub has_more: bool,
}

#[derive(Serialize)]
pub struct DmReq<'a> {
    pub conversation_id: &'a str,
    pub recipient_member_id: &'a str,
    pub ciphertext: String,
    pub signature: String,
    pub media_ids: Vec<String>,
    pub sealed_keys: Vec<DmKey>,
}

#[derive(Deserialize)]
pub struct Event {
    pub seq: i64,
    pub kind: String,
    pub author_device_id: String,
    pub key_version: u32,
    pub ciphertext: String,
    pub signature: String,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses() {
        assert_eq!(normalize_server("10.1.1.188").unwrap(), "https://10.1.1.188");
        assert_eq!(normalize_server(" https://example.org/ ").unwrap(), "https://example.org");
        assert_eq!(normalize_server("http://127.0.0.1:8000").unwrap(), "http://127.0.0.1:8000");
        assert!(normalize_server("http://10.1.1.188").is_err());
        assert!(normalize_server("ftp://example.org").is_err());
    }

    /// A throwaway self-signed root made with openssl, only for these tests.
    const ROOT: &str = include_str!("../tests-data/test-root.pem");
    /// `openssl x509 -noout -fingerprint -sha256 -in tests-data/test-root.pem`
    const ROOT_FP: &str = include_str!("../tests-data/test-root.sha256");

    #[test]
    fn fingerprints_and_pinned_roots() {
        let fp = fingerprint(ROOT).unwrap();
        assert_eq!(fp, ROOT_FP.trim().trim_start_matches("sha256 Fingerprint="));
        assert!(fp.chars().all(|c| c == ':' || c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        assert!(same_fingerprint(&fp, &fp.to_lowercase().replace(':', " ")));
        assert!(!same_fingerprint(&fp, &fp[..60]));
        assert!(fingerprint("not a pem").is_err());
        assert!(fingerprint(&format!("{ROOT}{ROOT}")).is_err());
        assert!(tls_config(None).is_ok());
        assert!(tls_config(Some("not a pem")).is_err());
        assert!(Api::new("https://10.1.1.191", Some(ROOT), None).unwrap().pinned.is_some());
        assert!(Api::new("https://tray.example.org", None, None).unwrap().pinned.is_none());
    }

    #[test]
    fn test_servers_are_ip_addresses() {
        assert!(is_ip_server("https://10.1.1.191"));
        assert!(is_ip_server("https://[::1]:8443"));
        assert!(!is_ip_server("https://tray.example.org"));
        assert!(normalize_server("https://tray.example.org/api").is_err());
    }

    #[test]
    fn socket_addresses() {
        assert_eq!(ws_url("https://10.1.1.188").unwrap(), "wss://10.1.1.188/api/v1/ws");
        assert_eq!(ws_url("http://127.0.0.1:8000").unwrap(), "ws://127.0.0.1:8000/api/v1/ws");
    }
}
