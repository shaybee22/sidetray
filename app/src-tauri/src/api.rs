//! Async client for the relay's /api/v1 (same wire types as the CLI's api.rs).
//!
//! TLS trust: if this build pins root certificates (`pinned-roots.pem`), or the
//! user gave one for their server in the wizard, the client trusts exactly
//! those roots and nothing else. With neither, it uses the public web roots.
//! Verification is never turned off.

use anyhow::{bail, Context, Result};
use reqwest::{Client, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;

/// Roots compiled into this build: Caddy's internal CA for the test relay.
/// Empty the file to fall back to the public web roots (e.g. once the server
/// has a real domain and a Let's Encrypt certificate).
pub const PINNED_ROOTS: &str = include_str!("../pinned-roots.pem");

#[derive(Clone)]
pub struct Api {
    http: Client,
    base: String,
    token: Option<String>,
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
    Ok(u.as_str().trim_end_matches('/').to_string())
}

fn roots(ca_pem: Option<&str>) -> Result<Vec<reqwest::Certificate>> {
    let pem = ca_pem.filter(|p| !p.trim().is_empty()).unwrap_or(PINNED_ROOTS);
    if pem.trim().is_empty() {
        return Ok(Vec::new());
    }
    let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes()).context("reading the pinned root certificate")?;
    if certs.is_empty() {
        bail!("the pinned root certificate file has no certificates in it");
    }
    Ok(certs)
}

impl Api {
    pub fn new(server: &str, ca_pem: Option<&str>, token: Option<&str>) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("sidetray-app/", env!("CARGO_PKG_VERSION")));
        let pinned = roots(ca_pem)?;
        if !pinned.is_empty() {
            builder = builder.tls_built_in_root_certs(false);
            for c in pinned {
                builder = builder.add_root_certificate(c);
            }
        }
        Ok(Api {
            http: builder.build().context("setting up HTTPS")?,
            base: format!("{}/api/v1", server.trim_end_matches('/')),
            token: token.map(str::to_string),
        })
    }

    fn auth(&self, req: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn checked(req: RequestBuilder) -> Result<reqwest::Response> {
        let resp = req.send().await.map_err(describe_send_error)?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("detail").map(|d| d.as_str().map(str::to_string).unwrap_or_else(|| d.to_string())))
            .unwrap_or(body);
        bail!("server said {status}: {detail}")
    }

    async fn json<T: DeserializeOwned>(req: RequestBuilder) -> Result<T> {
        let resp = Self::checked(req).await?;
        let body = resp.text().await.context("reading response")?;
        serde_json::from_str(&body).with_context(|| format!("unexpected response: {body}"))
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Self::json(self.auth(self.http.get(format!("{}{path}", self.base)))).await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        Self::json(self.auth(self.http.post(format!("{}{path}", self.base)).json(body))).await
    }

    /// Upload an encrypted blob; returns its media id.
    pub async fn upload_media(&self, blob: Vec<u8>) -> Result<String> {
        let req = self
            .http
            .post(format!("{}/media", self.base))
            .header("content-type", "application/octet-stream")
            .timeout(Duration::from_secs(300))
            .body(blob);
        let r: MediaResp = Self::json(self.auth(req)).await?;
        Ok(r.id)
    }

    pub async fn download_media(&self, id: &str) -> Result<Vec<u8>> {
        let req = self.http.get(format!("{}/media/{id}", self.base)).timeout(Duration::from_secs(300));
        let resp = Self::checked(self.auth(req)).await?;
        Ok(resp.bytes().await.context("downloading media")?.to_vec())
    }
}

fn describe_send_error(e: reqwest::Error) -> anyhow::Error {
    // Walk the source chain: certificate problems are buried a few levels down.
    let mut chain = String::new();
    let mut src: Option<&dyn std::error::Error> = Some(&e);
    while let Some(s) = src {
        chain.push_str(&format!(" {s}"));
        src = s.source();
    }
    if chain.contains("certificate") || chain.contains("UnknownIssuer") {
        anyhow::anyhow!(
            "the server's HTTPS certificate isn't one this app trusts. If your server uses its own \
             certificate authority, paste its root certificate under Advanced.\n({})",
            chain.trim()
        )
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

#[derive(Deserialize)]
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
}

/// The server's view of a member. Its role claim isn't parsed: roles come from certificates.
#[derive(Deserialize)]
pub struct Member {
    pub id: String,
    pub devices: Vec<MemberDevice>,
}

#[derive(Deserialize)]
pub struct MemberDevice {
    pub id: String,
    pub enc_pubkey: String,
    pub sign_pubkey: String,
    #[serde(default)]
    pub certs: Vec<CertJson>,
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

    #[test]
    fn pinned_roots_parse() {
        assert!(!roots(None).unwrap().is_empty());
        assert!(roots(Some("not a pem")).is_err());
    }
}
