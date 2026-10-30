//! Minimal blocking client for the relay's /api/v1.

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub struct Api {
    http: Client,
    base: String,
    token: Option<String>,
}

impl Api {
    pub fn new(server: &str, ca_pem: Option<&str>, token: Option<&str>) -> Result<Self> {
        let mut builder = Client::builder().timeout(std::time::Duration::from_secs(30));
        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes()).context("parsing CA certificate")?;
            builder = builder.add_root_certificate(cert);
        }
        Ok(Api {
            http: builder.build()?,
            base: format!("{}/api/v1", server.trim_end_matches('/')),
            token: token.map(str::to_string),
        })
    }

    fn send<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T> {
        let req = match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        };
        let resp = req.send().context("contacting server")?;
        let status = resp.status();
        let body = resp.text().context("reading response")?;
        if !status.is_success() {
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("detail").map(|d| d.to_string()))
                .unwrap_or(body);
            bail!("server said {status}: {detail}");
        }
        serde_json::from_str(&body).with_context(|| format!("unexpected response: {body}"))
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send(self.http.get(format!("{}{path}", self.base)))
    }

    pub fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.send(self.http.post(format!("{}{path}", self.base)).json(body))
    }
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

/// A member certificate as uploaded; the server fills in member and keys from its records.
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

#[derive(Serialize)]
pub struct RoleReq {
    pub role: String,
    pub certs: Vec<CertUpload>,
}

#[derive(Deserialize)]
pub struct Roster {
    pub members: Vec<Member>,
}

#[derive(Deserialize)]
/// The server's view of a member. Its role claim isn't parsed: roles come from certificates.
pub struct Member {
    pub id: String,
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
pub struct Seq {
    pub seq: i64,
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
}
