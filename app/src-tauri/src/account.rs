//! Joining, founding, Key Master approvals and the verified roster.
//! Same rules as the CLI (cli/src/main.rs); see README "Roster trust".

use crate::api::*;
use crate::db::{self, Identity};
use crate::secrets::{self, Secrets};
use crate::state::App;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use sidetray_crypto::roster::{self, Anchor, CertSubject, MemberCert, Role, VerifiedDevice};
use sidetray_crypto::{self as crypto, protocol, DeviceKeys, DevicePublicKeys, GroupKey};
use std::collections::BTreeMap;
use std::sync::Arc;

pub fn decode32(s: &str) -> Result<[u8; 32]> {
    let v = B64.decode(s).context("bad base64")?;
    v.try_into().map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))
}

fn pubkeys(enc_b64: &str, sign_b64: &str) -> Result<DevicePublicKeys> {
    Ok(DevicePublicKeys { enc: decode32(enc_b64)?, sign: decode32(sign_b64)? })
}

/// Codes are compared case-insensitively, ignoring spaces and dashes.
pub fn codes_match(a: &str, b: &str) -> bool {
    let n = |c: &str| -> String { c.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect() };
    !n(a).is_empty() && n(a) == n(b)
}

fn random_id() -> String {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).expect("OS random number generator");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- wizard ------------------------------------------------------------------

/// Whether a group of exactly this name (ignoring case) exists on the server.
/// The server never lists its groups, so the name has to come first.
pub async fn probe(server: &str, ca_pem: Option<&str>, group_name: &str) -> Result<GroupInfo> {
    let server = normalize_server(server)?;
    let name = group_name.trim();
    if name.is_empty() {
        bail!("enter the group's name");
    }
    Api::new(&server, ca_pem, None)?.get(&format!("/group?name={}", crate::invite::encode(name))).await
}

pub struct Registration<'a> {
    pub server: &'a str,
    pub ca_pem: Option<&'a str>,
    pub group_name: &'a str,
    pub display_name: &'a str,
    pub email: &'a str,
    /// Present only when founding the group.
    pub setup_token: Option<&'a str>,
}

/// Generate this device's keys and send the join request (or create the group).
/// Returns this device's safety code.
pub async fn register(app: &App, r: Registration<'_>) -> Result<String> {
    if app.identity()?.is_some() {
        bail!("this app has already joined a group");
    }
    let server = normalize_server(r.server)?;
    let (group_name, display_name, email) = (r.group_name.trim(), r.display_name.trim(), r.email.trim());
    if group_name.is_empty() || display_name.is_empty() {
        bail!("group name and display name are required");
    }
    if !email.contains('@') {
        bail!("that doesn't look like an email address");
    }
    let ca_pem = r.ca_pem.map(str::trim).filter(|p| !p.is_empty()).map(str::to_string);
    let keys = crypto::generate_device_keys();
    let public = keys.public();
    let api = Api::new(&server, ca_pem.as_deref(), None)?;
    let resp: JoinResp = api
        .post(
            "/join",
            &JoinReq {
                group_name,
                display_name,
                email,
                enc_pubkey: B64.encode(public.enc),
                sign_pubkey: B64.encode(public.sign),
                setup_token: r.setup_token.map(str::trim),
            },
        )
        .await?;
    let id = Identity {
        local_id: random_id(),
        server_url: server,
        ca_pem,
        group_id: resp.group_id,
        group_name: resp.group_name,
        member_id: resp.member_id,
        device_id: resp.device_id,
        display_name: display_name.to_string(),
        email: email.to_string(),
        status: resp.status,
        role: resp.role,
        enc_pubkey: public.enc,
        sign_pubkey: public.sign,
    };
    let s = Arc::new(Secrets::new(&resp.token, &keys));
    {
        let conn = app.db();
        secrets::store(&conn, &id.local_id, &s)?;
        db::save_identity(&conn, &id)?;
        if r.setup_token.is_some() {
            // The group's first key; it never leaves this device except sealed to approved devices.
            secrets::save_group_key(&conn, &s, &crypto::generate_group_key(1))?;
            db::pin_anchor(&conn, &id.device_id, &id.display_name, &public.sign)?;
        }
    }
    app.set_secrets(Some(s));
    if r.setup_token.is_some() {
        // The founder's certificate is self-signed; devices it approves pin its key.
        // If this fails, the first sync retries it.
        if let Err(e) = self_certify(app, &id, &keys).await {
            eprintln!("self-certifying after founding the group failed (will retry): {e:#}");
        }
    }
    Ok(crypto::safety_code(&public))
}

async fn self_certify(app: &App, id: &Identity, me: &DeviceKeys) -> Result<()> {
    let cert = issue_cert(id, me, &own_subject(id, Role::Keymaster));
    let _: serde_json::Value = app.api(id)?.post("/certs", &CertsReq { certs: vec![cert] }).await?;
    Ok(())
}

pub fn own_subject(id: &Identity, role: Role) -> CertSubject<'_> {
    CertSubject {
        group_id: &id.group_id,
        member_id: &id.member_id,
        device_id: &id.device_id,
        display_name: &id.display_name,
        role,
        enc_pk: id.enc_pubkey,
        sign_pk: id.sign_pubkey,
    }
}

pub fn issue_cert(id: &Identity, me: &DeviceKeys, subject: &CertSubject) -> CertUpload {
    let cert = MemberCert::issue(me, &id.device_id, subject);
    CertUpload {
        device_id: cert.device_id,
        role: cert.role.as_str().into(),
        display_name: cert.display_name,
        signature: B64.encode(&cert.signature),
    }
}

// --- waiting for approval --------------------------------------------------------

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JoinProgress {
    Pending { code: String },
    /// A Key Master approved and their signatures check out; the user still
    /// has to type the code that Key Master reads to them.
    Approved { approver_name: String },
    Denied,
    Active,
}

pub async fn join_progress(app: &App) -> Result<JoinProgress> {
    let mut id = app.require_identity()?;
    match id.status.as_str() {
        "active" => return Ok(JoinProgress::Active),
        "denied" => return Ok(JoinProgress::Denied),
        _ => {}
    }
    let js: JoinStatus = app.api(&id)?.get("/join/status").await?;
    match js.status.as_str() {
        "pending" => Ok(JoinProgress::Pending { code: crypto::safety_code(&id.public()) }),
        "denied" => {
            id.status = "denied".into();
            db::set_status(&app.db(), &id.status, &id.role)?;
            Ok(JoinProgress::Denied)
        }
        "active" => {
            let me = app.secrets(&id)?.device_keys()?;
            let a = verify_approval(&id, &me, &js)?;
            Ok(JoinProgress::Approved { approver_name: a.km_name })
        }
        other => bail!("unexpected join status {other}"),
    }
}

struct Approval {
    keys: Vec<GroupKey>,
    anchors: Vec<(String, [u8; 32])>,
    approver: String,
    km_name: String,
    km_keys: DevicePublicKeys,
    role: Option<String>,
}

/// Every grant and the handed-over anchors must be signed by the approving
/// Key Master. Nothing is stored here.
fn verify_approval(id: &Identity, me: &DeviceKeys, js: &JoinStatus) -> Result<Approval> {
    let approver = js.approved_by.clone().context("approved, but the server didn't say by whom")?;
    let first = js.sealed_keys.first().context("approved, but the server returned no sealed group keys")?;
    let km_sign = decode32(&first.signer_sign_pubkey).context("approver signing key")?;
    let km_keys = pubkeys(&first.signer_enc_pubkey, &first.signer_sign_pubkey)?;
    let km_name = first.signer_name.clone().unwrap_or_else(|| "the Key Master".into());

    let mut keys = Vec::new();
    for k in &js.sealed_keys {
        if k.signer_device_id.as_deref() != Some(approver.as_str()) || k.signer_sign_pubkey != first.signer_sign_pubkey {
            bail!("key v{} was granted by someone other than the approving Key Master", k.key_version);
        }
        let sealed = B64.decode(&k.sealed_blob)?;
        let msg = protocol::key_grant_message(&id.group_id, &id.device_id, &id.enc_pubkey, k.key_version, &sealed);
        crypto::verify(&km_sign, &msg, &B64.decode(&k.signature)?)
            .with_context(|| format!("key v{} is not signed by its Key Master; refusing it", k.key_version))?;
        let gk = crypto::unseal_group_key(me, &sealed).with_context(|| format!("can't unseal key v{}", k.key_version))?;
        if gk.version() != k.key_version {
            bail!("sealed key says v{} but was labelled v{}", gk.version(), k.key_version);
        }
        keys.push(gk);
    }
    let mut anchors = Vec::new();
    for a in &js.anchors {
        anchors.push((a.device_id.clone(), decode32(&a.sign_pubkey).context("anchor key")?));
    }
    if !anchors.iter().any(|(aid, pk)| *aid == approver && *pk == km_sign) {
        bail!("the approver's handed-over Key Master list doesn't include the approver");
    }
    crypto::verify(
        &km_sign,
        &protocol::anchors_message(&id.group_id, &id.device_id, &anchors),
        &B64.decode(&js.anchors_signature)?,
    )
    .context("the handed-over Key Master list isn't signed by the approver; refusing it")?;
    Ok(Approval { keys, anchors, approver, km_name, km_keys, role: js.role.clone() })
}

/// Finish joining: the user typed the code the approving Key Master read to them.
pub async fn confirm_approval(app: &App, heard: &str) -> Result<()> {
    let id = app.require_identity()?;
    if id.status != "pending" {
        bail!("this device isn't waiting for approval");
    }
    let s = app.secrets(&id)?;
    let api = app.api(&id)?;
    let js: JoinStatus = api.get("/join/status").await?;
    if js.status != "active" {
        bail!("not approved yet");
    }
    let a = verify_approval(&id, &s.device_keys()?, &js)?;
    if !codes_match(heard, &crypto::safety_code(&a.km_keys)) {
        bail!(
            "That code doesn't match the Key Master who approved you. Don't trust this approval: \
             call a Key Master you know (the server named the approver \"{}\").",
            a.km_name
        );
    }
    {
        let conn = app.db();
        let tx = conn.unchecked_transaction()?;
        for gk in &a.keys {
            secrets::save_group_key(&tx, &s, gk)?;
        }
        for (aid, pk) in &a.anchors {
            let name = if *aid == a.approver { a.km_name.clone() } else { format!("Key Master (vouched for by {})", a.km_name) };
            db::pin_anchor(&tx, aid, &name, pk)?;
        }
        db::set_status(&tx, "active", a.role.as_deref().unwrap_or(&id.role))?;
        tx.commit()?;
    }
    let id = app.require_identity()?;
    if let Err(e) = refresh_roster(app, &id, &api).await {
        eprintln!("roster refresh after joining failed: {e:#}");
    }
    Ok(())
}

/// Start over after a denied or abandoned join, or after being removed (this
/// deletes the saved posts and photos too). Refuses while the device is active.
pub fn reset(app: &App) -> Result<()> {
    let conn = app.db();
    if let Some(id) = db::identity(&conn)? {
        if id.status == "active" {
            bail!("this device is a member of {}; it can't be reset from here", id.group_name);
        }
        secrets::delete(&conn, &id.local_id)?;
    }
    db::wipe(&conn)?;
    drop(conn);
    if let Ok(dir) = std::fs::read_dir(&app.media_dir) {
        for f in dir.flatten() {
            let _ = std::fs::remove_file(f.path());
        }
    }
    app.set_secrets(None);
    Ok(())
}

// --- verified roster ---------------------------------------------------------

fn anchors(app: &App) -> Result<Vec<Anchor>> {
    Ok(db::anchors(&app.db())?.into_iter().map(|(device_id, _, sign_pk)| Anchor { device_id, sign_pk }).collect())
}

/// The server's roster, and the devices in it that verify.
pub struct CheckedRoster {
    pub raw: Roster,
    pub verified: BTreeMap<String, VerifiedDevice>,
    /// Removed or revoked devices whose certificates verified, with the last
    /// event seq before they were cut off. Their events up to then still count.
    pub former: BTreeMap<String, (VerifiedDevice, i64)>,
    /// The same devices with the last direct message seq before they were cut off.
    pub former_dm: BTreeMap<String, (VerifiedDevice, i64)>,
}

/// Certificates as the server relays them, rebuilt with our own group id and
/// the claimed fields; any lie breaks the signature.
fn certs_of(group_id: &str, members: &[Member]) -> Vec<MemberCert> {
    let mut certs = Vec::new();
    for m in members {
        for d in &m.devices {
            let (Ok(enc_pk), Ok(sign_pk)) = (decode32(&d.enc_pubkey), decode32(&d.sign_pubkey)) else { continue };
            for c in &d.certs {
                let (Some(role), Ok(signature)) = (Role::parse(&c.role), B64.decode(&c.signature)) else { continue };
                certs.push(MemberCert {
                    group_id: group_id.to_string(),
                    member_id: m.id.clone(),
                    device_id: d.id.clone(),
                    display_name: c.display_name.clone(),
                    role,
                    enc_pk,
                    sign_pk,
                    issuer_device_id: c.issuer_device_id.clone(),
                    signature,
                });
            }
        }
    }
    certs
}

/// Fetch the roster, keep only devices whose certificates chain to our anchors,
/// cache them, and pick up our own promotion.
pub async fn refresh_roster(app: &App, id: &Identity, api: &Api) -> Result<CheckedRoster> {
    let raw: Roster = api.get("/members").await?;
    let certs = certs_of(&id.group_id, &raw.members);
    let anchor_list = anchors(app)?;
    let verified = roster::verify_roster(&id.group_id, &anchor_list, &certs);
    // Former devices are checked as the roster stood with them in it; they
    // only ever count as authors of events up to their cut-off.
    let mut all = certs.clone();
    all.extend(certs_of(&id.group_id, &raw.former));
    let everyone = roster::verify_roster(&id.group_id, &anchor_list, &all);
    let cut_off = |pick: fn(&crate::api::MemberDevice) -> Option<i64>| -> BTreeMap<String, (VerifiedDevice, i64)> {
        raw.former
            .iter()
            .flat_map(|m| m.devices.iter().map(move |d| (m, d)))
            .filter(|(_, d)| !verified.contains_key(&d.id))
            .filter_map(|(m, d)| {
                let v = everyone.get(&d.id).filter(|v| v.member_id == m.id)?;
                Some((d.id.clone(), (v.clone(), pick(d)?)))
            })
            .collect()
    };
    let former = cut_off(|d| d.revoked_seq);
    let former_dm = cut_off(|d| d.revoked_dm_seq);

    // A Key Master whose own key is an anchor but who has no certificate yet
    // (founding's /certs call failed) certifies itself now.
    let self_anchor = anchor_list.iter().any(|a| a.device_id == id.device_id && a.sign_pk == id.sign_pubkey);
    if id.is_keymaster() && self_anchor && !verified.contains_key(&id.device_id) {
        let me = app.secrets(id)?.device_keys()?;
        // The next refresh sees the new certificate.
        self_certify(app, id, &me).await?;
    }

    let conn = app.db();
    let tx = conn.unchecked_transaction()?;
    tx.execute("UPDATE member_devices SET verified = 0", [])?;
    let mut by_member: BTreeMap<&str, &VerifiedDevice> = BTreeMap::new();
    for v in verified.values() {
        tx.execute(
            "INSERT OR REPLACE INTO member_devices (device_id, member_id, sign_pubkey, enc_pubkey, verified)
             VALUES (?1, ?2, ?3, ?4, 1)",
            rusqlite::params![v.device_id, v.member_id, &v.sign_pk[..], &v.enc_pk[..]],
        )?;
        let e = by_member.entry(&v.member_id).or_insert(v);
        if v.role > e.role {
            *e = v;
        }
    }
    for v in by_member.values() {
        tx.execute(
            "INSERT INTO members (id, display_name, role) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, role = excluded.role",
            rusqlite::params![v.member_id, v.display_name, v.role.as_str()],
        )?;
    }
    // Names for posts by people who have since left (kept if we already had them).
    for (v, _) in former.values() {
        tx.execute(
            "INSERT OR IGNORE INTO members (id, display_name, role) VALUES (?1, ?2, ?3)",
            rusqlite::params![v.member_id, v.display_name, v.role.as_str()],
        )?;
    }
    // Certified names replace the placeholder names of pinned Key Masters.
    for a in &anchor_list {
        if let Some(v) = verified.get(&a.device_id) {
            tx.execute("UPDATE anchors SET name = ?1 WHERE device_id = ?2", rusqlite::params![v.display_name, a.device_id])?;
        }
    }
    // Promotion: believe it only when a verified Key Master certificate says so.
    if let Some(me) = verified.get(&id.device_id) {
        // A Key Master accepted the name we chose: our certificate carries it now.
        if me.display_name != id.display_name {
            db::set_display_name(&tx, &me.display_name)?;
        }
        if me.role == Role::Keymaster && id.role != "keymaster" {
            db::set_status(&tx, "active", "keymaster")?;
            db::pin_anchor(&tx, &id.device_id, &id.display_name, &id.sign_pubkey)?;
        }
    }
    tx.commit()?;
    Ok(CheckedRoster { raw, verified, former, former_dm })
}

// --- Key Master: pending joins -------------------------------------------------

#[derive(Serialize)]
pub struct PendingView {
    pub device_id: String,
    pub display_name: String,
    pub email: String,
    pub existing_member: bool,
    pub keymaster: bool,
}

/// Pending joins. The expected safety code is deliberately not included: the
/// Key Master types what they heard and the app checks it.
pub async fn list_pending(app: &App) -> Result<Vec<PendingView>> {
    let id = app.require_keymaster()?;
    let list: PendingList = app.api(&id)?.get("/joins/pending").await?;
    Ok(list
        .pending
        .into_iter()
        .map(|p| PendingView {
            keymaster: p.role == "keymaster",
            device_id: p.device_id,
            display_name: p.display_name,
            email: p.email,
            existing_member: p.existing_member,
        })
        .collect())
}

#[derive(Serialize)]
pub struct Approved {
    pub display_name: String,
    /// This Key Master's own code, to read back to the new member.
    pub km_code: String,
}

pub async fn approve(app: &App, device_id: &str, heard: &str, as_keymaster: bool) -> Result<Approved> {
    let id = app.require_keymaster()?;
    let s = app.secrets(&id)?;
    let me = s.device_keys()?;
    let api = app.api(&id)?;
    let list: PendingList = api.get("/joins/pending").await?;
    let p = list
        .pending
        .iter()
        .find(|p| p.device_id == device_id)
        .context("that request is no longer pending")?;
    let theirs = pubkeys(&p.enc_pubkey, &p.sign_pubkey)?;
    // Computed here from the keys the server relayed, so a swapped key gives a different code.
    if !codes_match(heard, &crypto::safety_code(&theirs)) {
        bail!(
            "That isn't the code for this request. Don't approve it: check you heard it right, \
             and if it still doesn't match, someone may have swapped their keys. Deny it."
        );
    }
    let role = Role::parse(&p.role).context("unknown role")?;
    if role == Role::Keymaster && !as_keymaster {
        bail!("This device would get Key Master rights. Tick the Key Master box if that's really {}.", p.display_name);
    }
    // The relay insists on the current key version; make sure we have it.
    let roster = refresh_roster(app, &id, &api).await?;
    crate::manage::refresh_keys(app, &id, &api, &roster.verified).await?;
    let (group_keys, anchor_list) = {
        let conn = app.db();
        // Pin ourselves (a promoted Key Master might not have yet).
        db::pin_anchor(&conn, &id.device_id, &id.display_name, &id.sign_pubkey)?;
        let a: Vec<(String, [u8; 32])> = db::anchors(&conn)?.into_iter().map(|(d, _, k)| (d, k)).collect();
        (secrets::all_group_keys(&conn, &s)?, a)
    };
    if group_keys.is_empty() {
        bail!("this device holds no group keys to share");
    }
    let sealed_keys = group_keys
        .iter()
        .map(|gk| {
            let (sealed, sig) = crypto::grant_group_key(&me, &id.group_id, device_id, &theirs.enc, gk);
            SealedKeyUpload { key_version: gk.version(), sealed_blob: B64.encode(&sealed), signature: B64.encode(sig) }
        })
        .collect();
    let cert = issue_cert(
        &id,
        &me,
        &CertSubject {
            group_id: &id.group_id,
            member_id: &p.member_id,
            device_id,
            display_name: &p.display_name,
            role,
            enc_pk: theirs.enc,
            sign_pk: theirs.sign,
        },
    );
    let anchors_sig = crypto::sign(&me, &protocol::anchors_message(&id.group_id, device_id, &anchor_list));
    let _: serde_json::Value = api
        .post(
            &format!("/joins/{device_id}/approve"),
            &ApproveReq {
                sealed_keys,
                cert,
                anchors: anchor_list
                    .iter()
                    .map(|(d, pk)| AnchorJson { device_id: d.clone(), sign_pubkey: B64.encode(pk) })
                    .collect(),
                anchors_signature: B64.encode(anchors_sig),
            },
        )
        .await?;
    Ok(Approved { display_name: p.display_name.clone(), km_code: crypto::safety_code(&me.public()) })
}

pub async fn deny(app: &App, device_id: &str) -> Result<()> {
    let id = app.require_keymaster()?;
    let _: serde_json::Value = app.api(&id)?.post(&format!("/joins/{device_id}/deny"), &serde_json::json!({})).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_compare_loosely_but_not_emptily() {
        assert!(codes_match("tiger river maple lemon 42", "TIGER-RIVER-MAPLE-LEMON-42"));
        assert!(!codes_match("TIGER-RIVER-MAPLE-LEMON-43", "TIGER-RIVER-MAPLE-LEMON-42"));
        assert!(!codes_match("", ""));
        assert!(!codes_match("--", ""));
    }
}
