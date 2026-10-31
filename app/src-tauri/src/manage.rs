//! Phase 6: the member list, Key Master actions (promote, remove, revoke a
//! device), group key rotation, picking up rotated keys, and noticing that
//! this device has been removed.
//!
//! Rotation follows the join rules: the new key is sealed to each remaining
//! device's X25519 key *from the verified roster* and every grant is signed by
//! the rotating Key Master (`crypto::grant_group_key`). Receivers accept a new
//! version only if its grant is signed by a Key Master in their own verified
//! roster. Old versions stay, so old posts keep decrypting.

use crate::account::{self, issue_cert, CheckedRoster};
use crate::api::*;
use crate::db::{self, Identity};
use crate::secrets;
use crate::state::App;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use sidetray_crypto::roster::{CertSubject, Role, VerifiedDevice};
use sidetray_crypto::{self as crypto, DeviceKeys, GroupKey};
use std::collections::{BTreeMap, BTreeSet};

// --- picking up new keys -----------------------------------------------------------

/// Fetch this device's sealed keys and store any version it doesn't have yet.
/// A grant counts only if a Key Master in the verified roster signed it.
/// Returns the server's answer (current version, rotation pending).
pub async fn refresh_keys(app: &App, id: &Identity, api: &Api, verified: &BTreeMap<String, VerifiedDevice>) -> Result<KeysResp> {
    let keys: KeysResp = api.get("/keys").await?;
    let s = app.secrets(id)?;
    let me = s.device_keys()?;
    let have: BTreeSet<u32> = secrets::key_versions(&app.db())?.into_iter().collect();
    for k in keys.sealed_keys.iter().filter(|k| !have.contains(&k.key_version)) {
        match open_grant(id, &me, verified, k) {
            Ok(gk) => secrets::save_group_key(&app.db(), &s, &gk)?,
            // Refused grants are skipped (events under that version then fail
            // to decrypt and are counted as rejected), not fatal for the sync.
            Err(e) => eprintln!("refusing group key v{}: {e:#}", k.key_version),
        }
    }
    Ok(keys)
}

fn open_grant(id: &Identity, me: &DeviceKeys, verified: &BTreeMap<String, VerifiedDevice>, k: &SealedKey) -> Result<GroupKey> {
    let signer = k.signer_device_id.as_deref().context("the server didn't say who granted it")?;
    let km = verified
        .get(signer)
        .filter(|v| v.role == Role::Keymaster)
        .with_context(|| format!("it was granted by device {signer}, which isn't a verified Key Master"))?;
    let sealed = B64.decode(&k.sealed_blob).context("bad base64")?;
    let sig = B64.decode(&k.signature).context("bad base64")?;
    crypto::open_key_grant(me, &id.group_id, &id.device_id, k.key_version, &sealed, &sig, &km.sign_pk)
        .with_context(|| format!("its grant from {} doesn't check out", km.display_name))
}

/// Roster plus keys, for when a post was refused because a newer key exists.
pub async fn refresh_keys_now(app: &App) -> Result<()> {
    let id = app.require_active()?;
    let api = app.api(&id)?;
    let roster = account::refresh_roster(app, &id, &api).await?;
    let keys = refresh_keys(app, &id, &api, &roster.verified).await?;
    let latest = secrets::key_versions(&app.db())?.last().copied().unwrap_or(0);
    if latest < keys.key_version {
        bail!("the group key changed (v{}) and this device couldn't verify the new one", keys.key_version);
    }
    Ok(())
}

// --- rotation --------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct Rotated {
    pub key_version: u32,
    pub devices: usize,
}

/// Key Master, while a removal or revocation is waiting for it (the relay says
/// `rotation_pending`): make group key version N+1, seal it to every active
/// device in the verified roster (this one included), sign each grant, and
/// upload it. Every device the server lists must verify, or nothing is sent.
/// If nothing is pending (another Key Master got there first) it returns the
/// current version with `devices: 0`.
pub async fn rotate(app: &App) -> Result<Rotated> {
    let _one_at_a_time = app.rotate_lock.lock().await;
    let id = app.require_keymaster()?;
    let api = app.api(&id)?;
    let s = app.secrets(&id)?;
    let me = s.device_keys()?;
    let mut last_err = None;
    for _ in 0..3 {
        let roster = account::refresh_roster(app, &id, &api).await?;
        let keys = refresh_keys(app, &id, &api, &roster.verified).await?;
        if !keys.rotation_pending {
            // Already done (by us a moment ago, or by another Key Master).
            return Ok(Rotated { key_version: keys.key_version, devices: 0 });
        }
        let gk = crypto::generate_group_key(keys.key_version + 1);
        let sealed_keys = grants_for(&id, &me, &roster, &gk)?;
        let devices = sealed_keys.len();
        let req = RotateReq { key_version: gk.version(), sealed_keys };
        match api.post::<_, serde_json::Value>("/keys/rotate", &req).await {
            Ok(_) => {
                secrets::save_group_key(&app.db(), &s, &gk)?;
                return Ok(Rotated { key_version: gk.version(), devices });
            }
            // Someone rotated first, or a device joined or left meanwhile: look again.
            Err(e) if is_status(&e, 409) || is_status(&e, 422) => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("set on every retry")).context("the group's devices kept changing while changing the key")
}

/// One signed grant per device the server lists, using only verified keys.
fn grants_for(id: &Identity, me: &DeviceKeys, roster: &CheckedRoster, gk: &GroupKey) -> Result<Vec<GrantUpload>> {
    let mut out = Vec::new();
    for m in &roster.raw.members {
        for d in &m.devices {
            let v = roster.verified.get(&d.id).filter(|v| v.member_id == m.id).with_context(|| {
                format!(
                    "{}'s device {} has no valid member certificate, so this app won't hand it the new key. \
                     Revoke that device and try again.",
                    m.display_name, d.id
                )
            })?;
            let (sealed, sig) = crypto::grant_group_key(me, &id.group_id, &v.device_id, &v.enc_pk, gk);
            out.push(GrantUpload { device_id: v.device_id.clone(), sealed_blob: B64.encode(&sealed), signature: B64.encode(sig) });
        }
    }
    if !out.iter().any(|g| g.device_id == id.device_id) {
        bail!("this device isn't in the verified roster itself; can't rotate the key from here");
    }
    Ok(out)
}

/// Key Master, during a sync: finish a rotation a removal left pending (this
/// app crashed in between, or a Key Master removed someone with the CLI).
pub async fn rotate_if_pending(app: &App, keys: &KeysResp) -> Option<Result<Rotated>> {
    if !keys.rotation_pending {
        return None;
    }
    Some(rotate(app).await)
}

// --- Key Master actions ------------------------------------------------------------

#[derive(Serialize)]
pub struct Change {
    pub name: String,
    /// The new key, if rotation went through.
    pub rotated: Option<Rotated>,
    /// Why it didn't; the next sync tries again.
    pub rotate_error: Option<String>,
}

/// After someone is cut off, devices whose only certificate chain ran through
/// a removed Key Master would stop verifying (and rotation would refuse to
/// seal to them). Re-certify the ones this app verified just before, with the
/// same keys, role and name. Returns how many.
async fn recertify(app: &App, id: &Identity, api: &Api, before: &BTreeMap<String, VerifiedDevice>) -> Result<usize> {
    let now = account::refresh_roster(app, id, api).await?;
    let me = app.secrets(id)?.device_keys()?;
    let mut certs = Vec::new();
    for m in &now.raw.members {
        for d in &m.devices {
            if now.verified.contains_key(&d.id) {
                continue;
            }
            let Some(v) = before.get(&d.id).filter(|v| v.member_id == m.id) else { continue };
            let same_keys = account::decode32(&d.enc_pubkey).is_ok_and(|k| k == v.enc_pk)
                && account::decode32(&d.sign_pubkey).is_ok_and(|k| k == v.sign_pk);
            if !same_keys {
                continue;
            }
            certs.push(issue_cert(
                id,
                &me,
                &CertSubject {
                    group_id: &id.group_id,
                    member_id: &v.member_id,
                    device_id: &v.device_id,
                    display_name: &v.display_name,
                    role: v.role,
                    enc_pk: v.enc_pk,
                    sign_pk: v.sign_pk,
                },
            ));
        }
    }
    let n = certs.len();
    if n > 0 {
        let _: serde_json::Value = api.post("/certs", &CertsReq { certs }).await?;
    }
    Ok(n)
}

async fn rotate_after(app: &App, name: String) -> Change {
    match rotate(app).await {
        Ok(r) => Change { name, rotated: Some(r), rotate_error: None },
        Err(e) => {
            eprintln!("rotating the key after a removal failed (the next sync retries): {e:#}");
            Change { name, rotated: None, rotate_error: Some(format!("{e:#}")) }
        }
    }
}

fn member_name(app: &App, member_id: &str) -> String {
    app.db()
        .query_row("SELECT display_name FROM members WHERE id = ?1", [member_id], |r| r.get(0))
        .unwrap_or_else(|_| "that member".into())
}

/// Sign Key Master certificates for every device of a verified member.
pub async fn promote(app: &App, member_id: &str) -> Result<String> {
    let id = app.require_keymaster()?;
    let api = app.api(&id)?;
    let me = app.secrets(&id)?.device_keys()?;
    let roster = account::refresh_roster(app, &id, &api).await?;
    let m = roster.raw.members.iter().find(|m| m.id == member_id).context("that person isn't an active member")?;
    let mut certs = Vec::new();
    let mut name = m.display_name.clone();
    for d in &m.devices {
        // Only promote keys we've verified ourselves.
        let v = roster.verified.get(&d.id).filter(|v| v.member_id == member_id).with_context(|| {
            format!("{} has a device without a valid certificate; not promoting unverified keys", m.display_name)
        })?;
        name = v.display_name.clone();
        certs.push(issue_cert(
            &id,
            &me,
            &CertSubject {
                group_id: &id.group_id,
                member_id: &v.member_id,
                device_id: &v.device_id,
                display_name: &v.display_name,
                role: Role::Keymaster,
                enc_pk: v.enc_pk,
                sign_pk: v.sign_pk,
            },
        ));
    }
    if certs.is_empty() {
        bail!("{name} has no active devices to promote");
    }
    let _: serde_json::Value = api.post(&format!("/members/{member_id}/role"), &RoleReq { role: "keymaster", certs }).await?;
    account::refresh_roster(app, &id, &api).await?;
    Ok(name)
}

/// Accept the name a member chose in their (signed) profile: re-sign the
/// certificates of all their devices with it, same keys and role.
pub async fn accept_name(app: &App, member_id: &str) -> Result<String> {
    let id = app.require_keymaster()?;
    let api = app.api(&id)?;
    let me = app.secrets(&id)?.device_keys()?;
    let roster = account::refresh_roster(app, &id, &api).await?;
    let m = roster.raw.members.iter().find(|m| m.id == member_id).context("that person isn't an active member")?;
    let name = crate::profile::chosen_name(&app.db(), member_id).context("they haven't chosen a different name")?;
    let mut certs = Vec::new();
    for d in &m.devices {
        let v = roster.verified.get(&d.id).filter(|v| v.member_id == member_id).with_context(|| {
            format!("{} has a device without a valid certificate; not certifying unverified keys", m.display_name)
        })?;
        certs.push(issue_cert(
            &id,
            &me,
            &CertSubject {
                group_id: &id.group_id,
                member_id: &v.member_id,
                device_id: &v.device_id,
                display_name: &name,
                role: v.role,
                enc_pk: v.enc_pk,
                sign_pk: v.sign_pk,
            },
        ));
    }
    if certs.is_empty() {
        bail!("they have no active devices");
    }
    let _: serde_json::Value =
        api.post(&format!("/members/{member_id}/name"), &serde_json::json!({ "display_name": name, "certs": certs })).await?;
    account::refresh_roster(app, &id, &api).await?;
    Ok(name)
}

/// Remove a member (all their devices), then rotate the group key.
pub async fn remove_member(app: &App, member_id: &str) -> Result<Change> {
    let id = app.require_keymaster()?;
    if member_id == id.member_id {
        bail!("you can't remove yourself; ask another Key Master");
    }
    let name = member_name(app, member_id);
    let api = app.api(&id)?;
    let before = account::refresh_roster(app, &id, &api).await?.verified;
    let _: serde_json::Value = api.post(&format!("/members/{member_id}/remove"), &serde_json::json!({})).await?;
    if let Err(e) = recertify(app, &id, &api, &before).await {
        eprintln!("re-certifying devices after the removal: {e:#}");
    }
    Ok(rotate_after(app, name).await)
}

/// Revoke one device (lost or replaced), then rotate the group key.
pub async fn revoke_device(app: &App, device_id: &str) -> Result<Change> {
    let id = app.require_keymaster()?;
    if device_id == id.device_id {
        bail!("that's this device; revoke it from another one");
    }
    let owner: Option<String> =
        app.db().query_row("SELECT member_id FROM member_devices WHERE device_id = ?1", [device_id], |r| r.get(0)).ok();
    let name = owner.map(|m| format!("{}'s device", member_name(app, &m))).unwrap_or_else(|| "the device".into());
    let api = app.api(&id)?;
    let before = account::refresh_roster(app, &id, &api).await?.verified;
    let _: serde_json::Value = api.post(&format!("/devices/{device_id}/revoke"), &serde_json::json!({})).await?;
    if let Err(e) = recertify(app, &id, &api, &before).await {
        eprintln!("re-certifying devices after the revocation: {e:#}");
    }
    Ok(rotate_after(app, name).await)
}

// --- the member list ---------------------------------------------------------------

#[derive(Serialize)]
pub struct MemberView {
    pub id: String,
    /// The certified name.
    pub name: String,
    /// Key Masters only: the name they chose in their profile, if it differs
    /// from the certified one (waiting for a Key Master to accept it).
    pub chosen_name: Option<String>,
    pub avatar: Option<String>,
    /// "keymaster" or "member", from certificates (the server's claim if none verify).
    pub role: String,
    /// "verified", "partial" (some devices don't verify) or "unverified".
    pub cert_status: String,
    pub me: bool,
    pub devices: Vec<DeviceView>,
}

#[derive(Serialize)]
pub struct DeviceView {
    pub id: String,
    pub verified: bool,
    pub keymaster: bool,
    /// Who signed the certificate that set its role.
    pub certified_by: Option<String>,
    pub this_device: bool,
    pub last_seen: Option<i64>,
    pub joined_at: Option<i64>,
}

pub async fn list_members(app: &App) -> Result<Vec<MemberView>> {
    let id = app.require_active()?;
    let api = app.api(&id)?;
    let roster = account::refresh_roster(app, &id, &api).await?;
    let anchor_names: BTreeMap<String, String> = db::anchors(&app.db())?.into_iter().map(|(d, n, _)| (d, n)).collect();
    let mut views = member_views(&id, &roster, &anchor_names);
    let conn = app.db();
    for v in &mut views {
        let (avatar, chosen) = crate::profile::view(&conn, &v.id);
        v.avatar = avatar;
        v.chosen_name = chosen.filter(|c| id.is_keymaster() && *c != v.name && v.cert_status != "unverified");
    }
    Ok(views)
}

fn member_views(id: &Identity, roster: &CheckedRoster, anchor_names: &BTreeMap<String, String>) -> Vec<MemberView> {
    let issuer_name = |dev: &str| -> String {
        roster
            .verified
            .get(dev)
            .map(|v| v.display_name.clone())
            .or_else(|| anchor_names.get(dev).cloned())
            .unwrap_or_else(|| "a Key Master".into())
    };
    roster
        .raw
        .members
        .iter()
        .map(|m| {
            let mine: Vec<&VerifiedDevice> =
                m.devices.iter().filter_map(|d| roster.verified.get(&d.id).filter(|v| v.member_id == m.id)).collect();
            let top = mine.iter().max_by_key(|v| v.role);
            let cert_status = match (mine.len(), m.devices.len()) {
                (0, _) => "unverified",
                (n, total) if n < total => "partial",
                _ => "verified",
            };
            MemberView {
                id: m.id.clone(),
                name: top.map(|v| v.display_name.clone()).unwrap_or_else(|| m.display_name.clone()),
                chosen_name: None,
                avatar: None,
                role: top.map(|v| v.role.as_str()).unwrap_or("member").into(),
                cert_status: cert_status.into(),
                me: m.id == id.member_id,
                devices: m
                    .devices
                    .iter()
                    .map(|d| {
                        let v = roster.verified.get(&d.id).filter(|v| v.member_id == m.id);
                        DeviceView {
                            id: d.id.clone(),
                            verified: v.is_some(),
                            keymaster: v.is_some_and(|v| v.role == Role::Keymaster),
                            certified_by: v.map(|v| issuer_name(&v.issuer_device_id)),
                            this_device: d.id == id.device_id,
                            last_seen: d.last_seen,
                            joined_at: d.joined_at,
                        }
                    })
                    .collect(),
            }
        })
        .collect()
}

// --- being removed -----------------------------------------------------------------

/// Ask the relay where this device stands (after a `removed` push or a 401).
/// If it was removed or revoked, record that locally, which stops syncing;
/// the archive stays. Returns the new status if it changed.
pub async fn check_standing(app: &App) -> Result<Option<String>> {
    let id = app.require_identity()?;
    if id.status != "active" {
        return Ok(None);
    }
    let js: JoinStatus = app.api(&id)?.get("/join/status").await?;
    let status = match js.status.as_str() {
        "active" | "pending" => return Ok(None),
        "removed" => "removed",
        _ => "revoked",
    };
    db::set_status(&app.db(), status, &id.role)?;
    Ok(Some(status.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidetray_crypto::roster::MemberCert;

    fn roster_with(km: &DeviceKeys, devices: &[(&str, &str, &DeviceKeys, Role, bool)]) -> CheckedRoster {
        // (member, device, keys, role, certified)
        let mut raw_members: Vec<Member> = Vec::new();
        let mut verified = BTreeMap::new();
        for (m, d, k, role, certified) in devices {
            let p = k.public();
            let md = MemberDevice {
                id: d.to_string(),
                enc_pubkey: B64.encode(p.enc),
                sign_pubkey: B64.encode(p.sign),
                certs: vec![],
                last_seen: None,
                joined_at: None,
                revoked_seq: None,
                revoked_dm_seq: None,
            };
            match raw_members.iter_mut().find(|x| x.id == *m) {
                Some(x) => x.devices.push(md),
                None => raw_members.push(Member { id: m.to_string(), display_name: m.to_string(), devices: vec![md] }),
            }
            if *certified {
                let c = MemberCert::issue(
                    km,
                    "d_km",
                    &CertSubject { group_id: "g", member_id: m, device_id: d, display_name: m, role: *role, enc_pk: p.enc, sign_pk: p.sign },
                );
                verified.insert(
                    d.to_string(),
                    VerifiedDevice {
                        member_id: c.member_id,
                        device_id: c.device_id,
                        display_name: c.display_name,
                        role: c.role,
                        enc_pk: c.enc_pk,
                        sign_pk: c.sign_pk,
                        issuer_device_id: c.issuer_device_id,
                    },
                );
            }
        }
        CheckedRoster { raw: Roster { members: raw_members, former: vec![] }, verified, former: BTreeMap::new(), former_dm: BTreeMap::new() }
    }

    fn identity(member: &str, device: &str, k: &DeviceKeys) -> Identity {
        let p = k.public();
        Identity {
            local_id: "x".into(),
            server_url: "https://example.org".into(),
            ca_pem: None,
            group_id: "g".into(),
            group_name: "G".into(),
            member_id: member.into(),
            device_id: device.into(),
            display_name: member.into(),
            email: "e@x".into(),
            status: "active".into(),
            role: "keymaster".into(),
            enc_pubkey: p.enc,
            sign_pubkey: p.sign,
        }
    }

    #[test]
    fn rotation_grants_open_for_each_remaining_device_only() {
        let km = crypto::generate_device_keys();
        let ana = crypto::generate_device_keys();
        let roster = roster_with(&km, &[("m_km", "d_km", &km, Role::Keymaster, true), ("m_ana", "d_ana", &ana, Role::Member, true)]);
        let gk = crypto::generate_group_key(2);
        let me = identity("m_km", "d_km", &km);
        let grants = grants_for(&me, &km, &roster, &gk).unwrap();
        assert_eq!(grants.iter().map(|g| g.device_id.as_str()).collect::<Vec<_>>(), ["d_km", "d_ana"]);

        // Ana's side: a grant signed by a verified Key Master opens...
        let ana_id = identity("m_ana", "d_ana", &ana);
        let g = &grants[1];
        let sk = SealedKey {
            key_version: 2,
            sealed_blob: g.sealed_blob.clone(),
            signature: g.signature.clone(),
            signer_device_id: Some("d_km".into()),
            signer_sign_pubkey: String::new(),
            signer_enc_pubkey: String::new(),
            signer_name: None,
        };
        assert!(open_grant(&ana_id, &ana, &roster.verified, &sk).unwrap() == gk);
        // ...but not if the server claims a member signed it, or relabels it.
        let mut by_member = sk.clone();
        by_member.signer_device_id = Some("d_ana".into());
        assert!(open_grant(&ana_id, &ana, &roster.verified, &by_member).is_err());
        let mut relabelled = sk.clone();
        relabelled.key_version = 3;
        assert!(open_grant(&ana_id, &ana, &roster.verified, &relabelled).is_err());
        // Someone else's grant doesn't open for Ana.
        let mut kms = sk.clone();
        kms.sealed_blob = grants[0].sealed_blob.clone();
        kms.signature = grants[0].signature.clone();
        assert!(open_grant(&ana_id, &ana, &roster.verified, &kms).is_err());
    }

    #[test]
    fn rotation_refuses_unverified_devices() {
        let km = crypto::generate_device_keys();
        let x = crypto::generate_device_keys();
        let roster = roster_with(&km, &[("m_km", "d_km", &km, Role::Keymaster, true), ("m_x", "d_x", &x, Role::Member, false)]);
        let err = grants_for(&identity("m_km", "d_km", &km), &km, &roster, &crypto::generate_group_key(2)).err().expect("refused");
        assert!(format!("{err}").contains("no valid member certificate"));
    }

    #[test]
    fn member_list_shows_certificate_status() {
        let km = crypto::generate_device_keys();
        let (a1, a2, x) = (crypto::generate_device_keys(), crypto::generate_device_keys(), crypto::generate_device_keys());
        let roster = roster_with(
            &km,
            &[
                ("m_km", "d_km", &km, Role::Keymaster, true),
                ("m_ana", "d_a1", &a1, Role::Member, true),
                ("m_ana", "d_a2", &a2, Role::Member, false),
                ("m_x", "d_x", &x, Role::Member, false),
            ],
        );
        let names = BTreeMap::from([("d_km".to_string(), "James".to_string())]);
        let v = member_views(&identity("m_km", "d_km", &km), &roster, &names);
        let st: Vec<(&str, &str, &str, bool)> = v.iter().map(|m| (m.id.as_str(), m.role.as_str(), m.cert_status.as_str(), m.me)).collect();
        assert_eq!(
            st,
            [("m_km", "keymaster", "verified", true), ("m_ana", "member", "partial", false), ("m_x", "member", "unverified", false)]
        );
        // The certificate's issuer is named from the verified roster.
        assert_eq!(v[1].devices[0].certified_by.as_deref(), Some("m_km"));
        assert!(v[0].devices[0].this_device && v[1].devices[1].certified_by.is_none());
    }
}
