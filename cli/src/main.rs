//! `sidetray`: a development CLI for the join / Key Master flow (SPEC.md Phase 3).
//!
//! Every invocation acts as one device whose state lives in `--state <dir>`,
//! so a Key Master and a new member can run side by side on one machine.
//!
//! The roster from the server is never trusted as-is: every device needs a
//! member certificate that chains to a Key Master key this device pinned
//! (see `sidetray_crypto::roster`). Unverified devices are shown as such and
//! their posts are refused.

mod api;
mod state;

use anyhow::{bail, Context, Result};
use api::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use sidetray_crypto::roster::{self, Anchor, CertSubject, MemberCert, Role, VerifiedDevice};
use sidetray_crypto::{self as crypto, protocol, DeviceKeys, DevicePublicKeys};
use state::{decode32, Identity, State, TrustedKeymaster};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "sidetray", version, about = "Side Tray dev CLI")]
struct Cli {
    /// Directory holding this device's keys and state.
    #[arg(long, global = true, env = "SIDETRAY_STATE", default_value = ".sidetray")]
    state: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct Account {
    /// Relay address, e.g. https://10.1.1.188
    #[arg(long)]
    server: String,
    /// Extra root CA to trust (PEM), e.g. Caddy's internal root.crt.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// Group name.
    #[arg(long)]
    group: String,
    /// Your display name.
    #[arg(long)]
    name: String,
    #[arg(long)]
    email: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the group on an empty server and become its Key Master.
    InitGroup {
        #[command(flatten)]
        account: Account,
        /// The server operator's SIDETRAY_SETUP_TOKEN.
        #[arg(long, env = "SIDETRAY_SETUP_TOKEN", hide_env_values = true)]
        setup_token: String,
    },
    /// Ask to join an existing group; prints the safety code to read to a Key Master.
    Join {
        #[command(flatten)]
        account: Account,
    },
    /// Key Master: list devices waiting to join, with their safety codes.
    Pending,
    /// Key Master: approve a device after comparing safety codes on the phone.
    Approve {
        device_id: String,
        /// The code the new member read to you. Must match the code computed here.
        #[arg(long)]
        code: String,
        /// Required when the device belongs to an existing Key Master: it will get Key Master rights.
        #[arg(long)]
        keymaster: bool,
    },
    /// Key Master: reject a join request.
    Deny { device_id: String },
    /// Show this device. After approval, finish joining with the Key Master's code.
    Status {
        /// The code the approving Key Master read to you. Needed once, to finish joining.
        #[arg(long)]
        km_code: Option<String>,
    },
    /// Key Master: certify your own device, or an active device approved before
    /// certificates existed (needs that device's safety code).
    Certify {
        device_id: Option<String>,
        #[arg(long, requires = "device_id")]
        code: Option<String>,
        /// Certify it as a Key Master device rather than a member.
        #[arg(long)]
        keymaster: bool,
    },
    /// Key Master: promote a verified member to Key Master.
    Promote { member_id: String },
    /// List verified members and their devices, and flag anything unverified.
    Members,
    /// Encrypt, sign and post a text post.
    Post { text: String },
    /// Fetch new events, verify and decrypt them, and acknowledge.
    Pull,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let dir = cli.state.as_path();
    match cli.cmd {
        Cmd::InitGroup { account, setup_token } => register(dir, account, Some(&setup_token)),
        Cmd::Join { account } => register(dir, account, None),
        Cmd::Pending => pending(dir),
        Cmd::Approve { device_id, code, keymaster } => approve(dir, &device_id, &code, keymaster),
        Cmd::Deny { device_id } => deny(dir, &device_id),
        Cmd::Status { km_code } => status(dir, km_code.as_deref()),
        Cmd::Certify { device_id, code, keymaster } => certify(dir, device_id.as_deref(), code.as_deref(), keymaster),
        Cmd::Promote { member_id } => promote(dir, &member_id),
        Cmd::Members => members(dir),
        Cmd::Post { text } => post(dir, &text),
        Cmd::Pull => pull(dir),
    }
}

fn api_for(st: &State) -> Result<Api> {
    Api::new(&st.server, st.ca_pem.as_deref(), Some(&st.token))
}

fn pubkeys(enc_b64: &str, sign_b64: &str) -> Result<DevicePublicKeys> {
    Ok(DevicePublicKeys { enc: decode32(enc_b64)?, sign: decode32(sign_b64)? })
}

fn role_label(role: &str) -> &str {
    if role == "keymaster" {
        "Key Master"
    } else {
        "member"
    }
}

/// Codes are compared case-insensitively, ignoring spaces and dashes.
fn codes_match(a: &str, b: &str) -> bool {
    let n = |c: &str| -> String { c.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect() };
    n(a) == n(b)
}

// --- certificates and the verified roster -------------------------------------

/// Sign a member certificate for a device and package it for upload.
fn issue_cert(st: &State, me: &DeviceKeys, subject: &CertSubject) -> CertUpload {
    let cert = MemberCert::issue(me, &st.device_id, subject);
    CertUpload {
        device_id: cert.device_id,
        role: cert.role.as_str().into(),
        display_name: cert.display_name,
        signature: B64.encode(&cert.signature),
    }
}

/// Pin this device's own key as an anchor; only meaningful for a Key Master.
fn pin_self(st: &mut State, me: &DeviceKeys) {
    let p = me.public();
    st.trusted_keymasters.insert(
        st.device_id.clone(),
        TrustedKeymaster { name: st.display_name.clone(), sign_pubkey: B64.encode(p.sign), enc_pubkey: B64.encode(p.enc) },
    );
}

fn anchors(st: &State) -> Result<Vec<Anchor>> {
    st.trusted_keymasters
        .iter()
        .map(|(id, km)| Ok(Anchor { device_id: id.clone(), sign_pk: decode32(&km.sign_pubkey)? }))
        .collect()
}

/// The server's roster, plus the devices in it that actually verify.
struct CheckedRoster {
    raw: Roster,
    verified: BTreeMap<String, VerifiedDevice>,
}

fn checked_roster(st: &State, api: &Api) -> Result<CheckedRoster> {
    let raw: Roster = api.get("/members")?;
    let mut certs = Vec::new();
    for m in &raw.members {
        for d in &m.devices {
            let (Ok(enc_pk), Ok(sign_pk)) = (decode32(&d.enc_pubkey), decode32(&d.sign_pubkey)) else { continue };
            for c in &d.certs {
                let (Some(role), Ok(signature)) = (Role::parse(&c.role), B64.decode(&c.signature)) else { continue };
                // Built from our own group id and the claimed fields; any lie breaks the signature.
                certs.push(MemberCert {
                    group_id: st.group_id.clone(),
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
    let verified = roster::verify_roster(&st.group_id, &anchors(st)?, &certs);
    Ok(CheckedRoster { raw, verified })
}

// --- init-group / join ------------------------------------------------------

fn register(dir: &Path, a: Account, setup_token: Option<&str>) -> Result<()> {
    if state::exists(dir) {
        bail!("{} already holds a device; use another --state directory", dir.display());
    }
    let ca_pem = match &a.ca_cert {
        Some(p) => Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?),
        None => None,
    };
    let keys = crypto::generate_device_keys();
    let public = keys.public();
    let api = Api::new(&a.server, ca_pem.as_deref(), None)?;
    let resp: JoinResp = api.post(
        "/join",
        &JoinReq {
            group_name: &a.group,
            display_name: &a.name,
            email: &a.email,
            enc_pubkey: B64.encode(public.enc),
            sign_pubkey: B64.encode(public.sign),
            setup_token,
        },
    )?;
    let mut st = State::new(
        Identity {
            server: &a.server,
            ca_pem,
            group_id: &resp.group_id,
            group_name: &resp.group_name,
            member_id: &resp.member_id,
            device_id: &resp.device_id,
            display_name: &a.name,
            email: &a.email,
            token: &resp.token,
            status: &resp.status,
            role: &resp.role,
        },
        &keys,
    );
    let code = crypto::safety_code(&public);
    if setup_token.is_some() {
        // The group's first key; it never leaves this device except sealed to approved devices.
        st.add_group_key(&crypto::generate_group_key(1));
        pin_self(&mut st, &keys);
        state::save(dir, &st)?;
        // The founder's certificate is self-signed; devices it approves pin its key.
        let cert = issue_cert(&st, &keys, &own_subject(&st, &keys, Role::Keymaster));
        let _: serde_json::Value = api_for(&st)?.post("/certs", &CertsReq { certs: vec![cert] })?;
        println!("Created group \"{}\" on {}.", resp.group_name, a.server);
        println!("You are its Key Master. Device {}.", resp.device_id);
        println!("Your safety code: {code}");
        println!("Generated group key v1 (stored only on this device) and self-signed your member certificate.");
    } else {
        state::save(dir, &st)?;
        println!("Join request sent to \"{}\" as {} <{}>.", resp.group_name, a.name, a.email);
        println!("Device {} is waiting for a Key Master.", resp.device_id);
        println!();
        println!("  Your safety code:  {code}");
        println!();
        println!("Call a Key Master and read them this code. Run `status` once they approve.");
    }
    Ok(())
}

fn own_subject<'a>(st: &'a State, me: &DeviceKeys, role: Role) -> CertSubject<'a> {
    let p = me.public();
    CertSubject {
        group_id: &st.group_id,
        member_id: &st.member_id,
        device_id: &st.device_id,
        display_name: &st.display_name,
        role,
        enc_pk: p.enc,
        sign_pk: p.sign,
    }
}

// --- Key Master commands ----------------------------------------------------------

fn require_keymaster(st: &State) -> Result<()> {
    if st.status != "active" || st.role != "keymaster" {
        bail!("only an active Key Master device can do this (run `status` if you were just promoted)");
    }
    Ok(())
}

fn pending(dir: &Path) -> Result<()> {
    let st = state::load(dir)?;
    require_keymaster(&st)?;
    let list: PendingList = api_for(&st)?.get("/joins/pending")?;
    if list.pending.is_empty() {
        println!("No pending join requests.");
        return Ok(());
    }
    for p in list.pending {
        // Computed here from the keys the server relayed, so a swapped key shows a different code.
        let code = crypto::safety_code(&pubkeys(&p.enc_pubkey, &p.sign_pubkey)?);
        let who = if p.existing_member {
            format!("NEW DEVICE for existing {} {}", role_label(&p.role), p.display_name)
        } else {
            "new member".to_string()
        };
        println!("{}  {} <{}>  ({who})", p.device_id, p.display_name, p.email);
        println!("    safety code: {code}");
    }
    println!();
    println!("Call each person, have them read their code, then: approve <device_id> --code <their code>");
    Ok(())
}

fn approve(dir: &Path, device_id: &str, heard: &str, as_keymaster: bool) -> Result<()> {
    let mut st = state::load(dir)?;
    require_keymaster(&st)?;
    let api = api_for(&st)?;
    let list: PendingList = api.get("/joins/pending")?;
    let p = list
        .pending
        .iter()
        .find(|p| p.device_id == device_id)
        .with_context(|| format!("{device_id} is not a pending device"))?;
    let theirs = pubkeys(&p.enc_pubkey, &p.sign_pubkey)?;
    let expected = crypto::safety_code(&theirs);
    if !codes_match(heard, &expected) {
        bail!(
            "safety codes don't match: you heard {heard}, this device computes {expected}.\n\
             Don't approve. Someone may have swapped their keys; deny it with `deny {device_id}`."
        );
    }
    // The server says which member this device joins as; don't hand out Key Master
    // rights on the server's word alone.
    let role = Role::parse(&p.role).context("unknown role")?;
    if role == Role::Keymaster && !as_keymaster {
        bail!(
            "{device_id} would join as a device of Key Master {}. If that's really them, re-run with --keymaster.",
            p.display_name
        );
    }
    let me = st.device_keys()?;
    pin_self(&mut st, &me);
    let sealed_keys = st
        .group_keys()?
        .iter()
        .map(|gk| {
            let sealed = crypto::seal_group_key(gk, &theirs.enc);
            let msg = protocol::key_grant_message(&st.group_id, device_id, &theirs.enc, gk.version(), &sealed);
            SealedKeyUpload {
                key_version: gk.version(),
                sealed_blob: B64.encode(&sealed),
                signature: B64.encode(crypto::sign(&me, &msg)),
            }
        })
        .collect::<Vec<_>>();
    if sealed_keys.is_empty() {
        bail!("this device holds no group keys to share");
    }
    let cert = issue_cert(
        &st,
        &me,
        &CertSubject {
            group_id: &st.group_id,
            member_id: &p.member_id,
            device_id,
            display_name: &p.display_name,
            role,
            enc_pk: theirs.enc,
            sign_pk: theirs.sign,
        },
    );
    // Hand over every Key Master key we trust (ourselves included), signed.
    let anchor_list: Vec<(String, [u8; 32])> = anchors(&st)?.into_iter().map(|a| (a.device_id, a.sign_pk)).collect();
    let anchors_sig = crypto::sign(&me, &protocol::anchors_message(&st.group_id, device_id, &anchor_list));
    let n = sealed_keys.len();
    let _: serde_json::Value = api.post(
        &format!("/joins/{device_id}/approve"),
        &ApproveReq {
            sealed_keys,
            cert,
            anchors: anchor_list
                .iter()
                .map(|(id, pk)| AnchorJson { device_id: id.clone(), sign_pubkey: B64.encode(pk) })
                .collect(),
            anchors_signature: B64.encode(anchors_sig),
        },
    )?;
    state::save(dir, &st)?;
    println!("Codes match. Approved {} ({device_id}) as {}.", p.display_name, role_label(&p.role));
    println!("Sealed {n} group key version(s) to their device, signed each grant and their member certificate.");
    println!();
    println!("  Your Key Master code:  {}", crypto::safety_code(&me.public()));
    println!();
    println!("Read it to {}; they finish with `status --km-code <your code>`.", p.display_name);
    Ok(())
}

fn deny(dir: &Path, device_id: &str) -> Result<()> {
    let st = state::load(dir)?;
    require_keymaster(&st)?;
    let _: serde_json::Value = api_for(&st)?.post(&format!("/joins/{device_id}/deny"), &serde_json::json!({}))?;
    println!("Denied {device_id}.");
    Ok(())
}

fn certify(dir: &Path, device_id: Option<&str>, heard: Option<&str>, as_keymaster: bool) -> Result<()> {
    let mut st = state::load(dir)?;
    require_keymaster(&st)?;
    let me = st.device_keys()?;
    let api = api_for(&st)?;
    let cert = match device_id {
        None | Some("") => {
            pin_self(&mut st, &me);
            state::save(dir, &st)?;
            issue_cert(&st, &me, &own_subject(&st, &me, Role::Keymaster))
        }
        Some(id) if id == st.device_id => bail!("to certify yourself, run `certify` with no device"),
        Some(id) => {
            let heard = heard.context("certifying another device needs --code <its safety code>")?;
            let raw: Roster = api.get("/members")?;
            let (m, d) = raw
                .members
                .iter()
                .find_map(|m| m.devices.iter().find(|d| d.id == id).map(|d| (m, d)))
                .with_context(|| format!("{id} is not an active device"))?;
            let keys = pubkeys(&d.enc_pubkey, &d.sign_pubkey)?;
            let expected = crypto::safety_code(&keys);
            if !codes_match(heard, &expected) {
                bail!("safety codes don't match: you heard {heard}, this device computes {expected}. Don't certify it.");
            }
            let role = if as_keymaster { Role::Keymaster } else { Role::Member };
            issue_cert(
                &st,
                &me,
                &CertSubject {
                    group_id: &st.group_id,
                    member_id: &m.id,
                    device_id: id,
                    display_name: &m.display_name,
                    role,
                    enc_pk: keys.enc,
                    sign_pk: keys.sign,
                },
            )
        }
    };
    let who = format!("{} ({})", cert.device_id, role_label(&cert.role));
    let _: serde_json::Value = api.post("/certs", &CertsReq { certs: vec![cert] })?;
    println!("Certified {who}.");
    Ok(())
}

fn promote(dir: &Path, member_id: &str) -> Result<()> {
    let st = state::load(dir)?;
    require_keymaster(&st)?;
    let me = st.device_keys()?;
    let api = api_for(&st)?;
    let roster = checked_roster(&st, &api)?;
    let m = roster
        .raw
        .members
        .iter()
        .find(|m| m.id == member_id)
        .with_context(|| format!("{member_id} is not an active member"))?;
    let mut certs = Vec::new();
    for d in &m.devices {
        // Only promote keys we've verified ourselves.
        let v = roster.verified.get(&d.id).filter(|v| v.member_id == member_id).with_context(|| {
            format!("device {} of {} has no valid certificate; not promoting unverified keys", d.id, m.display_name)
        })?;
        certs.push(issue_cert(
            &st,
            &me,
            &CertSubject {
                group_id: &st.group_id,
                member_id: &v.member_id,
                device_id: &v.device_id,
                display_name: &v.display_name,
                role: Role::Keymaster,
                enc_pk: v.enc_pk,
                sign_pk: v.sign_pk,
            },
        ));
    }
    let n = certs.len();
    let _: serde_json::Value =
        api.post(&format!("/members/{member_id}/role"), &RoleReq { role: "keymaster".into(), certs })?;
    println!("Promoted {} to Key Master; signed Key Master certificates for {n} device(s).", m.display_name);
    Ok(())
}

// --- status: unlock the group key after approval ------------------------------

fn status(dir: &Path, km_code: Option<&str>) -> Result<()> {
    let mut st = state::load(dir)?;
    let me = st.device_keys()?;
    match st.status.as_str() {
        "pending" => {
            let js: JoinStatus = api_for(&st)?.get("/join/status")?;
            match js.status.as_str() {
                "pending" => {
                    println!("Still waiting for a Key Master to approve device {}.", st.device_id);
                    println!("Your safety code: {}", crypto::safety_code(&me.public()));
                    return Ok(());
                }
                "denied" => {
                    st.status = "denied".into();
                    state::save(dir, &st)?;
                    bail!("a Key Master denied this join request");
                }
                "active" => {
                    if !accept_approval(dir, &mut st, &me, js, km_code)? {
                        return Ok(());
                    }
                }
                other => bail!("unexpected status {other}"),
            }
        }
        "active" => {
            // Pick up a promotion (or anything else the server now says about us).
            let js: JoinStatus = api_for(&st)?.get("/join/status")?;
            if let Some(role) = js.role {
                if role != st.role {
                    println!("Your role changed: {} -> {}.", role_label(&st.role), role_label(&role));
                    st.role = role;
                    if st.role == "keymaster" {
                        pin_self(&mut st, &me);
                    }
                    state::save(dir, &st)?;
                }
            }
        }
        _ => {}
    }
    let trusts: Vec<&str> = st.trusted_keymasters.values().map(|k| k.name.as_str()).collect();
    println!("Group:    {} ({})", st.group_name, st.server);
    println!("You:      {} <{}>, {}", st.display_name, st.email, role_label(&st.role));
    println!("Device:   {} ({})", st.device_id, st.status);
    println!("Code:     {}", crypto::safety_code(&me.public()));
    println!("Keys:     group key versions {:?}", st.key_versions());
    println!("Trusts:   Key Master keys of {}", if trusts.is_empty() { "nobody yet".into() } else { trusts.join(", ") });
    println!("Synced:   through seq {}", st.last_seq);
    Ok(())
}

/// Verify the approval: every grant and the handed-over anchors must be signed
/// by the approving Key Master, and the user must confirm that Key Master's
/// safety code. Only then store keys and pin anchors. Returns false if it's
/// waiting for the code.
fn accept_approval(dir: &Path, st: &mut State, me: &DeviceKeys, js: JoinStatus, km_code: Option<&str>) -> Result<bool> {
    let approver = js.approved_by.clone().context("approved, but the server didn't say by whom")?;
    let first = js.sealed_keys.first().context("approved, but the server returned no sealed group keys")?;
    let km_sign = decode32(&first.signer_sign_pubkey).context("approver signing key")?;
    let km_keys = pubkeys(&first.signer_enc_pubkey, &first.signer_sign_pubkey)?;
    let km_name = first.signer_name.clone().unwrap_or_else(|| "the Key Master".into());
    let enc_pk = me.public().enc;

    let mut keys = Vec::new();
    for k in &js.sealed_keys {
        if k.signer_device_id.as_deref() != Some(approver.as_str()) || k.signer_sign_pubkey != first.signer_sign_pubkey {
            bail!("key v{} was granted by someone other than the approving Key Master", k.key_version);
        }
        let sealed = B64.decode(&k.sealed_blob)?;
        let msg = protocol::key_grant_message(&st.group_id, &st.device_id, &enc_pk, k.key_version, &sealed);
        crypto::verify(&km_sign, &msg, &B64.decode(&k.signature)?)
            .with_context(|| format!("key v{} is not signed by its Key Master; refusing it", k.key_version))?;
        let gk = crypto::unseal_group_key(me, &sealed).with_context(|| format!("can't unseal key v{}", k.key_version))?;
        if gk.version() != k.key_version {
            bail!("sealed key says v{} but was labelled v{}", gk.version(), k.key_version);
        }
        keys.push(gk);
    }
    let mut anchor_list = Vec::new();
    for a in &js.anchors {
        anchor_list.push((a.device_id.clone(), decode32(&a.sign_pubkey).context("anchor key")?));
    }
    if !anchor_list.iter().any(|(id, pk)| *id == approver && *pk == km_sign) {
        bail!("the approver's handed-over Key Master list doesn't include the approver");
    }
    crypto::verify(
        &km_sign,
        &protocol::anchors_message(&st.group_id, &st.device_id, &anchor_list),
        &B64.decode(&js.anchors_signature)?,
    )
    .context("the handed-over Key Master list isn't signed by the approver; refusing it")?;

    let km_code_expected = crypto::safety_code(&km_keys);
    let Some(heard) = km_code else {
        println!("Approved by {km_name}. Their signatures check out; one step left.");
        println!();
        println!("Ask {km_name} to read you their Key Master code, then run:");
        println!("  status --km-code <the code they read>");
        println!();
        println!("(Nothing is stored until you do. If the code you hear isn't {km_code_expected}, stop: it isn't {km_name}.)");
        return Ok(false);
    };
    if !codes_match(heard, &km_code_expected) {
        bail!(
            "Key Master code doesn't match: you heard {heard}, but whoever approved you has {km_code_expected}.\n\
             Don't trust this approval. Call a Key Master you know (the server named the approver \"{km_name}\")."
        );
    }

    for gk in &keys {
        st.add_group_key(gk);
    }
    for (id, pk) in &anchor_list {
        let pin = if *id == approver {
            TrustedKeymaster { name: km_name.clone(), sign_pubkey: B64.encode(pk), enc_pubkey: first.signer_enc_pubkey.clone() }
        } else {
            TrustedKeymaster { name: format!("Key Master {id} (vouched for by {km_name})"), sign_pubkey: B64.encode(pk), enc_pubkey: String::new() }
        };
        st.trusted_keymasters.insert(id.clone(), pin);
    }
    st.status = "active".into();
    st.role = js.role.unwrap_or_else(|| st.role.clone());
    // Replace placeholder names with certified ones where the roster verifies them.
    if let Ok(r) = checked_roster(st, &api_for(st)?) {
        for (id, km) in st.trusted_keymasters.iter_mut() {
            if let Some(v) = r.verified.get(id) {
                km.name = v.display_name.clone();
            }
        }
    }
    state::save(dir, st)?;
    println!("Key Master code matches. Joined, and unlocked group key version(s) {:?}.", st.key_versions());
    println!("Pinned {km_name}'s signing key{}.", if anchor_list.len() > 1 { " and the Key Masters they vouched for" } else { "" });
    println!();
    Ok(true)
}

// --- members / post / pull ---------------------------------------------------

fn require_active(st: &State) -> Result<()> {
    if st.status != "active" {
        bail!("this device is {}; run `status` after a Key Master approves it", st.status);
    }
    Ok(())
}

fn members(dir: &Path) -> Result<()> {
    let st = state::load(dir)?;
    require_active(&st)?;
    let r = checked_roster(&st, &api_for(&st)?)?;
    let mut by_member: BTreeMap<&str, Vec<&VerifiedDevice>> = BTreeMap::new();
    for v in r.verified.values() {
        by_member.entry(v.member_id.as_str()).or_default().push(v);
    }
    // Keep the server's order, but show only what verified, with the certified name and role.
    for m in &r.raw.members {
        let Some(devs) = by_member.get(m.id.as_str()) else { continue };
        let top = devs.iter().max_by_key(|d| d.role).expect("non-empty");
        let ids: Vec<&str> = devs.iter().map(|d| d.device_id.as_str()).collect();
        println!("{:<20} {:<10} devices: {}", top.display_name, role_label(top.role.as_str()), ids.join(", "));
    }
    for m in &r.raw.members {
        for d in m.devices.iter().filter(|d| !r.verified.contains_key(&d.id)) {
            println!("UNVERIFIED  \"{}\" device {}: no valid certificate from a trusted Key Master; ignored", m.display_name, d.id);
        }
    }
    Ok(())
}

fn post(dir: &Path, text: &str) -> Result<()> {
    let st = state::load(dir)?;
    require_active(&st)?;
    let me = st.device_keys()?;
    let gk = st.latest_group_key()?;
    let kind = "post";
    let body = serde_json::to_vec(&serde_json::json!({ "text": text }))?;
    let ct = crypto::encrypt(&gk, &body, &protocol::event_ad(&st.group_id, kind));
    let msg = protocol::event_message(&st.group_id, &st.device_id, kind, gk.version(), &ct);
    let sig = crypto::sign(&me, &msg);
    let r: Seq = api_for(&st)?.post(
        "/events",
        &EventReq {
            kind,
            key_version: gk.version(),
            ciphertext: B64.encode(&ct),
            signature: B64.encode(sig),
            media_ids: vec![],
        },
    )?;
    println!("Posted #{} ({} bytes of ciphertext, key v{}).", r.seq, ct.len(), gk.version());
    Ok(())
}

fn pull(dir: &Path) -> Result<()> {
    let mut st = state::load(dir)?;
    require_active(&st)?;
    let api = api_for(&st)?;
    let authors = checked_roster(&st, &api)?.verified;
    let mut shown = 0;
    loop {
        let page: EventPage = api.get(&format!("/events?after={}", st.last_seq))?;
        for e in &page.events {
            shown += 1;
            match open_event(&st, &authors, e) {
                Ok(line) => println!("#{:<4} {line}", e.seq),
                Err(err) => println!("#{:<4} [rejected: {err:#}]", e.seq),
            }
        }
        if page.last_seq > st.last_seq {
            let _: serde_json::Value = api.post("/ack", &serde_json::json!({ "seq": page.last_seq }))?;
            st.last_seq = page.last_seq;
            state::save(dir, &st)?;
        }
        if !page.has_more {
            break;
        }
    }
    if shown == 0 {
        println!("No new events.");
    }
    Ok(())
}

fn open_event(st: &State, authors: &BTreeMap<String, VerifiedDevice>, e: &Event) -> Result<String> {
    let author = authors
        .get(&e.author_device_id)
        .with_context(|| format!("author device {} has no valid member certificate", e.author_device_id))?;
    let ct = B64.decode(&e.ciphertext)?;
    let msg = protocol::event_message(&st.group_id, &e.author_device_id, &e.kind, e.key_version, &ct);
    crypto::verify(&author.sign_pk, &msg, &B64.decode(&e.signature)?).context("bad author signature")?;
    let gk = st.group_key(e.key_version)?.with_context(|| format!("no group key v{}", e.key_version))?;
    let plain = crypto::decrypt(&gk, &ct, &protocol::event_ad(&st.group_id, &e.kind)).context("can't decrypt")?;
    let body: serde_json::Value = serde_json::from_slice(&plain).context("bad payload")?;
    let text = body["text"].as_str().unwrap_or("");
    let who = match author.role {
        Role::Keymaster => format!("{} (Key Master)", author.display_name),
        Role::Member => author.display_name.clone(),
    };
    Ok(format!("{who}: {text}  [certified author, signature ok, key v{}]", e.key_version))
}
