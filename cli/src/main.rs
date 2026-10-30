//! `sidetray`: a development CLI for the join / Key Master flow (SPEC.md Phase 3).
//!
//! Every invocation acts as one device whose state lives in `--state <dir>`,
//! so a Key Master and a new member can run side by side on one machine.

mod api;
mod state;

use anyhow::{bail, Context, Result};
use api::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use sidetray_crypto::{self as crypto, protocol, DevicePublicKeys};
use state::{decode32, Identity, State, TrustedKeymaster};
use std::collections::HashMap;
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
    },
    /// Key Master: reject a join request.
    Deny { device_id: String },
    /// Show this device; while pending, check for approval and unlock the group key.
    Status,
    /// List members and their devices.
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
        Cmd::Approve { device_id, code } => approve(dir, &device_id, &code),
        Cmd::Deny { device_id } => deny(dir, &device_id),
        Cmd::Status => status(dir),
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
fn normalize_code(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
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
        state::save(dir, &st)?;
        println!("Created group \"{}\" on {}.", resp.group_name, a.server);
        println!("You are its Key Master. Device {}.", resp.device_id);
        println!("Your safety code: {code}");
        println!("Generated group key v1 (stored only on this device).");
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

// --- Key Master commands ----------------------------------------------------------

fn require_keymaster(st: &State) -> Result<()> {
    if st.status != "active" || st.role != "keymaster" {
        bail!("only an active Key Master device can do this");
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

fn approve(dir: &Path, device_id: &str, heard: &str) -> Result<()> {
    let st = state::load(dir)?;
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
    if normalize_code(heard) != normalize_code(&expected) {
        bail!(
            "safety codes don't match: you heard {heard}, this device computes {expected}.\n\
             Don't approve. Someone may have swapped their keys; deny it with `deny {device_id}`."
        );
    }
    let me = st.device_keys()?;
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
    let n = sealed_keys.len();
    let _: serde_json::Value = api.post(&format!("/joins/{device_id}/approve"), &ApproveReq { sealed_keys })?;
    println!("Codes match. Approved {} ({device_id}).", p.display_name);
    println!("Sealed {n} group key version(s) to their device and signed each grant.");
    println!();
    println!("  Your Key Master code:  {}", crypto::safety_code(&me.public()));
    println!();
    println!("Read it to {} so they can check it on their screen.", p.display_name);
    Ok(())
}

fn deny(dir: &Path, device_id: &str) -> Result<()> {
    let st = state::load(dir)?;
    require_keymaster(&st)?;
    let _: serde_json::Value = api_for(&st)?.post(&format!("/joins/{device_id}/deny"), &serde_json::json!({}))?;
    println!("Denied {device_id}.");
    Ok(())
}

// --- status: unlock the group key after approval ------------------------------

fn status(dir: &Path) -> Result<()> {
    let mut st = state::load(dir)?;
    let me = st.device_keys()?;
    if st.status == "pending" {
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
            "active" => accept_grants(dir, &mut st, &me, js)?,
            other => bail!("unexpected status {other}"),
        }
    }
    println!("Group:    {} ({})", st.group_name, st.server);
    println!("You:      {} <{}>, {}", st.display_name, st.email, role_label(&st.role));
    println!("Device:   {} ({})", st.device_id, st.status);
    println!("Code:     {}", crypto::safety_code(&me.public()));
    println!("Keys:     group key versions {:?}", st.key_versions());
    println!("Synced:   through seq {}", st.last_seq);
    Ok(())
}

/// Verify each grant's Key Master signature, unseal it, and only then store the keys.
fn accept_grants(dir: &Path, st: &mut State, me: &crypto::DeviceKeys, js: JoinStatus) -> Result<()> {
    if js.sealed_keys.is_empty() {
        bail!("approved, but the server returned no sealed group keys");
    }
    let enc_pk = me.public().enc;
    let mut keys = Vec::new();
    let mut signers: HashMap<String, TrustedKeymaster> = HashMap::new();
    for k in &js.sealed_keys {
        let signer_id = k.signer_device_id.as_deref().context("grant has no signer")?;
        let signer_pk = decode32(&k.signer_sign_pubkey).context("signer key")?;
        let sealed = B64.decode(&k.sealed_blob)?;
        let msg = protocol::key_grant_message(&st.group_id, &st.device_id, &enc_pk, k.key_version, &sealed);
        crypto::verify(&signer_pk, &msg, &B64.decode(&k.signature)?)
            .with_context(|| format!("key v{} is not signed by its Key Master; refusing it", k.key_version))?;
        let gk = crypto::unseal_group_key(me, &sealed)
            .with_context(|| format!("can't unseal key v{}", k.key_version))?;
        if gk.version() != k.key_version {
            bail!("sealed key says v{} but was labelled v{}", gk.version(), k.key_version);
        }
        keys.push(gk);
        signers.insert(
            signer_id.to_string(),
            TrustedKeymaster {
                name: k.signer_name.clone().unwrap_or_else(|| "?".into()),
                sign_pubkey: k.signer_sign_pubkey.clone(),
                enc_pubkey: k.signer_enc_pubkey.clone(),
            },
        );
    }
    for gk in &keys {
        st.add_group_key(gk);
    }
    st.trusted_keymasters.extend(signers.clone());
    st.status = "active".into();
    st.role = js.role.unwrap_or_else(|| st.role.clone());
    state::save(dir, st)?;

    println!("Approved! Verified the Key Master's signature and unlocked group key version(s) {:?}.", st.key_versions());
    for km in signers.values() {
        // Their signing key is the one that verified above; the code covers it and
        // their encryption key, so a server-substituted Key Master shows a different code.
        let code = crypto::safety_code(&pubkeys(&km.enc_pubkey, &km.sign_pubkey)?);
        println!();
        println!("  Signed by {}. Their Key Master code:  {code}", km.name);
        println!();
        println!("{} should read you the same code. If it differs, stop and tell them.", km.name);
    }
    println!();
    Ok(())
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
    let roster: Roster = api_for(&st)?.get("/members")?;
    for m in roster.members {
        let ids: Vec<&str> = m.devices.iter().map(|d| d.id.as_str()).collect();
        println!("{:<20} {:<10} devices: {}", m.display_name, role_label(&m.role), ids.join(", "));
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
    let roster: Roster = api.get("/members")?;
    let mut authors: HashMap<String, (String, String, [u8; 32])> = HashMap::new();
    for m in &roster.members {
        for d in &m.devices {
            authors.insert(d.id.clone(), (m.display_name.clone(), m.role.clone(), decode32(&d.sign_pubkey)?));
        }
    }
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

fn open_event(st: &State, authors: &HashMap<String, (String, String, [u8; 32])>, e: &Event) -> Result<String> {
    let (name, role, sign_pk) = authors
        .get(&e.author_device_id)
        .with_context(|| format!("unknown author device {}", e.author_device_id))?;
    let ct = B64.decode(&e.ciphertext)?;
    let msg = protocol::event_message(&st.group_id, &e.author_device_id, &e.kind, e.key_version, &ct);
    crypto::verify(sign_pk, &msg, &B64.decode(&e.signature)?).context("bad author signature")?;
    let gk = st.group_key(e.key_version)?.with_context(|| format!("no group key v{}", e.key_version))?;
    let plain = crypto::decrypt(&gk, &ct, &protocol::event_ad(&st.group_id, &e.kind)).context("can't decrypt")?;
    let body: serde_json::Value = serde_json::from_slice(&plain).context("bad payload")?;
    let text = body["text"].as_str().unwrap_or("");
    let who = if role == "keymaster" { format!("{name} (Key Master)") } else { name.clone() };
    Ok(format!("{who}: {text}  [signature ok, key v{}]", e.key_version))
}
