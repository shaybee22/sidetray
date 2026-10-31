//! Invite links (SPEC "Invite links"):
//! `sidetray://join?server=https%3A%2F%2Ftray.example.org&group=Smith%20Family`.
//!
//! A link carries no secret and grants nothing: it only fills in the wizard's
//! server and group name. The join still waits for a Key Master to compare
//! safety codes on the phone. Anything but exactly those two values, or a
//! server that isn't https://, is refused.

use crate::api;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;

pub const SCHEME: &str = "sidetray";
const MAX_GROUP: usize = 100;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Invite {
    pub server: String,
    pub group: String,
}

/// Percent-encode everything but RFC 3986's unreserved characters, so a
/// space is `%20` (not `+`) and the link survives any URL handling.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn link(server: &str, group: &str) -> Result<String> {
    if !api::is_https(server) {
        bail!("invite links only work for an https:// server");
    }
    Ok(format!("{SCHEME}://join?server={}&group={}", encode(server), encode(group)))
}

pub fn parse(link: &str) -> Result<Invite> {
    let u = reqwest::Url::parse(link.trim()).context("that isn't a valid invite link")?;
    if u.scheme() != SCHEME || u.host_str() != Some("join") || !matches!(u.path(), "" | "/") || u.fragment().is_some() {
        bail!("that isn't a Side Tray invite link (expected {SCHEME}://join?server=...&group=...)");
    }
    let (mut server, mut group) = (None, None);
    for (k, v) in u.query_pairs() {
        let slot = match k.as_ref() {
            "server" => &mut server,
            "group" => &mut group,
            other => bail!("the invite link has something unexpected in it ({other})"),
        };
        if slot.replace(v.into_owned()).is_some() {
            bail!("the invite link names its {k} twice");
        }
    }
    let server = server.context("the invite link doesn't say which server")?;
    let group = group.context("the invite link doesn't say which group")?;
    if !server.trim().starts_with("https://") {
        bail!("the invite link's server isn't an https:// address, so it's refused");
    }
    let server = api::normalize_server(&server)?;
    let group = group.trim().to_string();
    if group.is_empty() || group.chars().count() > MAX_GROUP || group.chars().any(char::is_control) {
        bail!("the invite link's group name isn't valid");
    }
    Ok(Invite { server, group })
}

/// The link as a QR code, as a `data:` URL the webview can show.
pub fn qr_data_url(link: &str) -> Result<String> {
    let code = qrcode::QrCode::with_error_correction_level(link.as_bytes(), qrcode::EcLevel::M).context("making the QR code")?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(format!("data:image/svg+xml;base64,{}", B64.encode(svg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_matches_the_spec_format() {
        let l = link("https://tray.example.org", "Smith Family").unwrap();
        assert_eq!(l, "sidetray://join?server=https%3A%2F%2Ftray.example.org&group=Smith%20Family");
        assert_eq!(parse(&l).unwrap(), Invite { server: "https://tray.example.org".into(), group: "Smith Family".into() });
        let odd = link("https://10.1.1.191", "Café & Co? 100%").unwrap();
        assert_eq!(parse(&odd).unwrap().group, "Café & Co? 100%");
    }

    #[test]
    fn anything_else_is_refused() {
        assert!(link("http://127.0.0.1:8000", "G").is_err());
        for bad in [
            "sidetray://join?server=http%3A%2F%2Fexample.org&group=G",
            "sidetray://join?server=http%3A%2F%2F127.0.0.1&group=G",
            "sidetray://join?server=example.org&group=G",
            "sidetray://join?server=https%3A%2F%2Fexample.org",
            "sidetray://join?group=G",
            "sidetray://join?server=https%3A%2F%2Fexample.org&group=G&token=x",
            "sidetray://join?server=https%3A%2F%2Fexample.org&group=G&group=H",
            "sidetray://join?server=https%3A%2F%2Fexample.org%2Fpath&group=G",
            "sidetray://join?server=https%3A%2F%2Fexample.org&group=%20",
            "sidetray://approve?server=https%3A%2F%2Fexample.org&group=G",
            "https://join?server=https%3A%2F%2Fexample.org&group=G",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn qr_code_is_an_svg() {
        let q = qr_data_url("sidetray://join?server=https%3A%2F%2Fexample.org&group=G").unwrap();
        let svg = String::from_utf8(B64.decode(q.trim_start_matches("data:image/svg+xml;base64,")).unwrap()).unwrap();
        assert!(svg.contains("<svg"));
    }
}
