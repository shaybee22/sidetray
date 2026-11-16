//! Link previews (SPEC.md Phase 10): the card under a post with a link.
//!
//! Only the person posting fetches the page, while composing; the preview
//! then travels inside the encrypted post, so the relay and the readers'
//! devices never contact the linked site. This module is that fetch: the
//! page's Open Graph tags (a small scanner, no HTML library), or YouTube's
//! oEmbed for YouTube links, and the page's picture made into a small WebP
//! through the photo pipeline (`photo::link_image`).
//!
//! The fetch only reaches public addresses: http or https, no `user:pass@`,
//! no `localhost`, and every address a name resolves to is checked before
//! connecting (loopback, private, link-local and other special ranges are
//! dropped), as is every redirect. Sizes and time are capped.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_URL: usize = 2048;
pub const MAX_TITLE: usize = 300;
pub const MAX_DESCRIPTION: usize = 500;
pub const MAX_SITE: usize = 100;

/// HTML read from a page: the `<head>` is what matters, and it's near the start.
const MAX_PAGE: usize = 512 * 1024;
const MAX_OEMBED: usize = 64 * 1024;
/// The page's picture, before it's decoded and made small.
const MAX_IMAGE_DOWNLOAD: usize = 5 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Page and picture together.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT: &str = concat!("SideTray/", env!("CARGO_PKG_VERSION"), " (link preview)");

/// What the composer shows and the post carries.
#[derive(Clone, Debug, PartialEq)]
pub struct Preview {
    /// As written in the post's text.
    pub url: String,
    pub title: String,
    pub description: Option<String>,
    pub site: Option<String>,
    /// WebP, at most `photo::MAX_LINK_IMAGE`, with its width and height.
    pub image: Option<(Vec<u8>, u32, u32)>,
}

/// Fetch the preview for `url` (as found by `first_url`). Any failure means no
/// preview; the composer says nothing about it.
pub async fn fetch(url: &str) -> Result<Preview> {
    fetch_with(url, false).await
}

async fn fetch_with(url: &str, allow_local: bool) -> Result<Preview> {
    let u = parse(url)?;
    check_url(&u, allow_local)?;
    let client = client(allow_local)?;
    let work = async {
        let (mut p, image_url) = if is_youtube(&u) { youtube(&client, &u).await? } else { page(&client, &u).await? };
        p.url = url.to_string();
        if let Some(image_url) = image_url {
            // A picture that can't be fetched or read just leaves the card without one.
            match picture(&client, image_url).await {
                Ok(img) => p.image = img,
                Err(e) => eprintln!("link preview picture: {e:#}"),
            }
        }
        Ok(p)
    };
    tokio::time::timeout(TOTAL_TIMEOUT, work).await.context("the site took too long")?
}

// --- where the fetch may go ------------------------------------------------------------

fn parse(url: &str) -> Result<Url> {
    if url.len() > MAX_URL {
        bail!("that address is too long");
    }
    Url::parse(url).context("that isn't a web address")
}

/// http or https, no user name or password, and not a name or address on this
/// computer or its network. Checked for the link and every redirect.
fn check_url(u: &Url, allow_local: bool) -> Result<()> {
    if !matches!(u.scheme(), "http" | "https") {
        bail!("only http and https links get a preview");
    }
    if !u.username().is_empty() || u.password().is_some() {
        bail!("links with a user name or password don't get a preview");
    }
    if u.as_str().len() > MAX_URL {
        bail!("that address is too long");
    }
    // The URL parser has already turned "0x7f000001" and the like into dotted form.
    let host = u.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']');
    let blocked = match host.parse::<IpAddr>() {
        Ok(ip) => blocked_ip(ip),
        Err(_) => {
            let d = host.trim_end_matches('.');
            d.is_empty() || d == "localhost" || d.ends_with(".localhost")
        }
    };
    if blocked && !allow_local {
        bail!("that address isn't on the public internet");
    }
    Ok(())
}

/// Addresses a preview never connects to: this computer, private networks,
/// link-local, carrier-grade NAT, and other special-purpose ranges.
pub fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => blocked_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return blocked_v4(v4);
            }
            let s = a.segments();
            let embedded = |hi: u16, lo: u16| Ipv4Addr::from(((hi as u32) << 16) | lo as u32);
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
                return blocked_v4(embedded(s[6], s[7])); // NAT64
            }
            if s[0] == 0x2002 {
                return blocked_v4(embedded(s[1], s[2])); // 6to4
            }
            s[0..6] == [0; 6] // ::, ::1 and IPv4-compatible
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] & 0xff00) == 0xff00 // multicast
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x2001 && s[1] == 0) // Teredo
        }
    }
}

fn blocked_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10, carrier-grade NAT
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15, benchmarking
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24
}

/// Resolves names, then drops every address `blocked_ip` refuses, so the
/// connection can only go to what's left (a name that points at the LAN, now
/// or after a rebinding trick, gets nothing).
struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            match public_addrs(&host).await {
                Ok(a) => Ok(Box::new(a.into_iter()) as reqwest::dns::Addrs),
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

async fn public_addrs(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0)).await?.filter(|a| !blocked_ip(a.ip())).collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, format!("{host} has no public address")));
    }
    Ok(addrs)
}

fn client(allow_local: bool) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        // Through a proxy, the address check below wouldn't apply.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error("too many redirects");
            }
            // An address in the link itself never reaches the resolver: check it here.
            match check_url(attempt.url(), allow_local) {
                Ok(()) => attempt.follow(),
                Err(e) => attempt.error(e.to_string()),
            }
        }));
    if !allow_local {
        b = b.dns_resolver(Arc::new(PublicOnly));
    }
    Ok(b.build()?)
}

/// Read at most `max` bytes of a body, stopping early once `enough` is happy.
/// The flag says whether that was all of it (or all `enough` wanted).
pub async fn read_capped(resp: &mut reqwest::Response, max: usize, enough: impl Fn(&[u8]) -> bool) -> reqwest::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        let room = max - out.len();
        if chunk.len() > room {
            out.extend_from_slice(&chunk[..room]);
            return Ok((out, false));
        }
        out.extend_from_slice(&chunk);
        if enough(&out) {
            return Ok((out, true));
        }
    }
    Ok((out, true))
}

async fn get(client: &reqwest::Client, url: Url, accept: &str) -> Result<reqwest::Response> {
    let resp = client.get(url).header(reqwest::header::ACCEPT, accept).send().await?;
    if !resp.status().is_success() {
        bail!("the site said {}", resp.status());
    }
    Ok(resp)
}

// --- web pages -------------------------------------------------------------------------

/// The page's preview and the address of its picture, if it names one.
async fn page(client: &reqwest::Client, u: &Url) -> Result<(Preview, Option<Url>)> {
    let mut resp = get(client, u.clone(), "text/html,application/xhtml+xml").await?;
    let final_url = resp.url().clone();
    let ctype = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    if !(ctype.is_empty() || ctype.starts_with("text/html") || ctype.starts_with("application/xhtml+xml")) {
        bail!("not a web page ({ctype})");
    }
    let (html, _) = read_capped(&mut resp, MAX_PAGE, end_of_head).await?;
    let tags = scan(&String::from_utf8_lossy(&html));
    let preview = from_tags(&tags).context("the page has no title")?;
    let image = ["og:image", "twitter:image", "twitter:image:src"]
        .iter()
        .find_map(|k| tags.meta.get(*k))
        .and_then(|src| final_url.join(src.trim()).ok())
        .filter(|i| matches!(i.scheme(), "http" | "https"));
    Ok((preview, image))
}

/// The head is over: nothing after it is read.
fn end_of_head(html: &[u8]) -> bool {
    let tail = &html[html.len().saturating_sub(64 * 1024)..];
    tail.windows(6).any(|w| w.eq_ignore_ascii_case(b"</head") || w[..5].eq_ignore_ascii_case(b"<body"))
}

/// What the scanner found in a page's head: `<meta>` tags by `property` or
/// `name` (lowercase; the first of each wins) and the `<title>`.
#[derive(Default, Debug)]
pub struct Tags {
    pub meta: HashMap<String, String>,
    pub title: Option<String>,
}

fn from_tags(t: &Tags) -> Option<Preview> {
    let pick = |keys: &[&str]| keys.iter().find_map(|k| t.meta.get(*k).map(String::as_str));
    let title = pick(&["og:title", "twitter:title"]).and_then(|s| clean(s, MAX_TITLE)).or_else(|| t.title.as_deref().and_then(|s| clean(s, MAX_TITLE)))?;
    Some(Preview {
        url: String::new(),
        title,
        description: pick(&["og:description", "twitter:description", "description"]).and_then(|s| clean(s, MAX_DESCRIPTION)),
        site: pick(&["og:site_name"]).and_then(|s| clean(s, MAX_SITE)),
        image: None,
    })
}

/// A small scanner for `<meta>` and `<title>` in a page's head. It skips
/// comments, `<script>` and `<style>`, and stops at `</head>` or `<body>`.
/// Attribute values are entity-decoded; nothing else is interpreted.
pub fn scan(html: &str) -> Tags {
    // ASCII lowercase keeps every byte offset, so positions found in `lower`
    // slice `html` too.
    let lower = html.to_ascii_lowercase();
    let mut tags = Tags::default();
    let mut i = 0;
    while let Some(off) = lower[i..].find('<') {
        let at = i + off;
        let rest = &lower[at..];
        if rest.starts_with("<!--") {
            i = lower[at..].find("-->").map_or(lower.len(), |e| at + e + 3);
            continue;
        }
        // The tag's name: "/" or "!" may only come first.
        let nb = rest.as_bytes();
        let mut name_end = 1;
        if name_end < nb.len() && matches!(nb[name_end], b'/' | b'!') {
            name_end += 1;
        }
        while name_end < nb.len() && (nb[name_end].is_ascii_alphanumeric() || nb[name_end] == b'-') {
            name_end += 1;
        }
        let name = &rest[1..name_end];
        let (attrs, end) = attributes(html, &lower, at + name_end);
        i = end;
        match name {
            "/head" | "body" => break,
            "script" | "style" => {
                let close = format!("</{name}");
                i = lower[end..].find(&close).map_or(lower.len(), |e| end + e);
            }
            "title" => {
                let close = lower[end..].find("</title").map_or(lower.len(), |e| end + e);
                if tags.title.is_none() {
                    tags.title = Some(decode_entities(&html[end..close]));
                }
                i = close;
            }
            "meta" => {
                let get = |k: &str| attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
                if let (Some(key), Some(content)) = (get("property").or_else(|| get("name")), get("content")) {
                    tags.meta.entry(key.trim().to_ascii_lowercase()).or_insert_with(|| decode_entities(content));
                }
            }
            _ => {}
        }
    }
    tags
}

/// A tag's attributes from `from` up to its `>`: (lowercase name, value), and
/// where the tag ends. Values may be double-quoted, single-quoted or bare.
fn attributes(html: &str, lower: &str, from: usize) -> (Vec<(String, String)>, usize) {
    let b = lower.as_bytes();
    let mut out = Vec::new();
    let mut i = from;
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return (out, b.len());
        }
        if b[i] == b'>' {
            return (out, i + 1);
        }
        let start = i;
        while i < b.len() && !(b[i].is_ascii_whitespace() || matches!(b[i], b'=' | b'>' | b'/')) {
            i += 1;
        }
        let name = lower[start..i].to_string();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let end = b[i + 1..].iter().position(|&c| c == q).map_or(b.len(), |e| i + 1 + e);
                value = html[i + 1..end].to_string();
                i = (end + 1).min(b.len());
            } else {
                let start = i;
                while i < b.len() && !(b[i].is_ascii_whitespace() || b[i] == b'>') {
                    i += 1;
                }
                value = html[start..i].to_string();
            }
        }
        if !name.is_empty() {
            out.push((name, value));
        } else if i == start {
            i += 1; // a stray character: move on
        }
    }
}

/// The entities page titles and descriptions actually use.
pub fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest[1..].find(';').filter(|&semi| semi <= 10).and_then(|semi| {
            let name = &rest[1..1 + semi];
            let c = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                "ndash" => Some('–'),
                "mdash" => Some('—'),
                "hellip" => Some('…'),
                "lsquo" => Some('‘'),
                "rsquo" => Some('’'),
                "ldquo" => Some('“'),
                "rdquo" => Some('”'),
                n if n.starts_with("#x") || n.starts_with("#X") => u32::from_str_radix(&n[2..], 16).ok().and_then(char::from_u32),
                n if n.starts_with('#') => n[1..].parse().ok().and_then(char::from_u32),
                _ => None,
            };
            c.map(|c| (c, semi + 2))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Plain text for the card: control characters and runs of whitespace become
/// one space, trimmed, and cut to `max` characters (with "…"). `None` if empty.
pub fn clean(s: &str, max: usize) -> Option<String> {
    let t = s.split(|c: char| c.is_whitespace() || c.is_control()).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
    if t.is_empty() {
        return None;
    }
    if t.chars().count() <= max {
        return Some(t);
    }
    let mut cut: String = t.chars().take(max - 1).collect::<String>().trim_end().to_string();
    cut.push('…');
    Some(cut)
}

// --- YouTube ---------------------------------------------------------------------------

pub fn is_youtube(u: &Url) -> bool {
    matches!(u.host_str(), Some("youtube.com" | "www.youtube.com" | "m.youtube.com" | "youtu.be"))
}

#[derive(Deserialize)]
struct OEmbed {
    title: String,
    author_name: Option<String>,
    thumbnail_url: Option<String>,
}

fn oembed_url(u: &Url) -> Url {
    Url::parse_with_params("https://www.youtube.com/oembed", &[("format", "json"), ("url", u.as_str())]).expect("a valid constant URL")
}

/// YouTube's own description of a video, instead of its (huge, and in Europe
/// consent-walled) page.
async fn youtube(client: &reqwest::Client, u: &Url) -> Result<(Preview, Option<Url>)> {
    let mut resp = get(client, oembed_url(u), "application/json").await?;
    let (body, whole) = read_capped(&mut resp, MAX_OEMBED, |_| false).await?;
    if !whole {
        bail!("YouTube's answer was too long");
    }
    from_oembed(&body)
}

fn from_oembed(body: &[u8]) -> Result<(Preview, Option<Url>)> {
    let o: OEmbed = serde_json::from_slice(body).context("YouTube's answer wasn't readable")?;
    let preview = Preview {
        url: String::new(),
        title: clean(&o.title, MAX_TITLE).context("the video has no title")?,
        description: o.author_name.as_deref().and_then(|a| clean(a, MAX_DESCRIPTION)),
        site: Some("YouTube".into()),
        image: None,
    };
    let image = o.thumbnail_url.and_then(|t| Url::parse(&t).ok()).filter(|i| matches!(i.scheme(), "http" | "https"));
    Ok((preview, image))
}

// --- the picture -----------------------------------------------------------------------

async fn picture(client: &reqwest::Client, url: Url) -> Result<Option<(Vec<u8>, u32, u32)>> {
    let mut resp = get(client, url, "image/*").await?;
    let (bytes, whole) = read_capped(&mut resp, MAX_IMAGE_DOWNLOAD, |_| false).await?;
    if !whole {
        bail!("the picture is over {} MB", MAX_IMAGE_DOWNLOAD / 1024 / 1024);
    }
    tokio::task::spawn_blocking(move || crate::photo::link_image(&bytes)).await?
}

// --- in the post, and in the archive ---------------------------------------------------

/// The post's `link` field: `{"url", "title", "description"?, "site"?, "image"?, "width"?, "height"?}`,
/// `image` a base64 WebP. Apps before Phase 10 ignore it.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct LinkRef {
    pub url: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

impl Preview {
    pub fn to_ref(&self) -> LinkRef {
        LinkRef {
            url: self.url.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            site: self.site.clone(),
            image: self.image.as_ref().map(|(webp, _, _)| B64.encode(webp)),
            width: self.image.as_ref().map(|i| i.1),
            height: self.image.as_ref().map(|i| i.2),
        }
    }
}

/// A received `link`, checked: what gets stored, or why it's dropped.
fn checked(v: &serde_json::Value, text: &str) -> Result<(LinkRef, Option<Vec<u8>>)> {
    let r: LinkRef = serde_json::from_value(v.clone()).context("not a link preview")?;
    let u = parse(&r.url)?;
    check_url(&u, false)?;
    if !text.contains(&r.url) {
        bail!("the link isn't in the post's text");
    }
    let plain = |s: &str, max: usize| !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control);
    if !plain(&r.title, MAX_TITLE) {
        bail!("bad title");
    }
    if r.description.as_deref().is_some_and(|d| !plain(d, MAX_DESCRIPTION)) || r.site.as_deref().is_some_and(|s| !plain(s, MAX_SITE)) {
        bail!("bad description or site");
    }
    let image = match &r.image {
        None => None,
        Some(b64) => {
            // Base64 is 4/3 the size: refuse a long one before decoding it.
            if b64.len() > crate::photo::MAX_LINK_IMAGE / 3 * 4 + 8 {
                bail!("picture too large");
            }
            let webp = B64.decode(b64).context("picture isn't base64")?;
            if webp.len() > crate::photo::MAX_LINK_IMAGE || webp.len() < 12 || &webp[..4] != b"RIFF" || &webp[8..12] != b"WEBP" {
                bail!("picture isn't a small WebP");
            }
            let img = image::load_from_memory_with_format(&webp, image::ImageFormat::WebP).context("picture doesn't decode")?;
            let side = crate::photo::LINK_SIDE;
            if Some(img.width()) != r.width || Some(img.height()) != r.height || img.width().max(img.height()) > side {
                bail!("picture size doesn't match");
            }
            Some(webp)
        }
    };
    Ok((r, image))
}

/// Store a received post's `link`. A bad one is dropped (`Ok(false)`, logged),
/// like a bad photo or video reference: the post still shows.
pub fn store(conn: &rusqlite::Connection, post_id: &str, v: &serde_json::Value, text: &str) -> Result<bool> {
    let (r, image) = match checked(v, text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("post {post_id}: link preview dropped: {e:#}");
            return Ok(false);
        }
    };
    let (w, h) = if image.is_some() { (r.width, r.height) } else { (None, None) };
    let n = conn.execute(
        "INSERT OR IGNORE INTO link_previews (post_id, url, title, description, site, image, width, height)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![post_id, r.url, r.title, r.description, r.site, image, w, h],
    )?;
    Ok(n > 0)
}

/// What the feed shows for a post's link.
#[derive(Serialize, Clone, Debug)]
pub struct LinkView {
    pub url: String,
    /// Where the link really goes, from the URL itself (not the sender's `site`).
    pub host: String,
    pub title: String,
    pub description: Option<String>,
    pub site: Option<String>,
    /// `media://localhost/link/<post id>.webp` (see `serve_media`).
    pub image: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

pub fn view(conn: &rusqlite::Connection, post_id: &str) -> Result<Option<LinkView>> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row(
            "SELECT url, title, description, site, image IS NOT NULL, width, height FROM link_previews WHERE post_id = ?1",
            [post_id],
            |r| {
                let url: String = r.get(0)?;
                let has_image: bool = r.get(4)?;
                Ok(LinkView {
                    host: host(&url),
                    title: r.get(1)?,
                    description: r.get(2)?,
                    site: r.get(3)?,
                    image: has_image.then(|| crate::feed::media_url(&format!("link/{post_id}.webp"))),
                    width: r.get(5)?,
                    height: r.get(6)?,
                    url,
                })
            },
        )
        .optional()?)
}

/// The picture of a post's link preview, for `serve_media`. Not for a deleted post.
pub fn image(conn: &rusqlite::Connection, post_id: &str) -> Option<Vec<u8>> {
    if post_id.len() != 32 || !post_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    conn.query_row(
        "SELECT l.image FROM link_previews l JOIN posts p ON p.id = l.post_id WHERE l.post_id = ?1 AND p.deleted = 0",
        [post_id],
        |r| r.get::<_, Option<Vec<u8>>>(0),
    )
    .ok()
    .flatten()
}

/// The host a link goes to, without "www.", for the card.
pub fn host(url: &str) -> String {
    let h = Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    h.strip_prefix("www.").map(str::to_string).unwrap_or(h)
}

// --- finding the link in a post ----------------------------------------------------------

/// The first http(s) address in `text`, as written, without the punctuation
/// that usually follows a link in a sentence. Only this one gets a preview.
pub fn first_url(text: &str) -> Option<&str> {
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    let start = loop {
        let at = from + ["http://", "https://"].iter().filter_map(|p| lower[from..].find(p)).min()?;
        // Not the tail of a longer word ("xhttp://").
        if !text[..at].chars().next_back().is_some_and(|c| c.is_alphanumeric()) {
            break at;
        }
        from = at + 4;
    };
    let rest = &text[start..];
    let end = rest.find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '“' | '”')).unwrap_or(rest.len());
    let mut url = &rest[..end];
    while let Some(last) = url.chars().next_back() {
        let unbalanced = |open: char, close: char| last == close && url.matches(open).count() < url.matches(close).count();
        if matches!(last, '.' | ',' | ';' | ':' | '!' | '?' | '\'' | '’' | '»')
            || unbalanced('(', ')')
            || unbalanced('[', ']')
            || unbalanced('{', '}')
        {
            url = &url[..url.len() - last.len_utf8()];
        } else {
            break;
        }
    }
    // Just a scheme ("https://") isn't a link.
    let scheme_len = if url.to_ascii_lowercase().starts_with("https://") { 8 } else { 7 };
    (url.len() > scheme_len).then_some(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn open_graph_wins_and_tricks_are_skipped() {
        let t = scan(include_str!("../testdata/link/og.html"));
        let p = from_tags(&t).unwrap();
        assert_eq!(p.title, "Rock & Roll – the \"real\" story");
        assert_eq!(p.description.as_deref(), Some("Line one and line two — ☺"));
        assert_eq!(p.site.as_deref(), Some("Example"));
        assert_eq!(t.meta.get("og:image").map(String::as_str), Some("/images/card.png"));
        assert_eq!(t.title.as_deref(), Some("The page title & more"));
        // Comments, scripts, styles and the body don't count.
        for decoy in ["Commented out", "From a script", "From a style", "In the body"] {
            assert!(!t.meta.values().any(|v| v.contains(decoy)), "{decoy}");
        }
    }

    #[test]
    fn twitter_tags_then_title_and_description() {
        let t = scan(include_str!("../testdata/link/twitter.html"));
        let p = from_tags(&t).unwrap();
        assert_eq!((p.title.as_str(), p.description.as_deref(), p.site), ("Twitter title", Some("Twitter description"), None));
        assert_eq!(t.meta.get("twitter:image:src").map(String::as_str), Some("https://cdn.example.org/t.jpg"));

        let p = from_tags(&scan(include_str!("../testdata/link/plain.html"))).unwrap();
        assert_eq!((p.title.as_str(), p.description.as_deref()), ("Just a title", Some("Only a description")));

        assert!(from_tags(&scan(include_str!("../testdata/link/notitle.html"))).is_none());
    }

    #[test]
    fn attribute_quoting_and_a_cut_off_page() {
        let t = scan(r#"<head><meta content="first" property="og:title"><meta property="og:title" content="second"><meta name=description content='it&apos;s "fine"'><meta property="og:description" content="unterminated"#);
        assert_eq!(t.meta["og:title"], "first");
        assert_eq!(t.meta["description"], "it's \"fine\"");
        // A page cut off mid-tag still gives what came before.
        let mut big = String::from("<head><title>Kept</title>");
        big.push_str(&"<!-- padding -->".repeat(40_000));
        big.push_str("<meta property=\"og:title\" content=\"Too late\">");
        let cut = &big[..MAX_PAGE];
        let t = scan(cut);
        assert_eq!(t.title.as_deref(), Some("Kept"));
        assert!(!t.meta.contains_key("og:title"));
    }

    #[test]
    fn entities_and_cleaning() {
        assert_eq!(decode_entities("a &amp; b &lt;c&gt; &#65;&#x42; &nbsp;&bogus; & &#xZZ;"), "a & b <c> AB \u{a0}&bogus; & &#xZZ;");
        assert_eq!(clean("  a\n\tb\u{7}c  ", 10).as_deref(), Some("a b c"));
        assert_eq!(clean(" \n ", 10), None);
        let long = clean(&"word ".repeat(100), 20).unwrap();
        assert_eq!(long.chars().count(), 19 + 1);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn finding_the_link() {
        assert_eq!(first_url("Look: https://example.org/a_(b)."), Some("https://example.org/a_(b)"));
        assert_eq!(first_url("(see https://example.org/x)"), Some("https://example.org/x"));
        assert_eq!(first_url("first http://a.example/, then https://b.example"), Some("http://a.example/"));
        assert_eq!(first_url("HTTPS://Example.org/Path?q=1!"), Some("HTTPS://Example.org/Path?q=1"));
        assert_eq!(first_url("“https://example.org/q”"), Some("https://example.org/q"));
        assert_eq!(first_url("xhttp://nope.example https://yes.example"), Some("https://yes.example"));
        assert_eq!(first_url("just https:// and nothing"), None);
        assert_eq!(first_url("no links here, example.org"), None);
    }

    #[test]
    fn private_and_special_addresses_are_refused() {
        for a in [
            "127.0.0.1", "10.1.1.188", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "255.255.255.255", "224.0.0.1", "198.18.0.1", "192.0.2.1", "240.0.0.1", "::", "::1",
            "::ffff:192.168.1.1", "64:ff9b::a01:101", "2002:c0a8:101::1", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1",
        ] {
            assert!(blocked_ip(a.parse().unwrap()), "{a} should be blocked");
        }
        for a in ["93.184.215.14", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"] {
            assert!(!blocked_ip(a.parse().unwrap()), "{a} should be allowed");
        }
    }

    #[test]
    fn link_addresses_are_checked() {
        let ok = |s: &str| check_url(&Url::parse(s).unwrap(), false).is_ok();
        assert!(ok("https://example.org/a"));
        assert!(ok("http://93.184.215.14/"));
        for bad in [
            "ftp://example.org/", "file:///etc/passwd", "https://user:pw@example.org/", "http://localhost:8000/",
            "http://LOCALHOST./", "http://app.localhost/", "http://127.0.0.1/", "http://[::1]/", "http://192.168.1.1/",
            "http://0x7f000001/", "http://2130706433/", "http://[::ffff:10.0.0.1]/",
        ] {
            assert!(!ok(bad), "{bad} should be refused");
        }
        assert!(parse(&format!("https://example.org/{}", "a".repeat(MAX_URL))).is_err());
    }

    #[test]
    fn youtube_links_and_oembed() {
        for u in ["https://www.youtube.com/watch?v=dQw4w9WgXcQ", "https://youtu.be/dQw4w9WgXcQ", "https://m.youtube.com/shorts/abc", "http://youtube.com/@chan"] {
            assert!(is_youtube(&Url::parse(u).unwrap()), "{u}");
        }
        for u in ["https://notyoutube.com/watch", "https://youtube.com.evil.example/", "https://www.youtube-nocookie.com/embed/x"] {
            assert!(!is_youtube(&Url::parse(u).unwrap()), "{u}");
        }
        let q = oembed_url(&Url::parse("https://youtu.be/dQw4w9WgXcQ?t=42").unwrap());
        assert_eq!(q.as_str(), "https://www.youtube.com/oembed?format=json&url=https%3A%2F%2Fyoutu.be%2FdQw4w9WgXcQ%3Ft%3D42");
        let (p, img) = from_oembed(include_bytes!("../testdata/link/oembed.json")).unwrap();
        assert_eq!((p.title.as_str(), p.description.as_deref(), p.site.as_deref()), ("A video & its title", Some("Some Channel"), Some("YouTube")));
        assert_eq!(img.unwrap().as_str(), "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg");
        assert!(from_oembed(b"{\"title\": \"  \"}").is_err());
    }

    #[test]
    fn the_post_field_leaves_out_what_it_lacks() {
        let p = Preview { url: "https://a.example/".into(), title: "T".into(), description: None, site: None, image: None };
        assert_eq!(serde_json::to_value(p.to_ref()).unwrap(), serde_json::json!({ "url": "https://a.example/", "title": "T" }));
        let p = Preview { image: Some((b"RIFF....WEBP".to_vec(), 3, 2)), ..p };
        let r = p.to_ref();
        assert_eq!((r.image.as_deref(), r.width, r.height), (Some("UklGRi4uLi5XRUJQ"), Some(3), Some(2)));
        assert_eq!(host("https://www.Example.org:8443/x"), "example.org");
        assert_eq!(host("https://m.youtube.com/watch"), "m.youtube.com");
        // Only a post id's shape reaches the database.
        let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
        assert!(image(&conn, "../../secrets").is_none());
    }

    // --- against a little local web server ---------------------------------------------

    /// path -> (status line, content type, body); also counts connections.
    type Routes = HashMap<&'static str, (&'static str, &'static str, Vec<u8>)>;

    async fn serve(routes: Routes) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (routes, h) = (Arc::new(routes), hits.clone());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&req).lines().next().unwrap_or("").to_string();
                    let path = line.split(' ').nth(1).unwrap_or("/").to_string();
                    let (status, ctype, body) = routes.get(path.as_str()).cloned().unwrap_or(("404 Not Found", "text/plain", b"no".to_vec()));
                    let location = if status.starts_with("30") { format!("Location: {}\r\n", String::from_utf8_lossy(&body)) } else { String::new() };
                    let head = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        (base, hits)
    }

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_fn(w, h, |x, y| image::Rgb([(x % 256) as u8, (y % 256) as u8, 90]));
        let mut out = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png).unwrap();
        out
    }

    #[tokio::test]
    async fn a_page_with_its_picture() {
        let html = include_bytes!("../testdata/link/og.html").to_vec();
        let mut routes = Routes::new();
        routes.insert("/article", ("200 OK", "text/html; charset=utf-8", html));
        routes.insert("/moved", ("301 Moved Permanently", "text/plain", b"/article".to_vec()));
        routes.insert("/images/card.png", ("200 OK", "image/png", png(1200, 630)));
        let (base, _) = serve(routes).await;
        let url = format!("{base}/moved");
        let p = fetch_with(&url, true).await.unwrap();
        assert_eq!(p.url, url);
        assert_eq!(p.title, "Rock & Roll – the \"real\" story");
        let (webp, w, h) = p.image.unwrap();
        assert_eq!((w, h), (600, 315));
        assert_eq!(&webp[8..12], b"WEBP");
        assert!(webp.len() <= crate::photo::MAX_LINK_IMAGE);
    }

    #[tokio::test]
    async fn no_preview_for_other_content_or_endless_redirects() {
        let mut routes = Routes::new();
        routes.insert("/file.pdf", ("200 OK", "application/pdf", b"%PDF-1.7".to_vec()));
        routes.insert("/loop", ("302 Found", "text/plain", b"/loop".to_vec()));
        routes.insert("/broken-picture", ("200 OK", "text/html", b"<title>Still a card</title><meta property=og:image content=/nothing.png>".to_vec()));
        let (base, _) = serve(routes).await;
        assert!(fetch_with(&format!("{base}/file.pdf"), true).await.is_err());
        assert!(fetch_with(&format!("{base}/loop"), true).await.is_err());
        assert!(fetch_with(&format!("{base}/missing"), true).await.is_err());
        // A picture that won't load leaves a card without one.
        let p = fetch_with(&format!("{base}/broken-picture"), true).await.unwrap();
        assert_eq!((p.title.as_str(), p.image.is_none()), ("Still a card", true));
    }

    #[tokio::test]
    async fn local_addresses_are_never_contacted() {
        let mut routes = Routes::new();
        routes.insert("/", ("200 OK", "text/html", b"<title>Secret router page</title>".to_vec()));
        let (base, hits) = serve(routes).await;
        let port = base.rsplit(':').next().unwrap();
        for url in [base.clone(), format!("http://localhost:{port}/"), format!("http://[::1]:{port}/")] {
            assert!(fetch(&url).await.is_err(), "{url}");
        }
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn names_resolving_to_local_addresses_are_dropped() {
        // What the resolver does for any name: "localhost" resolves to loopback only.
        assert!(public_addrs("localhost").await.is_err());
    }
}
