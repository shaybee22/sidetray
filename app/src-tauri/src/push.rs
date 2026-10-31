//! Push channel: keeps a WebSocket open to the relay's /api/v1/ws and wakes
//! the sync loop whenever the server says something changed.
//!
//! The socket carries no content, only "go sync" hints (see the server's /ws
//! docstring). If it drops, the sync loop falls back to polling every 30 s
//! while this loop reconnects with exponential backoff (1 s doubling to 60 s,
//! with jitter).

use crate::api;
use crate::db::Identity;
use crate::state::App;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};
use tokio_tungstenite::Connector;

/// The server drops sockets silent for 75 s; ping well inside that.
const PING_EVERY: Duration = Duration::from_secs(25);
/// No frame at all (not even a pong) for this long: assume the connection is dead.
const SILENCE_LIMIT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A connection that lasted this long was healthy: start backing off from the bottom again.
const HEALTHY_AFTER: Duration = Duration::from_secs(30);

enum Ended {
    /// Closed or went quiet; reconnect.
    Dropped,
    /// The server says this device was revoked or its member removed.
    Removed,
}

pub fn spawn(handle: AppHandle, app: Arc<App>) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = BACKOFF_MIN;
        loop {
            let id = match app.identity() {
                Ok(Some(id)) if id.status == "active" => id,
                _ => {
                    // Not joined yet: wait to be told, with a slow re-check just in case.
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                        _ = app.push_wake.notified() => {}
                    }
                    continue;
                }
            };
            let started = Instant::now();
            let outcome = run(&handle, &app, &id).await;
            if app.push_connected.swap(false, Ordering::SeqCst) {
                let _ = handle.emit("push-status", false);
                // Sync now, and the sync loop goes back to polling.
                app.wake.notify_one();
            }
            match outcome {
                Ok(Ended::Removed) => {
                    eprintln!("push: the server says this device was removed");
                    // Confirm with /join/status; that records it and stops syncing.
                    crate::removed_check(&handle, &app).await;
                    continue;
                }
                Ok(Ended::Dropped) => eprintln!("push: connection closed"),
                Err(e) => eprintln!("push: {e:#}"),
            }
            if started.elapsed() >= HEALTHY_AFTER {
                backoff = BACKOFF_MIN;
            }
            tokio::select! {
                _ = tokio::time::sleep(jitter(backoff)) => {}
                _ = app.push_wake.notified() => {}
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    });
}

/// 75–125 % of `d`, so many clients don't reconnect in lockstep after a server restart.
fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 1];
    let _ = getrandom::getrandom(&mut b);
    d.mul_f64(0.75 + f64::from(b[0]) / 510.0)
}

async fn run(handle: &AppHandle, app: &App, id: &Identity) -> Result<Ended> {
    let token = app.secrets(id)?.token.clone();
    let mut req = api::ws_url(&id.server_url)?.into_client_request().context("building the socket request")?;
    req.headers_mut().insert("authorization", HeaderValue::from_str(&format!("Bearer {token}")).context("token")?);
    let tls = api::tls_config(id.ca_pem.as_deref())?;
    let (ws, _) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(Connector::Rustls(tls))),
    )
    .await
    .context("connecting timed out")?
    .context("connecting")?;
    let (mut tx, mut rx) = ws.split();

    app.push_connected.store(true, Ordering::SeqCst);
    let _ = handle.emit("push-status", true);
    // Catch up on whatever happened while we weren't connected.
    app.wake.notify_one();

    let mut ping = tokio::time::interval(PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_heard = Instant::now();
    loop {
        tokio::select! {
            msg = rx.next() => match msg {
                None | Some(Ok(Message::Close(_))) => return Ok(Ended::Dropped),
                Some(Err(e)) => return Err(e).context("socket"),
                Some(Ok(Message::Text(text))) => {
                    last_heard = Instant::now();
                    let kind = serde_json::from_str::<serde_json::Value>(text.as_str())
                        .ok()
                        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
                        .unwrap_or_default();
                    match kind.as_str() {
                        // A sync picks up new events, pending joins and rotated keys.
                        "new_event" | "new_dm" | "roster" | "join_request" | "key_rotated" => app.wake.notify_one(),
                        "removed" => return Ok(Ended::Removed),
                        _ => {} // hello, pong
                    }
                }
                Some(Ok(_)) => last_heard = Instant::now(),
            },
            _ = ping.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT {
                    return Ok(Ended::Dropped);
                }
                tx.send(Message::text(r#"{"type":"ping"}"#)).await.context("sending ping")?;
            }
        }
    }
}
