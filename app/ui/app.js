// Side Tray UI. Plain JS over Tauri's global API (withGlobalTauri).
// Everything people type is inserted with textContent, never as HTML.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🎉"];

let view = null;          // last get_state()
let pollTimer = null;     // waiting-for-approval poll
let loadedCount = 50;     // how many posts the feed shows
let pendingTimer = null;

function showScreen(id) {
  for (const s of $$(".screen")) s.hidden = s.id !== id;
}

function showError(el, e) {
  el.textContent = typeof e === "string" ? e : (e && e.message) || String(e);
  el.hidden = false;
}

function hideError(el) { el.hidden = true; el.textContent = ""; }

/** Run an async action with a button disabled meanwhile. */
async function busy(button, fn) {
  const label = button.textContent;
  button.disabled = true;
  try { return await fn(); } finally { button.disabled = false; button.textContent = label; }
}

function when(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const secs = Math.round((Date.now() - d) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} h ago`;
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return d.toLocaleString(undefined, { month: "short", day: "numeric", year: sameYear ? undefined : "numeric", hour: "numeric", minute: "2-digit" });
}

function hue(name) {
  let h = 0;
  for (const c of name) h = (h * 31 + c.codePointAt(0)) % 360;
  return h;
}

// --- routing ------------------------------------------------------------------------

/** A phone (Android): no tray, autostart or self-update; the layout leans on this class too. */
let mobile = false;

/**
 * A file's bytes as an invoke argument. Desktop sends them as the raw request
 * body. Android's IPC only carries JSON, so there they go as one base64 string
 * (far smaller than a JSON array of numbers); the Rust side takes either.
 */
async function bytesArg(blob) {
  if (!mobile) return new Uint8Array(await blob.arrayBuffer());
  const read = () => new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    r.readAsDataURL(blob);
  });
  // A photo straight from Android's picker now and then can't be read on the
  // first try (NotReadableError); a moment later it can.
  let url;
  for (let attempt = 0; ; attempt++) {
    try {
      url = await read();
      break;
    } catch (e) {
      if (attempt >= 2 || !e || e.name !== "NotReadableError") throw e;
      await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
    }
  }
  return { b64: url.slice(url.indexOf(",") + 1) };
}

/**
 * Keep the page clear of the status bar, the gesture bar and camera cutouts.
 * Android's own numbers count where the WebView's env(safe-area-inset-*)
 * comes up short; checked again whenever the window changes (rotation, or
 * moving between a flip phone's inner and outer screens).
 */
async function applyInsets() {
  let i;
  try { i = await invoke("system_insets"); } catch (_) { return; }
  if (!i) return;
  const root = document.documentElement.style;
  ["--sat", "--sar", "--sab", "--sal"].forEach((v, n) => {
    const side = ["top", "right", "bottom", "left"][n];
    root.setProperty(v, `max(env(safe-area-inset-${side}, 0px), ${Math.round(i[n])}px)`);
  });
  fitChat();
}
let insetsTimer = null;
window.addEventListener("resize", () => {
  if (!mobile) return;
  clearTimeout(insetsTimer);
  insetsTimer = setTimeout(applyInsets, 150);
});

async function boot() {
  try {
    mobile = (await invoke("get_settings")).mobile;
  } catch (_) {}
  document.documentElement.classList.toggle("mobile", mobile);
  if (!mobile) $("#dm-text").placeholder = "Write a message… (Ctrl+Enter sends)";
  invoke("update_status").then(renderUpdate).catch(() => {});
  try {
    view = await invoke("get_state");
  } catch (e) {
    $("#screen-loading p").textContent = `Couldn't open the app's data: ${e}`;
    return;
  }
  if (mobile) await restoreDrafts();
  route();
  handleInvite();
  if (mobile) {
    restoreView();
    applyInsets();
    // Called by the activity (MainActivity.kt) on Back; true = the page took it.
    window.__sidetrayBack = () => { onBack(); return true; };
    checkShare();
  }
}

function route() {
  clearInterval(pollTimer);
  switch (view.stage) {
    case "setup": return startWizard();
    case "pending":
    case "denied": return startWaiting();
    case "active": return startMain();
    case "removed":
    case "revoked": return startRemoved();
    default: $("#screen-loading p").textContent = `Unexpected state: ${view.stage}`;
  }
}

// --- wizard -------------------------------------------------------------------------

// Step 1 server and group name; step 2 (test servers only) the certificate's
// fingerprint; step 3 your name and email (and the setup token to create a group).
let wz = { server: null, group: "", fingerprint: null, exists: false };

function wizardStep(id) {
  for (const step of ["wz-server", "wz-trust", "wz-details"]) $(`#${step}`).hidden = step !== id;
}

function startWizard(invite) {
  showScreen("screen-wizard");
  wizardStep("wz-server");
  for (const e of ["#wz-server-err", "#wz-trust-err", "#wz-details-err"]) hideError($(e));
  $("#wz-invite-note").hidden = !invite;
  if (invite) {
    // From a link: filled in and checked straight away; they type name and email.
    $("#wz-url").value = invite.server;
    $("#wz-group").value = invite.group;
    $("#wz-ca").value = "";
    return checkServer();
  }
  ($("#wz-url").value ? $("#wz-group") : $("#wz-url")).focus();
}

/** "AB:CD:..." as four lines of 8 pairs, easier to read out and compare. */
function renderFingerprint(el, fp) {
  const pairs = fp.split(":");
  const lines = [];
  for (let i = 0; i < pairs.length; i += 8) lines.push(pairs.slice(i, i + 8).join(":"));
  el.replaceChildren(...lines.map((l) => { const d = document.createElement("div"); d.textContent = l; return d; }));
}

$("#wz-server").addEventListener("submit", (ev) => { ev.preventDefault(); checkServer(); });

async function checkServer() {
  const err = $("#wz-server-err");
  hideError(err);
  const server = $("#wz-url").value.trim();
  const group = $("#wz-group").value.trim();
  if (!server) return showError(err, "Enter the server address you were given.");
  if (!group) return showError(err, "Enter the group's name. Servers don't list their groups, so you need its exact name.");
  await busy($("#wz-continue"), async () => {
    $("#wz-continue").textContent = "Checking…";
    try {
      const c = await invoke("check_server", { server, caPem: $("#wz-ca").value || null });
      wz = { server: c.server, group, fingerprint: c.fingerprint, exists: false };
      if (c.test_mode) {
        $("#wz-trust-server").textContent = c.server;
        renderFingerprint($("#wz-fp"), c.fingerprint);
        hideError($("#wz-trust-err"));
        wizardStep("wz-trust");
        $("#wz-trust-ok").focus();
        return;
      }
      await findGroup();
    } catch (e) {
      showError(err, e);
    }
  });
}

$("#wz-trust-back").addEventListener("click", () => wizardStep("wz-server"));

$("#wz-trust-ok").addEventListener("click", async () => {
  const err = $("#wz-trust-err");
  hideError(err);
  await busy($("#wz-trust-ok"), async () => {
    try {
      await invoke("trust_server", { fingerprint: wz.fingerprint });
      await findGroup();
    } catch (e) {
      showError(err, e);
    }
  });
});

async function findGroup() {
  const g = await invoke("probe_group", { groupName: wz.group });
  wz.exists = g.exists;
  if (g.exists) wz.group = g.name;
  $("#wz-found").textContent = g.exists
    ? `Found the group “${g.name}” on ${wz.server}.`
    : `There's no group called “${wz.group}” on ${wz.server}. If you were invited, check the name's spelling with them. To create it instead, and become its first Key Master, enter the setup token from whoever runs the server.`;
  $("#wz-token-row").hidden = g.exists;
  $("#wz-submit").textContent = g.exists ? "Ask to join" : "Create the group";
  hideError($("#wz-details-err"));
  wizardStep("wz-details");
  $("#wz-name").focus();
}

$("#wz-back").addEventListener("click", () => {
  wizardStep("wz-server");
  hideError($("#wz-details-err"));
});

$("#wz-details").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#wz-details-err");
  hideError(err);
  const founding = !wz.exists;
  const args = {
    groupName: wz.group,
    displayName: $("#wz-name").value.trim(),
    email: $("#wz-email").value.trim(),
    setupToken: founding ? $("#wz-token").value : null,
  };
  if (!args.displayName || !args.email) return showError(err, "Fill in your name and email.");
  if (!/^[^@\s]+@[^@\s]+$/.test(args.email)) return showError(err, "That doesn't look like an email address.");
  if (founding && !args.setupToken) return showError(err, "Creating a group needs the server's setup token.");
  await busy($("#wz-submit"), async () => {
    $("#wz-submit").textContent = founding ? "Creating…" : "Sending…";
    try {
      await invoke("register", args);
      view = await invoke("get_state");
      route();
    } catch (e) {
      showError(err, e);
    }
  });
});

// --- invite links -------------------------------------------------------------------------

async function handleInvite() {
  let msg;
  try { msg = await invoke("take_invite"); } catch (e) { return console.warn("take_invite", e); }
  if (!msg) return;
  if (msg.error) {
    return notice("That invite link can't be used", `${msg.error}.`);
  }
  if (!view || view.stage !== "setup") {
    const what = view && view.stage === "active" ? "a member of" : "set up for";
    return notice("Side Tray is already set up",
      `This app is already ${what} “${view ? view.group_name : ""}”. For now one installation joins one group, so the invite to “${msg.invite.group}” can't be used here.`);
  }
  startWizard(msg.invite);
}

listen("invite", handleInvite);

// --- Share → Side Tray (Android) ------------------------------------------------------------

let shareTray = null; // made on first use (the Attachments class is defined further down)
let shareText = "";
let shareChecking = null;
let shareGen = 0; // which share the dialog is showing; an older one's pictures stop loading

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Something shared from another app, if there is: wait while it's copied, then offer it. */
function checkShare() {
  if (!mobile || !view) return;
  shareChecking ??= (async () => {
    try {
      let s = await invoke("take_share");
      for (let i = 0; s && s.state === "copying" && i < 200; i++) {
        await sleep(250);
        s = await invoke("take_share");
      }
      if (s && s.state === "ready") receiveShare(s); // not awaited: a newer share may replace it
    } catch (e) {
      console.warn("take_share", e);
    } finally {
      shareChecking = null;
    }
  })();
}

listen("resumed", checkShare);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") checkShare(); });

/** A link shared from a browser comes as the page title (subject) and its address (text). */
function sharedText(s) {
  const text = (s.text || "").trim();
  const subject = (s.subject || "").trim();
  if (subject && !text.includes(subject)) return text ? `${subject}\n${text}` : subject;
  return text;
}

async function receiveShare(s) {
  const text = sharedText(s);
  const notes = [...s.errors];
  if (s.skipped) notes.push(`${s.skipped} shared file${s.skipped > 1 ? "s weren't pictures" : " wasn't a picture"}, so ${s.skipped > 1 ? "they were" : "it was"} left out.`);
  const active = view.stage === "active" && !$("#screen-main").classList.contains("readonly");
  if (!active) {
    invoke("end_share");
    const why = {
      setup: "Side Tray isn't in a group yet, so there's nowhere to share this. Join a group first (ask a Key Master for an invite link), then share it again.",
      pending: "Your request to join the group is still waiting for a Key Master. Once you're in, share it again.",
      denied: "Your request to join the group was turned down, so there's nowhere to share this.",
      removed: "This device isn't in the group any more, so it can't share anything.",
      revoked: "This device was disconnected from the group, so it can't share anything.",
    }[view.stage] || "Side Tray can't share anything right now.";
    return notice("Can't share this yet", why);
  }
  if (!s.photos && !text) {
    invoke("end_share");
    return notice("Nothing to share", notes.join(" ") || "Side Tray didn't receive a picture or any text.");
  }

  // A new share replaces one still waiting in the dialog.
  const gen = ++shareGen;
  if (!shareTray) {
    shareTray = new Attachments({ max: 20, noun: "share" });
    shareTray.attach($("#sh-photos"), $("#sh-hint"), $("#sh-err"));
  }
  shareTray.clear();
  shareText = text;
  const dlg = $("#share");
  if (!dlg.open) dlg.showModal();
  const what = [];
  if (s.photos) what.push(`${s.photos} picture${s.photos > 1 ? "s" : ""}`);
  if (text) what.push(/^https?:\/\/\S+$/.test(s.text.trim()) ? "a link" : "some text");
  $("#sh-what").textContent = `From another app: ${what.join(" and ")}. Where should it go?`;
  $("#sh-text").textContent = text;
  $("#sh-text").hidden = !text;
  hideError($("#sh-err"));
  if (notes.length) showError($("#sh-err"), notes.join("\n"));
  $("#sh-dm").hidden = true;
  invoke("dm_recipients").then((people) => {
    $("#sh-people").replaceChildren(...people.map((p) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "pick";
      const face = document.createElement("span");
      face.className = "avatar";
      face.setAttribute("aria-hidden", "true");
      avatar(face, p.name, p.avatar);
      const name = document.createElement("span");
      name.textContent = p.name;
      b.append(face, name);
      b.addEventListener("click", () => shareTo(p.member_id));
      return b;
    }));
    $("#sh-dm").hidden = !people.length;
  }).catch((e) => console.warn("dm_recipients", e));
  setShareReady(false);
  const sources = Array.from({ length: s.photos }, (_, index) => ({
    label: s.photos > 1 ? `Picture ${index + 1}` : "The picture",
    load: () => (gen === shareGen ? invoke("stage_shared_photo", { index }) : null),
  }));
  await shareTray.add(sources);
  if (gen !== shareGen) return;
  invoke("end_share");
  if (dlg.open) setShareReady(true);
}

/** Sending is possible once the pictures are ready (resized and stripped). */
function setShareReady(ready) {
  for (const b of $$("#sh-feed, #sh-people button")) b.disabled = !ready;
  $("#sh-feed").textContent = ready ? "Post it to the feed" : "Preparing pictures…";
}

function shareTo(memberId) {
  const items = shareTray.take();
  const text = shareText;
  shareText = "";
  $("#share").close("sent");
  const into = (input) => {
    input.value = input.value.trim() ? `${input.value.trimEnd()}\n\n${text}` : text;
  };
  if (memberId) {
    chatWith = memberId;
    selectTab("messages"); // opens the chat; its draft belongs to this person from here on
    into($("#dm-text"));
    dmTray.adopt(items);
  } else {
    selectTab("feed");
    into($("#cp-text"));
    postTray.adopt(items);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

$("#sh-feed").addEventListener("click", () => shareTo(null));
$("#share").addEventListener("close", () => {
  if ($("#share").returnValue === "sent") return;
  // Cancelled (the button, or Back): nothing of it is kept.
  shareTray?.clear();
  shareText = "";
  invoke("end_share");
});

// --- the Back button (Android) ----------------------------------------------------------------

/** Unsent words or photos anywhere: the composer, a comment, a message. */
function unsentWork() {
  const what = [];
  if ($("#cp-text").value.trim() || postTray.items.length) what.push("post");
  if ($$("#feed .comment-input").some((i) => i.value.trim()) || [...commentTrays.values()].some((t) => t.items.length)) what.push("comment");
  if ($("#dm-text").value.trim() || dmTray.items.length) what.push("message");
  return what;
}

/**
 * Back closes whatever is on top (the photo viewer, a dialog, a chat), then
 * goes back to the feed, and only then leaves the app (to the background, like
 * Home), asking first if something is half-written.
 */
async function onBack() {
  if (!$("#lightbox").hidden) return closeLightbox();
  const dlg = $$("dialog").find((d) => d.open);
  if (dlg) return dlg.close();
  const main = $("#screen-main");
  if (!$("#screen-wizard").hidden && $("#wz-server").hidden) return void $($("#wz-trust").hidden ? "#wz-back" : "#wz-trust-back").click();
  if (!main.hidden && main.classList.contains("readonly")) return startRemoved();
  if (!main.hidden) {
    if (!$("#panel-feed").hidden && $("#feed .react-picker")) return void loadFeed(); // an open emoji row
    if (!$("#panel-messages").hidden) {
      if (!$("#dm-picker").hidden) return void ($("#dm-picker").hidden = true);
      if (!$("#dm-chat-view").hidden) { chatWith = null; return showMessages(); }
    }
    if ($("#panel-feed").hidden) {
      selectTab("feed");
      return window.scrollTo({ top: 0 });
    }
    const unsent = unsentWork();
    if (unsent.length) {
      const list = unsent.length === 1 ? `an unsent ${unsent[0]}` : `an unsent ${unsent.slice(0, -1).join(", ")} and ${unsent.at(-1)}`;
      const leave = await askConfirm({
        title: "Leave without sending?",
        body: `You have ${list}. It stays here while Side Tray is in the background, but it's lost if Android closes the app.`,
        ok: "Leave",
        cancelLabel: "Keep writing",
      });
      if (!leave) return;
    }
  }
  invoke("leave_app").catch((e) => console.warn("leave_app", e));
}

// --- waiting for approval ----------------------------------------------------------------

function startWaiting() {
  showScreen("screen-waiting");
  $("#wt-group").textContent = view.group_name || "";
  $("#wt-code").textContent = view.safety_code || "";
  setWaitingState(view.stage === "denied" ? "denied" : "pending");
  if (view.stage !== "denied") {
    checkProgress();
    pollTimer = setInterval(checkProgress, 4000);
  }
}

function setWaitingState(state) {
  $("#wt-pending").hidden = state !== "pending";
  $("#wt-approved").hidden = state !== "approved";
  $("#wt-denied").hidden = state !== "denied";
  $("#wt-cancel").hidden = state === "denied";
}

async function checkProgress() {
  const err = $("#wt-poll-err");
  try {
    const p = await invoke("join_progress");
    hideError(err);
    if (p.state === "pending") {
      $("#wt-code").textContent = p.code;
    } else if (p.state === "approved") {
      clearInterval(pollTimer);
      for (const el of $$(".wt-approver")) el.textContent = p.approver_name;
      setWaitingState("approved");
      $("#wt-kmcode").focus();
    } else if (p.state === "denied") {
      clearInterval(pollTimer);
      setWaitingState("denied");
    } else if (p.state === "active") {
      clearInterval(pollTimer);
      view = await invoke("get_state");
      route();
    }
  } catch (e) {
    showError(err, `Couldn't check with the server: ${e}`);
  }
}

$("#wt-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#wt-err");
  hideError(err);
  const code = $("#wt-kmcode").value.trim();
  if (!code) return showError(err, "Type the code the Key Master read to you.");
  await busy($("#wt-unlock"), async () => {
    $("#wt-unlock").textContent = "Checking…";
    try {
      await invoke("confirm_approval", { code });
      view = await invoke("get_state");
      route();
    } catch (e) {
      showError(err, e);
    }
  });
});

async function startOver() {
  clearInterval(pollTimer);
  try {
    await invoke("reset");
  } catch (e) {
    return showError($("#wt-poll-err"), e);
  }
  view = await invoke("get_state");
  route();
}

$("#wt-restart").addEventListener("click", startOver);

// Two-step confirm without a dialog.
function confirmClick(button, question, action) {
  button.addEventListener("click", async () => {
    if (button.dataset.armed) {
      delete button.dataset.armed;
      return action();
    }
    const label = button.textContent;
    button.dataset.armed = "1";
    button.textContent = mobile ? question.replace(/^Click/, "Tap") : question;
    setTimeout(() => { delete button.dataset.armed; button.textContent = label; }, 4000);
  });
}
confirmClick($("#wt-cancel"), "Click again to cancel the request", startOver);

// --- main ---------------------------------------------------------------------------

function startMain() {
  showScreen("screen-main");
  $("#screen-main").classList.remove("readonly");
  $("#readonly-banner").hidden = true;
  $("#tb-group").textContent = view.group_name;
  renderMissed();
  renderCertProblem();
  $("#tab-km-btn").hidden = !view.keymaster;
  $("#km-code").textContent = view.safety_code;
  renderSyncStatus();
  renderDevice();
  renderDmBadge();
  loadFeed().then(markReadIfViewed).then(checkOpen);
  refreshPush();
}

function selectTab(name) {
  saveDraftsSoon();
  for (const t of $$(".tab")) t.setAttribute("aria-selected", String(t.dataset.tab === name));
  for (const p of $$(".panel")) p.hidden = p.id !== `panel-${name}`;
  clearInterval(pendingTimer);
  if (name === "km") {
    loadPending();
    pendingTimer = setInterval(loadPending, 10000);
  }
  if (name === "device") { renderDevice(); loadSettings(); loadProfile(); refreshPush(); }
  if (name === "members") loadMembers();
  if (name === "feed") loadFeed().then(markReadIfViewed);
  if (name === "messages") showMessages();
}
for (const t of $$(".tab")) t.addEventListener("click", () => selectTab(t.dataset.tab));

function renderSyncStatus(text) {
  const el = $("#sync-status");
  if (text == null && view.live) {
    // Connected to the server's push channel: new posts show up as they're made.
    const dot = document.createElement("span");
    dot.className = "live-dot";
    dot.setAttribute("aria-hidden", "true");
    el.replaceChildren(dot, "Live");
    el.title = "Connected: new posts arrive right away";
    return;
  }
  el.textContent = text ?? (view.last_sync_at ? `Synced ${when(view.last_sync_at)}` : "Not synced yet");
}

// --- unread, notifications, tray ------------------------------------------------------

/** The feed counts as read once it's on screen in a focused window. */
function feedInView() {
  return view && view.stage === "active" && !$("#panel-feed").hidden
    && document.visibilityState === "visible" && document.hasFocus();
}

async function markReadIfViewed() {
  if (!feedInView() || !view.unread) return;
  view.unread = 0;
  try { await invoke("mark_read"); } catch (e) { console.warn("mark_read", e); }
}

window.addEventListener("focus", () => { markReadIfViewed(); markChatRead(); });
document.addEventListener("visibilitychange", () => { markReadIfViewed(); markChatRead(); });

listen("push-status", async (ev) => {
  if (!view || view.stage !== "active") return;
  view.live = !!ev.payload;
  renderSyncStatus();
});

// The relay confirmed this device was removed or revoked: syncing has stopped.
listen("removed", async () => {
  view = await invoke("get_state");
  route();
});

// A notification was clicked: show what it was about.
listen("open-item", (ev) => openItem(ev.payload));

async function openItem(t) {
  if (t.kind === "update") return; // the window is up; the banner says the rest
  if (!view || view.stage !== "active") return;
  if (t.kind === "joins" && view.keymaster) return selectTab("km");
  if (t.kind === "dm") { chatWith = t.member_id; return selectTab("messages"); }
  if (t.kind === "messages") { chatWith = null; return selectTab("messages"); }
  selectTab("feed");
  await loadFeed();
  if (t.kind === "post") {
    const el = document.querySelector(`#feed .post[data-id="${CSS.escape(t.post_id)}"]`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.add("highlight");
      setTimeout(() => el.classList.remove("highlight"), 2500);
    }
  } else {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  markReadIfViewed();
}

// --- notifications on a phone (A3) ------------------------------------------------------------

let push = null; // the last push_status: notifications on/ask/off, delivery instant/periodic

/** A phone opened by tapping a notification: show what it was about. */
async function checkOpen() {
  if (!mobile || !view || view.stage !== "active") return;
  try {
    const t = await invoke("take_open");
    if (t) await openItem(t);
  } catch (e) {
    console.warn("take_open", e);
  }
}

async function refreshPush() {
  if (!mobile || !view || view.stage !== "active") return;
  try {
    push = await invoke("push_status");
  } catch (e) {
    console.warn("push_status", e);
    return;
  }
  renderNotifOffer();
  renderBatteryOffer();
  renderPushSettings();
}

/** Which of Side Tray and the push app Android holds back to save battery. */
function batteryProblems() {
  const b = push && push.battery;
  if (!b || push.notifications !== "on" || push.mode === "none") return { app: false, dist: false };
  return {
    app: !b.app_unrestricted || b.app_restricted,
    // The push app only matters while wake-ups come through it.
    dist: push.mode === "instant" && b.distributor_unrestricted === false,
  };
}

const distributorShort = (d) => (d === "io.heckel.ntfy" ? "ntfy" : "the push app");

/** What to do about battery restrictions, in words ("" if nothing). */
function batteryHow() {
  const p = batteryProblems();
  const names = [p.app && "Side Tray", p.dist && distributorShort(push.distributor)].filter(Boolean);
  if (!names.length) return "";
  const steps = [];
  if (p.app) {
    steps.push(push.battery.app_restricted
      ? "Allow Side Tray opens its App info: tap App battery usage (or Battery) and choose Unrestricted (on newer phones it's under Allow background usage)."
      : "Allow Side Tray asks Android to let it run in the background: tap Allow.");
  }
  if (p.dist) {
    steps.push(`Open ${distributorShort(push.distributor)}'s settings, tap App battery usage (or Battery) and choose Unrestricted (on newer phones it's under Allow background usage), then come back.`);
  }
  return `Android is saving battery by holding back ${names.join(" and ")}, so notifications can arrive late or not at all. ${steps.join(" ")}`;
}

/** A card on the feed when Side Tray or the push app is battery-restricted, until fixed or put off. */
function renderBatteryOffer() {
  const p = batteryProblems();
  const box = $("#battery-offer");
  if ((!p.app && !p.dist) || push.battery_later) { box.hidden = true; return; }
  $("#battery-text").textContent = batteryHow();
  $("#battery-app").hidden = !p.app;
  $("#battery-dist").hidden = !p.dist;
  $("#battery-dist").textContent = `Open ${distributorShort(push.distributor)}'s settings`;
  box.hidden = false;
}

async function openBattery(which) {
  try {
    await invoke("open_battery_settings", { which });
  } catch (e) {
    console.warn("open_battery_settings", e);
  }
  // Android's dialog or settings screen is its own window: look again afterwards.
  for (const ms of [1500, 4000]) setTimeout(refreshPush, ms);
}

$("#battery-app").addEventListener("click", () => openBattery("app"));
$("#battery-dist").addEventListener("click", () => openBattery("distributor"));
$("#battery-later").addEventListener("click", async () => {
  $("#battery-offer").hidden = true;
  await invoke("dismiss_notice", { which: "battery" }).catch((e) => console.warn("dismiss_notice", e));
  refreshPush();
});
$("#ns-battery-app").addEventListener("click", () => openBattery("app"));
$("#ns-battery-dist").addEventListener("click", () => openBattery("distributor"));

const distributorName = (d) => (d === "io.heckel.ntfy" ? "the ntfy app" : d || "a push app");

/** Why notifications aren't instant, in words, or "" if they are. */
function pushHow() {
  if (!push || push.mode !== "periodic") return "";
  switch (push.reason) {
    case "no_distributor":
      return "For instant notifications, install the free ntfy app (from F-Droid or Google Play), then open Side Tray again.";
    case "server_refused":
      return `Your ntfy app uses ${push.endpoint_host || "another server"}, but this group's server only sends to its own. In ntfy, open Settings → Default server, enter ${push.ntfy || "the address your group's server gives"}, then open Side Tray again.`;
    case "server_off":
      return "This group's server doesn't send instant notifications.";
    case "registering":
      return `Setting up instant notifications with ${distributorName(push.distributor)}…`;
    case "offline":
      return "Couldn't reach the server to set up instant notifications. Side Tray tries again each time you open it.";
    case "failed":
      return `${distributorName(push.distributor)} turned down the registration${push.detail ? ` (${push.detail})` : ""}.`;
    default:
      return "";
  }
}

/**
 * The offer to turn notifications on (once, after joining: Android 13+ asks for
 * permission), then, once, the note on how to get them instantly.
 */
function renderNotifOffer() {
  const box = $("#notif-offer");
  const noteDue = push && push.notifications === "on" && push.mode === "periodic" && !push.note_seen
    && ["no_distributor", "server_refused", "server_off"].includes(push.reason);
  if (push && push.notifications === "ask") {
    $("#notif-offer-title").textContent = "Get notified about new posts?";
    $("#notif-offer-text").textContent = "Side Tray can tell you about new posts, comments on your posts and messages, even while it's closed. Android will ask whether to allow it.";
    $("#notif-offer-yes").textContent = "Turn on";
    $("#notif-offer-no").textContent = "Not now";
    $("#notif-offer-no").hidden = false;
    box.dataset.offer = "notifications";
    box.hidden = false;
  } else if (noteDue) {
    $("#notif-offer-title").textContent = push.reason === "server_refused" ? "One more step for instant notifications" : "Notifications can take up to 15 minutes";
    $("#notif-offer-text").textContent = `Side Tray checks for new posts about every 15 minutes. ${pushHow()}`;
    $("#notif-offer-yes").textContent = "OK";
    $("#notif-offer-no").hidden = true;
    box.dataset.offer = "push_note";
    box.hidden = false;
  } else {
    box.hidden = true;
  }
}

async function askForNotifications() {
  try {
    await invoke("request_notifications");
  } catch (e) {
    console.warn("request_notifications", e);
  }
  // Android's prompt is its own window: look again once it has had a chance to close.
  for (const ms of [1000, 3000, 8000]) setTimeout(refreshPush, ms);
}

$("#notif-offer-yes").addEventListener("click", async () => {
  const which = $("#notif-offer").dataset.offer;
  $("#notif-offer").hidden = true;
  if (which === "notifications") return askForNotifications();
  await invoke("dismiss_notice", { which }).catch((e) => console.warn("dismiss_notice", e));
  refreshPush();
});

$("#notif-offer-no").addEventListener("click", async () => {
  $("#notif-offer").hidden = true;
  await invoke("dismiss_notice", { which: "notifications" }).catch((e) => console.warn("dismiss_notice", e));
  refreshPush();
});

/** This device → Settings, on a phone: whether notifications are on and how they arrive. */
function renderPushSettings() {
  if (!push) return;
  const on = push.notifications === "on";
  $("#ns-state").textContent = on ? "on" : push.notifications === "ask" ? "off (not turned on yet)" : "off (turned off in Android's settings)";
  $("#ns-turn-on").hidden = on;
  $("#ns-settings").hidden = on || push.notifications === "ask";
  $("#ns-mode").textContent = push.mode === "instant"
    ? `instant, through ${distributorName(push.distributor)}${push.endpoint_host ? ` (${push.endpoint_host})` : ""}`
    : push.mode === "periodic" ? "about every 15 minutes" : "none";
  const how = pushHow();
  $("#ns-how").textContent = how;
  $("#ns-how").hidden = !how;
  const b = push.battery;
  const p = batteryProblems();
  const state = (ok) => (ok ? "unrestricted" : "restricted to save battery");
  $("#ns-battery").textContent = !b ? "unknown"
    : `Side Tray ${state(b.app_unrestricted && !b.app_restricted)}`
      + (b.distributor_unrestricted === null || b.distributor_unrestricted === undefined ? ""
        : `, ${distributorShort(push.distributor)} ${state(b.distributor_unrestricted)}`);
  const bhow = batteryHow();
  $("#ns-battery-how").textContent = bhow;
  $("#ns-battery-how").hidden = !bhow;
  $("#ns-battery-app").hidden = !p.app;
  $("#ns-battery-dist").hidden = !p.dist;
  $("#ns-battery-dist").textContent = `Open ${distributorShort(push.distributor)}'s settings`;
}

$("#ns-turn-on").addEventListener("click", askForNotifications);
$("#ns-settings").addEventListener("click", () => invoke("open_notification_settings").catch((e) => console.warn(e)));
$("#ns-recheck").addEventListener("click", async () => {
  await busy($("#ns-recheck"), async () => {
    await invoke("push_setup").catch((e) => console.warn("push_setup", e));
    await sleep(2500); // the distributor answers in the background
    await refreshPush();
  });
});

listen("resumed", () => { checkOpen(); refreshPush(); });
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") { checkOpen(); refreshPush(); }
});

$("#sync-btn").addEventListener("click", async () => {
  await busy($("#sync-btn"), async () => {
    renderSyncStatus("Syncing…");
    try {
      await invoke("sync_now"); // also fires "synced"
    } catch (e) {
      renderSyncStatus("Couldn't sync");
      $("#sync-status").title = String(e);
    }
  });
});

listen("synced", async (ev) => {
  const r = ev.payload;
  const wasKm = view.keymaster;
  view = await invoke("get_state");
  if (view.stage !== "active") return route();
  $("#sync-status").title = "";
  renderSyncStatus();
  renderMissed();
  renderCertProblem();
  if (view.keymaster !== wasKm) startMain();
  if (!$("#panel-members").hidden && (r.rotated || r.new_events || r.avatars)) loadMembers();
  const badge = $("#km-badge");
  badge.textContent = String(r.pending_joins);
  badge.hidden = !r.pending_joins;
  if (!$("#panel-feed").hidden && (r.new_events || r.avatars || r.names_changed)) loadFeed();
  if (!$("#panel-members").hidden && r.names_changed) loadMembers();
  if (r.names_changed) renderDevice();
  if (!$("#panel-km").hidden) loadPending();
  if (!$("#panel-messages").hidden && (r.new_dms || r.avatars || r.names_changed)) refreshMessages();
  renderDmBadge();
  markReadIfViewed();
});

listen("sync-error", async (ev) => {
  renderSyncStatus("Couldn't sync");
  $("#sync-status").title = String(ev.payload);
  try { view = await invoke("get_state"); renderCertProblem(); } catch (e) { console.warn("get_state", e); }
});

/** The server's certificate was refused: say so where it can't be missed. */
function renderCertProblem() {
  const banner = $("#cert-banner");
  banner.hidden = !view.cert_problem;
  if (view.cert_problem) $("#cert-text").textContent = view.cert_problem.split("\n(")[0];
}

$("#cert-review").addEventListener("click", () => {
  selectTab("device");
  $("#cert-card").scrollIntoView({ behavior: "smooth", block: "start" });
});

setInterval(() => { if (view && view.stage === "active") renderSyncStatus(); }, 30000);

// --- feed ---------------------------------------------------------------------------

async function loadFeed() {
  // Keep half-typed comments and focus across re-renders.
  const drafts = {};
  for (const input of $$("#feed .comment-input")) if (input.value) drafts[input.dataset.post] = input.value;
  const focused = document.activeElement && document.activeElement.classList.contains("comment-input")
    ? document.activeElement.dataset.post : null;

  let posts;
  try {
    posts = await invoke("get_feed", { before: null, limit: loadedCount });
  } catch (e) {
    return showError($("#cp-err"), e);
  }
  const feed = $("#feed");
  feed.replaceChildren(...posts.map(renderPost));
  const shown = new Set(posts.map((p) => p.id));
  for (const [id, tray] of commentTrays) if (!shown.has(id)) { tray.clear(); commentTrays.delete(id); }
  $("#feed-empty").hidden = posts.length > 0;
  $("#load-more").hidden = posts.length < loadedCount;
  for (const input of $$("#feed .comment-input")) {
    const id = input.dataset.post;
    if (!drafts[id] && restoredCommentText[id]) drafts[id] = restoredCommentText[id];
    delete restoredCommentText[id];
    if (drafts[input.dataset.post]) input.value = drafts[input.dataset.post];
    if (input.dataset.post === focused) input.focus();
  }
}

$("#load-more").addEventListener("click", () => { loadedCount += 50; loadFeed(); });

/** A member's photo, or their initial on a coloured circle when there's none (yet). */
function avatar(el, name, url) {
  el.replaceChildren();
  el.style.background = `hsl(${hue(name)} 42% 46%)`;
  el.textContent = (name.trim()[0] || "?").toUpperCase();
  if (url) {
    const img = document.createElement("img");
    img.alt = "";
    // If the file can't be shown, the initial stays.
    img.addEventListener("load", () => { el.textContent = ""; el.append(img); el.style.background = "none"; });
    img.src = url;
  }
}

function renderPost(p) {
  const el = $("#tpl-post").content.firstElementChild.cloneNode(true);
  el.dataset.id = p.id;
  avatar($(".avatar", el), p.author, p.author_avatar);
  const author = $(".author", el);
  author.textContent = p.author;
  if (p.author_keymaster) {
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = "Key Master";
    author.append(tag);
  }
  if (p.author_pending_name) {
    // Key Masters only: they asked for a new name nobody has accepted yet.
    const tag = document.createElement("span");
    tag.className = "tag pending";
    tag.textContent = "name change pending";
    tag.title = `Wants to be called “${p.author_pending_name}”. Accept it under Members.`;
    author.append(tag);
  }
  $(".when", el).textContent = when(p.created_at) + (p.edited ? " · edited" : "");
  $(".when", el).title = new Date(p.created_at * 1000).toLocaleString();
  $(".post-text", el).textContent = p.text;

  const photos = $(".photos", el);
  const n = p.photos.length;
  photos.classList.add(n === 1 ? "n1" : n === 2 ? "n2" : n === 4 ? "n4" : "many");
  for (const ph of p.photos) photos.append(renderPhoto(ph, n === 1));

  renderReactions($(".reactions", el), p);

  const comments = $(".comments", el);
  for (const c of p.comments) {
    const row = document.createElement("div");
    row.className = "comment";
    const face = document.createElement("span");
    face.className = "avatar tiny";
    face.setAttribute("aria-hidden", "true");
    avatar(face, c.author, c.author_avatar);
    const b = document.createElement("b");
    b.textContent = c.author;
    const body = document.createElement("span");
    body.className = "body";
    body.textContent = c.text;
    const t = document.createElement("span");
    t.className = "muted small when";
    t.textContent = when(c.created_at);
    const text = document.createElement("div");
    text.className = "comment-body";
    text.append(b, body, t);
    if (c.photos.length) {
      const photos = document.createElement("div");
      photos.className = "photos small-grid";
      for (const ph of c.photos) photos.append(renderPhoto(ph, false));
      text.append(photos);
    }
    row.append(face, text);
    comments.append(row);
  }

  const form = $(".comment-form", el);
  const input = $(".comment-input", el);
  const err = $(".comment-err", el);
  input.dataset.post = p.id;
  const tray = commentTray(p.id);
  tray.attach($(".comment-photos", el), $(".comment-hint", el), err);
  onPicked($(".comment-file", el), tray);
  onPicked($(".comment-camera", el), tray);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    hideError(err);
    if (tray.preparing) return showError(err, "Wait for the photos to finish preparing.");
    const text = input.value.trim();
    const photos = tray.ids;
    if (!text && !photos.length) return;
    await busy($("button[type=submit]", form), async () => {
      try {
        await invoke("add_comment", { postId: p.id, text, photos });
        input.value = "";
        tray.sent();
        await loadFeed();
      } catch (e) {
        showError(err, e);
      }
    });
  });

  const del = $(".post-delete", el);
  if (p.mine) {
    del.hidden = false;
    confirmClick(del, "Delete for everyone?", async () => {
      try {
        await invoke("delete_post", { postId: p.id });
        await loadFeed();
      } catch (e) {
        showError($("#cp-err"), e);
      }
    });
  }
  return el;
}

function renderPhoto(ph, large) {
  // A lone photo is shown big, so use the full image once it's downloaded.
  const src = large ? ph.full || ph.thumb : ph.thumb || ph.full;
  if (!src) {
    const box = document.createElement("div");
    box.className = "photo missing";
    box.textContent = "Photo downloading…";
    return box;
  }
  const btn = document.createElement("button");
  btn.className = "photo";
  btn.type = "button";
  btn.setAttribute("aria-label", "Open photo");
  const img = document.createElement("img");
  img.src = src;
  img.alt = "";
  img.loading = "lazy";
  btn.append(img);
  btn.addEventListener("click", () => openLightbox(ph.full || src));
  return btn;
}

function renderReactions(box, p) {
  const mine = p.reactions.find((r) => r.mine);
  for (const r of p.reactions) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "react" + (r.mine ? " mine" : "");
    b.title = r.names.join(", ");
    const n = document.createElement("span");
    n.className = "n";
    n.textContent = String(r.count);
    b.append(r.emoji + " ", n);
    b.addEventListener("click", () => react(p.id, r.mine ? "" : r.emoji));
    box.append(b);
  }
  const add = document.createElement("button");
  add.type = "button";
  add.className = "react add";
  add.textContent = mine ? "Change" : "React";
  add.addEventListener("click", () => {
    const picker = document.createElement("span");
    picker.className = "react-picker";
    for (const e of REACTIONS) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = e;
      b.setAttribute("aria-label", `React ${e}`);
      b.addEventListener("click", () => react(p.id, mine && mine.emoji === e ? "" : e));
      picker.append(b);
    }
    add.replaceWith(picker);
  });
  box.append(add);
}

async function react(postId, emoji) {
  try {
    await invoke("set_reaction", { postId, emoji });
    await loadFeed();
  } catch (e) {
    showError($("#cp-err"), e);
  }
}

// The photo viewer: pinch (or the mouse wheel) to zoom, drag to move a zoomed
// photo, double-tap to zoom in or out, a single tap (or ×, Back, Esc) closes.
const lb = { s: 1, x: 0, y: 0, pts: new Map(), pinch: null, moved: false, lastTap: 0, tapTimer: null };

function openLightbox(src) {
  Object.assign(lb, { s: 1, x: 0, y: 0, pinch: null });
  lb.pts.clear();
  lbApply();
  $("#lightbox-img").src = src;
  $("#lightbox").hidden = false;
}
function closeLightbox() {
  clearTimeout(lb.tapTimer);
  $("#lightbox").hidden = true;
  $("#lightbox-img").removeAttribute("src");
}

function lbApply() {
  const img = $("#lightbox-img");
  // Keep the photo covering the screen where it's bigger than it, centred where it isn't.
  const maxX = Math.max(0, (img.offsetWidth * lb.s - innerWidth) / 2);
  const maxY = Math.max(0, (img.offsetHeight * lb.s - innerHeight) / 2);
  lb.x = Math.min(maxX, Math.max(-maxX, lb.x));
  lb.y = Math.min(maxY, Math.max(-maxY, lb.y));
  img.style.transform = lb.s === 1 ? "" : `translate(${lb.x}px, ${lb.y}px) scale(${lb.s})`;
}

/**
 * Zoom to `s` so that the photo point that was under (fx, fy) with the
 * transform `from` ends up under (px, py): zooming in place, or a pinch whose
 * fingers have also moved.
 */
function lbZoomAt(s, px, py, from = lb, fx = px, fy = py) {
  const img = $("#lightbox-img");
  // The photo's centre before the transform (it's centred in the full-screen box).
  const cx = img.offsetLeft + img.offsetWidth / 2, cy = img.offsetTop + img.offsetHeight / 2;
  const qx = (fx - cx - from.x) / from.s, qy = (fy - cy - from.y) / from.s;
  lb.s = Math.min(5, Math.max(1, s));
  lb.x = px - cx - lb.s * qx;
  lb.y = py - cy - lb.s * qy;
  if (lb.s === 1) lb.x = lb.y = 0;
  lbApply();
}

(() => {
  const box = $("#lightbox");
  const mid = () => { const [a, b] = [...lb.pts.values()]; return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2, d: Math.hypot(a.x - b.x, a.y - b.y) || 1 }; };
  box.addEventListener("pointerdown", (e) => {
    if (e.target.closest(".lightbox-close")) return;
    box.setPointerCapture(e.pointerId);
    box.classList.add("gesture");
    lb.pts.set(e.pointerId, { x: e.clientX, y: e.clientY, x0: e.clientX, y0: e.clientY });
    if (lb.pts.size === 1) lb.moved = false;
    if (lb.pts.size === 2) {
      const m = mid();
      lb.pinch = { fx: m.x, fy: m.y, d: m.d, s: lb.s, x: lb.x, y: lb.y };
      lb.moved = true;
    }
  });
  box.addEventListener("pointermove", (e) => {
    const p = lb.pts.get(e.pointerId);
    if (!p) return;
    const dx = e.clientX - p.x, dy = e.clientY - p.y;
    p.x = e.clientX; p.y = e.clientY;
    if (Math.hypot(p.x - p.x0, p.y - p.y0) > 10) lb.moved = true;
    if (lb.pts.size >= 2 && lb.pinch) {
      // Pinch: scale with the fingers' spread, and follow their midpoint.
      const m = mid(), p0 = lb.pinch;
      lbZoomAt(p0.s * (m.d / p0.d), m.x, m.y, p0, p0.fx, p0.fy);
    } else if (lb.s > 1) {
      lb.x += dx; lb.y += dy;
      lbApply();
    }
  });
  const up = (e) => {
    if (!lb.pts.delete(e.pointerId)) return;
    if (lb.pts.size < 2) lb.pinch = null;
    if (!lb.pts.size) box.classList.remove("gesture");
    if (lb.pts.size || lb.moved || e.type === "pointercancel") return;
    // A tap: a second one soon after zooms, otherwise it closes (unless zoomed in).
    const now = Date.now();
    clearTimeout(lb.tapTimer);
    if (now - lb.lastTap < 300) {
      lb.lastTap = 0;
      lbZoomAt(lb.s > 1 ? 1 : 2.5, e.clientX, e.clientY);
    } else {
      lb.lastTap = now;
      lb.tapTimer = setTimeout(() => { if (lb.s === 1) closeLightbox(); }, 300);
    }
  };
  box.addEventListener("pointerup", up);
  box.addEventListener("pointercancel", up);
  box.addEventListener("wheel", (e) => {
    e.preventDefault();
    lbZoomAt(lb.s * Math.exp(-e.deltaY / 400), e.clientX, e.clientY);
  }, { passive: false });
  $("#lightbox-close").addEventListener("click", closeLightbox);
})();
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeLightbox(); });

// --- attaching photos: picker, paste, drag and drop ------------------------------------

/**
 * Photos waiting to go out with a post, a comment or a message, shown as
 * thumbnails with a remove (×) button. Every way in (the picker, paste, drag
 * and drop) goes through stage_photo: resized, EXIF and GPS stripped,
 * re-encoded, thumbnailed; encrypted when it's sent.
 */
class Attachments {
  constructor({ max, noun, summary = false }) {
    this.items = [];   // [{id, preview, still}]; no preview yet while preparing
    this.max = max;
    this.noun = noun;
    this.summary = summary;
    this.box = this.hint = this.err = null;
  }

  /** Show in these elements (a comment's are new after every feed render). */
  attach(box, hint, err) {
    this.box = box;
    this.hint = hint;
    this.err = err;
    this.render();
  }

  get ids() { return this.items.map((s) => s.id); }
  get preparing() { return this.items.some((s) => !s.preview); }

  /** Drop everything, telling the app to forget the prepared photos. */
  clear() {
    for (const s of this.items) if (s.id) invoke("unstage_photo", { id: s.id });
    this.items = [];
    this.render();
  }

  /** After sending: the app has already let go of them. */
  sent() {
    this.items = [];
    this.render();
  }

  addFiles(files) {
    return this.add(files.map((f) => ({
      label: f.name,
      load: async () => invoke("stage_photo", await bytesArg(f)),
    })));
  }

  addUrl(url) {
    return this.add([{ label: "", load: () => invoke("stage_photo_url", { url }) }]);
  }

  async add(sources) {
    if (this.err) hideError(this.err);
    for (const src of sources) {
      if (this.items.length >= this.max) {
        this.fail(`At most ${this.max} photos per ${this.noun}.`);
        break;
      }
      const slot = { id: null, preview: null, still: false };
      this.items.push(slot);
      this.render();
      try {
        const r = await src.load();
        if (!r || !this.items.includes(slot)) { // removed meanwhile, or the source was withdrawn
          if (r) invoke("unstage_photo", { id: r.id });
          this.items = this.items.filter((o) => o !== slot);
          this.render();
          continue;
        }
        Object.assign(slot, { id: r.id, preview: r.preview, still: r.still });
      } catch (e) {
        this.items = this.items.filter((o) => o !== slot);
        this.fail(src.label ? `${src.label}: ${e}` : String(e));
      }
      this.render();
    }
  }

  fail(msg) { if (this.err) showError(this.err, msg); }

  /** Give up the (prepared) photos, to hand them to another tray with adopt(). */
  take() {
    const items = this.items;
    this.items = [];
    this.render();
    return items;
  }

  adopt(items) {
    if (this.err) hideError(this.err);
    const room = Math.max(0, this.max - this.items.length);
    for (const s of items.slice(room)) invoke("unstage_photo", { id: s.id });
    this.items.push(...items.slice(0, room));
    this.render();
    if (items.length > room) this.fail(`At most ${this.max} photos per ${this.noun}, so ${items.length - room} of them were left out.`);
  }

  render() {
    saveDraftsSoon();
    if (!this.box) return;
    this.box.replaceChildren(...this.items.map((s) => {
      const item = document.createElement("div");
      item.className = "staged-item" + (s.preview ? "" : " busy");
      if (s.preview) {
        const img = document.createElement("img");
        img.src = s.preview;
        img.alt = "";
        img.draggable = false;
        const x = document.createElement("button");
        x.type = "button";
        x.textContent = "×";
        x.setAttribute("aria-label", "Remove photo");
        x.addEventListener("click", () => {
          invoke("unstage_photo", { id: s.id });
          this.items = this.items.filter((o) => o !== s);
          this.render();
        });
        item.append(img, x);
        if (s.still) {
          const tag = document.createElement("span");
          tag.className = "still-tag";
          tag.textContent = "Still";
          tag.title = "Animation can't be kept: this goes out as a still image";
          item.append(tag);
        }
      } else {
        const sp = document.createElement("span");
        sp.className = "spinner";
        item.append(sp);
      }
      return item;
    }));
    if (!this.hint) return;
    const ready = this.items.filter((s) => s.preview);
    const parts = [];
    if (this.summary && ready.length) parts.push(`${ready.length} photo${ready.length > 1 ? "s" : ""}, resized and stripped of location data`);
    if (ready.some((s) => s.still)) parts.push("Animated pictures can't stay animated here, so they go out as still images.");
    this.hint.textContent = parts.join(". ");
    this.hint.hidden = !parts.length;
  }
}

/**
 * A photo input feeding a tray. The camera (Android) saves each shot as a
 * full-size JPEG in the app's folder; once staged, the app deletes it.
 */
function onPicked(input, tray) {
  input.addEventListener("change", async (ev) => {
    const files = [...ev.target.files];
    ev.target.value = "";
    await tray.addFiles(files);
    if (input.hasAttribute("capture")) invoke("forget_captures").catch(() => {});
  });
}

const commentTrays = new Map(); // post id -> Attachments, kept across feed re-renders
function commentTray(postId) {
  let t = commentTrays.get(postId);
  if (!t) commentTrays.set(postId, (t = new Attachments({ max: 4, noun: "comment" })));
  return t;
}

/** Where a paste or drop on `el` goes: the composer, a post's comments, or the open chat. */
function attachTarget(el) {
  if (!(el instanceof Element) || $("#screen-main").hidden || $("#screen-main").classList.contains("readonly")) return null;
  if (el.closest("#composer")) return { tray: postTray, zone: $("#composer"), input: $("#cp-text") };
  const post = el.closest("#feed .post");
  if (post) return { tray: commentTray(post.dataset.id), zone: post, input: $(".comment-input", post) };
  if (el.closest("#dm-chat-view") && !$("#dm-composer").hidden) return { tray: dmTray, zone: $("#dm-chat-view"), input: $("#dm-text") };
  return null;
}

/** A picture's bytes from a `data:` address (some pages drag those). */
function fileFromDataUrl(url) {
  const m = /^data:([^;,]*)((?:;[^;,]*)*),(.*)$/s.exec(url);
  if (!m) return null;
  const base64 = /;base64/i.test(m[2]);
  const raw = base64 ? atob(m[3].replace(/\s+/g, "")) : decodeURIComponent(m[3]);
  return new File([Uint8Array.from(raw, (c) => c.charCodeAt(0))], "dropped picture", { type: m[1] || "" });
}

/** Paste: a copied picture or picture file gets attached; text pastes as usual. */
document.addEventListener("paste", (e) => {
  const at = attachTarget(e.target);
  const dt = e.clipboardData;
  if (!at || !dt) return;
  const files = [...dt.files];
  // Copying from Word, Excel and the like also puts a picture of the text on
  // the clipboard: when there's text, the text is what was meant.
  if (!files.length || dt.getData("text/plain").trim()) return;
  e.preventDefault();
  at.tray.addFiles(files);
});

// Drag and drop. Tauri's own file-drop handling is off (dragDropEnabled), so
// the page gets the drop and nothing dropped can navigate the window away.
let dragFromApp = false;
let dropZone = null;
document.addEventListener("dragstart", () => { dragFromApp = true; });
document.addEventListener("dragend", () => { dragFromApp = false; });

function carriesPicture(dt) {
  return !!dt && [...dt.types].some((t) => t === "Files" || t === "text/uri-list" || t === "text/html");
}

function setDropZone(z) {
  if (dropZone === z) return;
  if (dropZone) dropZone.classList.remove("drop-target");
  dropZone = z;
  if (z) z.classList.add("drop-target");
}

document.addEventListener("dragover", (e) => {
  if (dragFromApp || !carriesPicture(e.dataTransfer)) return;
  e.preventDefault();
  const at = attachTarget(e.target);
  e.dataTransfer.dropEffect = at ? "copy" : "none";
  setDropZone(at && at.zone);
});
document.addEventListener("dragleave", (e) => { if (!e.relatedTarget) setDropZone(null); });

document.addEventListener("drop", (e) => {
  setDropZone(null);
  const dt = e.dataTransfer;
  if (dragFromApp || !carriesPicture(dt)) return;
  e.preventDefault();
  const at = attachTarget(e.target);
  if (!at) return;
  const files = [...dt.files];
  if (files.length) return void at.tray.addFiles(files);
  // A picture dragged out of a web page may come with only its address: the
  // <img> in the HTML (not a link around it), or the bare address without HTML.
  let url = null;
  const html = dt.getData("text/html");
  if (html) {
    const img = new DOMParser().parseFromString(html, "text/html").querySelector("img[src]");
    url = img && img.getAttribute("src");
  } else {
    url = (dt.getData("text/uri-list") || "").split(/\r?\n/).find((l) => l && !l.startsWith("#")) || null;
  }
  if (url && /^data:/i.test(url)) {
    const f = fileFromDataUrl(url);
    if (f) return void at.tray.addFiles([f]);
  } else if (url && /^https?:\/\//i.test(url.trim())) {
    return void at.tray.addUrl(url.trim());
  }
  // Not a picture after all (a selected bit of a web page, a link): drop it in as text.
  const text = dt.getData("text/plain");
  if (text && at.input) {
    at.input.focus();
    at.input.setRangeText(text, at.input.selectionStart, at.input.selectionEnd, "end");
    at.input.dispatchEvent(new Event("input", { bubbles: true }));
  }
});

// --- composer -----------------------------------------------------------------------

const postTray = new Attachments({ max: 10, noun: "post", summary: true });
postTray.attach($("#cp-photos"), $("#cp-hint"), $("#cp-err"));

onPicked($("#cp-file"), postTray);
onPicked($("#cp-camera"), postTray);

$("#composer").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#cp-err");
  hideError(err);
  if (postTray.preparing) return showError(err, "Wait for the photos to finish preparing.");
  const text = $("#cp-text").value;
  const photos = postTray.ids;
  if (!text.trim() && !photos.length) return;
  await busy($("#cp-post"), async () => {
    $("#cp-post").textContent = photos.length ? "Uploading…" : "Posting…";
    try {
      await invoke("create_post", { text, photos });
      $("#cp-text").value = "";
      postTray.sent();
      await loadFeed();
    } catch (e) {
      showError(err, e);
    }
  });
});

$("#cp-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) $("#composer").requestSubmit();
});

// --- Key Master ---------------------------------------------------------------------------

$("#inv-make").addEventListener("click", async () => {
  const err = $("#inv-err");
  hideError(err);
  try {
    const r = await invoke("invite_link");
    $("#inv-link").value = r.link;
    $("#inv-qr").src = r.qr;
    $("#inv-box").hidden = false;
    $("#inv-make").closest(".actions").hidden = true;
  } catch (e) {
    showError(err, e);
  }
});

$("#inv-copy").addEventListener("click", async () => {
  const input = $("#inv-link");
  try {
    await navigator.clipboard.writeText(input.value);
  } catch {
    input.select();
    document.execCommand("copy");
  }
  $("#inv-copy").textContent = "Copied";
  setTimeout(() => { $("#inv-copy").textContent = "Copy"; }, 2000);
});
$("#inv-link").addEventListener("focus", (e) => e.target.select());

const approvedHere = new Map(); // device_id -> rendered "done" element, kept after the request leaves the list

async function loadPending() {
  const err = $("#pending-err");
  let list;
  try {
    list = await invoke("list_pending");
    hideError(err);
  } catch (e) {
    return showError(err, e);
  }
  const box = $("#pending");
  // Don't wipe a form someone is typing into.
  const existing = new Map($$(".pending-item", box).map((el) => [el.dataset.device, el]));
  const items = list.map((p) => existing.get(p.device_id) || renderPending(p));
  for (const [id, el] of approvedHere) if (!list.some((p) => p.device_id === id)) items.push(el);
  box.replaceChildren(...items);
  $("#pending-empty").hidden = items.length > 0;
  const badge = $("#km-badge");
  badge.textContent = String(list.length);
  badge.hidden = !list.length;
}

function renderPending(p) {
  const el = $("#tpl-pending").content.firstElementChild.cloneNode(true);
  el.dataset.device = p.device_id;
  $(".p-name", el).textContent = p.display_name;
  $(".p-email", el).textContent = `<${p.email}>`;
  const flag = $(".p-flag", el);
  if (p.existing_member) {
    flag.hidden = false;
    flag.textContent = p.keymaster
      ? `A new device for Key Master ${p.display_name}. Approving gives it Key Master rights.`
      : `A new device for existing member ${p.display_name}.`;
  }
  $(".p-km-row", el).hidden = !p.keymaster;
  const err = $(".p-err", el);
  $(".pending-form", el).addEventListener("submit", async (ev) => {
    ev.preventDefault();
    hideError(err);
    const code = $(".p-code", el).value.trim();
    if (!code) return showError(err, `Type the code ${p.display_name} reads to you.`);
    await busy($(".p-approve", el), async () => {
      $(".p-approve", el).textContent = "Approving…";
      try {
        const r = await invoke("approve", { deviceId: p.device_id, code, asKeymaster: $(".p-km", el).checked });
        $(".pending-form", el).hidden = true;
        $(".p-done-name", el).textContent = r.display_name;
        $(".p-done-code", el).textContent = r.km_code;
        $(".p-done", el).hidden = false;
        approvedHere.set(p.device_id, el);
        loadPending();
      } catch (e) {
        showError(err, e);
      }
    });
  });
  confirmClick($(".p-deny", el), "Click again to deny", async () => {
    try {
      await invoke("deny", { deviceId: p.device_id });
      el.remove();
      loadPending();
    } catch (e) {
      showError(err, e);
    }
  });
  return el;
}

// --- confirmations ---------------------------------------------------------------------------

/** A modal yes/no. Cancel has the focus, so Enter alone never confirms. */
function askConfirm({ title, body, ok, danger = false, cancel = true, cancelLabel = "Cancel" }) {
  const dlg = $("#confirm");
  if (dlg.open) dlg.close();
  $("#cf-title").textContent = title;
  $("#cf-body").textContent = body;
  $("#cf-ok").textContent = ok;
  $("#cf-cancel").textContent = cancelLabel;
  $("#cf-ok").classList.toggle("danger", danger);
  $("#cf-cancel").hidden = !cancel;
  dlg.returnValue = "";
  dlg.showModal();
  (cancel ? $("#cf-cancel") : $("#cf-ok")).focus();
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
  });
}

/** Just tell the person something (OK only). */
function notice(title, body) {
  return askConfirm({ title, body, ok: "OK", cancel: false });
}

// --- members ---------------------------------------------------------------------------------

function lastSeen(ts) {
  return ts ? `last seen ${when(ts)}` : "";
}

async function loadMembers() {
  const err = $("#members-err");
  let list;
  try {
    list = await invoke("list_members");
    hideError(err);
  } catch (e) {
    $("#members-loading").hidden = true;
    return showError(err, e);
  }
  $("#members-loading").hidden = true;
  $("#members").replaceChildren(...list.map(renderMember));
}

function renderMember(m) {
  const el = $("#tpl-member").content.firstElementChild.cloneNode(true);
  el.dataset.member = m.id;
  avatar($(".avatar", el), m.name, m.avatar);
  $(".m-name", el).textContent = m.name;
  if (m.chosen_name) {
    // Only Key Masters get this: everyone else just sees the certified name.
    const chosen = $(".m-chosen", el);
    chosen.hidden = false;
    const tag = document.createElement("span");
    tag.className = "tag pending";
    tag.textContent = "name change pending";
    chosen.replaceChildren(tag, ` Wants to be called “${m.chosen_name}”. Everyone keeps seeing “${m.name}” until a Key Master accepts it.`);
  }
  if (!m.me && m.cert_status === "verified" && view.stage === "active") {
    const msg = $(".m-message", el);
    msg.hidden = false;
    msg.addEventListener("click", () => { chatWith = m.id; selectTab("messages"); });
  }
  $(".m-role", el).hidden = m.role !== "keymaster";
  $(".m-you", el).hidden = !m.me;
  const cert = $(".m-cert", el);
  const n = m.devices.length;
  if (m.cert_status === "verified") {
    cert.textContent = `Verified · ${n} device${n === 1 ? "" : "s"}`;
    cert.className = "small m-cert ok";
  } else if (m.cert_status === "partial") {
    cert.textContent = "Partly verified: a device has no valid certificate, and its posts are ignored";
    cert.className = "small m-cert bad";
  } else {
    cert.textContent = "Unverified: no certificate from a Key Master this app trusts. Name as the server reports it; posts are ignored";
    cert.className = "small m-cert bad";
  }

  const devices = $(".devices", el);
  for (const d of m.devices) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    const name = document.createElement("span");
    name.className = "mono";
    name.textContent = d.this_device ? "This device" : d.id;
    const facts = [d.verified ? `certified by ${d.certified_by}` : "no valid certificate", lastSeen(d.last_seen)].filter(Boolean);
    const rest = document.createElement("span");
    rest.textContent = " · " + facts.join(" · ");
    if (!d.verified) rest.className = "bad";
    label.append(name, rest);
    li.append(label);
    if (view.keymaster && !d.this_device) {
      const b = document.createElement("button");
      b.className = "ghost small danger";
      b.textContent = "Revoke";
      b.title = "For a lost or replaced device";
      b.addEventListener("click", () => revokeDevice(m, d, b));
      li.append(b);
    }
    devices.append(li);
  }

  if (view.keymaster && m.chosen_name && m.cert_status === "verified") {
    const accept = $(".m-accept", el);
    accept.hidden = false;
    accept.addEventListener("click", () => acceptName(m, accept));
  }
  if (view.keymaster && !m.me) {
    const promote = $(".m-promote", el);
    promote.hidden = m.role === "keymaster" || m.cert_status !== "verified";
    promote.addEventListener("click", () => promoteMember(m, promote));
    const remove = $(".m-remove", el);
    remove.hidden = false;
    remove.addEventListener("click", () => removeMember(m, remove));
  }
  return el;
}

function showMembersNote(text) {
  const note = $("#members-note");
  note.textContent = text;
  note.hidden = false;
}

function keyNote(c) {
  if (c.rotated && c.rotated.devices) {
    const n = c.rotated.devices;
    return ` The group key was changed (version ${c.rotated.key_version}) and sent to the ${n} remaining device${n === 1 ? "" : "s"}.`;
  }
  if (c.rotated) return ` The group key was already changed (version ${c.rotated.key_version}).`;
  return ` Changing the group key didn't finish (${c.rotate_error}). The app tries again on the next sync.`;
}

async function promoteMember(m, button) {
  const yes = await askConfirm({
    title: `Make ${m.name} a Key Master?`,
    body: `${m.name} will be able to approve new members, remove people and change the group key. Your app signs a Key Master certificate for each of their devices.`,
    ok: "Make Key Master",
  });
  if (!yes) return;
  hideError($("#members-err"));
  await busy(button, async () => {
    button.textContent = "Promoting…";
    try {
      const name = await invoke("promote_member", { memberId: m.id });
      showMembersNote(`${name} is now a Key Master.`);
      await loadMembers();
    } catch (e) {
      showError($("#members-err"), e);
    }
  });
}

async function acceptName(m, button) {
  const yes = await askConfirm({
    title: `Accept the name “${m.chosen_name}”?`,
    body: `Your app signs new certificates for ${m.name}'s devices with the name “${m.chosen_name}”. Only accept it if you know it's really them and the name is fine for the group.`,
    ok: "Accept name",
  });
  if (!yes) return;
  hideError($("#members-err"));
  await busy(button, async () => {
    button.textContent = "Signing…";
    try {
      const name = await invoke("accept_name", { memberId: m.id });
      showMembersNote(`${m.name} is now listed as ${name}.`);
      await loadMembers();
    } catch (e) {
      showError($("#members-err"), e);
    }
  });
}

async function removeMember(m, button) {
  const yes = await askConfirm({
    title: `Remove ${m.name} from the group?`,
    body: `Their devices are disconnected right away and the group key is changed, so they can't read anything posted from now on. They keep the posts already on their devices. To come back they'd have to ask to join again.`,
    ok: "Remove",
    danger: true,
  });
  if (!yes) return;
  hideError($("#members-err"));
  await busy(button, async () => {
    button.textContent = "Removing…";
    try {
      const c = await invoke("remove_member", { memberId: m.id });
      showMembersNote(`${c.name} was removed.` + keyNote(c));
      view = await invoke("get_state");
      await loadMembers();
    } catch (e) {
      showError($("#members-err"), e);
    }
  });
}

async function revokeDevice(m, d, button) {
  const seen = d.last_seen ? ` It was ${lastSeen(d.last_seen)}.` : "";
  const yes = await askConfirm({
    title: `Revoke this device of ${m.name}?`,
    body: `Device ${d.id} is disconnected right away and the group key is changed, so it can't read anything new.${seen} ${m.name} stays in the group; their other devices keep working, and they can join again from a new one.`,
    ok: "Revoke device",
    danger: true,
  });
  if (!yes) return;
  hideError($("#members-err"));
  await busy(button, async () => {
    button.textContent = "Revoking…";
    try {
      const c = await invoke("revoke_device", { deviceId: d.id });
      showMembersNote(`Revoked ${c.name}.` + keyNote(c));
      view = await invoke("get_state");
      await loadMembers();
    } catch (e) {
      showError($("#members-err"), e);
    }
  });
}

// --- missed posts ------------------------------------------------------------------------------

function renderMissed() {
  const banner = $("#missed-banner");
  if (!view.missed) { banner.hidden = true; return; }
  const days = Math.round(view.missed[1]);
  $("#missed-text").textContent = `You missed some posts. This device was away longer than the server keeps posts (${days} days), so some were deleted before it could download them. Other members' apps still have them.`;
  banner.hidden = false;
}

$("#missed-dismiss").addEventListener("click", async () => {
  try { await invoke("dismiss_missed"); } catch (e) { console.warn("dismiss_missed", e); }
  view.missed = null;
  renderMissed();
});

// --- removed --------------------------------------------------------------------------------------

function startRemoved() {
  showScreen("screen-removed");
  $("#rm-group").textContent = view.group_name || "";
  if (view.stage === "removed") {
    $("#rm-title").textContent = "You've been removed from this group";
    $("#rm-body").textContent = `A Key Master removed you from ${view.group_name}. This app has stopped syncing and can't read anything posted from now on.`;
  } else {
    $("#rm-title").textContent = "This device was disconnected";
    $("#rm-body").textContent = `A Key Master revoked this device's access to ${view.group_name}, for example because it was reported lost. It has stopped syncing. If that's a mistake, ask a Key Master: you can join again as a new device.`;
  }
  hideError($("#rm-err"));
}

$("#rm-archive").addEventListener("click", async () => {
  showScreen("screen-main");
  $("#screen-main").classList.add("readonly");
  $("#tb-group").textContent = view.group_name;
  $("#readonly-banner").hidden = false;
  $("#readonly-text").textContent = view.stage === "removed"
    ? `Saved posts from ${view.group_name}. You're no longer in this group, so this is read only.`
    : `Saved posts from ${view.group_name}. This device was disconnected, so this is read only.`;
  for (const p of $$(".panel")) p.hidden = p.id !== "panel-feed";
  $("#readonly-switch").textContent = "Messages";
  await loadFeed();
});

$("#readonly-back").addEventListener("click", () => startRemoved());

// Read only: switch between saved posts and saved messages.
$("#readonly-switch").addEventListener("click", () => {
  const toMessages = $("#panel-messages").hidden;
  for (const p of $$(".panel")) p.hidden = p.id !== (toMessages ? "panel-messages" : "panel-feed");
  $("#readonly-switch").textContent = toMessages ? "Posts" : "Messages";
  if (toMessages) { chatWith = null; showMessages(); } else loadFeed();
});

$("#rm-restart").addEventListener("click", async () => {
  const yes = await askConfirm({
    title: "Delete the saved posts?",
    body: `This deletes everything this app saved from ${view.group_name}, photos included, and starts the setup again so you can ask to join a group. It can't be undone.`,
    ok: "Delete and start over",
    danger: true,
  });
  if (!yes) return;
  try {
    await invoke("reset");
  } catch (e) {
    return showError($("#rm-err"), e);
  }
  view = await invoke("get_state");
  route();
});

// --- this device ---------------------------------------------------------------------------

function renderDevice() {
  const rows = [
    ["Group", view.group_name],
    ["Server", view.server + (view.test_server ? " (test server)" : "")],
    ["You", `${view.shown_name || view.display_name} <${view.email}>`],
    ["Role", view.keymaster ? "Key Master" : "Member"],
    ["Your safety code", view.safety_code, true],
    ["Device id", view.device_id, true],
    ["Trusts Key Masters", view.trusted_keymasters.join(", ") || "none yet"],
    ["Group key versions", view.key_versions.join(", ")],
    ["Synced through", `event #${view.last_seq}` + (view.last_sync_at ? `, ${when(view.last_sync_at)}` : "")],
  ];
  if (view.rejected) rows.push(["Rejected events", `${view.rejected} (unverified author or bad signature)`]);
  renderServerCert();
  $("#device-facts").replaceChildren(...rows.flatMap(([k, v, mono]) => {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v ?? "";
    if (mono) dd.className = "mono";
    return [dt, dd];
  }));
}

// --- the server's certificate --------------------------------------------------------------

function renderServerCert() {
  const mode = $("#srv-mode");
  const fp = $("#srv-fp");
  $("#srv-check").hidden = !view.test_server;
  if (!view.test_server) {
    mode.textContent = "Public certificate. The server is on a domain with a certificate from a public authority (such as Let's Encrypt), checked the way a browser checks it.";
    fp.hidden = true;
  } else if (view.cert_fingerprint) {
    mode.textContent = "Test server. It has its own certificate authority, and this app trusts exactly the root certificate you confirmed when you joined (SHA-256):";
    renderFingerprint(fp, view.cert_fingerprint);
    fp.hidden = false;
  } else {
    mode.textContent = "Test server, but no root certificate is pinned for it yet (this device joined with an older version of Side Tray). Check its certificate to pin it.";
    fp.hidden = true;
  }
}

$("#srv-check").addEventListener("click", async () => {
  const err = $("#srv-err");
  const out = $("#srv-result");
  hideError(err);
  out.hidden = true;
  await busy($("#srv-check"), async () => {
    $("#srv-check").textContent = "Checking…";
    let c;
    try {
      c = await invoke("check_server_cert");
    } catch (e) {
      return showError(err, e);
    }
    out.replaceChildren();
    const p = document.createElement("p");
    if (c.same) {
      p.className = "note";
      p.textContent = "The server still has the certificate you confirmed. Nothing to do.";
      out.append(p);
    } else {
      p.className = "error";
      p.textContent = c.pinned
        ? "The server now has a different root certificate from the one you confirmed. That happens when a server is set up again, but it's also what an attacker intercepting the connection looks like. Only trust it if whoever runs the server confirms this new fingerprint:"
        : "The server's root certificate. Only trust it if whoever runs the server confirms this fingerprint:";
      const box = document.createElement("div");
      box.className = "fingerprint small";
      renderFingerprint(box, c.current);
      const act = document.createElement("div");
      act.className = "actions start";
      const b = document.createElement("button");
      b.className = c.pinned ? "primary danger" : "primary";
      b.textContent = "They confirmed it: trust this certificate";
      b.addEventListener("click", () => repin(c.current, b));
      act.append(b);
      out.append(p, box, act);
    }
    out.hidden = false;
  });
});

async function repin(fingerprint, button) {
  const yes = await askConfirm({
    title: "Trust the new certificate?",
    body: "From now on this app trusts this root certificate for the server, and no other. Do this only after the server's operator read you the same fingerprint.",
    ok: "Trust it",
    danger: true,
  });
  if (!yes) return;
  await busy(button, async () => {
    try {
      await invoke("repin_server_cert", { fingerprint });
      view = await invoke("get_state");
      $("#srv-result").hidden = true;
      renderServerCert();
      renderCertProblem();
      renderDevice();
      invoke("sync_now").catch(() => {});
    } catch (e) {
      showError($("#srv-err"), e);
    }
  });
}

// --- profile and photo ---------------------------------------------------------------------

function renderProfile(p) {
  avatar($("#pf-avatar"), p.display_name, p.avatar);
  if (document.activeElement !== $("#pf-name")) $("#pf-name").value = p.display_name;
  $("#pf-remove").hidden = !p.avatar && !p.avatar_pending;
  const note = $("#pf-note");
  note.hidden = !p.pending_name;
  if (p.pending_name) {
    note.textContent = `You asked to be called “${p.pending_name}”. Everyone keeps seeing “${p.certified_name}” until a Key Master accepts the new name.`;
  }
}

async function loadProfile() {
  try {
    renderProfile(await invoke("get_profile"));
    hideError($("#pf-err"));
  } catch (e) {
    showError($("#pf-err"), e);
  }
}

$("#pf-name-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = $("#pf-name").value.trim();
  const err = $("#pf-err");
  hideError(err);
  if (!name) return showError(err, "Your name can't be empty.");
  await busy($("#pf-name-save"), async () => {
    $("#pf-name-save").textContent = "Saving…";
    try {
      $("#pf-name").blur();
      renderProfile(await invoke("set_display_name", { name }));
      view = await invoke("get_state");
      renderDevice();
    } catch (e) {
      showError(err, e);
    }
  });
});

$("#pf-remove").addEventListener("click", async () => {
  const yes = await askConfirm({ title: "Remove your photo?", body: "Your initial is shown instead, on everyone's devices.", ok: "Remove photo" });
  if (!yes) return;
  hideError($("#pf-err"));
  await busy($("#pf-remove"), async () => {
    try { renderProfile(await invoke("remove_avatar")); } catch (e) { showError($("#pf-err"), e); }
  });
});

// The cropper: the photo moves and scales under a fixed circle (like Discord);
// what's inside is drawn to a 256x256 canvas here and sent as a PNG, which the
// app re-encodes as WebP (no metadata survives either step).
const CROP_OUT = 256;
let crop = null; // { img, w, h, base, zoom, x, y }

function cropFrame() { return $("#crop-frame").clientWidth || 280; }

function cropLayout() {
  const f = cropFrame();
  const s = crop.base * crop.zoom;
  const w = crop.w * s, h = crop.h * s;
  crop.x = Math.min(0, Math.max(f - w, crop.x));
  crop.y = Math.min(0, Math.max(f - h, crop.y));
  const img = $("#crop-img");
  img.style.width = `${w}px`;
  img.style.height = `${h}px`;
  img.style.transform = `translate(${crop.x}px, ${crop.y}px)`;
}

/** Zoom keeping the point at (px, py) in the frame where it is. */
function cropZoom(zoom, px, py) {
  const f = cropFrame();
  px ??= f / 2; py ??= f / 2;
  const old = crop.base * crop.zoom;
  crop.zoom = Math.min(4, Math.max(1, zoom));
  const s = crop.base * crop.zoom;
  crop.x = px - ((px - crop.x) / old) * s;
  crop.y = py - ((py - crop.y) / old) * s;
  $("#crop-zoom").value = String(crop.zoom);
  cropLayout();
}

$("#pf-file").addEventListener("change", (ev) => {
  const file = ev.target.files[0];
  ev.target.value = "";
  if (!file) return;
  hideError($("#pf-err"));
  if (file.size > 40 * 1024 * 1024) return showError($("#pf-err"), "That file is too large for a profile photo.");
  const reader = new FileReader();
  reader.onerror = () => showError($("#pf-err"), "Couldn't read that file.");
  reader.onload = () => {
    const img = $("#crop-img");
    let converted = false;
    img.onerror = async () => {
      // The webview can't show HEIC/HEIF; the app can convert it (on a phone).
      if (converted) return showError($("#pf-err"), "That isn't a photo this app can read.");
      converted = true;
      try {
        img.src = await invoke("photo_preview", await bytesArg(file));
      } catch (e) {
        showError($("#pf-err"), String(e));
      }
    };
    img.onload = () => {
      hideError($("#crop-err"));
      $("#crop").showModal();
      const f = cropFrame();
      const w = img.naturalWidth, h = img.naturalHeight;
      const base = Math.max(f / w, f / h);
      crop = { img, w, h, base, zoom: 1, x: (f - w * base) / 2, y: (f - h * base) / 2 };
      $("#crop-zoom").value = "1";
      cropLayout();
      $("#crop-frame").focus();
    };
    img.src = reader.result;
  };
  reader.readAsDataURL(file);
});

(() => {
  const frame = $("#crop-frame");
  let drag = null;
  frame.addEventListener("pointerdown", (e) => {
    if (!crop) return;
    drag = { id: e.pointerId, x: e.clientX, y: e.clientY };
    frame.setPointerCapture(e.pointerId);
    frame.classList.add("dragging");
  });
  frame.addEventListener("pointermove", (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    crop.x += e.clientX - drag.x;
    crop.y += e.clientY - drag.y;
    drag.x = e.clientX;
    drag.y = e.clientY;
    cropLayout();
  });
  const end = () => { drag = null; frame.classList.remove("dragging"); };
  frame.addEventListener("pointerup", end);
  frame.addEventListener("pointercancel", end);
  frame.addEventListener("wheel", (e) => {
    if (!crop) return;
    e.preventDefault();
    const r = frame.getBoundingClientRect();
    cropZoom(crop.zoom * Math.exp(-e.deltaY / 500), e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });
  frame.addEventListener("keydown", (e) => {
    if (!crop) return;
    const step = e.shiftKey ? 40 : 10;
    const moves = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] };
    if (moves[e.key]) {
      crop.x += moves[e.key][0];
      crop.y += moves[e.key][1];
      cropLayout();
    } else if (e.key === "+" || e.key === "=") {
      cropZoom(crop.zoom * 1.1);
    } else if (e.key === "-") {
      cropZoom(crop.zoom / 1.1);
    } else {
      return;
    }
    e.preventDefault();
  });
  $("#crop-zoom").addEventListener("input", (e) => { if (crop) cropZoom(Number(e.target.value)); });
})();

$("#crop").addEventListener("close", () => { crop = null; $("#crop-img").removeAttribute("src"); });

$("#crop-save").addEventListener("click", async () => {
  if (!crop) return;
  const err = $("#crop-err");
  hideError(err);
  const f = cropFrame();
  const s = crop.base * crop.zoom;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = CROP_OUT;
  const ctx = canvas.getContext("2d");
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(crop.img, -crop.x / s, -crop.y / s, f / s, f / s, 0, 0, CROP_OUT, CROP_OUT);
  await busy($("#crop-save"), async () => {
    $("#crop-save").textContent = "Uploading…";
    try {
      const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
      const p = await invoke("set_avatar", await bytesArg(blob));
      $("#crop").close();
      renderProfile(p);
      view = await invoke("get_state");
    } catch (e) {
      showError(err, e);
    }
  });
});

// --- direct messages (Phase 5b) ----------------------------------------------------------------

let chatWith = null;   // member id of the open conversation, null for the list
let draftFor = null;   // whose conversation the composer's draft and photos belong to

function renderDmBadge() {
  const badge = $("#dm-badge");
  const n = (view && view.dm_unread) || 0;
  badge.textContent = n > 9 ? "9+" : String(n);
  badge.hidden = !n;
}

/** The open conversation counts as read once it's on screen in a focused window. */
function chatInView() {
  return chatWith && !$("#panel-messages").hidden && !$("#dm-chat-view").hidden
    && document.visibilityState === "visible" && document.hasFocus();
}

async function markChatRead() {
  if (!chatInView()) return;
  try {
    await invoke("mark_dm_read", { memberId: chatWith });
    view = await invoke("get_state");
    renderDmBadge();
  } catch (e) { console.warn("mark_dm_read", e); }
}

/** The Messages tab: the open conversation, or the list. */
function showMessages() {
  $("#dm-picker").hidden = true;
  if (chatWith) return openChat(chatWith);
  $("#dm-chat-view").hidden = true;
  $("#dm-list-view").hidden = false;
  loadConversations();
}

function refreshMessages() {
  if (!$("#dm-chat-view").hidden && chatWith) loadChat(false);
  else loadConversations();
}

async function loadConversations() {
  const err = $("#dm-list-err");
  let list;
  try {
    list = await invoke("list_conversations");
    hideError(err);
  } catch (e) {
    return showError(err, e);
  }
  $("#dm-list").replaceChildren(...list.map(renderConversation));
  $("#dm-empty").hidden = list.length > 0;
}

function renderConversation(c) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "conv" + (c.unread ? " unread" : "");
  const face = document.createElement("span");
  face.className = "avatar";
  face.setAttribute("aria-hidden", "true");
  avatar(face, c.name, c.avatar);
  const main = document.createElement("span");
  main.className = "conv-main";
  const top = document.createElement("span");
  top.className = "conv-top";
  const name = document.createElement("span");
  name.className = "conv-name";
  name.textContent = c.name;
  const t = document.createElement("span");
  t.className = "muted small";
  t.textContent = when(c.last_at);
  top.append(name, t);
  const last = document.createElement("span");
  last.className = "conv-last";
  last.textContent = (c.last_mine ? "You: " : "") + c.last_text;
  main.append(top, last);
  b.append(face, main);
  if (c.unread) {
    const n = document.createElement("span");
    n.className = "badge";
    n.textContent = c.unread > 9 ? "9+" : String(c.unread);
    n.setAttribute("aria-label", `${c.unread} unread`);
    b.append(n);
  }
  b.addEventListener("click", () => openChat(c.member_id));
  return b;
}

async function openChat(memberId) {
  if (draftFor !== memberId) {
    draftFor = memberId;
    dmTray.clear();
    $("#dm-text").value = "";
    hideError($("#dm-err"));
  }
  chatWith = memberId;
  $("#dm-list-view").hidden = true;
  $("#dm-chat-view").hidden = false;
  saveDraftsSoon();
  fitChat();
  await loadChat(true);
  // On a phone, focusing would throw the keyboard up before they've read anything.
  if (!mobile && !$("#dm-composer").hidden && !$("#screen-main").classList.contains("readonly")) $("#dm-text").focus();
}

/**
 * Phone: make the chat fill exactly what's visible below the top bar. Android
 * doesn't shrink an edge-to-edge page for the keyboard (only the visual
 * viewport shrinks), so CSS heights would leave the composer under the keyboard
 * or scroll the header away; size it from the visual viewport instead.
 */
function fitChat() {
  const chat = $("#dm-chat-view");
  if (!mobile || chat.hidden || $("#panel-messages").hidden) return;
  const vv = window.visualViewport;
  const height = vv ? vv.height : innerHeight;
  const keyboard = innerHeight - height > 80;
  const log = $("#dm-log");
  const atEnd = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  window.scrollTo(0, 0);
  const top = chat.getBoundingClientRect().top;
  // Below the chat: the tab bar (with the gesture bar under it), which the keyboard covers when it's up.
  const tabs = $(".tabs");
  const below = keyboard || readonlyMode() ? 8 : (tabs ? tabs.getBoundingClientRect().height : 0) + 8;
  chat.style.height = `${Math.max(220, Math.floor(height - top - below))}px`;
  if (atEnd) log.scrollTop = log.scrollHeight;
}
function readonlyMode() { return $("#screen-main").classList.contains("readonly"); }
window.visualViewport?.addEventListener("resize", fitChat);
window.addEventListener("resize", fitChat);

$("#dm-back").addEventListener("click", () => {
  chatWith = null;
  showMessages();
});

async function loadChat(scrollToEnd) {
  const member = chatWith;
  let c;
  try {
    c = await invoke("open_chat", { memberId: member });
  } catch (e) {
    return showError($("#dm-err"), e);
  }
  if (chatWith !== member) return; // switched away meanwhile
  avatar($("#dm-avatar"), c.name, c.avatar);
  $("#dm-name").textContent = c.name;
  const log = $("#dm-log");
  const atEnd = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  const items = [];
  let day = null;
  for (const m of c.messages) {
    const d = new Date(m.created_at * 1000).toDateString();
    if (d !== day) {
      day = d;
      const sep = document.createElement("div");
      sep.className = "day-sep";
      sep.textContent = new Date(m.created_at * 1000).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
      items.push(sep);
    }
    items.push(renderBubble(m));
  }
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = c.can_message ? `No messages with ${c.name} yet. Only the two of you will be able to read them.` : "No messages.";
    items.push(empty);
  }
  log.replaceChildren(...items);
  if (scrollToEnd || atEnd) log.scrollTop = log.scrollHeight;
  const readonly = $("#screen-main").classList.contains("readonly");
  const gone = $("#dm-gone");
  gone.hidden = c.can_message || readonly;
  gone.textContent = `${c.name} isn't a verified member of the group any more, so new messages can't be sent. What you exchanged stays here.`;
  $("#dm-composer").hidden = !c.can_message || readonly;
  markChatRead();
}

function renderBubble(m) {
  const row = document.createElement("div");
  row.className = "bubble-row" + (m.mine ? " mine" : "");
  const b = document.createElement("div");
  b.className = "bubble";
  if (m.photos.length) {
    const photos = document.createElement("div");
    const n = m.photos.length;
    photos.className = "photos " + (n === 1 ? "n1" : n === 2 ? "n2" : n === 4 ? "n4" : "many");
    for (const ph of m.photos) photos.append(renderPhoto(ph, n === 1));
    b.append(photos);
  }
  const text = document.createElement("div");
  text.className = "text";
  text.textContent = m.text;
  const t = document.createElement("div");
  t.className = "when";
  t.textContent = new Date(m.created_at * 1000).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  t.title = new Date(m.created_at * 1000).toLocaleString();
  b.append(text, t);
  row.append(b);
  return row;
}

// New message: pick someone from the verified roster.
$("#dm-new").addEventListener("click", async () => {
  const err = $("#dm-list-err");
  hideError(err);
  let people;
  try {
    people = await invoke("dm_recipients");
  } catch (e) {
    return showError(err, e);
  }
  $("#dm-picker-list").replaceChildren(...people.map((p) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "pick";
    const face = document.createElement("span");
    face.className = "avatar";
    face.setAttribute("aria-hidden", "true");
    avatar(face, p.name, p.avatar);
    const name = document.createElement("span");
    name.textContent = p.name;
    b.append(face, name);
    b.addEventListener("click", () => { $("#dm-picker").hidden = true; openChat(p.member_id); });
    return b;
  }));
  $("#dm-picker-empty").hidden = people.length > 0;
  $("#dm-picker").hidden = false;
});
$("#dm-picker-cancel").addEventListener("click", () => { $("#dm-picker").hidden = true; });

// The same pipeline as posts: resized, re-encoded as WebP, EXIF (GPS included) dropped.
const dmTray = new Attachments({ max: 10, noun: "message" });
dmTray.attach($("#dm-photos"), $("#dm-hint"), $("#dm-err"));

onPicked($("#dm-file"), dmTray);
onPicked($("#dm-camera"), dmTray);

$("#dm-composer").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#dm-err");
  hideError(err);
  if (dmTray.preparing) return showError(err, "Wait for the photos to finish preparing.");
  const text = $("#dm-text").value;
  const photos = dmTray.ids;
  if (!text.trim() && !photos.length) return;
  const member = chatWith;
  await busy($("#dm-send"), async () => {
    $("#dm-send").textContent = photos.length ? "Uploading…" : "Sending…";
    try {
      await invoke("send_dm", { memberId: member, text, photos });
      if (chatWith === member) {
        $("#dm-text").value = "";
        dmTray.sent();
        await loadChat(true);
      }
    } catch (e) {
      showError(err, e);
    }
  });
  $("#dm-text").focus();
});

$("#dm-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) $("#dm-composer").requestSubmit();
});

// --- settings ------------------------------------------------------------------------------

async function loadSettings() {
  try {
    const s = await invoke("get_settings");
    $("#set-autostart").checked = s.start_with_os;
    hideError($("#set-err"));
  } catch (e) {
    showError($("#set-err"), `Couldn't read settings: ${e}`);
  }
}

$("#set-autostart").addEventListener("change", async (ev) => {
  const box = ev.target;
  box.disabled = true;
  try {
    const s = await invoke("set_start_with_os", { enabled: box.checked });
    box.checked = s.start_with_os;
    hideError($("#set-err"));
  } catch (e) {
    box.checked = !box.checked;
    showError($("#set-err"), `Couldn't change that: ${e}`);
  } finally {
    box.disabled = false;
  }
});

// --- updates -------------------------------------------------------------------------------

function renderUpdate(u) {
  for (const el of $$(".app-version")) el.textContent = `Side Tray ${u.current_version}`;
  const ready = u.state === "ready";
  $("#update-banner").hidden = !ready;
  if (ready) {
    $("#update-text").textContent = `Side Tray ${u.version} is ready to install. The app closes for a moment and comes back.`;
  }
  const status = {
    off: mobile
      ? `Side Tray ${u.current_version}. On a phone, new versions come as a new app download for now.`
      : `Side Tray ${u.current_version}. This copy wasn't set up with the installer, so it doesn't update itself.`,
    idle: `Side Tray ${u.current_version}. ` + (u.checked_at ? `Up to date (checked ${when(u.checked_at)}).` : "It checks for updates every few hours."),
    checking: `Side Tray ${u.current_version}. Checking for updates…`,
    downloading: `Downloading Side Tray ${u.version}…`,
    ready: `Side Tray ${u.version} is downloaded. Choose Restart to update at the top of the window.`,
    failed: `Side Tray ${u.current_version}. Couldn't check for updates: ${u.message}`,
  }[u.state] || "";
  $("#upd-status").textContent = status;
  const check = $("#upd-check");
  check.hidden = u.state === "off" || ready;
  check.disabled = u.state === "checking" || u.state === "downloading";
}

listen("update", (ev) => renderUpdate(ev.payload));

$("#upd-check").addEventListener("click", async () => {
  hideError($("#upd-err"));
  renderUpdate(await invoke("check_for_updates"));
});

$("#update-install").addEventListener("click", async (ev) => {
  const btn = ev.target;
  btn.disabled = true;
  btn.textContent = "Installing…";
  try {
    await invoke("install_update"); // the app exits and the installer takes over
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Restart to update";
    $("#update-text").textContent = String(e);
  }
});

// --- drafts that outlive the page (Android) ---------------------------------------------------

// Android can rebuild the app's window (moving between a flip phone's screens,
// for one), which reloads this page. Half-written posts, comments and messages
// are kept here, and their photos stay staged in the app, so they come back.
const DRAFTS_KEY = "sidetray.drafts";
let draftsTimer = null;
let restoringDrafts = false;
let restoredCommentText = {}; // post id -> comment text, until the feed shows that post
let restoredView = null;       // the tab and chat that were open

/** The page was reloaded under a running app (a rebuilt window): go back to where it was. */
async function restoreView() {
  const v = restoredView;
  restoredView = null;
  if (!v || !view || view.stage !== "active") return;
  let boots = 1;
  try { boots = await invoke("page_boot"); } catch (_) {}
  if (boots < 2 || !v.tab || v.tab === "feed" && !v.chat) return;
  if (v.chat) chatWith = v.chat;
  if ($(`.tab[data-tab="${v.tab}"]`) && !$(`.tab[data-tab="${v.tab}"]`).hidden) selectTab(v.chat ? "messages" : v.tab);
}

function saveDraftsSoon() {
  if (!mobile || restoringDrafts) return;
  clearTimeout(draftsTimer);
  draftsTimer = setTimeout(saveDrafts, 300);
}

function saveDrafts() {
  const ids = (t) => t.items.filter((x) => x.id).map((x) => x.id);
  const comments = {};
  for (const [id, text] of Object.entries(restoredCommentText)) comments[id] = { text };
  for (const [id, t] of commentTrays) if (t.items.length) (comments[id] ??= {}).photos = ids(t);
  for (const i of $$("#feed .comment-input")) if (i.value.trim()) (comments[i.dataset.post] ??= {}).text = i.value;
  const chatOpen = chatWith && !$("#dm-chat-view").hidden;
  const d = {
    view: { tab: $(".tab[aria-selected=true]")?.dataset.tab || "feed", chat: chatOpen ? chatWith : null },
    post: { text: $("#cp-text").value, photos: ids(postTray) },
    dm: draftFor ? { member: draftFor, text: $("#dm-text").value, photos: ids(dmTray) } : null,
    comments,
  };
  try { localStorage.setItem(DRAFTS_KEY, JSON.stringify(d)); } catch (_) {}
}

document.addEventListener("input", saveDraftsSoon);

async function restoreDrafts() {
  let d;
  try { d = JSON.parse(localStorage.getItem(DRAFTS_KEY) || "null"); } catch (_) { return; }
  if (!d || !d.post) return;
  restoredView = d.view || null;
  restoringDrafts = true;
  try {
    const comments = d.comments || {};
    const all = [...(d.post.photos || []), ...((d.dm && d.dm.photos) || []), ...Object.values(comments).flatMap((c) => c.photos || [])];
    const views = all.length ? await invoke("staged_photos", { ids: all }) : [];
    const byId = new Map(all.map((id, i) => [id, views[i]]));
    const fill = (tray, list) => {
      tray.items = (list || []).map((id) => byId.get(id)).filter(Boolean).map((v) => ({ id: v.id, preview: v.preview, still: v.still }));
      tray.render();
    };
    if (!$("#cp-text").value) $("#cp-text").value = d.post.text || "";
    fill(postTray, d.post.photos);
    if (d.dm) {
      draftFor = d.dm.member;
      $("#dm-text").value = d.dm.text || "";
      fill(dmTray, d.dm.photos);
    }
    for (const [id, c] of Object.entries(comments)) {
      if (c.photos) fill(commentTray(id), c.photos);
      if (c.text) restoredCommentText[id] = c.text;
    }
  } catch (e) {
    console.warn("restoring drafts", e);
  } finally {
    restoringDrafts = false;
  }
}

boot();
