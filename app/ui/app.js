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
let photosStaged = [];    // [{id, preview}] in the composer
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

async function boot() {
  try {
    view = await invoke("get_state");
  } catch (e) {
    $("#screen-loading p").textContent = `Couldn't open the app's data: ${e}`;
    return;
  }
  route();
  handleInvite();
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
    button.textContent = question;
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
  loadFeed().then(markReadIfViewed);
}

function selectTab(name) {
  for (const t of $$(".tab")) t.setAttribute("aria-selected", String(t.dataset.tab === name));
  for (const p of $$(".panel")) p.hidden = p.id !== `panel-${name}`;
  clearInterval(pendingTimer);
  if (name === "km") {
    loadPending();
    pendingTimer = setInterval(loadPending, 10000);
  }
  if (name === "device") { renderDevice(); loadSettings(); loadProfile(); }
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
listen("open-item", async (ev) => {
  const t = ev.payload;
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
  $("#feed-empty").hidden = posts.length > 0;
  $("#load-more").hidden = posts.length < loadedCount;
  for (const input of $$("#feed .comment-input")) {
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
    row.append(face, text);
    comments.append(row);
  }

  const form = $(".comment-form", el);
  const input = $(".comment-input", el);
  input.dataset.post = p.id;
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    await busy($("button", form), async () => {
      try {
        await invoke("add_comment", { postId: p.id, text });
        input.value = "";
        await loadFeed();
      } catch (e) {
        showError($("#cp-err"), e);
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

function openLightbox(src) {
  $("#lightbox-img").src = src;
  $("#lightbox").hidden = false;
}
function closeLightbox() {
  $("#lightbox").hidden = true;
  $("#lightbox-img").removeAttribute("src");
}
$("#lightbox").addEventListener("click", closeLightbox);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeLightbox(); });

// --- composer -----------------------------------------------------------------------

function renderStaged() {
  const box = $("#cp-photos");
  box.replaceChildren(...photosStaged.map((s) => {
    const item = document.createElement("div");
    item.className = "staged-item" + (s.preview ? "" : " busy");
    if (s.preview) {
      const img = document.createElement("img");
      img.src = s.preview;
      img.alt = "";
      const x = document.createElement("button");
      x.type = "button";
      x.textContent = "×";
      x.setAttribute("aria-label", "Remove photo");
      x.addEventListener("click", () => {
        invoke("unstage_photo", { id: s.id });
        photosStaged = photosStaged.filter((o) => o !== s);
        renderStaged();
      });
      item.append(img, x);
    } else {
      const sp = document.createElement("span");
      sp.className = "spinner";
      item.append(sp);
    }
    return item;
  }));
  const ready = photosStaged.filter((s) => s.preview).length;
  $("#cp-hint").textContent = ready ? `${ready} photo${ready > 1 ? "s" : ""}, resized and stripped of location data` : "";
}

$("#cp-file").addEventListener("change", async (ev) => {
  const files = [...ev.target.files];
  ev.target.value = "";
  const err = $("#cp-err");
  hideError(err);
  for (const file of files) {
    if (photosStaged.length >= 10) { showError(err, "At most 10 photos per post."); break; }
    const slot = { id: null, preview: null };
    photosStaged.push(slot);
    renderStaged();
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const r = await invoke("stage_photo", bytes);
      slot.id = r.id;
      slot.preview = r.preview;
    } catch (e) {
      photosStaged = photosStaged.filter((o) => o !== slot);
      showError(err, `${file.name}: ${e}`);
    }
    renderStaged();
  }
});

$("#composer").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#cp-err");
  hideError(err);
  if (photosStaged.some((s) => !s.preview)) return showError(err, "Wait for the photos to finish preparing.");
  const text = $("#cp-text").value;
  const photos = photosStaged.map((s) => s.id);
  if (!text.trim() && !photos.length) return;
  await busy($("#cp-post"), async () => {
    $("#cp-post").textContent = photos.length ? "Uploading…" : "Posting…";
    try {
      await invoke("create_post", { text, photos });
      $("#cp-text").value = "";
      photosStaged = [];
      renderStaged();
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
function askConfirm({ title, body, ok, danger = false, cancel = true }) {
  const dlg = $("#confirm");
  if (dlg.open) dlg.close();
  $("#cf-title").textContent = title;
  $("#cf-body").textContent = body;
  $("#cf-ok").textContent = ok;
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
    img.onerror = () => showError($("#pf-err"), "That isn't a photo this app can read.");
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
      const bytes = new Uint8Array(await blob.arrayBuffer());
      const p = await invoke("set_avatar", bytes);
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
let dmStaged = [];     // [{id, preview}] in the chat composer
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
    for (const s of dmStaged) if (s.id) invoke("unstage_photo", { id: s.id });
    dmStaged = [];
    renderDmStaged();
    $("#dm-text").value = "";
    hideError($("#dm-err"));
  }
  chatWith = memberId;
  $("#dm-list-view").hidden = true;
  $("#dm-chat-view").hidden = false;
  await loadChat(true);
  if (!$("#dm-composer").hidden && !$("#screen-main").classList.contains("readonly")) $("#dm-text").focus();
}

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

function renderDmStaged() {
  $("#dm-photos").replaceChildren(...dmStaged.map((s) => {
    const item = document.createElement("div");
    item.className = "staged-item" + (s.preview ? "" : " busy");
    if (s.preview) {
      const img = document.createElement("img");
      img.src = s.preview;
      img.alt = "";
      const x = document.createElement("button");
      x.type = "button";
      x.textContent = "×";
      x.setAttribute("aria-label", "Remove photo");
      x.addEventListener("click", () => {
        invoke("unstage_photo", { id: s.id });
        dmStaged = dmStaged.filter((o) => o !== s);
        renderDmStaged();
      });
      item.append(img, x);
    } else {
      const sp = document.createElement("span");
      sp.className = "spinner";
      item.append(sp);
    }
    return item;
  }));
}

$("#dm-file").addEventListener("change", async (ev) => {
  const files = [...ev.target.files];
  ev.target.value = "";
  const err = $("#dm-err");
  hideError(err);
  for (const file of files) {
    if (dmStaged.length >= 10) { showError(err, "At most 10 photos per message."); break; }
    const slot = { id: null, preview: null };
    dmStaged.push(slot);
    renderDmStaged();
    try {
      // The same pipeline as posts: resized, re-encoded as WebP, EXIF (GPS included) dropped.
      const r = await invoke("stage_photo", new Uint8Array(await file.arrayBuffer()));
      slot.id = r.id;
      slot.preview = r.preview;
    } catch (e) {
      dmStaged = dmStaged.filter((o) => o !== slot);
      showError(err, `${file.name}: ${e}`);
    }
    renderDmStaged();
  }
});

$("#dm-composer").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#dm-err");
  hideError(err);
  if (dmStaged.some((s) => !s.preview)) return showError(err, "Wait for the photos to finish preparing.");
  const text = $("#dm-text").value;
  const photos = dmStaged.map((s) => s.id);
  if (!text.trim() && !photos.length) return;
  const member = chatWith;
  await busy($("#dm-send"), async () => {
    $("#dm-send").textContent = photos.length ? "Uploading…" : "Sending…";
    try {
      await invoke("send_dm", { memberId: member, text, photos });
      if (chatWith === member) {
        $("#dm-text").value = "";
        dmStaged = [];
        renderDmStaged();
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

boot();
