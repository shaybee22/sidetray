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
}

function route() {
  clearInterval(pollTimer);
  switch (view.stage) {
    case "setup": return startWizard();
    case "pending":
    case "denied": return startWaiting();
    case "active": return startMain();
    default: $("#screen-loading p").textContent = `Unexpected state: ${view.stage}`;
  }
}

// --- wizard -------------------------------------------------------------------------

let probe = null;

async function startWizard() {
  showScreen("screen-wizard");
  $("#wz-server").hidden = false;
  $("#wz-details").hidden = true;
  if (!$("#wz-url").value) {
    const d = await invoke("wizard_defaults");
    $("#wz-url").value = d.server;
  }
  $("#wz-url").focus();
}

$("#wz-server").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#wz-server-err");
  hideError(err);
  const server = $("#wz-url").value.trim();
  if (!server) return showError(err, "Enter the server address you were given.");
  await busy($("#wz-continue"), async () => {
    $("#wz-continue").textContent = "Checking…";
    try {
      probe = await invoke("probe_server", { server, caPem: $("#wz-ca").value || null });
    } catch (e) {
      return showError(err, e);
    }
    const founding = !probe.exists;
    $("#wz-found").textContent = founding
      ? "This server doesn't have a group yet. You can create one: you'll be its first Key Master. You need the server's setup token."
      : `Found the group “${probe.name}” on this server.`;
    $("#wz-group").value = founding ? "" : probe.name;
    $("#wz-token-row").hidden = !founding;
    $("#wz-submit").textContent = founding ? "Create the group" : "Ask to join";
    $("#wz-server").hidden = true;
    $("#wz-details").hidden = false;
    (founding ? $("#wz-group") : $("#wz-name")).focus();
  });
});

$("#wz-back").addEventListener("click", () => {
  $("#wz-details").hidden = true;
  $("#wz-server").hidden = false;
  hideError($("#wz-details-err"));
});

$("#wz-details").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#wz-details-err");
  hideError(err);
  const founding = !probe.exists;
  const args = {
    server: $("#wz-url").value.trim(),
    caPem: $("#wz-ca").value || null,
    groupName: $("#wz-group").value.trim(),
    displayName: $("#wz-name").value.trim(),
    email: $("#wz-email").value.trim(),
    setupToken: founding ? $("#wz-token").value : null,
  };
  if (!args.groupName || !args.displayName || !args.email) return showError(err, "Fill in every field.");
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
  $("#tb-group").textContent = view.group_name;
  $("#tab-km-btn").hidden = !view.keymaster;
  $("#km-code").textContent = view.safety_code;
  renderSyncStatus();
  renderDevice();
  loadFeed();
}

function selectTab(name) {
  for (const t of $$(".tab")) t.setAttribute("aria-selected", String(t.dataset.tab === name));
  for (const p of $$(".panel")) p.hidden = p.id !== `panel-${name}`;
  clearInterval(pendingTimer);
  if (name === "km") {
    loadPending();
    pendingTimer = setInterval(loadPending, 10000);
  }
  if (name === "device") renderDevice();
}
for (const t of $$(".tab")) t.addEventListener("click", () => selectTab(t.dataset.tab));

function renderSyncStatus(text) {
  $("#sync-status").textContent = text ?? (view.last_sync_at ? `Synced ${when(view.last_sync_at)}` : "Not synced yet");
}

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
  if (view.stage !== "active") return;
  $("#sync-status").title = "";
  renderSyncStatus();
  if (view.keymaster !== wasKm) startMain();
  const badge = $("#km-badge");
  badge.textContent = String(r.pending_joins);
  badge.hidden = !r.pending_joins;
  if (!$("#panel-feed").hidden && r.new_events) loadFeed();
  if (!$("#panel-km").hidden) loadPending();
});

listen("sync-error", (ev) => {
  renderSyncStatus("Couldn't sync");
  $("#sync-status").title = String(ev.payload);
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

function avatar(el, name) {
  el.textContent = (name.trim()[0] || "?").toUpperCase();
  el.style.background = `hsl(${hue(name)} 42% 46%)`;
}

function renderPost(p) {
  const el = $("#tpl-post").content.firstElementChild.cloneNode(true);
  el.dataset.id = p.id;
  avatar($(".avatar", el), p.author);
  const author = $(".author", el);
  author.textContent = p.author;
  if (p.author_keymaster) {
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = "Key Master";
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
    const b = document.createElement("b");
    b.textContent = c.author;
    const body = document.createElement("span");
    body.className = "body";
    body.textContent = c.text;
    const t = document.createElement("span");
    t.className = "muted small when";
    t.textContent = when(c.created_at);
    row.append(b, body, t);
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

// --- this device ---------------------------------------------------------------------------

function renderDevice() {
  const rows = [
    ["Group", view.group_name],
    ["Server", view.server],
    ["You", `${view.display_name} <${view.email}>`],
    ["Role", view.keymaster ? "Key Master" : "Member"],
    ["Your safety code", view.safety_code, true],
    ["Device id", view.device_id, true],
    ["Trusts Key Masters", view.trusted_keymasters.join(", ") || "none yet"],
    ["Group key versions", view.key_versions.join(", ")],
    ["Synced through", `event #${view.last_seq}` + (view.last_sync_at ? `, ${when(view.last_sync_at)}` : "")],
  ];
  if (view.rejected) rows.push(["Rejected events", `${view.rejected} (unverified author or bad signature)`]);
  $("#device-facts").replaceChildren(...rows.flatMap(([k, v, mono]) => {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v ?? "";
    if (mono) dd.className = "mono";
    return [dt, dd];
  }));
}

boot();
