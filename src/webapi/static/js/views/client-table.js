// Peer table shared by the Clients section and the per-file "Clients" tab in
// the Downloads / Shared Files detail panels. Columns, formatting helpers and
// the live `clients` store wiring live here once; each consumer decides which
// columns it shows by default and which rows it feeds in.

import { api } from "../api.js";
import { data } from "../events.js";
import { html, useState, useEffect, useStore } from "../dom.js";
import { Badge, listPlaceholder, Placeholder, CountryCell, toast } from "../components.js";
import { searches } from "../searches.js";
import { store, loadPref, savePref } from "../store.js";
import { VirtualTable, sortRows, textMatcher, useTablePrefs, ColumnPicker, ipNum } from "../table.js";
import { formatBytes, formatInt, formatSpeed } from "../format.js";
import { Icon } from "../icons.js";
import { t, terr } from "../i18n.js";

const ACTIVE = (s) => s && s !== "idle" && s !== "unknown";
export const isDown = (c) => (c.download_speed_bps || 0) > 0 || ACTIVE(c.download_state);
export const isUp = (c) => (c.upload_speed_bps || 0) > 0 || ACTIVE(c.upload_state);

// Column set, declared once. Every consumer offers all of them in the column
// picker and picks which ones start hidden (see ClientTable's defaultHidden),
// so a column is always one click away instead of missing from a tab.
const softLabel = (c) => [c.software ? t("downloads_peer_soft_" + c.software) : "", c.software === "unknown" ? "" : c.software_version].filter(Boolean).join(" ") || "—";
// `remote_queue_rank` is null when the peer's queue is full (the API turns
// amuled's 0xffff sentinel into null), and 0 when it reported no position at
// all. Both are "not a position", so they sort together as 0.
const rankLabel = (c) => c.remote_queue_rank === null ? t("downloads_peer_queue_full") : c.remote_queue_rank || "—";
const bytesOf = (c, k) => formatBytes((c.xfer || {})[k]);
// The "file" column is shared by both directions: download_file_name is the
// peer-advertised name of what we're pulling FROM them; upload_file_name is
// the partfile they're pulling FROM us. An upload-only peer has no
// download_file_name, so falling back to upload_file_name is what actually
// makes the column non-blank for uploads (previously always "—" there).
export const fileNameOf = (c) => c.download_file_name || c.upload_file_name || "";
// "" arrives from a daemon that sent no EC_TAG_CLIENT_FROM at all, which means
// the same thing as the API's own "unknown" token -- one label, not two.
const originLabel = (c) => t("downloads_peer_origin_" + (c.source_origin || "unknown"));
// Inverted on purpose: the wire field says whether browsing is *forbidden*,
// the column (like the desktop's "Shares File List") says whether it is
// allowed, so the peers that let you browse read "Yes".
const sharesListLabel = (c) => t(c.view_shared_disabled ? "common_no" : "common_yes");

// --- "Available Parts" column -------------------------------------------
//
// The Web UI's stand-in for the desktop's thePrefs::ShowProgBar(): with the bar
// off, the column degrades to the plain `n / total` count. There is no
// server-side preference for this (nothing in /preferences maps to it) and a
// purely visual choice does not belong in amuled's config, so it lives in
// localStorage via loadPref/savePref -- and mirrored into the reactive store so
// toggling it in one peer table redraws every mounted one.
const BAR_PREF = "peer_parts_bar";
if (store.get(BAR_PREF) === undefined) store.set(BAR_PREF, loadPref(BAR_PREF, true));
// Read (not subscribed) by the cell renderer; ClientTable holds the
// subscription that makes a toggle re-render, so the cell needs no hook.
const barOn = () => store.get(BAR_PREF) !== false;
export function useBarPref() { return useStore(BAR_PREF) !== false; }
export function setBarPref(on) { store.set(BAR_PREF, on); savePref(BAR_PREF, on); }

// How many parts of this file the peer holds. Prefer the bitmap when the caller
// opted into it (`?include_parts=true`), because it is the file-scoped truth;
// `available_parts` is the peer's scalar for whichever file it is linked to,
// which is the same file on every row of a per-file list and the only thing the
// global /clients row carries. `available_parts` is int-or-null and null is not
// 0 -- 0 is a real answer -- so the sort key keeps them apart by treating only
// null as "no answer" (sorted with 0, which is where "nothing" belongs).
const partsHeld = (c) => Array.isArray(c.parts)
  ? c.parts.reduce((n, held) => n + (held ? 1 : 0), 0)
  : (c.available_parts == null ? 0 : c.available_parts);

// One CSS custom property per part, in the desktop's evaluation order --
// GenericClientListCtrl.cpp:894-905, first match wins. Tokens rather than the
// desktop's raw RGBs: crNeither/crBoth/crPending/crNextPending/crClientOnly are
// wx literals with no dark-theme variant, so pasting them into the page would
// have looked wrong under half the themes this UI supports.
//
// `dl` / `next` are last_downloading_part / next_requested_part. They are
// int-or-null, 0 is a REAL and common index, and the key may be absent entirely
// depending on how the backend gates them -- so every test here is a strict
// `=== i` against a number, never a falsy check, and a missing key (undefined)
// simply never matches.
function partToken(have, local, dl, next, i) {
  if (!have) return "--surface-2";      // peer lacks it (desktop: crNeither)
  if (local) return "--ok";             // we hold it too (crBoth)
  if (dl === i) return "--warn";        // in flight from this peer (crPending)
  if (next === i) return "--piece-next"; // queued next from it (crNextPending)
  return "--piece-avail";               // still to gain from this source
}

// Hard-stop linear-gradient, one stop pair per run of same-coloured parts.
//
// Deliberately NOT the canvas PiecesBar the detail panels use: that component
// mounts a ResizeObserver, a MutationObserver and a matchMedia listener PER
// INSTANCE, and this is a virtual-table cell -- one instance per visible row,
// torn down and rebuilt on every scroll tick. A file with 200 sources would
// have paid 600 observers for a 14px strip. A gradient costs one style string,
// and because the stops are `var(--token)` the browser recolours it on a theme
// switch for free, which is the very thing those observers existed to do.
// Adjacent parts of the same colour collapse into one stop pair, so the string
// stays short for the common all-one-colour bitmap even on a huge file.
function partsGradient(parts, local, dl, next) {
  const n = parts.length;
  const pct = (i) => (i * 100 / n).toFixed(4) + "%";
  const stops = [];
  let runStart = 0;
  let runTok = partToken(parts[0], local && local[0], dl, next, 0);
  for (let i = 1; i <= n; i++) {
    const tok = i < n ? partToken(parts[i], local && local[i], dl, next, i) : null;
    if (tok !== runTok) {
      stops.push("var(" + runTok + ") " + pct(runStart) + " " + pct(i));
      runStart = i;
      runTok = tok;
    }
  }
  return "linear-gradient(90deg," + stops.join(",") + ")";
}

// Local name of the OTHER partfile an A4AF row is parked on. It is not on the
// row -- the desktop reads it off GetRequestFile()->GetFileName() -- so resolve
// the row's download_file_hash against the live `downloads` collection, which is
// the same object that hash indexes. Falls back to "?" exactly as the desktop
// does when GetRequestFile() is null (a peer whose other file we do not hold in
// the store yet, or which the daemon never resolved).
function a4afFileName(c) {
  const list = store.get("downloads");
  if (!Array.isArray(list) || !c.download_file_hash) return "?";
  const f = list.find((d) => d.hash === c.download_file_hash);
  return (f && f.name) || "?";
}

// Renders the column. `_file` is the per-file context FileClients hangs on each
// row (see there): a COLS cell only ever receives one row, and the part count,
// our own per-part state and "is this file stopped" all belong to the FILE.
function partsCell(c) {
  const f = c._file || {};
  // A4AF row: the desktop replaces the WHOLE cell with a centred, thin-bordered
  // "A4AF: <other file>" badge instead of a bar (SourceListCtrl.cpp:74-77 and
  // :82-111) -- a source parked here for another file has no bitmap for this
  // one. Text rather than colour, so it survives both themes, reads aloud, and
  // is how a user tells a parked source from a dead one.
  if (c.a4af) {
    const other = a4afFileName(c);
    return html`<span class="peer-a4af" title=${t("downloads_peer_a4af_tip") + " — " + other}>
      ${t("downloads_peer_a4af")}: ${other}</span>`;
  }
  // `parts` is ABSENT (not short, not empty) whenever there is no usable
  // bitmap: the caller did not pass include_parts, the peer never reported a
  // map, or the map could not cover the file -- the handler drops a short one
  // rather than padding it (Api.cpp ResolvePartBitmap), which is the same rule
  // the desktop applies before drawing per-part spans at all.
  const bitmap = Array.isArray(c.parts) && c.parts.length ? c.parts : null;
  // Denominator: `parts.length` when there is a bitmap, since the handler
  // guarantees it equals the file's part_count and it needs no prop threaded
  // through two panels; the `partCount` context only covers the no-bitmap case,
  // where there is no length to read.
  const total = bitmap ? bitmap.length : f.partCount;
  const held = bitmap ? partsHeld(c) : c.available_parts;
  // null is not 0 here: 0 means "this peer has none of it", null means it never
  // said. Only the latter is unknowable.
  const text = held == null ? "—"
    : total ? formatInt(held) + " / " + formatInt(total)
    : formatInt(held);
  if (!bitmap || !barOn()) return text;
  // The two index stripes and the green "we have it too" axis are download-side
  // only; on a shared file both are meaningless (see FileClients), which keeps
  // that bar two-state like the desktop's own ColumnUserAvailable.
  const dl = f.download ? c.last_downloading_part : null;
  const next = f.download ? c.next_requested_part : null;
  // A stopped file dims the whole bar, as the desktop blends every span by 50
  // when reqfile->IsStopped() (GenericClientListCtrl.cpp:908-910).
  return html`<span class=${"peer-parts-bar" + (f.stopped ? " is-dim" : "")} title=${text}
                    style=${{ background: partsGradient(bitmap, f.download ? f.localParts : null, dl, next) }}></span>`;
}

// Default order when no column sort is chosen: busiest peers first.
export const bySpeed = (a, b) =>
  ((b.download_speed_bps || 0) + (b.upload_speed_bps || 0)) -
  ((a.download_speed_bps || 0) + (a.upload_speed_bps || 0));

// Each column carries key + sortVal so the header is clickable-to-sort (the
// flags column has no key → stays non-sortable).
export const COLS = [
  { cls: "peer-flags", width: "60px", cell: (c) => peerFlags(c) },
  // Identity block, each field next to the one it qualifies: where the peer is
  // (country, address), who it claims (name, user_hash), what it runs (software, os).
  // Abbreviated header: a spelled-out "Country" would still be wider than the cell.
  { key: "country", th: "downloads_peer_col_country", width: "70px", sortable: true,
    sortVal: (c) => c.country_code || "", cell: (c) => html`<${CountryCell} code=${c.country_code} />` },
  // Empty ip: a peer we never connected to directly (LowID).
  { key: "address", th: "downloads_peer_col_address", num: true, width: "180px", sortable: true,
    sortVal: (c) => ipNum(c.ip), cell: (c) => c.ip ? c.ip + ":" + c.port : "—" },
  { key: "name", th: "downloads_peer_col_name", width: "170px", sortable: true,
    sortVal: (c) => (c.name || "").toLowerCase(),
    cell: (c) => html`<span title=${c.name}>${c.name || "—"}</span>` },
  { key: "user_hash", th: "downloads_peer_col_user_hash", width: "150px", sortable: true,
    sortVal: (c) => c.user_hash || "",
    cell: (c) => html`<span title=${c.user_hash}>${c.user_hash || "—"}</span>` },
  { key: "ident", th: "downloads_peer_col_ident", width: "130px", sortable: true,
    sortVal: (c) => identLabel(c.ident_state).toLowerCase(), cell: (c) => identBadge(c.ident_state) },
  { key: "software", th: "downloads_peer_col_software", width: "140px", sortable: true,
    sortVal: (c) => softLabel(c).toLowerCase(), cell: (c) => softLabel(c) },
  // The peer's own self-reported OS string -- frequently empty.
  { key: "os", th: "downloads_peer_col_os", width: "110px", sortable: true,
    sortVal: (c) => (c.os_info || "").toLowerCase(), cell: (c) => c.os_info || "—" },
  // How we found this peer, and whether it lets us browse its share -- both
  // promoted onto the row by issue #984 so a table needs no per-peer fetch.
  { key: "origin", th: "downloads_peer_col_origin", width: "120px", sortable: true,
    sortVal: (c) => originLabel(c).toLowerCase(), cell: (c) => originLabel(c) },
  { key: "shares_list", th: "downloads_peer_col_shares_list", width: "110px", sortable: true,
    sortVal: (c) => (c.view_shared_disabled ? 0 : 1),
    cell: (c) => html`<span title=${t("downloads_peer_col_shares_list_tip")}>${sharesListLabel(c)}</span>` },
  { key: "file", th: "downloads_peer_col_file", cls: "name", sortable: true,
    sortVal: (c) => fileNameOf(c).toLowerCase(),
    cell: (c) => html`<span title=${fileNameOf(c)}>${fileNameOf(c) || "—"}</span>` },

  // The peer's own chunk map of the file in hand -- a bar in the per-file tabs
  // (which fetch `?include_parts=true`), the scalar count everywhere else.
  { key: "parts", th: "downloads_peer_col_parts", cls: "peer-parts", width: "180px", sortable: true,
    sortVal: (c) => partsHeld(c), cell: (c) => partsCell(c) },

  { key: "dl_state", th: "downloads_peer_col_dl_state", width: "120px", sortable: true,
    sortVal: (c) => c.download_state || "", cell: (c) => stateBadge(c.download_state) },
  { key: "dl_speed", th: "downloads_peer_col_dl_speed", num: true, width: "100px", sortable: true,
    sortVal: (c) => c.download_speed_bps || 0, cell: (c) => formatSpeed(c.download_speed_bps) },
  { key: "downloaded", th: "downloads_peer_col_downloaded", num: true, width: "100px", sortable: true,
    sortVal: (c) => (c.xfer && c.xfer.down_total) || 0, cell: (c) => bytesOf(c, "down_total") },
  { key: "dl_session", th: "downloads_peer_col_downloaded_session", num: true, width: "100px", sortable: true,
    sortVal: (c) => (c.xfer && c.xfer.down_session) || 0, cell: (c) => bytesOf(c, "down_session") },
  { key: "remote_rank", th: "downloads_peer_col_remote_rank", num: true, width: "90px", sortable: true,
    sortVal: (c) => c.remote_queue_rank || 0, cell: (c) => rankLabel(c) },

  { key: "ul_state", th: "downloads_peer_col_ul_state", width: "120px", sortable: true,
    sortVal: (c) => c.upload_state || "", cell: (c) => stateBadge(c.upload_state) },
  { key: "ul_speed", th: "downloads_peer_col_ul_speed", num: true, width: "100px", sortable: true,
    sortVal: (c) => c.upload_speed_bps || 0, cell: (c) => formatSpeed(c.upload_speed_bps) },
  { key: "uploaded", th: "downloads_peer_col_uploaded", num: true, width: "100px", sortable: true,
    sortVal: (c) => (c.xfer && c.xfer.up_total) || 0, cell: (c) => bytesOf(c, "up_total") },
  { key: "ul_session", th: "downloads_peer_col_uploaded_session", num: true, width: "100px", sortable: true,
    sortVal: (c) => (c.xfer && c.xfer.up_session) || 0, cell: (c) => bytesOf(c, "up_session") },
  { key: "queue_pos", th: "downloads_peer_col_queue_pos", num: true, width: "90px", sortable: true,
    sortVal: (c) => c.queue_waiting_position || 0, cell: (c) => c.queue_waiting_position || "—" },
  { key: "score", th: "downloads_peer_col_score", num: true, width: "80px", sortable: true,
    sortVal: (c) => c.score || 0, cell: (c) => c.score || "—" },

  // "View files": browse this peer's share, the desktop's context-menu action.
  // A browse is an ordinary search on the API, so it opens as a tab in the
  // Search section, which is where this jumps to. Rides the shared column set,
  // so it also appears in the detail panels' Clients tab -- it targets a peer,
  // not a file, so that is correct.
  { key: "actions", th: "downloads_peer_col_actions", cls: "row-actions admin-only", width: "70px",
    cell: (c) => html`
      <button class="btn btn-icon btn-sm" type="button" title=${t("search_view_files")}
              onClick=${() => searches.browse(c.ecid, c.name).catch((e) => toast(terr(e), "error"))}>
        <${Icon} name="shared" />
      </button>` },
];

// Raw-detail columns no consumer leads with; each adds its own defaultHidden set
// on top of these.
export const HIDDEN_EVERYWHERE = ["address", "os", "user_hash", "ident", "origin", "shares_list"];

// 1:1 with ClientIdentStateName() in src/webapi/Refresher.cpp.
export const IDENT_STATES = ["identified", "not_available", "id_needed", "id_failed", "bad_guy", "unknown"];
export const identLabel = (s) => t("downloads_peer_ident_" + (s || "unknown"));
export const IDENT_FILTERS = ["all", ...IDENT_STATES].map((v) => [v, t("downloads_peer_ident_" + v)]);

// Live `clients` collection (GET /clients seed + SSE client_added/updated/
// removed). register/ensure are idempotent, so every consumer can just call
// this; the resource starts on the first mount and stays live from then on.
// Returns the raw store value: undefined until the first snapshot lands, []
// once there are known to be no peers (see ClientTable's `loading`).
export function useClients() {
  useEffect(() => {
    data.register({ key: "clients", eventPrefix: "client", id: "ecid",
      list: () => api.get("clients").then((r) => r.clients || []) });
    data.ensure("clients");
  }, []);
  return useStore("clients");
}

// Compact status icons (replacing the ident/obfuscation/friend columns). Each
// icon carries an explanatory tooltip; only meaningful states show an icon.
export function peerFlags(c) {
  const flags = [];
  const identTip = () => t("downloads_peer_ident") + ": " + identLabel(c.ident_state);
  // bad_guy / id_failed both mean "this peer's identity is wrong"; the other
  // states are just an absence of SecIdent and earn no icon.
  if (c.ident_state === "identified") flags.push(["verified", identTip()]);
  else if (c.ident_state === "bad_guy" || c.ident_state === "id_failed") flags.push(["warning", identTip()]);
  if (c.obfuscation_status === "enabled")
    flags.push(["lock", t("downloads_peer_obfuscation") + ": " + t("downloads_peer_enabled")]);
  if (c.friend_slot)
    flags.push(["star", t("downloads_peer_friend")]);
  return flags.map(([name, tip]) => html`<${Icon} name=${name} size=${18} title=${tip} />`);
}

const IDENT_KIND = { identified: "downloading", id_failed: "stopped", bad_guy: "stopped", id_needed: "waiting" };
export function identBadge(s) {
  return html`<${Badge} kind=${IDENT_KIND[s] || "paused"}>${identLabel(s)}<//>`;
}

export function stateBadge(s) {
  if (!s || s === "idle") return html`<${Badge}>${t("downloads_peer_state_" + (s || "idle"))}<//>`;
  const kind = s === "downloading" || s === "uploading" ? "downloading"
    : s === "banned" || s === "error" ? "paused" : "waiting";
  return html`<${Badge} kind=${kind}>${t("downloads_peer_state_" + s)}<//>`;
}

// Toolbar + peer table, shared by every consumer. Always offers the full
// column set in the picker; `defaultHidden` / `defaultSort` are only the
// starting point, and `prefsKey` is where the user's choice (sort, hidden
// columns, widths) is persisted. Every caller sorts descending by default
// (biggest transfer first), so only the column key is a prop. `toolbar` is
// whatever filter controls the caller wants left of the picker. Returns the
// two siblings so the caller keeps owning the layout box around them.
// `loading` (rows still undefined) makes empty `rows` mean "not seeded yet"
// rather than "no peers"; `empty` overrides that whole placeholder for a caller
// that has something more specific to say (a failed fetch, say).
export function ClientTable({ rows, prefsKey, defaultHidden, defaultSort, toolbar, toolbarCls = "toolbar",
                              loading = false, empty = null }) {
  const { sortKey, sortDir, hidden, widths, toggleSort, toggleCol, setWidth, resetPrefs } =
    useTablePrefs(prefsKey, { sortKey: defaultSort, sortDir: -1, hidden: defaultHidden });
  // Subscribing here is what makes the bar toggle repaint the rows: partsCell
  // reads the pref straight off the store, so this hook is the re-render.
  const bar = useBarPref();

  const columns = COLS.map((col) => ({ ...col, label: col.th ? t(col.th) : "" }));
  const shown = columns.filter((c) => !c.key || !hidden.has(c.key));
  // Sort by the chosen column when set; otherwise keep the default "busiest
  // peers first" order (combined dl+ul speed, descending).
  const list = columns.some((c) => c.key === sortKey && c.sortVal)
    ? sortRows(rows, columns, sortKey, sortDir)
    : rows.slice().sort(bySpeed);

  return html`
    <div class=${toolbarCls}>
      ${toolbar}
      <div class="spacer"></div>
      <label class="peer-bar-toggle" title=${t("downloads_peer_parts_bar_tip")}>
        <input type="checkbox" checked=${bar} onChange=${(e) => setBarPref(e.target.checked)} />
        ${t("downloads_peer_parts_bar")}
      </label>
      <${ColumnPicker} columns=${columns} hidden=${hidden} onToggle=${toggleCol} onReset=${resetPrefs} />
    </div>
    <${VirtualTable} columns=${shown} rows=${list} rowKey=${(c) => c.ecid}
                     sortKey=${sortKey} sortDir=${sortDir} onSort=${toggleSort}
                     widths=${widths} onResize=${setWidth}
                     maxHeight="none"
                     empty=${empty || listPlaceholder(loading, t("downloads_peer_empty"))} />`;
}

// Per-file peer table for the detail panels, fed by GET {scope}/{hash}/clients
// (issue #984). `scope` is the collection the hash belongs to -- "downloads" or
// "shared" -- and is a prop rather than a guess, because a partfile with one
// completed chunk is in both at once and only the caller knows which panel it
// is drawing.
//
// This used to join the global `clients` store against download_file_hash /
// upload_file_hash client-side. That join could never produce an A4AF row: a
// source parked on another file has neither hash pointing here, so the peers a
// user most wants to see -- the ones queued for this file behind something else
// -- were exactly the ones missing. The route does the selection against the
// same snapshot the store is built from, and adds `role`, `a4af` and (opt-in)
// the per-peer `parts` bitmap that no global row carries.
//
// `partCount`, `localParts` and `stopped` are the FILE's, not the peer's: the
// parts column needs a denominator when a row carries no bitmap, the bar needs
// to know which chunks we already hold to paint "have it too" green, and a
// stopped file dims every bar. `localParts` is null wherever that axis carries
// no information.
//
// `scope` also decides how much of the bar is meaningful. On a download it is
// the desktop's five-state source bar. On a shared file it stays TWO-state --
// the file is fully local, so "we have it too" is constant, and the in-flight /
// next-requested indices describe a download that, from this panel's point of
// view, is not what the user is looking at. That mirrors the desktop, whose
// shared-side bar (ColumnUserAvailable, GenericClientListCtrl.cpp:919-940) is
// two-state for exactly the same reason.
//
// Refresh: the old store-backed rows were live, so a one-shot fetch would have
// made the tab quietly go stale. It re-fetches on each tick of the same store
// the parent detail panel ticks on (download-detail.js / shared-detail.js do
// exactly this for the file itself) -- registered by the list view that owns
// the panel, so this only ever reads it. GET is ETag-cached, so an unchanged
// frame short-circuits to a 304.
//
// Nothing here polls while the tab is closed, and `include_parts=true` is
// scoped for free: both callers render <FileClients/> inside a
// `tab === "clients"` branch (download-detail.js, shared-detail.js), so the
// component -- and this effect -- unmounts the moment the tab loses focus.
// Verified: neither caller keeps it mounted behind a visibility flag.
export function FileClients({ hash, scope, partCount = 0, localParts = null, stopped = false,
                              prefsKey, defaultHidden, defaultSort }) {
  const tick = useStore(scope);
  // An A4AF badge names the other partfile by resolving its hash against the
  // `downloads` collection, so this panel needs that collection live even when
  // it is showing a *shared* file. register/ensure are idempotent (the Downloads
  // view calls the identical pair), so this only starts it if nothing else has.
  useEffect(() => {
    data.register({ key: "downloads", eventPrefix: "download", id: "hash",
      list: () => api.get("downloads?status=all").then((r) => r.downloads || []) });
    data.ensure("downloads");
  }, []);
  // Subscribed for the side effect only: partsCell reads the collection through
  // store.get(), so this is what repaints an A4AF badge when the other file's
  // name lands.
  useStore("downloads");
  const [rows, setRows] = useState(undefined); // undefined until the first fetch lands
  const [failed, setFailed] = useState(null);
  const [ident, setIdent] = useState("all");
  const [q, setQ] = useState("");

  useEffect(() => {
    if (!hash || !scope) { setRows(undefined); return; }
    let alive = true;
    api.get(scope + "/" + hash + "/clients?include_parts=true")
      .then((r) => { if (alive) { setRows(r.clients || []); setFailed(null); } })
      // Keep the last good rows on a transient failure -- the tick re-fetches
      // in a moment, and blanking a populated table for one bad frame is worse
      // than showing rows a second old. The message shows only when there is
      // nothing to show instead.
      .catch((e) => { if (alive) { setFailed(e); setRows((prev) => prev || []); } });
    return () => { alive = false; };
  }, [hash, scope, tick]);

  // Hung on every row because a COLS cell only ever receives one row; see
  // partsCell. Same object identity for all rows of a render, so it costs one
  // allocation, not one per peer.
  const fileCtx = { partCount, localParts, stopped, download: scope === "downloads" };
  let list = (rows || []).map((c) => ({ ...c, _file: fileCtx }));
  if (ident !== "all") list = list.filter((c) => c.ident_state === ident);
  if (q) { const match = textMatcher(q); list = list.filter((c) => match((c.name || "") + " " + fileNameOf(c))); }

  const errorNode = failed && !(rows || []).length
    ? html`<${Placeholder} kind="error">${terr(failed)}<//>` : null;

  return html`
    <div class="detail-clients">
      <${ClientTable} rows=${list} prefsKey=${prefsKey} defaultHidden=${defaultHidden}
                      defaultSort=${defaultSort} loading=${rows === undefined}
                      empty=${errorNode}
                      toolbar=${ClientFilters({ ident, setIdent, q, setQ })} />
    </div>`;
}

// The identity <select> + free-text box, identical in both consumers.
export function ClientFilters({ ident, setIdent, q, setQ }) {
  return html`
    <select class="input input-sm" value=${ident} onChange=${(e) => setIdent(e.target.value)}>
      ${IDENT_FILTERS.map(([v, l]) => html`<option value=${v}>${l}</option>`)}
    </select>
    <input class="input input-sm" type="text" placeholder=${t("downloads_peer_filter")} value=${q} onInput=${(e) => setQ(e.target.value)} />`;
}
