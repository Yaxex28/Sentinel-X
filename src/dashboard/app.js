const REFRESH_MS = 5000;
const NOTICE_KEY = "sentinelNoticeDismissed";
const openState = {};

// Every piece of text goes through textContent, never innerHTML.
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}

function scroller(child) {
  const wrap = el("div", null, "scroll");
  wrap.append(child);
  return wrap;
}

function emptyNote(text) {
  return el("p", text, "empty");
}

function simpleTable(headers, rows) {
  const table = el("table");
  const head = el("tr");
  headers.forEach((h) => head.append(el("th", h)));
  table.append(head);
  rows.forEach((cells) => {
    const tr = el("tr");
    cells.forEach((cell) => tr.append(cell));
    table.append(tr);
  });
  return scroller(table);
}

function descCell(ev) {
  const td = el("td", ev.description);
  if (ev.attack) {
    td.append(el("code", ev.attack.technique_id + " " + ev.attack.technique));
  }
  return td;
}

function statsBlock(data) {
  const top = data.top_events.length ? data.top_events[0].score : 0;
  const rows = [
    ["events collected", data.total],
    ["activity clusters", data.clusters.length],
    ["flagged clusters", data.flagged_count],
    ["highest score", top.toFixed(1)],
  ];
  const pre = el("pre");
  pre.append(el("span", "# summary\n", "prompt"));
  pre.append(document.createTextNode(rows.map(([label, value]) => label.padEnd(20) + String(value).padStart(6)).join("\n")));
  return pre;
}

function barBlock(title, counts, total) {
  const wrap = el("div");
  wrap.append(el("h3", title));
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    wrap.append(emptyNote("No data yet."));
    return wrap;
  }
  const pre = el("pre");
  entries.forEach(([name, count], i) => {
    const filled = total ? Math.max(1, Math.round((40 * count) / total)) : 0;
    pre.append(document.createTextNode((i ? "\n" : "") + name.padEnd(18) + String(count).padStart(5) + "  "));
    pre.append(el("span", "\u2588".repeat(filled), "bar"));
  });
  wrap.append(pre);
  return wrap;
}

function clusterNode(c, index) {
  const details = el("details", null, c.flagged ? "flagged" : null);
  details.open = c.start in openState ? openState[c.start] : c.flagged;
  details.addEventListener("toggle", () => { openState[c.start] = details.open; });

  const summary = el(
    "summary",
    "Cluster " + index + " | " + c.start + " to " + c.end + " | " + c.event_count + " events | " + c.sources.join(", ")
  );
  if (c.flagged) summary.append(el("span", "[FLAGGED]", "flag"));
  details.append(summary);

  if (c.explanation) {
    const p = el("p", null, "explain");
    p.append(el("b", "automated summary: "), document.createTextNode(c.explanation));
    details.append(p);
  }
  const rows = c.events.map((ev) => [
    el("td", ev.timestamp), el("td", ev.source), descCell(ev), el("td", ev.score.toFixed(1), "num"),
  ]);
  details.append(simpleTable(["Time", "Source", "Event", "Score"], rows));
  return details;
}

function section(id, title, children) {
  const node = el("section");
  node.id = id;
  node.append(el("h2", title));
  children.forEach((child) => node.append(child));
  return node;
}

function codeCell(value) {
  const td = el("td", null, "ioc");
  td.append(el("code", value));
  return td;
}

function iocTable(list) {
  return simpleTable(["Type", "Value", "Events", "First seen", "Last seen", "Seen in"],
    list.map((i) => [el("td", i.type), codeCell(i.value), el("td", i.count, "num"),
      el("td", i.first_seen), el("td", i.last_seen), el("td", i.contexts.join(", "))]));
}

function iocGroup(key, title, list) {
  const details = el("details");
  details.open = openState[key] === true;
  details.addEventListener("toggle", () => { openState[key] = details.open; });
  details.append(el("summary", title), iocTable(list));
  return details;
}

function iocNotableTable(list) {
  return simpleTable(["Type", "Value", "Events", "Why", "Seen in"],
    list.map((i) => [el("td", i.type), codeCell(i.value), el("td", i.count, "num"),
      el("td", (i.reasons || []).join("; ")), el("td", i.contexts.join(", "))]));
}

function iocNodes(data) {
  if (!data.iocs.length) return [emptyNote("No indicators extracted yet.")];
  const notable = data.iocs.filter((i) => (i.reasons || []).length);
  const rest = data.iocs.filter((i) => !(i.reasons || []).length);
  const nodes = [el("p", "Every public address this machine contacted is an indicator, and most are ordinary browser and service traffic. Indicators with extra context are listed first; the rest are in the dropdowns.")];
  nodes.push(el("h3", "Notable (" + notable.length + ")"));
  nodes.push(notable.length
    ? iocNotableTable(notable)
    : emptyNote("None. No indicator was tied to a suspicious port, a deleted file, or a cluster with elevated severity."));
  nodes.push(el("h3", "Everything else (" + rest.length + ")"));
  const ips = rest.filter((i) => i.type === "ip");
  const hashes = rest.filter((i) => i.type === "sha256");
  const v6 = ips.filter((i) => i.value.includes(":")).length;
  if (ips.length) nodes.push(iocGroup("ioc-ip", "IP addresses: " + ips.length + " (" + (ips.length - v6) + " IPv4, " + v6 + " IPv6)", ips));
  if (hashes.length) nodes.push(iocGroup("ioc-sha256", "File hashes: " + hashes.length, hashes));
  if (!rest.length) nodes.push(emptyNote("Nothing else."));
  return nodes;
}

function render(data) {
  const topTable = data.top_events.length
    ? simpleTable(["Score", "Time", "Event"],
        data.top_events.map((e) => [el("td", e.score.toFixed(1), "num"), el("td", e.timestamp), descCell(e)]))
    : emptyNote("No events yet.");

  const overview = section("overview", "Overview", [
    statsBlock(data),
    barBlock("Events by source", data.by_source, data.total),
    barBlock("Events by severity", data.by_severity, data.total),
    el("h3", "Highest-scored events"),
    topTable,
  ]);

  const alerts = section("alerts", "Alerts (medium and high severity)", [
    data.alerts.length
      ? simpleTable(["Time", "Source", "Description"],
          data.alerts.map((a) => [el("td", a.timestamp), el("td", a.source), el("td", a.description)]))
      : emptyNote("No medium or high severity events."),
  ]);

  const attack = section("attack", "MITRE ATT&CK techniques observed", [
    data.techniques.length
      ? simpleTable(["ID", "Technique", "Tactic", "Events"],
          data.techniques.map((t) => [el("td", t.technique_id), el("td", t.technique), el("td", t.tactic), el("td", t.count, "num")]))
      : emptyNote("No techniques observed."),
  ]);

  const iocs = section("iocs", "Indicators of compromise", iocNodes(data));

  const clusterNodes = data.clusters.length
    ? data.clusters.map((c, i) => clusterNode(c, i + 1))
    : [emptyNote("No events collected yet. Press Start monitoring.")];
  const clusters = section("clusters", "Activity clusters", clusterNodes);

  document.getElementById("root").replaceChildren(overview, alerts, attack, iocs, clusters);
}

async function refresh() {
  const status = document.getElementById("status");
  try {
    const response = await fetch("/api/report", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    render(data);
    status.textContent = "updated " + new Date().toLocaleTimeString() + " | " + data.total + " events | refreshes every " + REFRESH_MS / 1000 + " s";
    status.className = "meta";
  } catch (err) {
    status.textContent = "cannot reach the dashboard server: " + err.message;
    status.className = "meta error";
  }
}

function applyMonitorState(s) {
  const btn = document.getElementById("monitor-btn");
  const label = document.getElementById("monitor-status");
  btn.textContent = s.running ? "Stop monitoring" : "Start monitoring";
  btn.className = s.running ? "btn stop" : "btn start";
  btn.disabled = false;
  if (s.running) label.textContent = "monitoring (PID " + s.pid + ")";
  else if (s.exit_code !== null) label.textContent = "runner exited on its own (exit code " + s.exit_code + "), see logs/monitors.log";
  else label.textContent = "not running";
  document.getElementById("monitor-warn").textContent = s.is_admin
    ? ""
    : "Not running as Administrator: login monitoring will not work. Restart the dashboard from an Administrator PowerShell.";
}

async function refreshMonitor() {
  try {
    const response = await fetch("/api/monitor", { cache: "no-store" });
    if (response.ok) applyMonitorState(await response.json());
  } catch (err) {
    // the status line already reports an unreachable server
  }
}

async function toggleMonitor() {
  const btn = document.getElementById("monitor-btn");
  const label = document.getElementById("monitor-status");
  const wasRunning = btn.classList.contains("stop");
  btn.disabled = true;
  try {
    const response = await fetch(wasRunning ? "/api/monitor/stop" : "/api/monitor/start", {
      method: "POST",
      headers: { "X-Sentinel-Action": "1" },
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    applyMonitorState(await response.json());
  } catch (err) {
    label.textContent = "action failed: " + err.message;
    btn.disabled = false;
  }
}

function setupNotice() {
  const box = document.getElementById("notice");
  let dismissed = false;
  try { dismissed = localStorage.getItem(NOTICE_KEY) === "1"; } catch (err) { dismissed = false; }
  box.hidden = dismissed;
  document.getElementById("notice-ok").addEventListener("click", () => {
    box.hidden = true;
    try { localStorage.setItem(NOTICE_KEY, "1"); } catch (err) { /* private mode: it will just show again */ }
  });
}

document.getElementById("monitor-btn").addEventListener("click", toggleMonitor);
setupNotice();
refresh();
refreshMonitor();
setInterval(() => { refresh(); refreshMonitor(); }, REFRESH_MS);
