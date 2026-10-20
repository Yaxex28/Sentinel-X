const REFRESH_MS = 5000;
const openState = {};

// Every piece of text goes through textContent, never innerHTML.
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}

function statCard(number, label) {
  const card = el("div", null, "stat");
  card.append(el("div", number, "n"), el("div", label, "l"));
  return card;
}

function barTable(title, counts, total) {
  const wrap = el("div");
  wrap.append(el("h3", title));
  const table = el("table", null, "counts");
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  for (const [name, count] of entries) {
    const row = el("tr");
    const barCell = el("td");
    const bar = el("div", null, "bar");
    bar.style.width = (total ? Math.round((100 * count) / total) : 0) + "%";
    barCell.append(bar);
    row.append(el("td", name), el("td", count, "num"), barCell);
    table.append(row);
  }
  wrap.append(table);
  return wrap;
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
  return table;
}

function descCell(ev) {
  const td = el("td", ev.description);
  if (ev.attack) {
    td.append(el("span", ev.attack.technique_id + " " + ev.attack.technique, "attack"));
  }
  return td;
}

function clusterNode(c, index) {
  const details = el("details", null, c.flagged ? "flagged" : null);
  details.open = c.start in openState ? openState[c.start] : c.flagged;
  details.addEventListener("toggle", () => { openState[c.start] = details.open; });

  const summary = el(
    "summary",
    "Cluster " + index + ": " + c.start + " to " + c.end + " | " + c.event_count + " events | " + c.sources.join(", ")
  );
  if (c.flagged) summary.append(el("span", "FLAGGED", "badge flagged"));
  details.append(summary);

  if (c.explanation) {
    const p = el("p", null, "explain");
    p.append(el("b", "Automated summary: "), document.createTextNode(c.explanation));
    details.append(p);
  }
  const rows = c.events.map((ev) => [
    el("td", ev.timestamp), el("td", ev.source), descCell(ev), el("td", ev.score.toFixed(1), "num"),
  ]);
  details.append(simpleTable(["Time", "Source", "Event", "Score"], rows));
  return details;
}

function render(data) {
  const top = data.top_events.length ? data.top_events[0].score : 0;
  const stats = el("div", null, "stats");
  stats.append(
    statCard(data.total, "events collected"),
    statCard(data.clusters.length, "activity clusters"),
    statCard(data.flagged_count, "flagged clusters"),
    statCard(top.toFixed(1), "highest score")
  );

  const overview = el("div");
  overview.append(
    el("h2", "Overview"),
    barTable("Events by source", data.by_source, data.total),
    barTable("Events by severity", data.by_severity, data.total)
  );

  const alerts = el("div");
  alerts.append(
    el("h2", "Alerts (medium and high severity)"),
    simpleTable(["Time", "Source", "Description"],
      data.alerts.map((a) => [el("td", a.timestamp), el("td", a.source), el("td", a.description)]))
  );

  const techniques = el("div");
  techniques.append(
    el("h2", "MITRE ATT&CK techniques observed"),
    simpleTable(["ID", "Technique", "Tactic", "Events"],
      data.techniques.map((t) => [el("td", t.technique_id), el("td", t.technique), el("td", t.tactic), el("td", t.count, "num")]))
  );

  const topEvents = el("div");
  topEvents.append(
    el("h2", "Highest-scored events"),
    simpleTable(["Score", "Time", "Event"],
      data.top_events.map((e) => [el("td", e.score.toFixed(1), "num"), el("td", e.timestamp), descCell(e)]))
  );

  const clusters = el("div");
  clusters.append(el("h2", "Activity clusters"));
  data.clusters.forEach((c, i) => clusters.append(clusterNode(c, i + 1)));

  document.getElementById("root").replaceChildren(stats, overview, alerts, techniques, topEvents, clusters);
}

async function refresh() {
  const status = document.getElementById("status");
  try {
    const response = await fetch("/api/report", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    render(await response.json());
    status.textContent = "Updated " + new Date().toLocaleTimeString() + " (every " + REFRESH_MS / 1000 + " s)";
    status.className = "";
  } catch (err) {
    status.textContent = "Cannot reach the dashboard server: " + err.message;
    status.className = "error";
  }
}

refresh();
setInterval(refresh, REFRESH_MS);