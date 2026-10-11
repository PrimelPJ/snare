// Snare live map. All attacker supplied text is written with textContent,
// never innerHTML, because usernames and paths are attacker controlled.
(() => {
  "use strict";

  const COLORS = { ssh: "#ff4d5e", telnet: "#ffb547", http: "#3ad1ff" };
  const MAX_ARCS = 60;
  const MAX_FEED = 40;
  const ARC_STEPS = 48;
  const ARC_MS = 1100;

  let home = null;
  let arcs = 0;
  const seen = new Map(); // ip -> circle marker
  const $ = (id) => document.getElementById(id);

  const map = L.map("map", {
    worldCopyJump: true, zoomControl: false, attributionControl: true,
    minZoom: 2, maxBounds: [[-85, -400], [85, 400]],
  });
  // Fit the whole world into the part of the screen the side panel does not cover.
  const wide = window.innerWidth > 820;
  map.fitBounds([[-50, -165], [72, 165]], wide ? { paddingBottomRight: [380, 0] } : { paddingBottomRight: [0, window.innerHeight * 0.46] });
  // Offline vector world map (Natural Earth), so the page needs no tile server.
  map.attributionControl.addAttribution("Natural Earth");
  fetch("/static/vendor/countries-110m.json").then((r) => r.json()).then((topo) => {
    const land = topojson.feature(topo, topo.objects.countries);
    // Russia, Fiji and Antarctica jump from +180 to -180 inside one ring,
    // which Leaflet draws as a line across the whole map. Unwrap them.
    const unwrap = (ring) => {
      let prev = null;
      return ring.map(([x, y]) => {
        if (prev !== null) { while (x - prev > 180) x -= 360; while (prev - x > 180) x += 360; }
        prev = x;
        return [x, y];
      });
    };
    for (const f of land.features) {
      const g = f.geometry;
      if (g.type === "Polygon") g.coordinates = g.coordinates.map(unwrap);
      if (g.type === "MultiPolygon") g.coordinates = g.coordinates.map((p) => p.map(unwrap));
    }
    const style = { color: "#1f2a37", weight: 0.7, fillColor: "#111821", fillOpacity: 1, interactive: false };
    for (const shift of [-360, 0, 360]) {   // copies so arcs across the dateline still sit on land
      L.geoJSON(land, { style, coordsToLatLng: (c) => L.latLng(c[1], c[0] + shift) }).addTo(map).bringToBack();
    }
  });

  // ---------- arcs ----------
  function curve(from, to) {
    // Flat-map arcs (no wrap round the dateline) so every arc starts at its visible dot.
    const [lat1, lon1] = from;
    const [lat2, lon2] = to;
    const dx = lon2 - lon1, dy = lat2 - lat1;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const cLat = Math.min(80, (lat1 + lat2) / 2 + dist * 0.22);
    const cLon = (lon1 + lon2) / 2;
    const pts = [];
    for (let i = 0; i <= ARC_STEPS; i++) {
      const t = i / ARC_STEPS, u = 1 - t;
      pts.push([u * u * lat1 + 2 * u * t * cLat + t * t * lat2,
                u * u * lon1 + 2 * u * t * cLon + t * t * lon2]);
    }
    return pts;
  }

  function fire(ev) {
    if (!home || ev.lat == null || ev.lon == null) return;
    const color = COLORS[ev.sensor] || "#fff";
    markSource(ev, color);
    if (arcs >= MAX_ARCS) return;
    arcs++;
    const pts = curve([ev.lat, ev.lon], [home.lat, home.lon]);
    const line = L.polyline([], { color, weight: 1.6, opacity: 0.9, interactive: false }).addTo(map);
    const head = L.circleMarker(pts[0], { radius: 2.5, color, fillColor: color, fillOpacity: 1, weight: 0, interactive: false }).addTo(map);
    const start = performance.now();

    function step(now) {
      const p = Math.min(1, (now - start) / ARC_MS);
      const n = Math.max(2, Math.floor(p * ARC_STEPS) + 1);
      line.setLatLngs(pts.slice(0, n));
      head.setLatLng(pts[n - 1]);
      if (p < 1) return requestAnimationFrame(step);
      map.removeLayer(head);
      impact(color);
      fade(line);
    }
    requestAnimationFrame(step);
  }

  function fade(line) {
    let o = 0.9;
    const t = setInterval(() => {
      o -= 0.06;
      if (o <= 0) { clearInterval(t); map.removeLayer(line); arcs--; return; }
      line.setStyle({ opacity: o });
    }, 60);
  }

  function impact(color) {
    const ring = L.circleMarker([home.lat, home.lon], { radius: 4, color, weight: 1.5, fill: false, interactive: false }).addTo(map);
    let r = 4, o = 1;
    const t = setInterval(() => {
      r += 1.6; o -= 0.08;
      if (o <= 0) { clearInterval(t); map.removeLayer(ring); return; }
      ring.setRadius(r); ring.setStyle({ opacity: o });
    }, 30);
  }

  function markSource(ev, color) {
    let m = seen.get(ev.src_ip);
    if (!m) {
      if (seen.size > 3000) return;
      m = L.circleMarker([ev.lat, ev.lon], { radius: 3, color, weight: 0, fillColor: color, fillOpacity: 0.55 });
      m.hits = 0;
      m.bindTooltip("", { direction: "top", className: "" });
      m.addTo(map);
      seen.set(ev.src_ip, m);
    }
    m.hits++;
    m.setRadius(Math.min(3 + Math.log2(m.hits + 1) * 1.5, 12));
    const where = [ev.city, ev.country].filter(Boolean).join(", ");
    const tip = document.createElement("div");
    tip.textContent = `${ev.src_ip}  ${where}  (${m.hits} events)`;
    m.setTooltipContent(tip);
  }

  // ---------- panel ----------
  const fmt = (n) => n.toLocaleString();
  const flag = (cc) => cc && cc.length === 2
    ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0))) : "";

  function li(parts) {
    const el = document.createElement("li");
    for (const [cls, text] of parts) {
      const s = document.createElement("span");
      s.className = cls; s.textContent = text;
      el.appendChild(s);
    }
    return el;
  }

  function renderStats(s) {
    $("k-total").textContent = fmt(s.total);
    $("k-ips").textContent = fmt(s.unique_ips);
    if (s.logins != null) $("k-logins").textContent = fmt(s.logins);
    if (s.countries) {
      $("k-countries").textContent = fmt(s.country_count ?? s.countries.length);
      const box = $("t-countries"); box.replaceChildren();
      const max = s.countries.length ? s.countries[0][2] : 1;
      for (const [cc, name, n] of s.countries) {
        const el = li([["k", `${flag(cc)}  ${name}`], ["n", fmt(n)]]);
        const fill = document.createElement("span");
        fill.className = "fill"; fill.style.width = `${(n / max) * 100}%`;
        el.prepend(fill);
        box.appendChild(el);
      }
    }
    if (s.usernames) fillList("t-users", s.usernames);
    if (s.passwords) fillList("t-pass", s.passwords);
    if (s.timeline) spark(s.timeline);
  }

  function fillList(id, rows) {
    const box = $(id); box.replaceChildren();
    for (const [k, n] of rows.slice(0, 8)) box.appendChild(li([["k", k === "" ? "(blank)" : k], ["n", fmt(n)]]));
  }

  function spark(values) {
    const c = $("spark");
    const dpr = window.devicePixelRatio || 1;
    const w = c.clientWidth, h = 48;
    c.width = w * dpr; c.height = h * dpr;
    const g = c.getContext("2d");
    g.scale(dpr, dpr);
    const max = Math.max(1, ...values);
    const bw = w / values.length;
    values.forEach((v, i) => {
      const bh = (v / max) * (h - 4);
      g.fillStyle = i === values.length - 1 ? "#7cff9e" : "rgba(255,77,94,0.7)";
      g.fillRect(i * bw + 0.5, h - bh, Math.max(1, bw - 1), bh);
    });
  }

  function feed(ev) {
    const time = new Date(ev.time).toLocaleTimeString([], { hour12: false });
    let what = ev.kind.replace("_", " ");
    if (ev.kind === "login_attempt") what = `${ev.username ?? ""} : ${ev.password ?? ""}`;
    if (ev.kind === "http_request") what = `${ev.method ?? ""} ${ev.path ?? ""}`;
    const el = document.createElement("li");
    const t = document.createElement("span"); t.className = "t"; t.textContent = time;
    const d = document.createElement("span"); d.className = "d";
    const s = document.createElement("span"); s.className = `s ${ev.sensor}`; s.textContent = ev.sensor.toUpperCase();
    const body = document.createElement("span");
    body.textContent = `${ev.country_code ? flag(ev.country_code) + " " : ""}${ev.src_ip}  ${what}`;
    d.append(s, body);
    el.append(t, d);
    const box = $("feed");
    box.prepend(el);
    while (box.children.length > MAX_FEED) box.lastChild.remove();
  }

  // ---------- socket ----------
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => { $("status").textContent = "live"; $("live-dot").classList.add("on"); };
    ws.onclose = () => {
      $("status").textContent = "disconnected, retrying...";
      $("live-dot").classList.remove("on");
      setTimeout(connect, 3000);
    };
    ws.onmessage = (m) => {
      const msg = JSON.parse(m.data);
      if (msg.type === "hello") {
        home = msg.home;
        $("home-name").textContent = `/ ${home.name}`;
        L.marker([home.lat, home.lon], {
          icon: L.divIcon({ className: "", html: '<div class="home-pin"></div>', iconSize: [14, 14] }),
          interactive: false,
        }).addTo(map);
        renderStats(msg.stats);
        for (const ev of msg.recent.slice(-MAX_FEED)) feed(ev);
        for (const ev of msg.recent) if (ev.lat != null) markSource(ev, COLORS[ev.sensor]);
      } else if (msg.type === "event") {
        fire(msg.event);
        feed(msg.event);
        renderStats(msg.stats);
      } else if (msg.type === "stats") {
        renderStats(msg.stats);
      }
    };
  }
  connect();
})();
