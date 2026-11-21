// ---- Role toggle (DFIR vs Detection Engineering) ----
const TERMINAL = {
  dfir: [
    ["cmd", "$ triage --host FIN-WS-0412 --scope credential-leak"],
    ["", "[*] Collecting artifacts: Prefetch, LNK, Amcache, EVTX..."],
    ["hit", "[!] 4624 LogonType 10 from unusual source"],
    ["hit", "[!] Suspicious LNK -> powershell -enc ..."],
    ["", "[*] Mapping to MITRE ATT&CK: T1078, T1059.001"],
    ["ok", "[+] Root cause identified · containment initiated"],
    ["ok", "[+] Report drafted for stakeholders"],
  ],
  de: [
    ["cmd", "$ detect --validate rules/ --replay last_90d"],
    ["", "[*] Loaded 150 detections (SPL · KQL · EQL · Sigma)"],
    ["", "[*] Running attack simulation + historical replay..."],
    ["hit", "[!] 12 noisy rules → tuning applied"],
    ["ok", "[+] False positives ↓ · ATT&CK coverage ↑"],
    ["ok", "[+] Splunk ingestion optimized: -38%"],
    ["ok", "[+] Regression tests passed"],
  ],
};

let typingTimer = null;
function typeTerminal(role) {
  const el = document.getElementById("termBody");
  clearTimeout(typingTimer);
  el.innerHTML = "";
  const lines = TERMINAL[role];
  let li = 0, ci = 0, html = "";
  const step = () => {
    if (li >= lines.length) {
      el.innerHTML = html + '<span class="cursor">&nbsp;</span>';
      return;
    }
    const [cls, text] = lines[li];
    ci++;
    const partial = text.slice(0, ci).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    el.innerHTML = html + `<span class="c-${cls}">${partial}</span><span class="cursor">&nbsp;</span>`;
    if (ci >= text.length) {
      html += `<span class="c-${cls}">${partial}</span>\n`;
      li++; ci = 0;
      typingTimer = setTimeout(step, 260);
    } else {
      typingTimer = setTimeout(step, cls === "cmd" ? 28 : 10);
    }
  };
  step();
}

function setRole(role) {
  document.body.dataset.role = role;
  document.querySelectorAll(".role-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.setRole === role));
  history.replaceState(null, "", role === "de" ? "?focus=detection" : location.pathname);
  typeTerminal(role);
}

document.querySelectorAll(".role-btn").forEach(b =>
  b.addEventListener("click", () => setRole(b.dataset.setRole)));

// Share a direct link: ?focus=detection opens the Detection Engineering view
setRole(new URLSearchParams(location.search).get("focus") === "detection" ? "de" : "dfir");

// ---- Mobile menu ----
const navLinks = document.getElementById("navLinks");
document.getElementById("menuBtn").addEventListener("click", () => navLinks.classList.toggle("open"));
navLinks.querySelectorAll("a").forEach(a => a.addEventListener("click", () => navLinks.classList.remove("open")));

// ---- Counters + reveal on scroll ----
const countUp = el => {
  const target = +el.dataset.count, start = performance.now(), dur = 1200;
  const tick = t => {
    const p = Math.min((t - start) / dur, 1);
    el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
};

document.querySelectorAll(".section .container > *, .stat").forEach(el => el.classList.add("reveal"));
const io = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (!e.isIntersecting) return;
    e.target.classList.add("in");
    const c = e.target.querySelector("[data-count]");
    if (c) countUp(c);
    io.unobserve(e.target);
  });
}, { threshold: 0.12 });
document.querySelectorAll(".reveal").forEach(el => io.observe(el));

document.getElementById("year").textContent = new Date().getFullYear();
