const form = document.getElementById("scanForm");
const domainInput = document.getElementById("domainInput");
const scanBtn = document.getElementById("scanBtn");
const btnText = scanBtn.querySelector(".btn-text");
const btnLoader = scanBtn.querySelector(".btn-loader");
const resultsEl = document.getElementById("results");
const errorEl = document.getElementById("error");
const statusEl = document.getElementById("scanStatus");
const pdfBtn = document.getElementById("pdfBtn");

let lastScannedDomain = null;
let scanning = false;

const SEVERITY_ORDER = ["kritik", "yuqori", "o'rta", "past", "ma'lumot"];
const SEVERITY_LABELS = {
  kritik: "Kritik",
  yuqori: "Yuqori",
  "o'rta": "O'rta",
  past: "Past",
  "ma'lumot": "Ma'lumot",
};

const SCAN_TIMEOUT_MS = 180000;

function setLoading(loading) {
  scanning = loading;
  scanBtn.disabled = loading;
  domainInput.disabled = loading;
  btnText.classList.toggle("hidden", loading);
  btnLoader.classList.toggle("hidden", !loading);
  btnText.textContent = loading ? "Tekshirilmoqda..." : "Tekshirish";

  if (loading) {
    statusEl.textContent = "Sayt tekshirilmoqda, biroz kuting...";
    statusEl.classList.remove("hidden");
  } else {
    statusEl.classList.add("hidden");
    statusEl.textContent = "";
  }
}

async function runScan(domain) {
  if (!domain || scanning) return;

  setLoading(true);
  resultsEl.classList.add("hidden");
  errorEl.classList.add("hidden");
  pdfBtn.classList.add("hidden");

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
      signal: controller.signal,
    });

    if (!res.ok) {
      let message = "Tekshiruvda xatolik yuz berdi";
      try {
        const err = await res.json();
        message = err.detail || message;
      } catch (_) {}
      throw new Error(message);
    }

    const data = await res.json();
    lastScannedDomain = domain;
    renderResults(data);
  } catch (err) {
    if (err.name === "AbortError") {
      errorEl.textContent = "Tekshiruv vaqti tugadi (3 daqiqa). Qayta urinib ko'ring.";
    } else {
      errorEl.textContent = err.message || "Noma'lum xatolik";
    }
    errorEl.classList.remove("hidden");
  } finally {
    clearTimeout(timeoutId);
    setLoading(false);
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runScan(domainInput.value.trim());
});

function renderInfrastructure(infra) {
  const section = document.getElementById("infraSection");
  const content = document.getElementById("infraContent");

  if (!infra || !infra.host) {
    section.classList.add("hidden");
    return;
  }

  let html = "";

  if (infra.unique_ips?.length) {
    html += `
      <div class="infra-block">
        <h4>IP manzillar (${infra.unique_ips.length})</h4>
        <div class="infra-tags">${infra.unique_ips.map((ip) => `<span class="infra-tag">${escapeHtml(ip)}</span>`).join("")}</div>
      </div>`;
  }

  if (infra.subdomains?.length) {
    html += `
      <div class="infra-block">
        <h4>Subdomenlar (${infra.subdomains.length})</h4>
        <table class="infra-table">
          <thead><tr><th>Subdomen</th><th>IP manzillar</th><th>Holat</th></tr></thead>
          <tbody>
            ${infra.subdomains.map((s) => `
              <tr class="${s.risky ? "infra-risky" : ""}">
                <td>${escapeHtml(s.name)}</td>
                <td>${escapeHtml(s.ips.join(", "))}</td>
                <td>${s.risky ? '<span class="badge badge-yuqori">Xavfli</span>' : '<span class="badge badge-past">Normal</span>'}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }

  if (infra.ports?.length) {
    html += `
      <div class="infra-block">
        <h4>Ochiq portlar — ${escapeHtml(infra.host)} (${infra.ports.length})</h4>
        <table class="infra-table">
          <thead><tr><th>Port</th><th>Xizmat</th><th>Holat</th></tr></thead>
          <tbody>
            ${infra.ports.map((p) => `
              <tr class="${p.risky ? "infra-risky" : ""}">
                <td>${p.port}</td>
                <td>${escapeHtml(p.service)}</td>
                <td>${p.risky ? '<span class="badge badge-yuqori">Xavfli</span>' : '<span class="badge badge-ma\'lumot">Ochiq</span>'}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }

  const dns = infra.dns || {};
  const dnsRows = [];
  if (dns.a?.length) dnsRows.push(["A", dns.a.join(", ")]);
  if (dns.aaaa?.length) dnsRows.push(["AAAA", dns.aaaa.join(", ")]);
  if (dns.mx?.length) dnsRows.push(["MX", dns.mx.join(", ")]);
  if (dns.ns?.length) dnsRows.push(["NS", dns.ns.join(", ")]);
  if (dns.ptr?.length) dnsRows.push(["PTR", dns.ptr.join(", ")]);
  if (dns.spf) dnsRows.push(["SPF", "Mavjud"]);
  if (dns.dmarc) dnsRows.push(["DMARC", "Mavjud"]);
  if (dns.txt?.length) dnsRows.push(["TXT", dns.txt.slice(0, 3).join("; ") + (dns.txt.length > 3 ? "..." : "")]);

  if (dnsRows.length) {
    html += `
      <div class="infra-block">
        <h4>DNS yozuvlari</h4>
        <table class="infra-table">
          <thead><tr><th>Turi</th><th>Qiymat</th></tr></thead>
          <tbody>
            ${dnsRows.map(([t, v]) => `<tr><td>${t}</td><td>${escapeHtml(v)}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }

  if (dns.ports_by_ip) {
    for (const [ip, ports] of Object.entries(dns.ports_by_ip)) {
      if (ip === infra.host) continue;
      html += `
        <div class="infra-block">
          <h4>Ochiq portlar — ${escapeHtml(ip)} (${ports.length})</h4>
          <table class="infra-table">
            <thead><tr><th>Port</th><th>Xizmat</th><th>Holat</th></tr></thead>
            <tbody>
              ${ports.map((p) => `
                <tr class="${p.risky ? "infra-risky" : ""}">
                  <td>${p.port}</td>
                  <td>${escapeHtml(p.service)}</td>
                  <td>${p.risky ? '<span class="badge badge-yuqori">Xavfli</span>' : '<span class="badge badge-ma\'lumot">Ochiq</span>'}</td>
                </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
    }
  }

  content.innerHTML = html || '<p class="infra-empty">Tarmoq ma\'lumotlari topilmadi.</p>';
  section.classList.remove("hidden");
}

function getRiskClass(score) {
  if (score >= 80) return "risk-critical";
  if (score >= 60) return "risk-high";
  if (score >= 40) return "risk-medium";
  if (score >= 20) return "risk-low";
  return "risk-minimal";
}

function renderResults(data) {
  const riskCard = document.getElementById("riskCard");
  riskCard.className = `risk-card ${getRiskClass(data.risk_score)}`;

  document.getElementById("riskScore").textContent = data.risk_score;
  document.getElementById("riskLevel").textContent = data.risk_level;
  document.getElementById("domainInfo").textContent =
    `${data.target_type ? data.target_type.toUpperCase() + " | " : ""}${data.domain} → ${data.url}`;
  document.getElementById("scanTime").textContent =
    `Tekshiruv vaqti: ${(data.scan_duration_ms / 1000).toFixed(1)}s`;

  const summaryGrid = document.getElementById("summaryGrid");
  summaryGrid.innerHTML = SEVERITY_ORDER.map((sev) => {
    const count = data.summary[sev] || 0;
    return `
      <div class="summary-item sev-${sev}">
        <div class="summary-count">${count}</div>
        <div class="summary-label">${SEVERITY_LABELS[sev]}</div>
      </div>
    `;
  }).join("");

  renderInfrastructure(data.infrastructure || {});

  const findingsList = document.getElementById("findingsList");
  if (data.findings.length === 0) {
    findingsList.innerHTML =
      '<p style="color: var(--text-muted)">Zaiflik topilmadi.</p>';
  } else {
    findingsList.innerHTML = data.findings
      .map(
        (f) => `
      <div class="finding-card sev-${f.severity}">
        <div class="finding-header">
          <span class="finding-title">${escapeHtml(f.title)}</span>
          <span class="badge badge-${f.severity}">${SEVERITY_LABELS[f.severity] || f.severity}</span>
        </div>
        <p class="finding-desc">${escapeHtml(f.description)}</p>
        <div class="finding-meta">Kategoriya: ${escapeHtml(f.category)}</div>
        ${f.recommendation ? `<div class="finding-rec">${escapeHtml(f.recommendation)}</div>` : ""}
      </div>
    `
      )
      .join("");
  }

  resultsEl.classList.remove("hidden");
  pdfBtn.classList.remove("hidden");
}

pdfBtn.addEventListener("click", async () => {
  if (!lastScannedDomain) return;

  pdfBtn.disabled = true;
  pdfBtn.textContent = "PDF tayyorlanmoqda...";

  try {
    const res = await fetch("/api/scan/pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: lastScannedDomain }),
    });

    if (!res.ok) throw new Error("PDF yaratishda xatolik");

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `zaiflik-${lastScannedDomain}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove("hidden");
  } finally {
    pdfBtn.disabled = false;
    pdfBtn.textContent = "PDF hisobot yuklab olish";
  }
});

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

setLoading(false);
