const form = document.getElementById("scanForm");
const domainInput = document.getElementById("domainInput");
const scanBtn = document.getElementById("scanBtn");
const btnText = scanBtn.querySelector(".btn-text");
const btnLoader = scanBtn.querySelector(".btn-loader");
const resultsEl = document.getElementById("results");
const errorEl = document.getElementById("error");
const pdfBtn = document.getElementById("pdfBtn");

let lastScannedDomain = null;

const SEVERITY_ORDER = ["kritik", "yuqori", "o'rta", "past", "ma'lumot"];
const SEVERITY_LABELS = {
  kritik: "Kritik",
  yuqori: "Yuqori",
  "o'rta": "O'rta",
  past: "Past",
  "ma'lumot": "Ma'lumot",
};

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = domainInput.value.trim();
  if (!domain) return;

  setLoading(true);
  resultsEl.classList.add("hidden");
  errorEl.classList.add("hidden");

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Tekshiruvda xatolik yuz berdi");
    }

    const data = await res.json();
    lastScannedDomain = domain;
    renderResults(data);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove("hidden");
  } finally {
    setLoading(false);
  }
});

function setLoading(loading) {
  scanBtn.disabled = loading;
  btnText.classList.toggle("hidden", loading);
  btnLoader.classList.toggle("hidden", !loading);
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
  document.getElementById("domainInfo").textContent = `${data.domain} → ${data.url}`;
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
        ${f.recommendation ? `<div class="finding-rec">💡 ${escapeHtml(f.recommendation)}</div>` : ""}
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
