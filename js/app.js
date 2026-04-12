/**
 * ThreatScan — Cybersecurity Threat Classifier
 * Author: Tarunima Amisha
 * Course: CY 201 — Intro to Cybersecurity, SEMO 2024
 *
 * Classifies suspicious emails, URLs, log entries, and code snippets
 * using an LLM inference backend. Maps results to NIST CSF controls.
 */

const API_URL = 'https://api.anthropic.com/v1/messages';
const MODEL   = 'claude-sonnet-4-5';

// ─── Sample inputs for each tab ───────────────────────────────────────────────
const EXAMPLES = {
  email: [
    "URGENT: Your PayPal account has been limited. Verify immediately at http://paypa1-secure.tk/login or your account will be closed in 24 hours.",
    "Hi team, I've attached the Q4 budget summary. Please review before Thursday's meeting. Let me know if you have questions.",
    "Congratulations! You've been selected for a $5,000 Amazon gift card. Click here to claim: http://amaz0n-rewards.ru/claim?id=usr884"
  ],
  url: [
    "http://secure-paypa1.tk/login?redirect=banking&session=abc123&token=xyz",
    "https://semo.edu/student-portal/registration",
    "http://45.33.32.156/admin?cmd=exec&payload=;rm%20-rf%20/"
  ],
  log: [
    "2024-11-14 03:22:41 FAILED_LOGIN user=root src_ip=185.220.101.45 attempts=1243 duration=8min",
    "2024-11-14 09:05:12 INFO user=amisha.t action=login src_ip=10.0.1.22 status=success browser=Chrome",
    "2024-11-14 02:18:33 ALERT port_scan src=45.33.32.156 target=192.168.1.0/24 ports=22,23,80,443,3306,5432,8080"
  ],
  code: [
    "void process_input() {\n    char buf[64];\n    printf(\"Enter name: \");\n    gets(buf);\n    strcpy(output, buf);\n}",
    "String query = \"SELECT * FROM users WHERE id = '\" + userId + \"' AND pass='\" + password + \"'\";",
    "def calculate_average(numbers):\n    total = sum(numbers)\n    return total / len(numbers)"
  ]
};

// ─── State ────────────────────────────────────────────────────────────────────
let currentTab   = 'email';
let totalScans   = 0;
let totalThreats = 0;
let totalSafe    = 0;

// ─── Tab switching ────────────────────────────────────────────────────────────
function setTab(tab, el) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('on'));
  el.classList.add('on');
  document.getElementById('inputBox').value = '';
  renderExamples();
  resetOutput();
}

function renderExamples() {
  document.getElementById('exRow').innerHTML = EXAMPLES[currentTab]
    .map((_, i) => `<button class="ex-btn" onclick="loadEx(${i})">ex_0${i + 1}</button>`)
    .join('');
}

function loadEx(i) {
  document.getElementById('inputBox').value = EXAMPLES[currentTab][i];
}

function resetOutput() {
  document.getElementById('idleBox').style.display  = 'flex';
  document.getElementById('spinBox').style.display  = 'none';
  document.getElementById('resBox').style.display   = 'none';
}

// ─── Main scan function ───────────────────────────────────────────────────────
async function runScan() {
  const input = document.getElementById('inputBox').value.trim();
  if (!input) return;

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;

  document.getElementById('idleBox').style.display = 'none';
  document.getElementById('spinBox').style.display = 'flex';
  document.getElementById('resBox').style.display  = 'none';

  const systemPrompt = `You are a cybersecurity analyst. Classify this ${currentTab} input and respond ONLY with valid JSON, no markdown:
{
  "verdict": "MALICIOUS" or "SUSPICIOUS" or "SAFE" or "INFORMATIONAL",
  "confidence": <integer 0-100>,
  "threat_type": "<concise label e.g. Phishing, SQL Injection, Port Scan, Safe>",
  "severity": "Critical" or "High" or "Medium" or "Low" or "None",
  "nist_functions": ["<e.g. DE.AE-1>", "<e.g. RS.AN-1>"],
  "indicators": ["<specific indicator 1>", "<specific indicator 2>", "<specific indicator 3>"],
  "explanation": "<2-3 sentences explaining findings in plain English>",
  "recommendation": "<1 concrete action to take>"
}`;

  // send to classifier
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1000,
        system: systemPrompt,
        messages: [{ role: 'user', content: `Analyze this ${currentTab}:\n\n${input}` }]
      })
    });

    const data   = await response.json();
    const result = JSON.parse(data.content[0].text);

    renderResult(result);

    totalScans++;
    if (result.verdict === 'MALICIOUS' || result.verdict === 'SUSPICIOUS') {
      totalThreats++;
    } else {
      totalSafe++;
    }

    updateStats();
    // console.log('scan complete:', result.verdict);

  } catch (err) {
    showError();
    console.error('ThreatScan error:', err);
  }

  btn.disabled = false;
}

// ─── Render result ────────────────────────────────────────────────────────────
function renderResult(r) {
  document.getElementById('spinBox').style.display = 'none';

  const rb = document.getElementById('resBox');
  rb.style.display = 'flex';

  const cardClass = r.verdict === 'MALICIOUS' ? 'vc-danger'
                  : r.verdict === 'SUSPICIOUS' ? 'vc-warn'
                  : r.verdict === 'SAFE'        ? 'vc-safe'
                  : 'vc-info';

  const icon = r.verdict === 'MALICIOUS' ? '🚨'
             : r.verdict === 'SUSPICIOUS' ? '⚠️'
             : r.verdict === 'SAFE'        ? '✅'
             : 'ℹ️';

  const confColor = r.confidence > 74 ? 'var(--green)'
                  : r.confidence > 44 ? 'var(--orange)'
                  : 'var(--red)';

  const dotColors = {
    Critical: 'var(--red)',
    High:     'var(--red)',
    Medium:   'var(--orange)',
    Low:      'var(--cyan)',
    None:     'var(--green)'
  };

  const nistHTML = (r.nist_functions || [])
    .map(n => `<span class="nmap-tag">${n}</span>`)
    .join('');

  const indicatorsHTML = (r.indicators || [])
    .map(ind => `
      <div class="ind-row">
        <span class="ind-dot" style="background:${dotColors[r.severity] || 'var(--cyan)'}"></span>
        <span>${ind}</span>
      </div>`)
    .join('');

  rb.innerHTML = `
    <div class="verdict-card ${cardClass}">
      <span class="vc-icon">${icon}</span>
      <div>
        <div class="vc-label">${r.verdict}</div>
        <div class="vc-sub">${r.threat_type}&nbsp;&nbsp;·&nbsp;&nbsp;Severity: ${r.severity}</div>
      </div>
    </div>

    <div class="conf-card">
      <div class="conf-top">
        <span class="conf-lbl">Confidence Score</span>
        <span class="conf-pct">${r.confidence}%</span>
      </div>
      <div class="conf-track">
        <div class="conf-fill" style="width:${r.confidence}%; background:${confColor}"></div>
      </div>
    </div>

    <div class="explain-card">
      ${r.explanation}<br><br>
      <strong>Action:</strong> ${r.recommendation}
    </div>

    ${nistHTML ? `
    <div class="nist-map">
      <div class="nist-map-title">NIST CSF Mapping</div>
      <div class="nist-map-tags">${nistHTML}</div>
    </div>` : ''}

    <div class="inds-card">
      <div class="inds-title">// indicators detected</div>
      ${indicatorsHTML}
    </div>`;
}

function showError() {
  document.getElementById('spinBox').style.display = 'none';
  const rb = document.getElementById('resBox');
  rb.style.display = 'flex';
  rb.innerHTML = `
    <div class="verdict-card vc-warn">
      <span class="vc-icon">⚠️</span>
      <div>
        <div class="vc-label">CONNECTION ERROR</div>
        <div class="vc-sub">Could not reach analysis backend. Check console.</div>
      </div>
    </div>`;
}

function updateStats() {
  document.getElementById('cntScans').textContent   = totalScans;
  document.getElementById('cntThreats').textContent = totalThreats;
  document.getElementById('cntSafe').textContent    = totalSafe;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
renderExamples();
