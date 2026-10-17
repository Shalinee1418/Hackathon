/**
 * AegisAgent - Main Application Controller
 * Handles tabs, chat pipeline execution, VSS math lab, and audit ledger.
 */

let visualizer;
let nodeTopology;
let currentVSSData = null;

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Visualizer and Node Topology
  visualizer = new VSSVisualizer('vssCanvas');
  nodeTopology = new NodeTopologyManager('nodesGridContainer');
  nodeTopology.fetchClusterStatus();

  // Setup Navigation Tabs
  setupNavigation();

  // Setup Chat Agent Handlers
  setupChatAgent();

  // Setup VSS Math Lab Handlers
  setupVSSLab();

  // Setup Audit Log Refresh
  setupAuditExplorer();

  // Initial VSS Demo Split on load
  runInitialVSSSplit();
});

/* ================= Navigation Tabs ================= */
function setupNavigation() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));

      tab.classList.add('active');
      const targetView = tab.getAttribute('data-target');
      const viewEl = document.getElementById(targetView);
      if (viewEl) viewEl.classList.add('active');

      if (targetView === 'viewMathLab') {
        setTimeout(() => visualizer.initCanvas(), 100);
      }
      if (targetView === 'viewNodes') {
        nodeTopology.fetchClusterStatus();
      }
      if (targetView === 'viewAudit') {
        fetchAuditLog();
      }
    });
  });
}

/* ================= Private AI Agent Chat ================= */
function setupChatAgent() {
  const btn = document.getElementById('btnDispatchPrompt');
  const promptInput = document.getElementById('txtAgentPrompt');
  if (!btn || !promptInput) return;

  btn.addEventListener('click', async () => {
    const prompt = promptInput.value.trim();
    if (!prompt) return;

    btn.disabled = true;
    btn.innerHTML = `<span class="pulse-led" style="background:#fff"></span> Orchestrating VSS Quorum...`;

    resetTimeline();

    try {
      const res = await fetch('/api/agent/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: prompt, client_tag: 'Client-Enclave-01' }),
      });

      const data = await res.json();
      if (data.status === 'SUCCESS') {
        renderAgentExecution(data);
      } else {
        alert('Execution Error: ' + (data.detail || 'Quorum verification failed'));
      }
    } catch (err) {
      console.error(err);
      alert('Communication failure with AegisAgent daemon.');
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<span>🔒</span> Client-Side Encrypt & Execute`;
      nodeTopology.fetchClusterStatus();
    }
  });

  // Prompt Templates
  window.loadTemplate = (type) => {
    if (type === 'finance') {
      promptInput.value = "Conduct private compliance audit on client portfolio alice@hedgefund.com with asset balance $4,850,000 USD and secret auth PIN 987654.";
    } else if (type === 'api') {
      promptInput.value = "Validate infrastructure health for microservices using master gateway credential sk-live-prod-token-998877665544332211.";
    } else if (type === 'medical') {
      promptInput.value = "Review confidential medical diagnosis for patient SSN 042-99-1234 regarding therapy regimen and insurance authorization.";
    }
  };
}

function resetTimeline() {
  for (let i = 1; i <= 6; i++) {
    const stepEl = document.getElementById(`step-${i}`);
    if (stepEl) {
      stepEl.classList.remove('active');
      const lat = stepEl.querySelector('.step-latency');
      if (lat) lat.innerText = 'Pending...';
    }
  }
  document.getElementById('txtUpstreamPrompt').innerText = 'Awaiting blind pipeline dispatch...';
  document.getElementById('txtUpstreamResponse').innerText = 'Awaiting upstream LLM response...';
  document.getElementById('txtClientResponse').innerText = 'Decrypting final payload in client perimeter...';
}

function renderAgentExecution(data) {
  // Animate Timeline Steps
  data.timeline.forEach((step, idx) => {
    setTimeout(() => {
      const stepEl = document.getElementById(`step-${step.step}`);
      if (stepEl) {
        stepEl.classList.add('active');
        const lat = stepEl.querySelector('.step-latency');
        if (lat) lat.innerText = `Latency: ${step.time_ms} ms | Status: ${step.status}`;
      }
    }, idx * 150);
  });

  // Update What Upstream LLM Sees (Notice: Zero Master Key & Only Shadow Tokens!)
  document.getElementById('txtUpstreamPrompt').innerText = data.sanitized_prompt;
  document.getElementById('txtUpstreamResponse').innerText = data.upstream_response;

  // Update Client Final Response
  document.getElementById('txtClientResponse').innerText = data.final_response;

  // Update Audit preview
  if (data.receipt) {
    document.getElementById('clientReceiptPreview').innerText = JSON.stringify(data.receipt, null, 2);
  }
}

/* ================= VSS Mathematical Lab ================= */
function setupVSSLab() {
  const btnSplit = document.getElementById('btnRunVSSSplit');
  if (!btnSplit) return;

  btnSplit.addEventListener('click', async () => {
    const secret = document.getElementById('vssSecretInput').value.trim() || 'sk-aegis-master-live-token-42';
    const threshold = parseInt(document.getElementById('vssThresholdInput').value, 10);
    const n = parseInt(document.getElementById('vssParticipantsInput').value, 10);
    const scheme = document.getElementById('vssSchemeInput').value;

    btnSplit.disabled = true;
    btnSplit.innerText = 'Calculating Commitments...';

    try {
      const res = await fetch('/api/vss/split', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, threshold, num_participants: n, scheme }),
      });
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        currentVSSData = data;
        renderVSSLabResults(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      btnSplit.disabled = false;
      btnSplit.innerText = '⚡ Compute VSS Commitments & Shares';
    }
  });

  // Tamper share in table
  window.tamperShare = (index) => {
    if (!currentVSSData) return;
    const share = currentVSSData.shares.find(s => s.index === index);
    if (share) {
      share.is_tampered = !share.is_tampered;
      if (share.is_tampered) {
        share.secret_share_hex = '0xDEADBEEF' + share.secret_share_hex.slice(10);
      }
      renderVSSLabResults(currentVSSData);
    }
  };

  // Reconstruct secret from shares in table
  const btnReconstruct = document.getElementById('btnVSSReconstruct');
  if (btnReconstruct) {
    btnReconstruct.addEventListener('click', async () => {
      if (!currentVSSData) return;
      try {
        const res = await fetch('/api/vss/reconstruct', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            shares: currentVSSData.shares,
            commitments_hex: currentVSSData.commitments_hex,
            threshold: currentVSSData.threshold,
            scheme: 'pedersen'
          }),
        });
        const data = await res.json();
        const resultBox = document.getElementById('reconstructResultBox');
        if (data.status === 'SUCCESS') {
          resultBox.innerHTML = `
            <span class="badge-valid">✅ Reconstructed Successfully</span><br>
            <strong>Recovered Secret:</strong> <span style="color:#fbbf24">${data.secret_str}</span><br>
            <span style="font-size:0.75rem; color:#94a3b8">Valid Shares Verified: ${data.valid_shares_count}/${currentVSSData.shares.length}</span>
          `;
        } else {
          resultBox.innerHTML = `
            <span class="badge-tampered">❌ Reconstruction Failed</span><br>
            <span style="color:#f43f5e">${data.detail || 'Quorum not reached'}</span>
          `;
        }
      } catch (err) {
        console.error(err);
      }
    });
  }
}

async function runInitialVSSSplit() {
  try {
    const res = await fetch('/api/vss/split', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: 'sk-aegis-master-live-token-42', threshold: 3, num_participants: 5, scheme: 'pedersen' }),
    });
    const data = await res.json();
    if (data.status === 'SUCCESS') {
      currentVSSData = data;
      renderVSSLabResults(data);
    }
  } catch (err) {
    console.error('Initial split error:', err);
  }
}

function renderVSSLabResults(data) {
  // Render Canvas Curve
  visualizer.renderCurve(data.curve_points, data.shares, data.threshold);

  // Render Commitments Preview
  const commBox = document.getElementById('commitmentsList');
  if (commBox) {
    commBox.innerHTML = data.commitments_hex.map((c, i) => `
      <div style="margin-bottom:0.4rem; padding:0.4rem; background:rgba(255,255,255,0.02); border-radius:4px;">
        <span style="color:var(--accent-cyan)">C_${i}</span>: ${c.slice(0, 24)}...
      </div>
    `).join('');
  }

  // Render Table
  const tbody = document.getElementById('vssTableBody');
  if (tbody) {
    tbody.innerHTML = '';
    data.shares.forEach(s => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>Node ${s.index}</strong></td>
        <td><code>${s.secret_share_hex.slice(0, 16)}...</code></td>
        <td><code>${(s.blinder_share_hex || 'N/A').slice(0, 16)}...</code></td>
        <td>
          <span class="${s.is_tampered ? 'badge-tampered' : 'badge-valid'}">
            ${s.is_tampered ? '❌ TAMPERED' : '✅ VERIFIED'}
          </span>
        </td>
        <td>
          <button class="chip-btn" onclick="tamperShare(${s.index})">
            ${s.is_tampered ? 'Reset' : 'Simulate Bit-Flip'}
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }
}

/* ================= Audit Log Explorer ================= */
async function fetchAuditLog() {
  const container = document.getElementById('auditLogContainer');
  if (!container) return;
  try {
    const res = await fetch('/api/agent/audit-log');
    const data = await res.json();
    if (data.status === 'SUCCESS') {
      document.getElementById('merkleRootDisplay').innerText = data.memory_vault.merkle_root;
      document.getElementById('totalRecordsDisplay').innerText = data.memory_vault.total_records;

      container.innerHTML = data.receipts.map(r => `
        <div class="step-card active" style="margin-bottom:0.75rem;">
          <div class="step-content">
            <div class="step-title" style="display:flex; justify-content:space-between;">
              <span>🧾 Receipt ID: ${r.receipt_id}</span>
              <span class="perimeter-tag tag-isolated">ZERO-LEAKAGE VERIFIED</span>
            </div>
            <div style="font-size:0.75rem; color:var(--text-dim); margin-top:0.25rem;">
              Prompt Hash: <code>${r.prompt_hash.slice(0, 24)}...</code><br>
              Valid Shares: ${r.valid_shares_verified} | Ephemeral Zeroization: ${r.ephemeral_zeroization_verified ? 'CONFIRMED' : 'FAIL'}<br>
              Linked Merkle Root: <code>${r.merkle_root.slice(0, 24)}...</code>
            </div>
          </div>
        </div>
      `).join('') || '<div style="color:var(--text-dim); padding:1rem;">No inferences dispatched yet. Submit a query in AI Agent Enclave to generate receipts.</div>';
    }
  } catch (err) {
    console.error('Audit fetch error:', err);
  }
}

function setupAuditExplorer() {
  const btnRefresh = document.getElementById('btnRefreshAudit');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', fetchAuditLog);
  }
}
