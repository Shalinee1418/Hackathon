/**
 * AegisAgent - Custodian Network Manager
 * Renders node enclaves, tracks status, and handles live Byzantine tamper simulations.
 */

class NodeTopologyManager {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.nodes = [];
    this.threshold = 3;
  }

  async fetchClusterStatus() {
    try {
      const res = await fetch('/api/agent/custodians');
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        this.nodes = data.cluster.nodes;
        this.threshold = data.cluster.threshold;
        this.render();
        this.updateHeaderBadge();
      }
    } catch (err) {
      console.error('Failed to load custodian status:', err);
    }
  }

  updateHeaderBadge() {
    const badge = document.getElementById('quorumHeaderBadge');
    if (!badge) return;
    const activeCount = this.nodes.filter(n => n.status === 'ACTIVE' && !n.tamper_flag).length;
    badge.innerHTML = `
      <span class="pulse-led" style="${activeCount < this.threshold ? 'background:#f43f5e;box-shadow:0 0 10px #f43f5e;' : ''}"></span>
      VSS QUORUM: ${activeCount}/${this.nodes.length} ONLINE (Req: ${this.threshold})
    `;
  }

  async toggleTamper(nodeId, shouldTamper) {
    const endpoint = shouldTamper ? '/api/agent/custodian/tamper' : '/api/agent/custodian/restore';
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: nodeId }),
      });
      const data = await res.json();
      if (data.status === 'SUCCESS') {
        await this.fetchClusterStatus();
      }
    } catch (err) {
      console.error('Error toggling node tamper state:', err);
    }
  }

  render() {
    if (!this.container) return;
    this.container.innerHTML = '';

    this.nodes.forEach(node => {
      const isBad = node.status === 'COMPROMISED' || node.tamper_flag;
      const card = document.createElement('div');
      card.className = `node-card ${isBad ? 'compromised' : ''}`;

      card.innerHTML = `
        <div class="node-top">
          <div>
            <div class="node-title">${node.name}</div>
            <div class="node-region">${node.region}</div>
          </div>
          <span class="perimeter-tag ${isBad ? 'tag-public' : 'tag-private'}">
            ${isBad ? 'COMPROMISED' : 'ACTIVE'}
          </span>
        </div>

        <div>
          <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:0.25rem;">Custodied Share Fragment:</div>
          <div class="node-share-box">${node.share_preview || 'No share allocated'}</div>
        </div>

        <div style="font-size:0.72rem; color:var(--text-dim); display:flex; justify-content:space-between;">
          <span>Requests: ${node.requests_served}</span>
          <span>Status: ${isBad ? 'Tampered Share' : 'Verified OK'}</span>
        </div>

        <button class="${isBad ? 'btn-restore' : 'btn-tamper'}" onclick="nodeTopology.toggleTamper(${node.node_id}, ${!isBad})">
          ${isBad ? '🛡️ Restore Honest State' : '⚠️ Inject Byzantine Fault'}
        </button>
      `;

      this.container.appendChild(card);
    });
  }
}
