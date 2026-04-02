/* ═══════════════════════════════════════════════
   Network Security Monitor – Dashboard JS
   Socket.IO + Chart.js integration
   ═══════════════════════════════════════════════ */

'use strict';

// ── Socket.IO ──────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect', () => console.log('[NSM] Socket connected:', socket.id));
socket.on('disconnect', () => console.log('[NSM] Socket disconnected'));

socket.on('stats_update', (stats) => {
  updateStatCards(stats);
  pushTrafficChart(stats);
});

socket.on('new_alert', (alert) => {
  prependAlertRow(alert);
  incrementAlertBadge();
  showToast(alert);
});

// ── Chart.js setup ─────────────────────────────
const MAX_CHART_POINTS = 30;

const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      {
        label: 'Packets/sec',
        data: [],
        borderColor: '#4f8ef7',
        backgroundColor: 'rgba(79,142,247,0.1)',
        borderWidth: 2,
        pointRadius: 2,
        tension: 0.4,
        fill: true,
        yAxisID: 'y',
      },
      {
        label: 'Bytes/sec',
        data: [],
        borderColor: '#22d3ee',
        backgroundColor: 'rgba(34,211,238,0.08)',
        borderWidth: 2,
        pointRadius: 2,
        tension: 0.4,
        fill: true,
        yAxisID: 'y1',
      },
    ],
  },
  options: {
    responsive: true,
    animation: { duration: 300 },
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: {
        ticks: { color: '#9090b0', maxTicksLimit: 8, font: { size: 10 } },
        grid: { color: 'rgba(255,255,255,0.05)' },
      },
      y: {
        position: 'left',
        ticks: { color: '#4f8ef7', font: { size: 10 } },
        grid: { color: 'rgba(255,255,255,0.05)' },
        title: { display: true, text: 'Pkts/s', color: '#4f8ef7', font: { size: 10 } },
      },
      y1: {
        position: 'right',
        ticks: { color: '#22d3ee', font: { size: 10 } },
        grid: { drawOnChartArea: false },
        title: { display: true, text: 'Bytes/s', color: '#22d3ee', font: { size: 10 } },
      },
    },
    plugins: {
      legend: { labels: { color: '#e8e8f0', font: { size: 11 } } },
    },
  },
});

const protocolCtx = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(protocolCtx, {
  type: 'doughnut',
  data: {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: ['#4f8ef7', '#22d3ee', '#f59e0b', '#ef4444', '#22c55e', '#a78bfa'],
      borderWidth: 2,
      borderColor: '#1a1a35',
    }],
  },
  options: {
    responsive: true,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#e8e8f0', font: { size: 11 }, padding: 10 },
      },
    },
    cutout: '62%',
  },
});

// ── Stat Card updater ──────────────────────────
function updateStatCards(stats) {
  setText('card-pps', formatNumber(stats.packets_per_second));
  updateProtocolChart(stats.protocol_counts || {});
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function formatNumber(n) {
  if (n === undefined || n === null) return '0';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return parseFloat(n).toFixed(n < 10 ? 1 : 0);
}

// ── Traffic chart push ─────────────────────────
function pushTrafficChart(stats) {
  const now = new Date().toLocaleTimeString('en-US', { hour12: false });
  const chart = trafficChart;
  chart.data.labels.push(now);
  chart.data.datasets[0].data.push(stats.packets_per_second || 0);
  chart.data.datasets[1].data.push(stats.bytes_per_second || 0);
  if (chart.data.labels.length > MAX_CHART_POINTS) {
    chart.data.labels.shift();
    chart.data.datasets[0].data.shift();
    chart.data.datasets[1].data.shift();
  }
  chart.update('none');
}

// ── Protocol doughnut update ───────────────────
function updateProtocolChart(counts) {
  const labels = Object.keys(counts);
  const values = Object.values(counts);
  protocolChart.data.labels = labels;
  protocolChart.data.datasets[0].data = values;
  protocolChart.update('none');
}

// ── Alert table helpers ────────────────────────
let alertCount = 0;

function prependAlertRow(alert) {
  const tbody = document.getElementById('alerts-tbody');
  const noRow = document.getElementById('no-alerts-row');
  if (noRow) noRow.remove();

  const tr = document.createElement('tr');
  tr.id = `alert-${alert.id}`;
  tr.classList.add('row-new');
  if (alert.acknowledged) tr.classList.add('row-ack');

  tr.innerHTML = `
    <td class="text-nowrap">${formatTime(alert.timestamp)}</td>
    <td><code class="text-info">${escHtml(alert.alert_type)}</code></td>
    <td><span class="badge-severity badge-${(alert.severity || '').toLowerCase()}">${escHtml(alert.severity)}</span></td>
    <td class="text-nowrap font-monospace">${escHtml(alert.source_ip || '—')}</td>
    <td class="text-nowrap font-monospace">${escHtml(alert.destination_ip || '—')}</td>
    <td class="text-wrap" style="max-width:320px">${escHtml(alert.description || '')}</td>
    <td>
      <button class="btn-ack" id="ack-btn-${alert.id}"
        onclick="acknowledgeAlert(${alert.id})"
        ${alert.acknowledged ? 'disabled' : ''}>
        ${alert.acknowledged ? 'Acked' : 'Ack'}
      </button>
    </td>`;
  tbody.insertBefore(tr, tbody.firstChild);
  alertCount++;
  setText('card-alerts', alertCount);
}

function incrementAlertBadge() {
  const badge = document.getElementById('alerts-badge');
  if (badge) badge.textContent = parseInt(badge.textContent || 0) + 1;
}

function formatTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleTimeString();
  } catch { return iso; }
}

function escHtml(s) {
  if (!s && s !== 0) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Monitor controls ───────────────────────────
async function startMonitor() {
  try {
    const res = await fetch('/api/v1/monitor/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const data = await res.json();
    if (data.success) {
      setMonitorRunning(true);
    } else {
      alert('Error: ' + (data.error || 'Unknown'));
    }
  } catch (e) {
    console.error('startMonitor failed', e);
  }
}

async function stopMonitor() {
  try {
    const res = await fetch('/api/v1/monitor/stop', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      setMonitorRunning(false);
    } else {
      alert('Error: ' + (data.error || 'Unknown'));
    }
  } catch (e) {
    console.error('stopMonitor failed', e);
  }
}

function setMonitorRunning(running) {
  const indicator = document.getElementById('status-indicator');
  const statusText = document.getElementById('status-text');
  const btnStart = document.getElementById('btn-start');
  const btnStop = document.getElementById('btn-stop');

  if (running) {
    indicator.className = 'status-badge status-running';
    statusText.textContent = 'Running';
    btnStart.classList.add('d-none');
    btnStop.classList.remove('d-none');
  } else {
    indicator.className = 'status-badge status-stopped';
    statusText.textContent = 'Stopped';
    btnStart.classList.remove('d-none');
    btnStop.classList.add('d-none');
    document.getElementById('uptime-display').textContent = '';
  }
}

// ── Alert actions ──────────────────────────────
async function acknowledgeAlert(id) {
  try {
    const res = await fetch(`/api/v1/alerts/${id}/acknowledge`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      const row = document.getElementById(`alert-${id}`);
      if (row) row.classList.add('row-ack');
      const btn = document.getElementById(`ack-btn-${id}`);
      if (btn) { btn.textContent = 'Acked'; btn.disabled = true; }
    }
  } catch (e) {
    console.error('acknowledgeAlert failed', e);
  }
}

async function clearAllAlerts() {
  if (!confirm('Clear all alerts?')) return;
  try {
    const res = await fetch('/api/v1/alerts', { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      document.getElementById('alerts-tbody').innerHTML =
        '<tr id="no-alerts-row"><td colspan="7" class="text-center text-secondary fst-italic py-4">No alerts yet.</td></tr>';
      alertCount = 0;
      setText('card-alerts', 0);
      document.getElementById('alerts-badge').textContent = '0';
    }
  } catch (e) {
    console.error('clearAllAlerts failed', e);
  }
}

// ── Connections ────────────────────────────────
async function loadConnections() {
  try {
    const res = await fetch('/api/v1/connections');
    const data = await res.json();
    if (!data.success) return;
    const connections = data.data || [];
    setText('card-connections', connections.length);
    document.getElementById('connections-badge').textContent = connections.length;
    const tbody = document.getElementById('connections-tbody');
    if (!connections.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-secondary fst-italic py-4">No connections tracked.</td></tr>';
      return;
    }
    tbody.innerHTML = connections.map(c => `
      <tr>
        <td class="font-monospace">${escHtml(c.src_ip || '—')}</td>
        <td class="font-monospace">${escHtml(c.dst_ip || '—')}</td>
        <td>${c.src_port || '—'}</td>
        <td>${c.dst_port || '—'}</td>
        <td>${escHtml(c.protocol || '—')}</td>
        <td>${escHtml(c.state || '—')}</td>
      </tr>`).join('');
  } catch (e) {
    console.error('loadConnections failed', e);
  }
}

// ── Threat summary ─────────────────────────────
async function loadThreatSummary() {
  try {
    const res = await fetch('/api/v1/threats/summary');
    const data = await res.json();
    if (!data.success) return;
    const counts = data.data || {};
    const container = document.getElementById('threat-summary-row');
    const entries = Object.entries(counts);
    if (!entries.length) {
      container.innerHTML = '<div class="col text-secondary small fst-italic">No threats detected yet.</div>';
      setText('card-threats', 0);
      return;
    }
    const total = entries.reduce((s, [, v]) => s + v, 0);
    setText('card-threats', total);
    container.innerHTML = entries.map(([type, count]) => `
      <div class="col-auto">
        <div class="threat-chip">
          <i class="fa-solid fa-skull-crossbones text-danger"></i>
          <span>${escHtml(type.replace(/_/g, ' '))}</span>
          <span class="threat-count">${count}</span>
        </div>
      </div>`).join('');
  } catch (e) {
    console.error('loadThreatSummary failed', e);
  }
}

// ── Load initial data ──────────────────────────
async function loadInitialData() {
  // Status
  try {
    const res = await fetch('/api/v1/status');
    const data = await res.json();
    if (data.success) {
      setMonitorRunning(data.data.is_running);
      if (data.data.uptime !== null && data.data.uptime !== undefined) {
        document.getElementById('uptime-display').textContent = `Uptime: ${data.data.uptime}s`;
      }
    }
  } catch (e) {
    console.error('loadStatus failed', e);
  }

  // Alerts
  try {
    const res = await fetch('/api/v1/alerts?limit=50');
    const data = await res.json();
    if (data.success && data.data.length) {
      data.data.forEach(a => prependAlertRow(a));
      // Fix count after bulk load
      alertCount = data.data.length;
      setText('card-alerts', alertCount);
      document.getElementById('alerts-badge').textContent = alertCount;
    }
  } catch (e) {
    console.error('loadAlerts failed', e);
  }

  // Stats
  try {
    const res = await fetch('/api/v1/stats');
    const data = await res.json();
    if (data.success) updateStatCards(data.data);
  } catch (e) {
    console.error('loadStats failed', e);
  }

  await loadConnections();
  await loadThreatSummary();
}

// ── Toast notification ─────────────────────────
function showToast(alert) {
  const container = document.getElementById('toast-container');
  const id = `toast-${Date.now()}`;
  const sevClass = (alert.severity || 'low').toLowerCase();
  const html = `
    <div id="${id}" class="toast nsm-toast show" role="alert" aria-live="assertive" data-bs-delay="5000">
      <div class="toast-header">
        <span class="badge-severity badge-${sevClass} me-2">${escHtml(alert.severity)}</span>
        <strong class="me-auto">${escHtml(alert.alert_type)}</strong>
        <small>${formatTime(alert.timestamp)}</small>
        <button type="button" class="btn-close btn-close-white ms-2" data-bs-dismiss="toast"></button>
      </div>
      <div class="toast-body small">${escHtml(alert.description || '')}</div>
    </div>`;
  container.insertAdjacentHTML('beforeend', html);
  const el = document.getElementById(id);
  const toast = new bootstrap.Toast(el, { delay: 5000 });
  toast.show();
  el.addEventListener('hidden.bs.toast', () => el.remove());
}

// ── Uptime ticker ──────────────────────────────
let uptimeSeconds = 0;
setInterval(() => {
  const indicator = document.getElementById('status-indicator');
  if (indicator && indicator.classList.contains('status-running')) {
    uptimeSeconds++;
    document.getElementById('uptime-display').textContent = `Uptime: ${uptimeSeconds}s`;
  }
}, 1000);

// ── Auto-refresh connections every 5 s ─────────
setInterval(loadConnections, 5000);
setInterval(loadThreatSummary, 10000);

// ── Boot ───────────────────────────────────────
document.addEventListener('DOMContentLoaded', loadInitialData);
