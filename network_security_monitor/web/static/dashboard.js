'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let alerts = JSON.parse($('initial-alerts').textContent);
  let refreshing = false;
  const label = value => String(value || 'Unknown').replaceAll('_', ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
  const text = (tag, value, className) => {
    const el = document.createElement(tag);
    el.textContent = value;
    if (className) el.className = className;
    return el;
  };
  const date = alert => {
    const value = alert.iso_time || alert.timestamp;
    if (value == null) return 'Unknown';
    // Text-log timestamps have no timezone; preserve their original representation.
    if (typeof value === 'string' && !value.includes('T')) return value;
    const parsed = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  };
  function inspect(alert) {
    const fields = $('detail-fields');
    fields.replaceChildren();
    for (const [key, value] of Object.entries({Severity: alert.severity, Detection: label(alert.threat_type), Source: alert.src_ip, Destination: alert.dst_ip, Port: alert.dst_port, 'Detected at': date(alert), Description: alert.description, 'Linked incidents': (alert.incident_ids || []).join(', '), Metadata: alert.metadata && JSON.stringify(alert.metadata, null, 2), Evidence: alert.raw})) {
      if (value === undefined || value === null || value === '') continue;
      fields.append(text('dt', key), text('dd', String(value)));
    }
    $('detail').showModal();
  }
  function render() {
    $('total').textContent = alerts.length;
    $('critical').textContent = alerts.filter(a => a.severity === 'CRITICAL').length;
    $('high').textContent = alerts.filter(a => a.severity === 'HIGH').length;
    $('sources').textContent = new Set(alerts.map(a => a.src_ip).filter(Boolean)).size;
    const threats = new Map();
    alerts.forEach(a => threats.set(label(a.threat_type), (threats.get(label(a.threat_type)) || 0) + 1));
    const breakdown = $('breakdown');
    breakdown.replaceChildren();
    if (!alerts.length) breakdown.append(text('p', 'Detection patterns will appear as alerts arrive.'));
    [...threats].sort((a, b) => b[1] - a[1]).slice(0, 4).forEach(([name, count]) => {
      const row = text('div', '', 'bar-row');
      const track = text('div', '', 'bar-track');
      const bar = text('div', '', 'bar');
      bar.style.width = `${count / alerts.length * 100}%`;
      track.append(bar);
      row.append(text('span', name), track, text('span', count));
      breakdown.append(row);
    });
    const query = $('search').value.trim().toLowerCase();
    const severity = $('severity').value;
    const filtered = alerts.filter(a => (!severity || a.severity === severity) && [a.src_ip, a.dst_ip, a.threat_type, label(a.threat_type), a.description, a.raw].some(v => String(v || '').toLowerCase().includes(query))).slice().reverse();
    $('result-count').textContent = `${filtered.length} of ${alerts.length} alerts`;
    const rows = $('alerts');
    rows.replaceChildren();
    filtered.forEach(alert => {
      const row = document.createElement('tr');
      const severityCell = document.createElement('td');
      const knownSeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(alert.severity) ? alert.severity : '';
      severityCell.append(text('span', alert.severity || 'UNKNOWN', `badge ${knownSeverity}`));
      row.append(severityCell, text('td', label(alert.threat_type)), text('td', alert.src_ip || 'Unknown'), text('td', date(alert)));
      const evidence = document.createElement('td');
      const button = text('button', 'Inspect →', 'inspect');
      button.type = 'button';
      button.setAttribute('aria-label', `Inspect ${label(alert.threat_type)} from ${alert.src_ip || 'unknown source'}`);
      button.addEventListener('click', () => inspect(alert));
      evidence.append(button);
      row.append(evidence);
      rows.append(row);
    });
    $('empty').hidden = filtered.length > 0;
    $('empty-copy').textContent = alerts.length ? 'Try another search or severity filter.' : 'Run a simulation to generate your first detections, then refresh this view.';
    $('start-command').hidden = alerts.length > 0;
  }
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    $('refresh').disabled = true;
    try {
      const response = await fetch('/api/alerts', {cache: 'no-store'});
      if (!response.ok) throw new Error('Unable to load alerts');
      const payload = await response.json();
      if (!Array.isArray(payload.alerts)) throw new Error('Invalid alerts response');
      alerts = payload.alerts;
      render();
      $('sync-status').textContent = `Updated at ${new Date().toLocaleTimeString()}`;
    } catch (_) {
      $('sync-status').textContent = 'Refresh failed. Showing previous data; retrying automatically.';
    } finally {
      refreshing = false;
      $('refresh').disabled = false;
    }
  }
  $('search').addEventListener('input', render);
  $('severity').addEventListener('change', render);
  $('refresh').addEventListener('click', refresh);
  $('close-detail').addEventListener('click', () => $('detail').close());
  setInterval(() => { if (!document.hidden) refresh(); }, 15000);
  render();
})();
