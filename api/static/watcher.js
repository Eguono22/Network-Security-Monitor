'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let snapshot = JSON.parse($('watcher-data').textContent);
  let busy = false;
  const node = (tag, value, className) => {
    const element = document.createElement(tag);
    element.textContent = value;
    if (className) element.className = className;
    return element;
  };
  const deviceLink = ip => {
    const link = node('a', ip);
    link.href = `/devices/${encodeURIComponent(ip)}`;
    return link;
  };
  function render() {
    $('watcher-alerts').textContent = snapshot.recent_alerts;
    $('watcher-sources').textContent = snapshot.source_count;
    $('watcher-violations').textContent = snapshot.topology.violations.length;
    $('watcher-actions').textContent = snapshot.recent_soc_actions;
    const sourceRows = $('watcher-source-rows');
    sourceRows.replaceChildren();
    snapshot.sources.forEach(source => {
      const row = document.createElement('tr');
      const address = document.createElement('td');
      address.append(deviceLink(source.ip));
      const context = document.createElement('td');
      const link = deviceLink(source.ip);
      link.textContent = 'Inspect asset →';
      context.append(link);
      row.append(address, node('td', source.alert_count), node('td', `${source.critical_count} / ${source.high_count}`), node('td', source.threat_types.map(t => t.replaceAll('_', ' ')).join(', '), 'wrap-cell'), context);
      sourceRows.append(row);
    });
    $('watcher-source-empty').hidden = snapshot.sources.length > 0;
    const zones = $('watcher-zones');
    zones.replaceChildren();
    snapshot.topology.zones.forEach(zone => {
      const card = node('article', '', 'zone-card');
      card.append(node('h3', zone.label), node('p', `${zone.asset_count} source assets`), node('small', zone.cidrs.join(', ') || 'Inventory zone'), node('p', zone.description));
      zones.append(card);
    });
    if (!snapshot.topology.zones.length) zones.append(node('p', 'No zones defined. Configure NSM_TOPOLOGY_FILE with named zones and CIDR ranges.'));
    const filter = $('path-filter').value;
    const paths = snapshot.topology.observed_paths.filter(path => !filter || (filter === 'review' ? path.status !== 'allowed' : path.status === 'allowed'));
    $('watcher-path-count').textContent = `${paths.length} of ${snapshot.topology.observed_paths.length} paths`;
    const rows = $('watcher-path-rows');
    rows.replaceChildren();
    paths.forEach(path => {
      const row = document.createElement('tr');
      const status = document.createElement('td');
      const labels = {allowed: 'Allowed', blocked: 'Disallowed by policy', unknown: 'No allow policy'};
      const classes = {allowed: 'LOW', blocked: 'CRITICAL', unknown: 'HIGH'};
      status.append(node('span', labels[path.status] || 'Unknown', `badge ${classes[path.status] || ''}`));
      const sources = document.createElement('td');
      path.sample_src_ips.forEach((ip, index) => {
        if (index) sources.append(document.createTextNode(', '));
        sources.append(deviceLink(ip));
      });
      row.append(node('td', `${path.src_zone} → ${path.dst_zone}`), status, node('td', path.policy_name || 'Not configured'), node('td', path.observation_count), sources);
      rows.append(row);
    });
    $('watcher-path-empty').hidden = paths.length > 0;
  }
  async function refresh() {
    if (busy) return;
    busy = true;
    $('watcher-refresh').disabled = true;
    try {
      const response = await fetch('/api/network-watcher', {cache: 'no-store'});
      if (!response.ok) throw new Error('Refresh failed');
      const data = await response.json();
      if (!Array.isArray(data.sources) || !Array.isArray(data.topology?.observed_paths)) throw new Error('Invalid data');
      snapshot = data;
      render();
      $('watcher-status').textContent = `Updated at ${new Date().toLocaleTimeString()}`;
    } catch (_) {
      $('watcher-status').textContent = 'Refresh failed. Showing previous data; retrying automatically.';
    } finally {
      busy = false;
      $('watcher-refresh').disabled = false;
    }
  }
  $('path-filter').addEventListener('change', render);
  $('watcher-refresh').addEventListener('click', refresh);
  setInterval(() => { if (!document.hidden) refresh(); }, 15000);
  render();
})();
