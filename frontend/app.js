let currentFilter = 'ALL';

document.addEventListener('DOMContentLoaded', () => {
  fetchMetrics();
  fetchAlerts();
  fetchLogs();

  // Setup refresh button
  document.getElementById('refreshBtn').addEventListener('click', () => {
    fetchMetrics();
    fetchAlerts();
    fetchLogs();
  });

  // Setup filter buttons
  document.querySelectorAll('.filter-chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
      e.target.classList.add('active');
      currentFilter = e.target.getAttribute('data-filter');
      fetchAlerts();
    });
  });

  // Setup manual log injection
  document.getElementById('sendManualLogBtn').addEventListener('click', sendManualLog);
  document.getElementById('manualLogInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendManualLog();
  });

  // Periodic poll
  setInterval(() => {
    fetchMetrics();
    fetchLogs();
  }, 6000);
});

async function fetchMetrics() {
  try {
    const res = await fetch('/api/v1/alerts/metrics/summary');
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('metricTotalLogs').textContent = data.total_logs;
    document.getElementById('metricOpenAlerts').textContent = data.open_alerts;
    document.getElementById('metricCritical').textContent = data.critical_alerts;
    document.getElementById('metricHigh').textContent = data.high_alerts;
    document.getElementById('metricResolved').textContent = data.resolved_alerts;
  } catch (err) {
    console.error('Error fetching metrics:', err);
  }
}

async function fetchAlerts() {
  try {
    let url = '/api/v1/alerts';
    if (currentFilter === 'OPEN') {
      url += '?status=OPEN';
    }
    const res = await fetch(url);
    if (!res.ok) return;
    let alerts = await res.json();

    if (currentFilter === 'CRITICAL') {
      alerts = alerts.filter(a => a.severity === 'CRITICAL');
    } else if (currentFilter === 'HIGH') {
      alerts = alerts.filter(a => a.severity === 'HIGH');
    }

    renderAlerts(alerts);
  } catch (err) {
    console.error('Error fetching alerts:', err);
  }
}

function renderAlerts(alerts) {
  const container = document.getElementById('incidentsList');
  if (!alerts || alerts.length === 0) {
    container.innerHTML = `<div class="empty-state">No incidents matching filter [${currentFilter}]. Telemetry steady.</div>`;
    return;
  }

  container.innerHTML = alerts.map(a => `
    <div class="incident-card" id="card-${a.id}">
      <div class="card-top">
        <span class="id-badge">${a.id} • ${a.rule_id}</span>
        <span class="severity-pill sev-${a.severity}">${a.severity}</span>
      </div>
      <div class="card-title">${escapeHtml(a.rule_name)}</div>
      <div class="card-meta">
        <span class="mitre-tag">${escapeHtml(a.mitre_technique)}</span>
        <span>IP: <strong>${escapeHtml(a.source_ip)}</strong></span>
        <span>STATUS: <strong>${a.status}</strong></span>
      </div>
      <p class="card-desc">${escapeHtml(a.description)}</p>
      <div class="playbook-box">
        <span class="playbook-code">${escapeHtml(a.playbook_command)}</span>
      </div>
      <div class="card-actions">
        ${a.status !== 'INVESTIGATING' ? `
          <button class="btn-action" onclick="updateAlertStatus('${a.id}', 'INVESTIGATING')">Investigate</button>
        ` : ''}
        ${a.status !== 'RESOLVED' ? `
          <button class="btn-action btn-resolve" onclick="updateAlertStatus('${a.id}', 'RESOLVED')">Mitigate &amp; Resolve</button>
        ` : `
          <button class="btn-action" onclick="updateAlertStatus('${a.id}', 'OPEN')">Reopen Incident</button>
        `}
      </div>
    </div>
  `).join('');
}

async function updateAlertStatus(alertId, newStatus) {
  try {
    const res = await fetch(`/api/v1/alerts/${alertId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      fetchAlerts();
      fetchMetrics();
    }
  } catch (err) {
    console.error('Failed to update alert:', err);
  }
}

async function fetchLogs() {
  try {
    const res = await fetch('/api/v1/logs?limit=40');
    if (!res.ok) return;
    const logs = await res.json();
    const terminal = document.getElementById('logStream');

    if (!logs || logs.length === 0) {
      terminal.innerHTML = '<div class="empty-state">No telemetry ingested yet.</div>';
      return;
    }

    terminal.innerHTML = logs.map(l => `
      <div class="log-line">
        <span class="log-ts">${new Date(l.timestamp).toLocaleTimeString()}</span>
        <span class="log-src">[${escapeHtml(l.source)}]</span>
        <span class="log-ip">${escapeHtml(l.ip_address || '—')}</span>
        <span class="log-msg">${escapeHtml(l.raw_message)}</span>
      </div>
    `).join('');
  } catch (err) {
    console.error('Error fetching logs:', err);
  }
}

async function sendManualLog() {
  const input = document.getElementById('manualLogInput');
  const msg = input.value.trim();
  if (!msg) return;

  await postLog(msg, 'manual_operator.log');
  input.value = '';
}

async function simulateAttack(type) {
  const scenarios = {
    sqli: {
      msg: 'GET /api/v1/products?cat=electronics%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1 200',
      src: 'nginx_access.log'
    },
    traversal: {
      msg: 'GET /download?file=../../../../etc/passwd HTTP/1.1 403',
      src: 'nginx_access.log'
    },
    sudo: {
      msg: 'bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow',
      src: 'auth.log'
    },
    scanner: {
      msg: 'GET /test.php HTTP/1.1 404 "Mozilla/5.0" "sqlmap/1.7.2#dev"',
      src: 'waf.log'
    },
    benign: {
      msg: 'GET /dashboard/overview HTTP/1.1 200 4520 "Mozilla/5.0 Chrome/122.0.0.0"',
      src: 'nginx_access.log'
    }
  };

  const item = scenarios[type];
  if (!item) return;

  await postLog(item.msg, item.src);
}

async function postLog(message, source) {
  try {
    const res = await fetch('/api/v1/logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, source })
    });
    if (res.ok) {
      await fetchLogs();
      await fetchAlerts();
      await fetchMetrics();
    }
  } catch (err) {
    console.error('Failed to post log:', err);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
