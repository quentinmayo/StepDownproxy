'use strict';
let credential = '';
const $ = id => document.getElementById(id);
function message(text, error = false) { $('message').textContent = text; $('message').className = error ? 'error' : 'success'; }
async function api(path, method = 'GET', body) {
  const response = await fetch(path, {method, headers: {'Authorization': 'Bearer ' + credential, 'Content-Type': 'application/json'}, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', redirect: 'error'});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
async function run(fn) { try { await fn(); } catch (error) { message(error.message, true); } }
async function refresh() {
  const data = await api('/api/overview');
  $('service-count').textContent = data.services.length;
  $('client-count').textContent = data.clients.length;
  $('backend').textContent = data.knox_enabled ? 'Knox connected' : 'Configured providers';
  $('asset-editor').value = JSON.stringify({services: data.services}, null, 2);
  $('services').replaceChildren(...data.services.map(service => {
    const card = document.createElement('article'); card.className = 'card';
    for (const [tag, text] of [['strong', service.id], ['p', service.url], ['small', service.credential.provider + ' · ' + service.header]]) {
      const element = document.createElement(tag); element.textContent = text; card.append(element);
    } return card;
  }));
  $('events').replaceChildren(...data.events.slice().reverse().map(event => {
    const row = document.createElement('tr');
    for (const text of [new Date(event.time).toLocaleTimeString(), event.principal || 'anonymous', event.service || '—', event.status, event.reason]) { const cell = document.createElement('td'); cell.textContent = text; row.append(cell); }
    return row;
  }));
  message('Connected. Configuration and activity loaded.');
}
$('connect').onclick = () => run(async () => { credential = $('token').value; $('token').value = ''; await refresh(); });
$('refresh').onclick = () => run(refresh);
$('lock').onclick = () => location.reload();
$('save-assets').onclick = () => run(async () => { await api('/api/assets', 'PUT', JSON.parse($('asset-editor').value)); await refresh(); message('Assets validated, persisted, and applied.'); });
$('evaluate').onclick = () => run(async () => { const result = await api('/api/evaluate', 'POST', JSON.parse($('policy-input').value)); $('decision').textContent = result.allow ? 'ALLOW' : 'DENY'; $('decision').className = result.allow ? 'success' : 'error'; });
