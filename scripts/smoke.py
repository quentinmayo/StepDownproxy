#!/usr/bin/env python3
"""Exercise the real Docker/OPA stack; never print credential values."""
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

env = dict(line.split('=', 1) for line in (Path(__file__).resolve().parents[1] / '.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
base = 'http://127.0.0.1:' + env.get('STEPDOWN_PORT', '18080')
admin = 'http://127.0.0.1:' + env.get('STEPDOWN_ADMIN_PORT', '19090')
def request(url, token='', method='GET', body=None):
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    req = urllib.request.Request(url, headers=headers, method=method, data=None if body is None else json.dumps(body).encode())
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, response.read()

for attempt in range(60):
    try:
        if request(base + '/healthz')[0] == 200:
            break
    except (OSError, urllib.error.URLError):
        pass
    time.sleep(1)
else:
    raise SystemExit('Proxy did not become healthy.')

path = '/proxy/github/repos/example/project/issues'
token = env['STEPDOWN_CLIENT_TOKEN']
for attempt in range(60):
    if request(base + path, token)[0] == 200:
        break
    time.sleep(1)
else:
    raise SystemExit('OPA and upstream did not become ready.')
for label, url, auth, method, expected in [
    ('allowed read with injected token', base + path, token, 'GET', 200),
    ('write denied', base + path, token, 'DELETE', 403),
    ('other repository denied', base + path.replace('/project/', '/other/'), token, 'GET', 403),
    ('credential query denied', base + path + '?access_token=forbidden', token, 'GET', 400),
    ('unauthenticated denied', base + path, '', 'GET', 401),
    ('proxy token cannot administer', admin + '/api/overview', token, 'GET', 401),
    ('admin token cannot proxy', base + path, env['STEPDOWN_ADMIN_TOKEN'], 'GET', 401),
    ('management access', admin + '/api/overview', env['STEPDOWN_ADMIN_TOKEN'], 'GET', 200),
]:
    status, body = request(url, auth, method)
    if status != expected:
        raise SystemExit(f'FAIL: {label}: expected {expected}, got {status}')
    if any(value.encode() in body for name, value in env.items() if 'TOKEN' in name):
        raise SystemExit('FAIL: credential appeared in a response')
    if label.startswith('allowed') and json.loads(body).get('token_injected') is not True:
        raise SystemExit('FAIL: upstream did not verify injected token')
    print('PASS:', label)

status, body = request(admin + '/api/evaluate', env['STEPDOWN_ADMIN_TOKEN'], 'POST', {'principal':'demo-reader','service':'github','method':'DELETE','path':'/repos/example/project/issues','query':{},'headers':{},'body':None})
assert status == 200 and json.loads(body)['allow'] is False
print('PASS: management policy simulation')
