#!/usr/bin/env python3
"""Generate local demo credentials without printing or overwriting them."""
import os
from pathlib import Path
import secrets

path = Path(__file__).resolve().parents[1] / '.env'
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print('Existing .env retained.')
else:
    with os.fdopen(fd, 'w') as stream:
        for name in ('STEPDOWN_CLIENT_TOKEN', 'STEPDOWN_ADMIN_TOKEN', 'DEMO_UPSTREAM_TOKEN'):
            stream.write(f'{name}={secrets.token_urlsafe(48)}\n')
    print('Generated .env (mode 0600). No credential values printed.')
