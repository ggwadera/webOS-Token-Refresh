"""Refresh stored developer tokens with bounded, non-disclosing requests."""
import logging
import os
import sqlite3
import time

import requests
from cryptography.fernet import Fernet

DB_FILE = os.getenv('DB_FILE', '/usr/src/app/db/keys.db')
INTERVAL = max(300, int(os.getenv('SCRIPT_INTERVAL', '86400')))
MAX_TOKENS = 1000
CONCURRENCY = 4
ENDPOINT = 'https://developer.lge.com/secure/ResetDevModeSession.dev'

def read_secret(name):
    path = os.getenv(name + '_FILE')
    value = open(path, encoding='ascii').read().strip() if path else os.getenv(name)
    if not value:
        raise RuntimeError(f'{name} is not configured')
    return value

cipher = Fernet(read_secret('ENCRYPTION_KEY').encode())
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
# HTTP libraries can include full URLs (and therefore query tokens) in diagnostics.
logging.getLogger('urllib3').disabled = True
logging.getLogger('requests').disabled = True

def refresh_one(encrypted):
    try:
        token = cipher.decrypt(encrypted).decode('ascii')
        # The LG API currently accepts the token only as a query parameter. Never
        # log request URLs or exception text because both can contain that token.
        response = requests.get(ENDPOINT, params={'sessionToken': token}, timeout=(5, 15),
                                allow_redirects=False)
        logging.info('LG refresh completed with HTTP %d', response.status_code)
        response.close()
    except (requests.RequestException, ValueError, UnicodeError):
        logging.warning('LG refresh failed (details suppressed)')
    except Exception:
        logging.warning('Token refresh failed (details suppressed)')

def refresh_cycle():
    started = time.monotonic()
    try:
        with sqlite3.connect(f'file:{DB_FILE}?mode=ro', uri=True, timeout=5) as conn:
            rows = conn.execute('SELECT encrypted_key FROM keys LIMIT ?', (MAX_TOKENS,)).fetchall()
        # A small fixed worker pool avoids process forking and unbounded fan-out.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            list(pool.map(refresh_one, (row[0] for row in rows)))
        logging.info('Refresh cycle processed %d token(s)', len(rows))
    except sqlite3.Error:
        logging.error('Refresh cycle could not read token database')
    return max(0, INTERVAL - (time.monotonic() - started))

if __name__ == '__main__':
    while True:
        time.sleep(refresh_cycle())
