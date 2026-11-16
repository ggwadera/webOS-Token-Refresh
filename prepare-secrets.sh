#!/bin/sh
set -eu
umask 077
mkdir -p secrets
python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())' > secrets/encryption_key
openssl rand -hex 32 > secrets/flask_secret
chmod 0400 secrets/encryption_key secrets/flask_secret
printf '%s\n' 'Generated two random secrets. Next, set their owner to container UID 10001:' \
  '  sudo chown 10001:10001 secrets/encryption_key secrets/flask_secret'
