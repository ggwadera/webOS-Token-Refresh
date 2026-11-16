#!/bin/sh
set -eu
: "${AGE_RECIPIENT:?Set AGE_RECIPIENT to your age public key}"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p backups
chmod 0700 backups
plain="backups/keys-${stamp}.db"
encrypted="${plain}.age"
trap 'rm -f "$plain"' EXIT HUP INT TERM

# SQLite's online backup API produces a consistent snapshot while the app runs.
docker run --rm --network none --read-only \
  --user "$(id -u):$(id -g)" \
  -v webos-token-refresh-database:/data:ro \
  -v "$PWD/backups:/backup:rw" \
  --entrypoint python webos-token-refresh:local -c \
  'import os,sqlite3; os.umask(0o077); src=sqlite3.connect("file:/data/keys.db?mode=ro", uri=True); dst=sqlite3.connect("/backup/keys-'"$stamp"'.db"); src.backup(dst); dst.close(); src.close()'
age -r "$AGE_RECIPIENT" -o "$encrypted" "$plain"
rm -f "$plain"
trap - EXIT HUP INT TERM
printf 'Encrypted backup written to %s\n' "$encrypted"
