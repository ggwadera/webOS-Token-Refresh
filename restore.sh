#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo "Usage: AGE_IDENTITY=/path/to/age-key.txt ./restore.sh backups/file.db.age" >&2
  exit 2
fi
: "${AGE_IDENTITY:?Set AGE_IDENTITY to the age private-key file}"
archive=$1
mkdir -p backups
chmod 0700 backups
plain="backups/restore-$$.db"
trap 'rm -f "$plain"; docker compose start app worker >/dev/null 2>&1 || true' EXIT HUP INT TERM
age -d -i "$AGE_IDENTITY" -o "$plain" "$archive"
docker compose stop app worker
docker run --rm --network none --read-only \
  -v webos-token-refresh-database:/data:rw \
  -v "$PWD/backups:/restore:ro" \
  --user 0:0 --entrypoint python webos-token-refresh:local -c \
  'import os,shutil,sqlite3; p="/restore/restore-'"$$"'.db"; c=sqlite3.connect(p); assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"; c.close(); [os.remove(x) for x in ("/data/keys.db-wal","/data/keys.db-shm") if os.path.exists(x)]; shutil.copyfile(p,"/data/keys.db"); os.chown("/data/keys.db",10001,10001); os.chmod("/data/keys.db",0o600)'
docker compose start app worker
trap - EXIT HUP INT TERM
rm -f "$plain"
printf '%s\n' 'Restore finished. Check docker compose ps and logs before using the app.'
