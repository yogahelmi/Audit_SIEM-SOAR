#!/bin/bash
# CLO3 active response: quarantine a malicious file (PB-03 Malware).
# Target path = extra_args[0] (sent by Shuffle) or alert.syscheck.path.
# Prosedur aman: hanya file biasa di dalam /var/www/html, dipindah (bukan dihapus)
# ke /var/ossec/quarantine dengan permission 000 + metadata hash, lalu diverifikasi.
source /var/ossec/active-response/bin/clo3-lib.sh

FILE=${ARG1:-$(jq -r '.parameters.alert.syscheck.path // empty' <<<"$INPUT_JSON")}
ALLOWED_ROOT=/var/www/html
QDIR=/var/ossec/quarantine

[ "$COMMAND" = "delete" ] && exit 0   # quarantine is never auto-reverted

REAL=$(readlink -f -- "$FILE" 2>/dev/null)
if [ -z "$REAL" ] || [[ "$REAL" != "$ALLOWED_ROOT"/* ]]; then
  report quarantine-file skipped "${FILE:-none}" "path outside $ALLOWED_ROOT"; exit 0
fi
if [ ! -f "$REAL" ]; then
  if ls "$QDIR"/*"$(basename "$REAL")" >/dev/null 2>&1; then
    report quarantine-file success "$REAL" "already quarantined"
  else
    report quarantine-file failed "$REAL" "file not found"
  fi
  exit 0
fi

mkdir -p "$QDIR" && chmod 700 "$QDIR"
MD5=$(md5sum "$REAL" | awk '{print $1}')
SHA256=$(sha256sum "$REAL" | awk '{print $1}')
DEST="$QDIR/$(date -u +%Y%m%dT%H%M%SZ)_$(basename "$REAL")"
mv -f -- "$REAL" "$DEST" && chmod 000 "$DEST"
printf 'original=%s\nmd5=%s\nsha256=%s\nalert_id=%s\n' "$REAL" "$MD5" "$SHA256" "$ALERT_ID" > "$DEST.meta"

# --- Verify ---
if [ ! -e "$REAL" ] && [ -e "$DEST" ]; then
  report quarantine-file success "$REAL" "moved to $DEST md5=$MD5"
else
  report quarantine-file failed "$REAL" "file still present after move"
fi
