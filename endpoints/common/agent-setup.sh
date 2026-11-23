#!/bin/bash
# Configure the Wazuh agent idempotently (aman dijalankan ulang saat container restart).
# Usage: agent-setup.sh <role>   role = web | sensor
set -e
ROLE=${1:?role required}
CONF=/var/ossec/etc/ossec.conf

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER:-wazuh.manager}</address>|" "$CONF"

# Hapus blok CLO3 lama, lalu tulis ulang (tidak ada duplikasi saat restart).
sed -i '/<!-- CLO3-BEGIN -->/,/<!-- CLO3-END -->/d' "$CONF"

{
  echo '<!-- CLO3-BEGIN -->'
  echo '<ossec_config>'
  cat <<EOF
  <labels>
    <label key="kelompok.nim">${GROUP_NIM:-101032300037,101032300151}</label>
    <label key="kelompok.nama">${GROUP_NAMES:-Yoga Helmi Ilham Saputra, Muhammad Hafidz Abdurrahman}</label>
    <label key="endpoint.role">${ROLE}</label>
  </labels>

  <!-- Bukti verifikasi active response (rule 100500/100501) -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/clo3-response.log</location>
  </localfile>
EOF

  if [ "$ROLE" = "web" ]; then
    # Hanya tambahkan auth.log jika belum dipantau konfigurasi default (hindari event ganda).
    if ! grep -q '<location>/var/log/auth.log</location>' "$CONF"; then
      printf '  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n'
    fi
    cat <<'EOF'
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <!-- FIM + deteksi malware (md5 dicocokkan dengan CDB list di manager) -->
  <syscheck>
    <directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>
  </syscheck>
EOF
  fi

  if [ "$ROLE" = "sensor" ]; then
    cat <<'EOF'
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
EOF
  fi

  echo '</ossec_config>'
  echo '<!-- CLO3-END -->'
} >> "$CONF"

touch /var/log/clo3-response.log
/var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || /var/ossec/bin/wazuh-control start
