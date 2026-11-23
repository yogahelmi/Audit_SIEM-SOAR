#!/bin/bash
set -e
rm -f /var/run/suricata.pid /run/nginx.pid
mkdir -p /var/log/suricata
touch /var/log/suricata/eve.json

/usr/local/bin/agent-setup.sh sensor

# -S  : muat HANYA rule lab (local.rules), deterministik dan tanpa unduh ruleset.
# -k none : abaikan checksum (offload pada veth Docker membuat checksum tampak salah).
# stats.enabled=no : event "stats" punya ratusan field -> "Too many fields for JSON decoder" di Wazuh.
suricata -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules \
         -i eth0 -k none -l /var/log/suricata --set stats.enabled=no -D

nginx
exec tail -F /var/log/suricata/eve.json
