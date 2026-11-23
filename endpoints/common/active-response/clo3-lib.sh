#!/bin/bash
# Shared helpers for CLO3 active-response scripts.
# Wazuh execd passes one JSON line on stdin:
#   {"command":"add|delete","parameters":{"extra_args":[...],"alert":{...}}}
# Each script writes ONE JSON verification line to /var/log/clo3-response.log.
# The Wazuh agent ships that file (log_format json) -> rule 100500 / 100501.

RESPONSE_LOG=/var/log/clo3-response.log
AR_LOG=/var/ossec/logs/active-responses.log

read -r INPUT_JSON || true
COMMAND=$(jq -r '.command // "add"' <<<"$INPUT_JSON" 2>/dev/null)
ARG1=$(jq -r '.parameters.extra_args[0] // empty' <<<"$INPUT_JSON" 2>/dev/null)
ARG2=$(jq -r '.parameters.extra_args[1] // empty' <<<"$INPUT_JSON" 2>/dev/null)
ALERT_ID=$(jq -r '.parameters.alert.id // empty' <<<"$INPUT_JSON" 2>/dev/null)

# stdout skrip dibaca wazuh-execd; jangan kirim keluaran perintah (mis. iptables -C) ke sana.
exec >/dev/null 2>>"$AR_LOG"

report() {  # report <action> <status> <target> <detail>
  local line
  line=$(jq -nc --arg action "$1" --arg status "$2" --arg target "$3" --arg detail "$4" \
      --arg host "$(hostname)" --arg alert "$ALERT_ID" --arg cmd "$COMMAND" \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{clo3_response:{action:$action,status:$status,target:$target,detail:$detail,host:$host,alert_id:$alert,command:$cmd,time:$ts}}')
  echo "$line" >> "$RESPONSE_LOG"
  echo "$(date '+%Y/%m/%d %H:%M:%S') $(basename "$0"): $line" >> "$AR_LOG"
}
