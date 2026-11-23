#!/bin/bash
# CLO3 active response: block a source IP with iptables (PB-01 Brute force / Port scan).
# Target IP = extra_args[0] (sent by Shuffle) or alert.data.srcip / alert.data.src_ip.
# command "delete" removes the block. Result is verified with `iptables -C`.
source /var/ossec/active-response/bin/clo3-lib.sh

IP=${ARG1:-$(jq -r '.parameters.alert.data.srcip // .parameters.alert.data.src_ip // empty' <<<"$INPUT_JSON")}
CHAIN=CLO3-BLOCK
IPT=iptables
$IPT -L -n >/dev/null 2>&1 || IPT=iptables-legacy

# --- Validasi IP (prosedur aman) ---
if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  report block-ip skipped "${IP:-none}" "invalid IPv4 address"; exit 0
fi
GATEWAY=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')
OWN_IPS=$(hostname -I 2>/dev/null)
PROTECTED=" 127.0.0.1 $GATEWAY $OWN_IPS ${CLO3_PROTECTED_IPS:-} "
if [[ "$PROTECTED" == *" $IP "* ]]; then
  report block-ip skipped "$IP" "IP is protected (gateway/self/allowlist)"; exit 0
fi

$IPT -N "$CHAIN" 2>/dev/null
$IPT -C INPUT -j "$CHAIN" 2>/dev/null || $IPT -I INPUT 1 -j "$CHAIN"

if [ "$COMMAND" = "delete" ]; then
  while $IPT -D "$CHAIN" -s "$IP" -j DROP 2>/dev/null; do :; done
  if $IPT -C "$CHAIN" -s "$IP" -j DROP 2>/dev/null; then
    report unblock-ip failed "$IP" "rule still present"
  else
    report unblock-ip success "$IP" "iptables DROP removed"
  fi
  exit 0
fi

$IPT -C "$CHAIN" -s "$IP" -j DROP 2>/dev/null || $IPT -I "$CHAIN" 1 -s "$IP" -j DROP
# Putuskan koneksi yang sudah terbentuk dari IP tersebut (mis. sesi SSH).
command -v conntrack >/dev/null && conntrack -D -s "$IP" >/dev/null 2>&1

# --- Verify ---
if $IPT -C "$CHAIN" -s "$IP" -j DROP 2>/dev/null; then
  report block-ip success "$IP" "iptables DROP active in chain $CHAIN"
else
  report block-ip failed "$IP" "iptables rule not found after insert"
fi
