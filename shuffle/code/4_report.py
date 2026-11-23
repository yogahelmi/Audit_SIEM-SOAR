# ============================================================================
# Shuffle node "report"  (Shuffle Tools -> Execute python)
# REPORT: catat incident ke index `clo3-incidents` (Wazuh Indexer -> dashboard)
#         dan kirim notifikasi Telegram.
# Workflow variables: $indexer_url, $indexer_user, $indexer_pass,
#                     $telegram_token, $telegram_chat_id
# ============================================================================
import html
import json
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings()


def node(raw):
    data = json.loads(raw) if raw.strip().startswith("{") else {}
    msg = data.get("message")
    return msg if isinstance(msg, dict) else data


def parse_ts(value):
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    if len(value) > 5 and value[-5] in "+-" and value[-3] != ":":   # +0000 -> +00:00
        value = value[:-2] + ":" + value[-2:]
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


a = node(r'''$analyze''')
r = node(r'''$respond''')
v = node(r'''$verify''')
m = a.get("mapped", {})
now = datetime.now(timezone.utc)
alert_ts = parse_ts(m.get("timestamp"))

if r.get("executed"):
    outcome = "MITIGATED" if v.get("verified") else "MITIGATION_FAILED"
elif r.get("status") == "error":
    outcome = "MITIGATION_FAILED"
else:
    outcome = "INCIDENT_OPEN"          # incident + notifikasi, menunggu investigasi analis

incident = {
    "@timestamp": now.isoformat(),
    "incident_id": f"CLO3-{now.strftime('%Y%m%d%H%M%S')}-{m.get('rule_id', '')}",
    "kelompok": "101032300037 Yoga Helmi Ilham Saputra / 101032300151 Muhammad Hafidz Abdurrahman",
    "playbook": a.get("playbook"),
    "alert_id": m.get("alert_id"), "alert_timestamp": m.get("timestamp"),
    "rule_id": m.get("rule_id"), "rule_level": m.get("rule_level"),
    "description": m.get("description"),
    "src_ip": m.get("src_ip"), "dst_ip": m.get("dst_ip"),
    "agent_name": m.get("agent_name"), "agent_id": m.get("agent_id"),
    "risk": a.get("risk"), "decision": a.get("decision"), "reasons": a.get("reasons"),
    "action": a.get("action"), "target": a.get("target"),
    "response_status": r.get("status"), "verified": bool(v.get("verified")),
    "verify_evidence": v.get("evidence", ""), "outcome": outcome,
    "latency_seconds": round((now - alert_ts).total_seconds(), 2) if alert_ts else None,
}

report = {"incident": incident}

# --- 1. Simpan incident ke Wazuh Indexer ---
try:
    res = requests.post("$indexer_url".rstrip("/") + "/clo3-incidents/_doc",
                        json=incident, auth=("$indexer_user", "$indexer_pass"),
                        verify=False, timeout=10)
    report["indexed"] = res.status_code in (200, 201)
    report["index_result"] = res.json().get("result", res.text[:200])
except Exception as exc:  # noqa: BLE001
    report["indexed"] = False
    report["index_result"] = str(exc)

# --- 2. Notifikasi Telegram ---
icon = {"MITIGATED": "✅", "MITIGATION_FAILED": "❌", "INCIDENT_OPEN": "⚠️"}[outcome]
e = html.escape
text = (
    f"{icon} <b>[CLO3 {e(str(incident['playbook']))}] {e(outcome)}</b>\n"
    f"<b>Incident:</b> {e(incident['incident_id'])}\n"
    f"<b>Risk:</b> {e(str(incident['risk']))} | <b>Rule:</b> {e(str(incident['rule_id']))} (lvl {e(str(incident['rule_level']))})\n"
    f"<b>Event:</b> {e(str(incident['description']))}\n"
    f"<b>Agent:</b> {e(str(incident['agent_name']))} | <b>Src IP:</b> {e(str(incident['src_ip'] or '-'))}\n"
    f"<b>Decision:</b> {e(str(incident['decision']))} -> {e(str(incident['target'] or '-'))}\n"
    f"<b>Alasan:</b> {e('; '.join(incident['reasons'] or []))}\n"
    f"<b>Verify:</b> {e(str(v.get('status')))} {e(str(v.get('evidence', '')))}\n"
    f"<b>Latency:</b> {incident['latency_seconds']} s\n"
    f"<b>Waktu alert:</b> {e(str(incident['alert_timestamp']))}"
)
if a.get("syscheck_diff"):
    text += f"\n<b>Diff:</b>\n<pre>{e(a['syscheck_diff'])}</pre>"
try:
    tg = requests.post("https://api.telegram.org/bot$telegram_token/sendMessage",
                       json={"chat_id": "$telegram_chat_id", "text": text, "parse_mode": "HTML"},
                       timeout=15)
    report["telegram_sent"] = tg.json().get("ok", False)
except Exception as exc:  # noqa: BLE001
    report["telegram_sent"] = False
    report["telegram_error"] = str(exc)

print(json.dumps(report))
