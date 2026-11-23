# ============================================================================
# Shuffle node "verify"  (Shuffle Tools -> Execute python)
# VERIFY: pastikan mitigasi benar-benar berhasil di endpoint.
# Skrip active response menulis hasil cek (iptables -C / file pindah / passwd -S)
# ke /var/log/clo3-response.log -> Wazuh rule 100500 (sukses) / 100501 (gagal).
# Node ini mencari alert tersebut di Wazuh Indexer.
# Workflow variables: $indexer_url, $indexer_user, $indexer_pass
# ============================================================================
import json
import time
from datetime import datetime, timedelta, timezone

import requests
import urllib3

urllib3.disable_warnings()


def node(raw):
    data = json.loads(raw) if raw.strip().startswith("{") else {}
    msg = data.get("message")
    return msg if isinstance(msg, dict) else data


a = node(r'''$analyze''')
r = node(r'''$respond''')
out = {"verified": False, "status": "not_required"}

if r.get("executed"):
    since = (datetime.fromisoformat(r["requested_at"]) - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    query = {
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"terms": {"rule.id": ["100500", "100501"]}},
            {"match_phrase": {"data.clo3_response.target": a.get("target", "")}},
            {"range": {"timestamp": {"gte": since}}},
        ]}},
    }
    url = "$indexer_url".rstrip("/") + "/wazuh-alerts-*/_search"
    out["status"] = "timeout"
    for _ in range(15):                       # tunggu maks ~45 detik
        try:
            res = requests.post(url, json=query, auth=("$indexer_user", "$indexer_pass"),
                                verify=False, timeout=10).json()
            hits = res.get("hits", {}).get("hits", [])
        except Exception as exc:  # noqa: BLE001
            out["error"] = str(exc)
            hits = []
        if hits:
            src = hits[0]["_source"]
            cr = src.get("data", {}).get("clo3_response", {})
            out.update({
                "verified": src["rule"]["id"] == "100500",
                "status": cr.get("status", ""),
                "evidence": cr.get("detail", ""),
                "endpoint": src.get("agent", {}).get("name", ""),
                "evidence_alert_id": src.get("id", ""),
                "verified_at": datetime.now(timezone.utc).isoformat(),
            })
            break
        time.sleep(3)
elif r.get("status") == "error":
    out["status"] = "response_error"
    out["evidence"] = r.get("detail", "")

print(json.dumps(out))
