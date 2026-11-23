# ============================================================================
# Shuffle node "respond"  (Shuffle Tools -> Execute python)
# RESPOND: jalankan active response di agent lewat Wazuh API (PUT /active-response).
# Workflow variables: $wazuh_api, $wazuh_user, $wazuh_pass
# ============================================================================
import json
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings()


def node(raw):
    data = json.loads(raw) if raw.strip().startswith("{") else {}
    msg = data.get("message")
    return msg if isinstance(msg, dict) else data


a = node(r'''$analyze''')
result = {"executed": False, "requested_at": datetime.now(timezone.utc).isoformat()}

if not a.get("should_respond"):
    result["status"] = "skipped"
    result["detail"] = f"decision={a.get('decision')} -> tidak ada aksi mitigasi"
else:
    api = "$wazuh_api".rstrip("/")
    agent_id = a["mapped"].get("agent_id", "")
    try:
        auth = requests.post(f"{api}/security/user/authenticate",
                             auth=("$wazuh_user", "$wazuh_pass"), verify=False, timeout=15)
        auth.raise_for_status()
        token = auth.json()["data"]["token"]
        body = {
            "command": a["action"],            # "!script" = jalankan skrip di active-response/bin
            "arguments": [a["target"]],         # extra_args[0] untuk skrip CLO3
            "alert": {"id": a["mapped"].get("alert_id", ""),
                      "data": {"srcip": a["mapped"].get("src_ip", ""),
                               "srcuser": a["mapped"].get("src_user", "")},
                      "syscheck": {"path": a["mapped"].get("file_path", "")}},
        }
        r = requests.put(f"{api}/active-response", params={"agents_list": agent_id},
                         headers={"Authorization": f"Bearer {token}"},
                         json=body, verify=False, timeout=20)
        resp = r.json()
        affected = resp.get("data", {}).get("total_affected_items", 0)
        result.update({
            "executed": affected > 0,
            "status": "sent" if affected > 0 else "error",
            "http_status": r.status_code,
            "agent_id": agent_id,
            "command": a["action"],
            "target": a["target"],
            "detail": resp.get("message", ""),
            "failed_items": resp.get("data", {}).get("failed_items", []),
        })
    except Exception as exc:  # noqa: BLE001 - laporkan error ke node berikutnya
        result.update({"status": "error", "detail": str(exc)})

print(json.dumps(result))
