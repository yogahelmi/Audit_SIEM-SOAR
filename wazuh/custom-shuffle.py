#!/var/ossec/framework/python/bin/python3
"""Forward Wazuh JSON alerts to a Shuffle webhook (CLO3).

Wazuh integratord calls:  custom-shuffle <alert_file> <api_key> <hook_url> [debug]
The hook URL comes from <hook_url> in ossec.conf, so no secret lives here.

Payload sent to Shuffle:
  {
    "source": "wazuh",
    "forwarded_at": "<UTC ISO time, used to measure SOAR latency>",
    "mapped": { alert_id, timestamp, rule_id, rule_level, src_ip, dst_ip,
                agent_id, agent_name, description, groups, ... },   # Langkah 2
    "alert": { ...full original Wazuh alert... }
  }
"""
import json
import sys
import urllib.request
from datetime import datetime, timezone


def pick(data, *paths):
    """Return the first non-empty value among dotted paths."""
    for path in paths:
        value = data
        for key in path.split("."):
            if not isinstance(value, dict) or key not in value:
                value = None
                break
            value = value[key]
        if value not in (None, ""):
            return value
    return ""


def map_fields(alert):
    rule = alert.get("rule", {})
    return {
        "alert_id": alert.get("id", ""),
        "timestamp": alert.get("timestamp", ""),
        "rule_id": str(rule.get("id", "")),
        "rule_level": int(rule.get("level", 0) or 0),
        "rule_groups": rule.get("groups", []),
        "src_ip": pick(alert, "data.srcip", "data.src_ip"),
        "dst_ip": pick(alert, "data.dstip", "data.dest_ip", "agent.ip"),
        "agent_id": pick(alert, "agent.id"),
        "agent_name": pick(alert, "agent.name"),
        "description": rule.get("description", ""),
        # Extra context used by the playbooks
        "src_user": pick(alert, "data.srcuser"),
        "dst_user": pick(alert, "data.dstuser"),
        "file_path": pick(alert, "syscheck.path"),
        "file_event": pick(alert, "syscheck.event"),
        "file_md5": pick(alert, "syscheck.md5_after"),
        "file_sha256": pick(alert, "syscheck.sha256_after"),
        "firedtimes": rule.get("firedtimes", 1),
        "full_log": alert.get("full_log", "")[:500],
    }


def main(argv):
    alert_path = argv[1]
    # api_key may be an empty string; take the first argument that looks like a URL.
    hook_url = next((a for a in argv[2:] if a.startswith("http")), "")
    if not hook_url:
        raise SystemExit("custom-shuffle: hook_url missing")

    with open(alert_path, encoding="utf-8") as alert_file:
        alert = json.load(alert_file)

    body = {
        "source": "wazuh",
        "forwarded_at": datetime.now(timezone.utc).isoformat(),
        "mapped": map_fields(alert),
        "alert": alert,
    }
    request = urllib.request.Request(
        hook_url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Shuffle returned {response.status}")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as error:  # integratord logs stderr in integrations.log
        print(f"custom-shuffle: {error}", file=sys.stderr)
        sys.exit(1)
