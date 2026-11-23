# ============================================================================
# Shuffle node "analyze"  (app: Shuffle Tools -> action: Execute python)
# ANALYZE + DECIDE: petakan field alert, hitung tingkat risiko, tentukan respons.
# Ganti PLAYBOOK sesuai workflow: PB-01 | PB-02 | PB-03 | PB-04
# ============================================================================
import ipaddress
import json
from datetime import datetime, timezone

PLAYBOOK = "PB-01"

LAB_SUBNET = ipaddress.ip_network("172.30.0.0/24")
PROTECTED_IPS = {"172.30.0.1", "172.30.0.10", "172.30.0.20"}   # gateway/host, web, sensor
PROTECTED_USERS = {"root", "yoga", "hafidz"}                     # admin yang diizinkan
KNOWN_BAD_MD5 = {"44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File"}  # = CDB list Wazuh
CRITICAL_PATHS = ("/var/www/html/index.html", "/var/www/html/uploads")

raw = r'''$exec'''
event = json.loads(raw) if raw.strip().startswith("{") else {}
m = event.get("mapped") or {}
alert = event.get("alert") or {}
rule_id = str(m.get("rule_id", ""))
level = int(m.get("rule_level") or 0)


def risk_from_level(lvl):
    if lvl >= 12:
        return "CRITICAL"
    if lvl >= 10:
        return "HIGH"
    if lvl >= 7:
        return "MEDIUM"
    return "LOW"


risk = risk_from_level(level)
decision, action, target, reasons = "notify", "none", "", []

if PLAYBOOK == "PB-01":                      # Brute force / port scan -> block IP
    ip = m.get("src_ip", "")
    target = ip
    try:
        addr = ipaddress.ip_address(ip)
        valid = True
    except ValueError:
        valid = False
    hits = int(m.get("firedtimes") or 1)
    if not valid:
        reasons.append("src_ip tidak valid")
    elif ip in PROTECTED_IPS:
        reasons.append(f"{ip} ada di allowlist (gateway/endpoint)")
    elif addr not in LAB_SUBNET:
        reasons.append(f"{ip} di luar subnet lab, hanya notifikasi")
    elif level < 10:
        reasons.append(f"level {level} di bawah threshold 10")
    else:
        decision, action = "block_ip", "!clo3-block-ip.sh"
        reasons.append(f"IP valid di subnet lab, rule {rule_id} level {level} "
                       f"(threshold frekuensi terlampaui, fired {hits}x)")

elif PLAYBOOK == "PB-02":                    # FIM -> incident + notification + investigasi
    path = m.get("file_path", "")
    ev = m.get("file_event", "")
    target = path
    critical = path.startswith(CRITICAL_PATHS)
    if critical or ev == "deleted":
        risk = "HIGH" if risk in ("LOW", "MEDIUM") else risk
    decision = "create_incident"
    reasons.append(f"lokasi={'kritis' if critical else 'web content'}, jenis perubahan={ev}")
    sc = alert.get("syscheck", {})
    reasons.append(f"md5 {sc.get('md5_before', '-')} -> {sc.get('md5_after', '-')}, "
                   f"owner={sc.get('uname_after', '-')}, perm={sc.get('perm_after', '-')}")

elif PLAYBOOK == "PB-03":                    # Malware -> quarantine
    path = m.get("file_path", "")
    md5 = m.get("file_md5", "")
    target = path
    if level >= 12 and md5 in KNOWN_BAD_MD5:
        decision, action, risk = "quarantine", "!clo3-quarantine.sh", "CRITICAL"
        reasons.append(f"severity {level} >= 12 dan hash {md5} = {KNOWN_BAD_MD5[md5]}")
    else:
        reasons.append(f"hash {md5 or '-'} tidak terkonfirmasi / level {level} < 12, hanya notifikasi")

elif PLAYBOOK == "PB-04":                    # Unauthorized login / privilege escalation
    if rule_id == "100600":
        user = m.get("src_user", "")
        target = user
        if user and user not in PROTECTED_USERS:
            decision, action, risk = "lock_user", "!clo3-lock-user.sh", "CRITICAL"
            reasons.append(f"user '{user}' bukan sudoers mencoba sudo -> kunci akun (kebijakan)")
        else:
            reasons.append(f"user '{user}' dilindungi kebijakan, hanya incident")
            decision = "create_incident"
    else:
        target = m.get("dst_user") or m.get("src_user") or m.get("src_ip", "")
        decision = "create_incident"
        reasons.append("login dari akun tidak dikenal / tidak diizinkan -> incident + notifikasi")

print(json.dumps({
    "playbook": PLAYBOOK,
    "decision": decision,
    "should_respond": action != "none",
    "action": action,
    "target": target,
    "risk": risk,
    "reasons": reasons,
    "analyzed_at": datetime.now(timezone.utc).isoformat(),
    "mapped": m,
    "forwarded_at": event.get("forwarded_at", ""),
    "syscheck_diff": (alert.get("syscheck", {}).get("diff") or "")[:400],
}))
