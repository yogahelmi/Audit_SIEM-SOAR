# SOC Lab: Wazuh SIEM + Shuffle SOAR

**Kelompok**

| NIM | Nama |
|---|---|
| 101032300037 | Yoga Helmi Ilham Saputra |
| 101032300151 | Muhammad Hafidz Abdurrahman |

Identitas kelompok muncul di nama dan hostname container (`*-101032300037-101032300151`), label Docker `clo3.kelompok.*`, label agent Wazuh (`agent.labels.kelompok.*` di setiap alert), banner SSH, halaman web, header `X-CLO3-Sensor`, dan setiap dokumen incident.

## Arsitektur

```text
                         ┌──────────────── clo3-soc-net 172.30.0.0/24 ────────────────┐
 attacker .66 ──HTTP──>  SENSOR .20  (Nginx reverse proxy + Suricata IDS + Wazuh agent) ──> WEB .10
     │                                                                                     (Nginx, SSH, FIM,
     └────────SSH / sudo / nmap──────────────────────────────────────────────────────────>  Wazuh agent)
                                    │ log (eve.json, auth.log, FIM, response log)
                                    ▼
                    Wazuh Manager (rules 1001xx–1006xx, CDB list) ──> Indexer ──> Dashboard
                                    │ integration custom-shuffle (rule_id filter)
                                    ▼
             Shuffle SOAR: PB-01..PB-04  analyze → respond → verify → report
                    │ Wazuh API PUT /active-response            │ index clo3-incidents
                    ▼                                           ▼            ▼
        active response di agent (block IP,          Wazuh Dashboard     Telegram bot
        karantina file, kunci akun) ─ bukti ─> rule 100500/100501 (Verify)
```

| Komponen | Fungsi | Akses |
|---|---|---|
| Endpoint 1 **web** | Nginx + SSH, sumber log auth/nginx, FIM `/var/www/html` | `http://localhost:8080`, SSH `localhost:2222` |
| Endpoint 2 **sensor** | Reverse proxy ke web + Suricata (`eve.json`), firewall untuk port scan | `http://localhost:8081` |
| attacker | Kali dengan `nmap`, `hydra`, `sshpass`, `attack.sh` | `docker exec` |
| Wazuh Dashboard | Monitoring dan evaluasi | `https://localhost` |
| Wazuh API / Indexer | Active response / query alert dan incident | `:55000` / `:9200` |
| Shuffle | Workflow SOAR | `http://localhost:3001` |

Pemetaan skenario ke rule, playbook, dan respons ada di [wazuh/local_rules.xml](wazuh/local_rules.xml), [shuffle/PLAYBOOKS.md](shuffle/PLAYBOOKS.md), dan [tests/README.md](tests/README.md).

## Prasyarat

- **RAM.** Stack lengkap butuh sekitar 6 GB untuk Docker, jadi mesin host idealnya ≥ 12–16 GB. Wazuh indexer, dashboard, manager, Shuffle OpenSearch, dan endpoint tidak muat di 3 GB; container akan mati dengan exit code 137 (OOM) atau Docker Engine hang.
  - Host 16 GB: buat `%UserProfile%\.wslconfig` berisi `[wsl2]`, `memory=8GB`, `processors=4`, lalu jalankan `wsl --shutdown` dan buka ulang Docker Desktop.
  - Host ≤ 8 GB: jalankan lab di laptop anggota lain yang RAM-nya lebih besar, atau di VM cloud 8 GB. Pilihan lain: `memory=5GB` + `swap=8GB` di `.wslconfig` dan matikan aplikasi lain (akan lambat).
- PowerShell, Git, dan koneksi internet (untuk build image).

## Menjalankan lab

```powershell
# 0. (sekali) jika pernah menjalankan versi lama: hapus container & jaringan lama
docker compose down
docker rm -f web-101032300037-yoga sensor-101032300037-yoga attacker-101032300037-yoga 2>$null
docker network rm clo3-soc-net 2>$null          # gagal? matikan dulu Wazuh: cd wazuh-docker/single-node; docker compose down

# 1. Siapkan .env
Copy-Item .env.example .env                     # lalu isi TELEGRAM_* (token baru)

# 2. Endpoint + Shuffle
docker compose up -d --build

# 3. Wazuh (manager, indexer, dashboard) + rule + list + integrasi
./wazuh/Initialize-Wazuh.ps1
```

4. Buka Wazuh Dashboard → **Agents**, pastikan `web-101032300037-101032300151` dan `sensor-101032300037-101032300151` berstatus **Active**. Jika belum muncul, jalankan `docker compose restart web sensor`. Agent lama (`*-101032300037-yoga`) bisa dihapus dengan `docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -r <ID>`.
5. Buka Shuffle (`http://localhost:3001`), buat akun admin, lalu buat 4 workflow sesuai [shuffle/PLAYBOOKS.md](shuffle/PLAYBOOKS.md). Salin URL webhook ke `.env` (`SHUFFLE_HOOK_PB0x_*`).
6. Jalankan lagi `./wazuh/Initialize-Wazuh.ps1` agar integrasi ke keempat webhook aktif.
7. Uji: `./tests/run-10x.ps1 -Scenario bruteforce -Iterations 1`, lalu jalankan versi lengkap `./tests/run-10x.ps1`.

Cek cepat:

```powershell
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t          # sintaks rule
docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/integrations.log  # kiriman ke Shuffle
docker exec web-101032300037-101032300151 tail -f /var/log/clo3-response.log      # hasil active response
docker exec attacker-101032300037-101032300151 attack.sh sqli                    # alert Suricata 100200
```

## Struktur proyek

```text
docker-compose.yml               endpoint web/sensor/attacker + Shuffle
endpoints/common/                agent-setup.sh (konfigurasi agent idempotent) + skrip active response
endpoints/web|sensor|attacker/   Dockerfile per container
wazuh/local_rules.xml            rule deteksi CLO3 (diuji dengan wazuh-logtest)
wazuh/lists/                     CDB list: hash malware, akun yang diizinkan
wazuh/custom-shuffle.py          integrasi Wazuh → Shuffle + pemetaan field
wazuh/Initialize-Wazuh.ps1       instal/perbarui Wazuh + generate ossec.conf
wazuh/docker-compose.override.yml mount konfigurasi CLO3 ke manager
shuffle/PLAYBOOKS.md, code/      panduan dan kode 4 playbook
tests/run-10x.ps1                pengujian 10x per skenario + metrik
```

## Pemetaan field alert (Langkah 2)

`custom-shuffle.py` mengirim `{"mapped": {...}, "alert": {...}}` ke Shuffle:

| Field | Sumber di alert Wazuh | Di Shuffle |
|---|---|---|
| Alert ID | `id` | `$exec.mapped.alert_id` |
| Timestamp | `timestamp` | `$exec.mapped.timestamp` |
| Rule ID | `rule.id` | `$exec.mapped.rule_id` |
| Rule Level | `rule.level` | `$exec.mapped.rule_level` |
| Source IP | `data.srcip` / `data.src_ip` (Suricata) | `$exec.mapped.src_ip` |
| Destination IP | `data.dstip` / `data.dest_ip` / `agent.ip` | `$exec.mapped.dst_ip` |
| Agent Name | `agent.name` | `$exec.mapped.agent_name` |
| Event Description | `rule.description` | `$exec.mapped.description` |
| Tambahan | `agent.id`, `syscheck.path/md5_after`, `data.srcuser/dstuser` | `agent_id`, `file_path`, `file_md5`, `src_user`, ... |

## Dashboard monitoring dan evaluasi

Di Wazuh Dashboard (**Dashboard Management → Dashboards Management → Index patterns**) buat index pattern `clo3-incidents*` dengan time field `@timestamp`. Lalu di **Visualize**, buat panel berikut dan gabungkan dalam dashboard **CLO3 SOC Monitoring**:

| Panel | Index | Tipe / field |
|---|---|---|
| Alert CLO3 per rule | `wazuh-alerts-*`, filter `rule.groups: clo3` | Data table `rule.description` |
| Alert per agent | `wazuh-alerts-*` | Bar `agent.name` |
| Timeline serangan | `wazuh-alerts-*`, filter `rule.level >= 10` | Line per menit, split `rule.id` |
| Incident per playbook & outcome | `clo3-incidents*` | Bar `playbook`, split `outcome` |
| Rata-rata latency detect → report | `clo3-incidents*` | Metric avg `latency_seconds` |
| Risk distribution | `clo3-incidents*` | Pie `risk` |

## Catatan keamanan

- Token Telegram lama sempat ter-commit di `ba0e8f3`. **Revoke token itu di BotFather** dan pakai token baru. `.env` sekarang tidak lagi dilacak git, tetapi riwayat lama masih menyimpan token tersebut, jadi jangan push riwayat itu ke repo publik.
- Kredensial default Wazuh (`admin/SecretPassword`, `wazuh-wui/MyS3cr37P450r.*-`) dan akun lab (`yoga`, `hafidz`, `intern`) hanya untuk lab terisolasi.
- Shuffle me-mount Docker socket; jalankan hanya di mesin/VM lab.
- Skrip active response punya pengaman: IP gateway/endpoint tidak pernah diblokir, karantina hanya di `/var/www/html` (file dipindah, tidak dihapus), dan akun admin tidak pernah dikunci.
