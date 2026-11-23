# Playbook Shuffle CLO3

Ada empat workflow dengan struktur yang sama, sesuai alur **Detect → Analyze → Decide → Respond → Verify → Report** (Langkah 5):

```text
Webhook ──> analyze ──> respond ──> verify ──> report
(Wazuh)     (risk +     (Wazuh API   (cek bukti   (incident di indexer
            decision)   active resp) di endpoint) + Telegram)
```

| Workflow | Trigger (rule Wazuh) | Decision (node `analyze`) | Automated response | Verify |
|---|---|---|---|---|
| **PB-01 Block IP** | 100100/100101 SSH brute force, 100210 port scan | IP valid, ada di subnet lab, tidak di allowlist, level ≥ 10 (threshold frekuensi terlewati) | `clo3-block-ip.sh`: iptables DROP di agent yang diserang | `iptables -C` → rule 100500 |
| **PB-02 File Integrity** | 100300 perubahan di `/var/www/html` | Periksa lokasi (kritis atau tidak), jenis perubahan, hash, owner, diff | Membuat incident dan notifikasi (tanpa mitigasi, untuk diinvestigasi) | Dokumen incident tersimpan |
| **PB-03 Malware** | 100400 md5 cocok dengan CDB list | Severity ≥ 12 **dan** hash ada di daftar malicious | `clo3-quarantine.sh`: file dipindah ke `/var/ossec/quarantine` (chmod 000 + metadata) | File asal hilang dan ada di karantina → rule 100500 |
| **PB-04 Akun & Privilege** | 100110/100111/100112 unauthorized login, 100600 privilege escalation | Unauthorized login → incident. Privesc oleh akun non-admin → kunci akun | `clo3-lock-user.sh`: `usermod -L`, expire, kill sesi | `passwd -S` = L → rule 100500 |

PB-01 sampai PB-03 adalah tiga playbook wajib dari Langkah 3; PB-04 adalah tambahan untuk skenario 2 dan 5. Respons otomatis yang benar-benar bekerja (Langkah 4): block IP, karantina file, dan kunci akun.

## 1. Workflow variables (sekali per workflow)

Buka workflow, lalu klik ikon **Variables** (`{x}`) dan buat variabel berikut. Shuffle menjalankan app di container terpisah, jadi Wazuh diakses lewat port yang dipublikasikan ke host (`host.docker.internal`).

| Nama | Nilai |
|---|---|
| `wazuh_api` | `https://host.docker.internal:55000` |
| `wazuh_user` | `wazuh-wui` |
| `wazuh_pass` | `MyS3cr37P450r.*-` |
| `indexer_url` | `https://host.docker.internal:9200` |
| `indexer_user` | `admin` |
| `indexer_pass` | `SecretPassword` |
| `telegram_token` | token bot dari BotFather (yang baru, setelah token lama di-rotate) |
| `telegram_chat_id` | chat ID tujuan |

> Sebelum **export** workflow untuk laporan, kosongkan `telegram_token` dan password agar tidak ikut tersimpan di file JSON.

## 2. Membuat satu workflow (ulangi untuk PB-01 s.d. PB-04)

1. **Workflows → Create workflow**, beri nama misalnya `PB-01 Block IP`.
2. Tarik trigger **Webhook** ke canvas, lalu klik **Start**. Salin URL webhook ke `.env`:
   - PB-01 → `SHUFFLE_HOOK_PB01_BLOCK`
   - PB-02 → `SHUFFLE_HOOK_PB02_FIM`
   - PB-03 → `SHUFFLE_HOOK_PB03_MALWARE`
   - PB-04 → `SHUFFLE_HOOK_PB04_ACCOUNT`
3. Tambahkan 4 node app **Shuffle Tools**, action **Execute python**. **Nama node harus persis** seperti di bawah, karena kode merujuk `$analyze`, `$respond`, dan `$verify`:

   | Nama node | Isi field `code` |
   |---|---|
   | `analyze` | [code/1_analyze.py](code/1_analyze.py). **Ubah baris `PLAYBOOK = "PB-01"`** sesuai workflow |
   | `respond` | [code/2_respond.py](code/2_respond.py) |
   | `verify` | [code/3_verify.py](code/3_verify.py) |
   | `report` | [code/4_report.py](code/4_report.py) |

4. Hubungkan: `Webhook → analyze → respond → verify → report`.
5. (Opsional, agar decision terlihat di canvas) Pada garis `analyze → respond`, tambahkan **Condition** `$analyze.message.should_respond` *equals* `true`, lalu tambahkan cabang kedua `analyze → report` untuk kasus tanpa mitigasi.
6. **Save**.

Setelah keempat URL webhook ada di `.env`, jalankan `./wazuh/Initialize-Wazuh.ps1` dari root proyek. Script membuat satu blok `<integration>` per playbook (difilter `rule_id`) dan me-restart manager.

## 3. Uji cepat tanpa serangan

Kirim contoh alert ke webhook PB-02 (ganti URL):

```powershell
$body = '{"source":"wazuh","mapped":{"alert_id":"test-1","timestamp":"2026-11-23T10:00:00.000+0000","rule_id":"100300","rule_level":10,"agent_id":"001","agent_name":"web-101032300037-101032300151","description":"CLO3 test","file_path":"/var/www/html/index.html","file_event":"modified"},"alert":{}}'
Invoke-RestMethod -Method Post -Uri "http://localhost:3001/api/v1/hooks/webhook_XXXX" -Body $body -ContentType "application/json"
```

Hasil yang diharapkan: ada execution baru di Shuffle, dokumen baru di index `clo3-incidents`, dan pesan Telegram.

## 4. Bukti untuk laporan

- Export tiap workflow (**⋮ → Export**) ke `shuffle/workflows/PB-0x.json`. Kosongkan secret terlebih dahulu.
- Screenshot canvas workflow, daftar **Executions** (10× per skenario), dan detail satu execution (output `analyze` / `verify` / `report`).
- Screenshot pesan Telegram.

## Troubleshooting

| Gejala | Cek |
|---|---|
| Execution tidak muncul | `docker exec single-node-wazuh.manager-1 tail /var/ossec/logs/integrations.log` dan pastikan blok `<integration>` ada di `wazuh/generated/ossec.conf` |
| `respond` error koneksi | Ubah `wazuh_api` menjadi `https://wazuh.manager:55000` jika worker Shuffle berada di jaringan `clo3-soc-net` |
| `respond` sukses tetapi `verify` timeout | `docker exec web-101032300037-101032300151 tail /var/log/clo3-response.log` dan `/var/ossec/logs/active-responses.log` |
| Output node berupa teks, bukan JSON | Pastikan tidak ada `print()` lain selain baris terakhir |
