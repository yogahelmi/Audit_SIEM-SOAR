# Pengujian dan evaluasi (Langkah 5)

Jalankan dari root proyek setelah kedua agent berstatus **Active** dan keempat workflow Shuffle aktif:

```powershell
./tests/run-10x.ps1                                   # 6 skenario x 10 iterasi (~45 menit)
./tests/run-10x.ps1 -Scenario bruteforce -Iterations 1  # uji cepat satu skenario
```

Untuk setiap iterasi, script:
1. **Reset**: membuka blokir IP dan membuka kunci akun dari iterasi sebelumnya.
2. **Attack**: menjalankan serangan sungguhan dari container attacker (`attack.sh`) atau perubahan file di endpoint web.
3. **Detect**: menunggu alert dengan rule yang sesuai di index `wazuh-alerts-*`.
4. **Analyze, Decide, Respond, Verify, Report**: menunggu dokumen incident yang dibuat Shuffle di index `clo3-incidents`, lengkap dengan `outcome` dan `verified`.
5. **Effect**: memeriksa sendiri bahwa mitigasi bekerja (SSH/HTTP tidak bisa dijangkau, file sudah dikarantina, akun terkunci).

| # | Skenario | Serangan | Rule Wazuh | Playbook | Lulus jika |
|---|---|---|---|---|---|
| 1 | SSH Brute Force | 8× password salah (`sshpass`) ke web:22 | 100100 | PB-01 | IP attacker terblokir, verified |
| 2 | Unauthorized Login | Login sukses akun `intern` (tidak ada di allowlist) | 100111 (100112 bila setelah brute force) | PB-04 | Incident + Telegram |
| 3 | File Integrity | Mengubah `/var/www/html/index.html` | 100300 | PB-02 | Incident + Telegram (dengan diff) |
| 4 | Malware | File EICAR di `/var/www/html/uploads/` | 100400 | PB-03 | File dikarantina, verified |
| 5 | Privilege Escalation | `intern` menjalankan `sudo` | 100600 | PB-04 | Akun `intern` terkunci, verified |
| 6 | Port Scanning | `nmap -sS` 1000 port ke sensor | 100210 | PB-01 | IP attacker terblokir di sensor |

Hasil disimpan di `tests/results/`:
- `results-<waktu>.csv`: satu baris per iterasi (Detected, RuleId, DetectLatencySec, IncidentReported, Outcome, Verified, SoarLatencySec, MitigationEffective).
- `summary-<waktu>.csv`: per skenario. **Detection rate** = alert/10, **Report rate** = incident/10, **Mitigation rate** = mitigasi efektif/10, rata-rata latency deteksi, dan rata-rata *detect → report* (MTTR otomatis).

## Bukti untuk laporan
- Tabel `summary-*.csv` dan cuplikan `results-*.csv`.
- Wazuh Dashboard: halaman Agents, Discover dengan filter `rule.groups: clo3`, dan dashboard **CLO3 SOC Monitoring** (lihat README utama).
- Shuffle: daftar Executions untuk tiap workflow (≥ 10).
- Telegram: pesan incident.
- Endpoint: `docker exec web-101032300037-101032300151 tail /var/log/clo3-response.log`.

## Uji rule tanpa serangan
[logtest-samples.txt](logtest-samples.txt) berisi contoh log untuk `wazuh-logtest`:

```powershell
Get-Content tests/logtest-samples.txt | docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```
