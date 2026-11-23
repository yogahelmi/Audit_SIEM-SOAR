<#
.SYNOPSIS
  Buka port Windows Firewall di PC SERVER (Wazuh + Shuffle) agar laptop endpoint
  dan browser di LAN bisa terhubung. Jalankan di PowerShell "Run as Administrator".

  1514/tcp  agent -> manager (event + active response)
  1515/tcp  pendaftaran agent
  55000/tcp Wazuh API
  9200/tcp  Wazuh Indexer (dipakai tests/run-10x.ps1 dari laptop)
  443/tcp   Wazuh Dashboard
  3001/tcp  Shuffle UI
  Hanya untuk profil jaringan Private (LAN/hotspot), bukan Public.
#>
$ErrorActionPreference = 'Stop'
$ports = 1514, 1515, 55000, 9200, 443, 3001
$name  = 'CLO3 SOC Lab (Wazuh + Shuffle)'
Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP `
  -LocalPort $ports -Profile Private | Out-Null
Write-Host "Port $($ports -join ', ') dibuka (profil Private)."
Write-Host "Pastikan jaringan Wi-Fi/LAN PC ini diset ke 'Private' (Settings > Network > Properties)."
Write-Host "IP PC ini:"
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.|172\.)' } |
  ForEach-Object { "  $($_.IPAddress)  ($($_.InterfaceAlias))" }
