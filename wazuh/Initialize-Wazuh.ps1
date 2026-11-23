<#
.SYNOPSIS
  Pasang / perbarui Wazuh 4.9.2 single-node untuk lab CLO3.

.DESCRIPTION
  1. Clone wazuh-docker (sekali) dan buat sertifikat (sekali).
  2. Bangun wazuh/generated/ossec.conf = ossec.conf resmi + CDB list CLO3
     + blok <integration> ke webhook Shuffle (dibaca dari .env).
  3. Jalankan Wazuh dengan wazuh/docker-compose.override.yml (rule, list, integrasi,
     dan jaringan clo3-soc-net alias wazuh.manager).
  Jalankan ulang script ini setiap kali URL webhook Shuffle di .env berubah.

.EXAMPLE
  ./wazuh/Initialize-Wazuh.ps1
#>
param(
  [string]$Version = "v4.9.2"
)

$ErrorActionPreference = "Stop"
$root     = Split-Path -Parent $PSScriptRoot
$target   = Join-Path $root "wazuh-docker"
$single   = Join-Path $target "single-node"
$override = Join-Path $PSScriptRoot "docker-compose.override.yml"
$genDir   = Join-Path $PSScriptRoot "generated"

# --- 0. Jaringan lab harus sudah ada (dibuat oleh `docker compose up -d` di root) ---
$net = docker network ls --filter "name=^clo3-soc-net$" --format "{{.Name}}"
if (-not $net) {
  throw "Jaringan clo3-soc-net belum ada. Jalankan dulu dari root proyek: docker compose up -d --build"
}

# --- 1. wazuh-docker + sertifikat ---
if (-not (Test-Path $target)) {
  git clone --depth 1 --branch $Version https://github.com/wazuh/wazuh-docker.git $target
}
if (-not (Test-Path (Join-Path $single "config/wazuh_indexer_ssl_certs/root-ca.pem"))) {
  Push-Location $single
  try { docker compose -f generate-indexer-certs.yml run --rm generator } finally { Pop-Location }
}

# --- 2. Baca .env ---
$envFile = Join-Path $root ".env"
$cfg = @{}
if (Test-Path $envFile) {
  foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') { $cfg[$Matches[1]] = $Matches[2].Trim('"') }
  }
}

# URL webhook dari UI Shuffle (http://localhost:3001/api/v1/hooks/webhook_xxx) diubah ke
# alamat internal yang bisa dijangkau manager: http://shuffle-backend:5001/api/v1/hooks/webhook_xxx
function Convert-HookUrl([string]$url) {
  if ([string]::IsNullOrWhiteSpace($url) -or $url -match 'REPLACE') { return $null }
  if ($url -match '(/api/v1/hooks/[A-Za-z0-9_\-]+)') { return "http://shuffle-backend:5001$($Matches[1])" }
  return $url
}

$playbooks = @(
  @{ Key = 'SHUFFLE_HOOK_PB01_BLOCK';   Name = 'PB-01 Block IP (brute force, port scan)'; Rules = '100100,100101,100210' },
  @{ Key = 'SHUFFLE_HOOK_PB02_FIM';     Name = 'PB-02 File Integrity';                   Rules = '100300' },
  @{ Key = 'SHUFFLE_HOOK_PB03_MALWARE'; Name = 'PB-03 Malware';                          Rules = '100400' },
  @{ Key = 'SHUFFLE_HOOK_PB04_ACCOUNT'; Name = 'PB-04 Unauthorized login / PrivEsc';     Rules = '100110,100111,100112,100600' }
)

$integrations = "  <!-- CLO3-BEGIN: Wazuh -> Shuffle (dibuat oleh Initialize-Wazuh.ps1) -->`n"
foreach ($pb in $playbooks) {
  $hook = Convert-HookUrl $cfg[$pb.Key]
  if (-not $hook) {
    Write-Warning "$($pb.Key) kosong di .env -> integrasi $($pb.Name) dilewati."
    continue
  }
  $integrations += @"
  <!-- $($pb.Name) -->
  <integration>
    <name>custom-shuffle</name>
    <hook_url>$hook</hook_url>
    <rule_id>$($pb.Rules)</rule_id>
    <alert_format>json</alert_format>
  </integration>

"@
  Write-Host "Integrasi $($pb.Name) -> $hook (rule $($pb.Rules))"
}
$integrations += "  <!-- CLO3-END -->`n"

# --- 3. Bangun ossec.conf ---
$base = Get-Content -Raw (Join-Path $single "config/wazuh_cluster/wazuh_manager.conf")
$base = $base -replace "`r`n", "`n"
$lists = "  <list>etc/lists/clo3-malware-hashes</list>`n    <list>etc/lists/clo3-authorized-users</list>`n  </ruleset>"
$regex = [regex]'</ruleset>'
$conf  = $regex.Replace($base, $lists, 1)
$regex = [regex]'</ossec_config>'
$conf  = $regex.Replace($conf, "$integrations</ossec_config>", 1)
# Endpoint container yang dibuat ulang kehilangan client.keys lalu mendaftar ulang dengan
# nama yang sama. Default Wazuh menolaknya ("Duplicate agent name") sampai agent lama
# terputus > 1 jam; untuk lab, izinkan penggantian langsung.
$force = @"
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="no">1h</disconnected_time>
      <after_registration_time>0</after_registration_time>
    </force>
  </auth>
"@
$force = ($force.TrimStart()) -replace "`r`n", "`n"
$regex = [regex]'</auth>'
$conf  = $regex.Replace($conf, $force, 1)

New-Item -ItemType Directory -Force $genDir | Out-Null
[IO.File]::WriteAllText((Join-Path $genDir "ossec.conf"), $conf, (New-Object Text.UTF8Encoding $false))
Write-Host "wazuh/generated/ossec.conf dibuat."

# --- 4. Jalankan / restart Wazuh ---
Push-Location $single
try {
  $wasRunning = docker compose -f docker-compose.yml -f $override ps -q wazuh.manager
  docker compose -f docker-compose.yml -f $override up -d
  if ($wasRunning) {
    # Restart agar isi /wazuh-config-mount disalin ulang ke /var/ossec.
    docker compose -f docker-compose.yml -f $override restart wazuh.manager
  }
} finally { Pop-Location }

Write-Host ""
Write-Host "Wazuh Dashboard : https://localhost   (admin / SecretPassword - ganti setelah instalasi)"
Write-Host "Wazuh API       : https://localhost:55000  (wazuh-wui / MyS3cr37P450r.*-)"
Write-Host "Cek rule        : docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t"
