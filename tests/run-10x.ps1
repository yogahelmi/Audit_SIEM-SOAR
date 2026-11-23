<#
.SYNOPSIS
  Pengujian otomatis CLO3: tiap skenario dijalankan N kali (default 10) lalu diukur
  Detect (alert Wazuh), Respond + Verify + Report (incident dari Shuffle) dan efek mitigasi.

.EXAMPLE
  ./tests/run-10x.ps1                          # semua skenario, 10x
  ./tests/run-10x.ps1 -Scenario bruteforce,malware -Iterations 3
#>
param(
  [ValidateSet('bruteforce','unauth','fim','malware','privesc','portscan','all')]
  [string[]]$Scenario = @('all'),
  [int]$Iterations = 10,
  [int]$TimeoutSec = 90
)

$ErrorActionPreference = 'Stop'
$root     = Split-Path -Parent $PSScriptRoot
$suffix   = '101032300037-101032300151'
$web      = "web-$suffix"
$sensor   = "sensor-$suffix"
$attacker = "attacker-$suffix"
$eicarB64 = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='

# ---------- konfigurasi dari .env ----------
$cfg = @{
  WAZUH_INDEXER_URL      = 'https://localhost:9200'
  WAZUH_INDEXER_USER     = 'admin'
  WAZUH_INDEXER_PASSWORD = 'SecretPassword'
}
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
  foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*(WAZUH_INDEXER_[A-Z_]+)\s*=\s*(.+?)\s*$') { $cfg[$Matches[1]] = $Matches[2].Trim('"') }
  }
}

# ---------- helper ----------
function Assert-ContainerRunning([string]$Name) {
  $state = docker inspect --format '{{.State.Running}}' $Name
  if ($LASTEXITCODE -ne 0 -or "$state".Trim() -ne 'true') {
    throw "Container '$Name' belum berjalan. Jalankan dari root proyek: docker compose --profile endpoints up -d --build"
  }
}

function ConvertTo-Utc([string]$Value) {
  if (-not $Value) { return $null }
  $v = $Value -replace '([+-]\d\d)(\d\d)$', '$1:$2'
  return [DateTimeOffset]::Parse($v, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function Search-Indexer([string]$Index, [hashtable]$Query) {
  $tmp = [IO.Path]::GetTempFileName()
  try {
    $json = $Query | ConvertTo-Json -Depth 20 -Compress
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding $false))
    $auth = "$($cfg.WAZUH_INDEXER_USER):$($cfg.WAZUH_INDEXER_PASSWORD)"
    $out = & curl.exe -s -k -u $auth -H 'Content-Type: application/json' -X POST `
      "$($cfg.WAZUH_INDEXER_URL)/$Index/_search" --data-binary "@$tmp"
  } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
  if (-not $out) { return @() }
  try { $res = ($out -join "`n") | ConvertFrom-Json } catch { return @() }
  if ($res.hits -and $res.hits.hits) { return @($res.hits.hits) }
  return @()
}

function Wait-Hit([string]$Index, [string]$TimeField, [string]$RuleField, [string[]]$RuleIds,
                  [datetime]$SinceUtc, [hashtable[]]$Extra = @()) {
  $filters = @(
    @{ terms = @{ $RuleField = $RuleIds } },
    @{ range = @{ $TimeField = @{ gte = $SinceUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } } }
  ) + $Extra
  $query = @{ size = 1; sort = @(@{ $TimeField = @{ order = 'asc' } }); query = @{ bool = @{ filter = $filters } } }
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    $hits = Search-Indexer $Index $query
    if ($hits.Count -gt 0) { return $hits[0]._source }
    Start-Sleep -Seconds 3
  }
  return $null
}

function Invoke-Quiet([scriptblock]$Block) { & $Block *> $null; return $LASTEXITCODE }

# ---------- definisi skenario ----------
$scenarios = [ordered]@{
  bruteforce = @{
    Title = '1. SSH Brute Force'; Rules = @('100100','100101'); Cooldown = 35; ExpectMitigation = $true
    Reset  = { docker exec $web sh -c 'iptables -F CLO3-BLOCK 2>/dev/null || iptables-legacy -F CLO3-BLOCK 2>/dev/null; true' }
    Attack = { docker exec $attacker attack.sh bruteforce }
    Effect = { (Invoke-Quiet { docker exec $attacker attack.sh check-ssh }) -ne 0 }   # SSH tidak terjangkau = terblokir
  }
  unauth = @{
    Title = '2. Unauthorized Login'; Rules = @('100111','100112'); Cooldown = 5; ExpectMitigation = $false
    Reset  = { docker exec $web sh -c 'usermod -U intern; chage -E -1 intern' }
    Attack = { docker exec $attacker attack.sh unauth }
    Effect = { $true }
  }
  fim = @{
    Title = '3. File Integrity Monitoring'; Rules = @('100300'); Cooldown = 5; ExpectMitigation = $false
    Reset  = { }
    Attack = { docker exec $web sh -c "echo '<!-- CLO3 FIM test $i $(Get-Date -Format s) -->' >> /var/www/html/index.html" }
    Effect = { $true }
  }
  malware = @{
    Title = '4. Malware Detection'; Rules = @('100400'); Cooldown = 5; ExpectMitigation = $true
    Reset  = { }
    Attack = { docker exec $web sh -c "echo $eicarB64 | base64 -d > /tmp/invoice-$i.exe && mv /tmp/invoice-$i.exe /var/www/html/uploads/invoice-$i.exe" }
    Effect = {
      $gone = (Invoke-Quiet { docker exec $web test -e "/var/www/html/uploads/invoice-$i.exe" }) -ne 0
      $inQ  = (Invoke-Quiet { docker exec $web sh -c "ls /var/ossec/quarantine | grep -q invoice-$i.exe" }) -eq 0
      $gone -and $inQ
    }
  }
  privesc = @{
    Title = '5. Privilege Escalation'; Rules = @('100600'); Cooldown = 5; ExpectMitigation = $true
    Reset  = { docker exec $web sh -c 'usermod -U intern; chage -E -1 intern' }
    Attack = { docker exec $attacker attack.sh privesc }
    Effect = { ((docker exec $web passwd -S intern) -split '\s+')[1] -eq 'L' }
  }
  portscan = @{
    Title = '6. Port Scanning'; Rules = @('100210'); Cooldown = 15; ExpectMitigation = $true
    Reset  = { docker exec $sensor sh -c 'iptables -F CLO3-BLOCK 2>/dev/null || iptables-legacy -F CLO3-BLOCK 2>/dev/null; true' }
    Attack = { docker exec $attacker attack.sh portscan }
    Effect = { (Invoke-Quiet { docker exec $attacker attack.sh check-http }) -ne 0 }  # HTTP sensor tidak terjangkau = terblokir
  }
}

# ---------- pre-check ----------
@($attacker, $web, $sensor) | ForEach-Object { Assert-ContainerRunning $_ }
$ping = & curl.exe -s -k -o NUL -w '%{http_code}' -u "$($cfg.WAZUH_INDEXER_USER):$($cfg.WAZUH_INDEXER_PASSWORD)" $cfg.WAZUH_INDEXER_URL
if ($ping -ne '200') { throw "Wazuh Indexer tidak bisa diakses di $($cfg.WAZUH_INDEXER_URL) (HTTP $ping)." }

$selected = if ($Scenario -contains 'all') { @($scenarios.Keys) } else { $Scenario }
$resultsDir = Join-Path $PSScriptRoot 'results'
New-Item -ItemType Directory -Force $resultsDir | Out-Null
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath = Join-Path $resultsDir "results-$stamp.csv"
$rows    = New-Object System.Collections.Generic.List[object]

foreach ($key in $selected) {
  $s = $scenarios[$key]
  Write-Host "`n=== $($s.Title) ($Iterations x) ===" -ForegroundColor Cyan
  if ($key -eq 'fim') { docker exec $web cp /var/www/html/index.html /root/index.html.bak }

  for ($i = 1; $i -le $Iterations; $i++) {
    & $s.Reset *> $null
    Start-Sleep -Seconds 2
    $start = (Get-Date).ToUniversalTime().AddSeconds(-1)
    & $s.Attack *> $null

    $alert = Wait-Hit 'wazuh-alerts-*' 'timestamp' 'rule.id' $s.Rules $start
    $incident = $null
    if ($alert) { $incident = Wait-Hit 'clo3-incidents' '@timestamp' 'rule_id' $s.Rules $start }
    $effective = $false
    if ($incident) { $effective = [bool](& $s.Effect) }

    $detectLatency = $null
    if ($alert) { $detectLatency = [Math]::Round(((ConvertTo-Utc $alert.timestamp) - $start).TotalSeconds - 1, 2) }

    $row = [pscustomobject]@{
      Scenario            = $s.Title
      Iteration           = $i
      StartUtc            = $start.AddSeconds(1).ToString('s')
      Detected            = [bool]$alert
      RuleId              = if ($alert) { $alert.rule.id } else { '' }
      AlertId             = if ($alert) { $alert.id } else { '' }
      DetectLatencySec    = $detectLatency
      IncidentReported    = [bool]$incident
      Outcome             = if ($incident) { $incident.outcome } else { '' }
      Verified            = if ($incident) { [bool]$incident.verified } else { $false }
      SoarLatencySec      = if ($incident) { $incident.latency_seconds } else { $null }
      MitigationEffective = if ($s.ExpectMitigation) { $effective } else { [bool]$incident }
    }
    $rows.Add($row)
    $row | Export-Csv -Path $csvPath -Append -NoTypeInformation -Encoding UTF8
    $mark = if ($row.Detected -and $row.IncidentReported -and $row.MitigationEffective) { 'OK  ' } else { 'FAIL' }
    Write-Host ("[{0}] #{1,2} detect={2} report={3} outcome={4} verified={5} effect={6} latency={7}s" -f `
      $mark, $i, $row.Detected, $row.IncidentReported, $row.Outcome, $row.Verified, $row.MitigationEffective, $row.SoarLatencySec)
    Start-Sleep -Seconds $s.Cooldown
  }

  & $s.Reset *> $null
  if ($key -eq 'fim') { docker exec $web cp /root/index.html.bak /var/www/html/index.html }
}

# ---------- ringkasan evaluasi ----------
$summary = $rows | Group-Object Scenario | ForEach-Object {
  $g = $_.Group; $n = $g.Count
  $lat = @($g | Where-Object { $_.SoarLatencySec -ne $null -and $_.SoarLatencySec -ne '' } | ForEach-Object { [double]$_.SoarLatencySec })
  $det = @($g | Where-Object { $_.DetectLatencySec -ne $null } | ForEach-Object { [double]$_.DetectLatencySec })
  [pscustomobject]@{
    Scenario            = $_.Name
    Runs                = $n
    'DetectionRate%'    = [Math]::Round(100 * @($g | Where-Object Detected).Count / $n, 1)
    'ReportRate%'       = [Math]::Round(100 * @($g | Where-Object IncidentReported).Count / $n, 1)
    'MitigationRate%'   = [Math]::Round(100 * @($g | Where-Object MitigationEffective).Count / $n, 1)
    AvgDetectSec        = if ($det.Count) { [Math]::Round(($det | Measure-Object -Average).Average, 2) } else { $null }
    AvgDetectToReportSec = if ($lat.Count) { [Math]::Round(($lat | Measure-Object -Average).Average, 2) } else { $null }
  }
}
$summaryPath = Join-Path $resultsDir "summary-$stamp.csv"
$summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
$summary | Format-Table -AutoSize
Write-Host "Detail : $csvPath"
Write-Host "Ringkas: $summaryPath"
