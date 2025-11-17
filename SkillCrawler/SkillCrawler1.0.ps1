<# ===========================
 Security Copilot Skill Dumper
 PS 5.1–compatible (no ?:, ??, ?.)
 Hardened + paginated + HAR fallback
=========================== #>

# -------------------- USER CONFIG --------------------
$PodId     = "<UpdateMe>" # ← your Pod ID
$BaseUrl   = 'https://us.api.securityplatform.microsoft.com'
$Workspace = '<UpdateMe>'             # ← your workspace name
$OutDir    = 'Security Copilot Plugins'
$HarPath   = 'c:\temp\'            # file or directory, optional

# -------------------- HELPERS --------------------

function ConvertFrom-SecureStringPlain {
  param([Parameter(Mandatory)][securestring]$Secure)
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
  }
}

function Sanitize-Name([string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Name)) { return 'unnamed' }
  $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
  return ($Name -replace "[${invalid}]", '_')
}

function Save-Json {
  param([Parameter(Mandatory)][object]$Obj,[Parameter(Mandatory)][string]$Path)
  try {
    $json = $Obj | ConvertTo-Json -Depth 100
  } catch {
    $json = ConvertTo-Json -InputObject @{ raw = $true; body = ($Obj | Out-String) } -Depth 5
  }
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Extract-Array {
  <#
    Normalizes many common shapes to a PowerShell array:
      - Array already
      - Object with 'items' or 'value' array
      - Single object
  #>
  param([Parameter(Mandatory)][object]$Data)
  if ($null -eq $Data) { return @() }   # PS 5.1-safe empty array
  if ($Data -is [System.Array]) { return $Data }
  if ($Data.PSObject.Properties.Name -contains 'items' -and ($Data.items -is [System.Array])) { return $Data.items }
  if ($Data.PSObject.Properties.Name -contains 'value' -and ($Data.value -is [System.Array])) { return $Data.value }
  return ,$Data
}

function Invoke-ApiJson {
  param(
    [Parameter(Mandatory)][string]$Url,
    [hashtable]$Headers,
    [int]$TimeoutSec = 120,
    [int]$MaxRetries = 4
  )
  $delay = 1
  for ($i = 0; $i -le $MaxRetries; $i++) {
    try {
      return Invoke-RestMethod -Method GET -Uri $Url -Headers $Headers -TimeoutSec $TimeoutSec -ErrorAction Stop
    } catch {
      $resp = $_.Exception.Response
      $code = $null
      if ($resp -and $resp.StatusCode) { $code = $resp.StatusCode.Value__ }
      if ($code -eq 429 -or ($code -ge 500 -and $code -lt 600)) {
        Start-Sleep -Seconds $delay
        if ($delay -lt 30) { $delay = $delay * 2 } else { $delay = 30 }
        continue
      }
      Write-Warning ("GET {0} failed ({1}): {2}" -f $Url, $code, $_.Exception.Message)
      return $null
    }
  }
  Write-Warning "GET $Url exhausted retries."
  return $null
}

function Invoke-ApiAllPages {
  <#
    Follows @odata.nextLink / nextLink / continuationToken
    Returns a flattened array of items (via Extract-Array)
  #>
  param(
    [Parameter(Mandatory)][string]$Url,
    [hashtable]$Headers,
    [int]$TimeoutSec = 120
  )
  $out = @()
  $next = $Url
  while ($next) {
    $page = Invoke-ApiJson -Url $next -Headers $Headers -TimeoutSec $TimeoutSec
    if ($null -eq $page) { break }
    $out += (Extract-Array $page)

    $next = $null
    foreach ($pn in '@odata.nextLink','nextLink','continuationToken') {
      if ($page.PSObject.Properties.Name -contains $pn -and $page.$pn) {
        if ($pn -eq 'continuationToken') {
          # reuse the initial URL and append the continuation token
          $sep = '?'
          if ($Url -match '\?') { $sep = '&' }
          $next = ("{0}{1}continuationToken={2}" -f $Url, $sep, $page.$pn)
        } else {
          $next = $page.$pn
        }
        break
      }
    }
  }
  return $out
}

function Get-SkillsetsFromApi {
  param(
    [string]$BaseUrl,[string]$PodId,[string]$Workspace,[hashtable]$Headers
  )
  $wsEnc = [System.Uri]::EscapeDataString($Workspace)
  $url   = "$BaseUrl/pods/$PodId/workspaces/$wsEnc/securitycopilot/skillsets?`$top=1000"
  $items = Invoke-ApiAllPages -Url $url -Headers $Headers
  if (-not $items) { return @() }

  $names = @()
  foreach ($s in $items) {
    $n = $null
    foreach ($candidate in 'name','id','skillsetName','displayName') {
      if ($s.PSObject.Properties.Name -contains $candidate -and $s.$candidate) { $n = $s.$candidate; break }
    }
    if (-not $n -and $s.PSObject.Properties.Name.Count -gt 0) {
      $n = ($s.PSObject.Properties[0].Value | Out-String).Trim()
    }
    if ($n) { $names += ($n -as [string]) }
  }
  $names | Sort-Object -Unique
}

function Get-SkillsetsFromHar {
  <#
    Accepts a single HAR file or a directory containing one or more HARs.
    Extracts skillset names for the specified workspace.
  #>
  param(
    [Parameter(Mandatory)][string]$HarPath,
    [string]$Workspace = 'default'
  )

  $paths = @()
  if (Test-Path -LiteralPath $HarPath -PathType Container) {
    $paths = Get-ChildItem -LiteralPath $HarPath -Filter *.har -File -Recurse | Select-Object -Expand FullName
  } elseif (Test-Path -LiteralPath $HarPath -PathType Leaf) {
    $paths = @($HarPath)
  } else {
    return @()
  }

  $wsEsc = [Regex]::Escape($Workspace)
  $rx = [regex]"^https://[^/]*\.?api\.securityplatform\.microsoft\.com/pods/[^/]+/workspaces/$wsEsc/securitycopilot/skillsets/([^/]+)/skills(?:\?.*)?$"

  $names = New-Object System.Collections.Generic.HashSet[string]
  foreach ($p in $paths) {
    try {
      $har = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
    } catch {
      Write-Warning "Failed to read HAR '$p': $($_.Exception.Message)"
      continue
    }
    $entries = $har.log.entries
    foreach ($e in $entries) {
      $u = [string]$e.request.url
      if (-not $u) { continue }
      $m = $rx.Match($u)
      if ($m.Success) { [void]$names.Add([System.Uri]::UnescapeDataString($m.Groups[1].Value)) }
    }
  }
  return $names.ToArray() | Sort-Object
}

function Write-Hashes {
  param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$OutCsvPath)
  $files = Get-ChildItem -LiteralPath $Directory -File
  $hasGetFileHash = $false
  try {
    $cmd = Get-Command -Name Get-FileHash -ErrorAction Stop
    if ($cmd) { $hasGetFileHash = $true }
  } catch { $hasGetFileHash = $false }

  if ($hasGetFileHash) {
    $files | Get-FileHash -Algorithm SHA256 | Export-Csv -NoTypeInformation -Path $OutCsvPath -Encoding UTF8
  } else {
    $rows = @()
    foreach ($f in $files) {
      $fs = [System.IO.File]::OpenRead($f.FullName)
      try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha.ComputeHash($fs)
      } finally {
        $fs.Dispose()
      }
      $hashString = -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
      $rows += [pscustomobject]@{
        Path      = $f.FullName
        Algorithm = 'SHA256'
        Hash      = $hashString
      }
    }
    $rows | Export-Csv -NoTypeInformation -Path $OutCsvPath -Encoding UTF8
  }
}

# -------------------- TOKEN --------------------

# Prefer environment variable (recommended): setx SECPLAT_TOKEN "<token>"
$BearerToken = $env:SECPLAT_TOKEN

# SecretManagement vault (optional; uncomment if configured)
# try { $BearerToken = (Get-Secret -Name SecPlatToken) } catch {}

# Interactive paste (hidden input) if still empty
if ([string]::IsNullOrWhiteSpace($BearerToken)) {
  $sec = Read-Host "Paste bearer token (input hidden)" -AsSecureString
  if ($null -eq $sec) { Write-Error "No bearer token provided."; return }
  $BearerToken = ConvertFrom-SecureStringPlain -Secure $sec
}

if ([string]::IsNullOrWhiteSpace($BearerToken)) {
  Write-Error "No bearer token provided. Set SECPLAT_TOKEN env var or paste when prompted."
  return
}

# -------------------- MAIN --------------------

$Headers = @{
  'Authorization' = "Bearer $BearerToken"
  'Accept'        = 'application/json'
}

if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

Write-Host "Discovering skillsets..." -ForegroundColor Cyan
$skillsets = Get-SkillsetsFromApi -BaseUrl $BaseUrl -PodId $PodId -Workspace $Workspace -Headers $Headers

if (-not $skillsets -and $HarPath) {
  Write-Warning "API discovery returned nothing; trying HAR fallback..."
  $skillsets = Get-SkillsetsFromHar -HarPath $HarPath -Workspace $Workspace
}

if (-not $skillsets) {
  Write-Error "Could not discover any skillsets. Provide a HAR with DevTools capture, or verify your token/pod/base URL."
  return
}

Write-Host ("Found {0} skillset(s)." -f $skillsets.Count) -ForegroundColor Green

$wsEnc = [System.Uri]::EscapeDataString($Workspace)
$index = @()
$aggSkillsets = [ordered]@{}
$collisionCounter = @{}  # avoid file overwrites across identical IDs

foreach ($ss in $skillsets) {
  $ssEnc  = [System.Uri]::EscapeDataString($ss)
  $ssSafe = Sanitize-Name $ss
  $url    = "$BaseUrl/pods/$PodId/workspaces/$wsEnc/securitycopilot/skillsets/$ssEnc/skills?`$top=1000"

  Write-Host "→ Skillset: $ss" -ForegroundColor Yellow
  $skills = Invoke-ApiAllPages -Url $url -Headers $Headers

  # Ensure array bucket exists in aggregator
  if (-not $aggSkillsets.Contains($ss)) {
    $aggSkillsets[$ss] = New-Object System.Collections.ArrayList
  }

  if (-not $skills) {
    # Try to still persist raw response (best-effort)
    $resp = Invoke-ApiJson -Url $url -Headers $Headers
    $single = Join-Path $OutDir "$ssSafe.json"
    Save-Json -Obj $resp -Path $single
    [void]$aggSkillsets[$ss].Add($resp)
    $index += [pscustomobject]@{
      Skillset=$ss; SkillId='(all)'; SkillName='(raw list)'; File=$single; SourceUrl=$url
    }
    Write-Host "  Saved raw list: $single"
    continue
  }

  $i = 0
  foreach ($sk in $skills) {
    $i++

    # Extract stable identifiers / names where possible
    $id   = $null; foreach ($p in 'id','skillId','name','key') { if ($sk.PSObject.Properties.Name -contains $p -and $sk.$p) { $id = $sk.$p; break } }
    $name = $null; foreach ($p in 'name','displayName','title') { if ($sk.PSObject.Properties.Name -contains $p -and $sk.$p) { $name = $sk.$p; break } }
    if (-not $id)   { $id   = "idx_$i" }
    if (-not $name) { $name = $id }

    $safeId = Sanitize-Name ([string]$id)
    $key    = "$ssSafe|$safeId"

    # Null-coalesce replacement for PS 5.1
    $prev = 0
    if ($collisionCounter.ContainsKey($key)) { $prev = $collisionCounter[$key] }
    $collisionCounter[$key] = 1 + $prev

    $suffix = ""
    if ($collisionCounter[$key] -gt 1) { $suffix = "__$($collisionCounter[$key])" }

    $file = Join-Path $OutDir ("{0}__{1}{2}.json" -f $ssSafe, $safeId, $suffix)
    Save-Json -Obj $sk -Path $file
    [void]$aggSkillsets[$ss].Add($sk)

    $index += [pscustomobject]@{
      Skillset=$ss; SkillId=([string]$id); SkillName=([string]$name); File=$file; SourceUrl=$url
    }
    Write-Host "  ✓ $name  →  $file"
  }
}

# Write an index for convenience
$indexPath = Join-Path $OutDir 'skills-index.csv'
$index | Export-Csv -NoTypeInformation -Path $indexPath -Encoding UTF8

# Build and write the consolidated JSON with all skills (as plain arrays)
$skillsetsObj = @{}
foreach ($k in $aggSkillsets.Keys) { $skillsetsObj[$k] = @($aggSkillsets[$k]) }

$allDoc = [ordered]@{
  podId       = $PodId
  workspace   = $Workspace
  collectedAt = (Get-Date).ToUniversalTime().ToString("o")
  skillsets   = $skillsetsObj
}
$allPath = Join-Path $OutDir 'all-skills.json'
Save-Json -Obj $allDoc -Path $allPath

# Write file hashes for integrity tracking (with PS 5.1 fallback)
$hashPath = Join-Path $OutDir 'hashes.csv'
Write-Hashes -Directory $OutDir -OutCsvPath $hashPath

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  Per-skill files and raw lists: $OutDir"
Write-Host "  Index CSV: $indexPath"
Write-Host "  Consolidated JSON (all skills): $allPath"
Write-Host "  Hash manifest: $hashPath"
