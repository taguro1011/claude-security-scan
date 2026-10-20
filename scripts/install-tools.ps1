# gitleaks と osv-scanner の Windows 版を公式GitHubリリースから bin\ に取得し、SHA256 を検証する。
# 使い方（PowerShell）:  powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1
# winget / scoop 等で既に入っていれば不要（PATH 上のものを使う）。
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$GitleaksVersion = '8.30.1'
$OsvVersion = '2.7.0'

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root 'bin'
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ('sscan-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { $glArch = 'x64'; $osvArch = 'amd64' }
    'ARM64' { $glArch = 'arm64'; $osvArch = 'arm64' }
    default { throw "未対応のCPU: $arch" }
}

function Get-File([string]$url, [string]$dest) { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest }

function Assert-Sha256([string]$file, [string]$sums) {
    $name = Split-Path -Leaf $file
    $line = Get-Content -LiteralPath $sums | Where-Object { ($_ -split '\s+')[1] -in @($name, "*$name") } | Select-Object -First 1
    if (-not $line) { throw "チェックサムが見つからない: $name" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLower()
    if ($expected -ne $actual) { throw "チェックサム不一致: $name" }
    Write-Host "  OK $name の SHA256 を確認"
}

try {
    Write-Host "gitleaks v$GitleaksVersion (windows/$glArch)"
    $gl = "gitleaks_${GitleaksVersion}_windows_${glArch}.zip"
    $base = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion"
    Get-File "$base/$gl" (Join-Path $Tmp $gl)
    Get-File "$base/gitleaks_${GitleaksVersion}_checksums.txt" (Join-Path $Tmp 'gl_sums.txt')
    Assert-Sha256 (Join-Path $Tmp $gl) (Join-Path $Tmp 'gl_sums.txt')
    Expand-Archive -LiteralPath (Join-Path $Tmp $gl) -DestinationPath (Join-Path $Tmp 'gl') -Force
    Copy-Item -LiteralPath (Join-Path $Tmp 'gl\gitleaks.exe') -Destination (Join-Path $Bin 'gitleaks.exe') -Force

    Write-Host "osv-scanner v$OsvVersion (windows/$osvArch)"
    $osv = "osv-scanner_windows_${osvArch}.exe"
    $base = "https://github.com/google/osv-scanner/releases/download/v$OsvVersion"
    Get-File "$base/$osv" (Join-Path $Tmp $osv)
    Get-File "$base/osv-scanner_SHA256SUMS" (Join-Path $Tmp 'osv_sums.txt')
    Assert-Sha256 (Join-Path $Tmp $osv) (Join-Path $Tmp 'osv_sums.txt')
    Copy-Item -LiteralPath (Join-Path $Tmp $osv) -Destination (Join-Path $Bin 'osv-scanner.exe') -Force

    # 検証済みなので「インターネットから取得したファイル」の印を外す（SmartScreen の確認を出さない）
    Unblock-File -LiteralPath (Join-Path $Bin 'gitleaks.exe'), (Join-Path $Bin 'osv-scanner.exe')
    & (Join-Path $Bin 'gitleaks.exe') version
    & (Join-Path $Bin 'osv-scanner.exe') --version | Select-Object -First 1
    Write-Host "完了: $Bin"
}
finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
