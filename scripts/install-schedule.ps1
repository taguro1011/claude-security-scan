# 毎週のスキャンを Windows のタスクスケジューラに登録する（既定: 月曜 8:00）。管理者権限は不要。
# 使い方（PowerShell）:
#   powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1                       # 月曜 8:00
#   powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1 -Day Sunday -Time 21:00
#   powershell -ExecutionPolicy Bypass -File scripts\install-schedule.ps1 -Remove
# 新しい緊急・高があればトースト通知。ログは reports\schedule.log
param(
    [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')][string]$Day = 'Monday',
    [ValidatePattern('^\d{1,2}:\d{2}$')][string]$Time = '8:00',
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$TaskName = 'security-scan'
$TaskPath = '\security-scan\'
$Root = Split-Path -Parent $PSScriptRoot

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host '解除しました'
    exit 0
}

# Python 3.11 以上を探す（py ランチャー → python の順）。ストアを開くだけのダミー python.exe は除外される
$exe = $null
foreach ($cand in @(@('py', '-3'), @('python'))) {
    if (-not (Get-Command $cand[0] -ErrorAction SilentlyContinue)) { continue }
    # 引用符を含めない書き方にする（PowerShell 5.1 は外部コマンドへの " の受け渡しが壊れやすい）
    $cmdArgs = @($cand | Select-Object -Skip 1) + @('-c', 'import sys;sys.version_info>=(3,11) and print(sys.executable)')
    $p = (& $cand[0] @cmdArgs 2>$null | Select-Object -First 1)
    if ($p -and (Test-Path -LiteralPath $p)) { $exe = $p; break }
}
if (-not $exe) { throw 'Python 3.11 以上が見つかりません。https://www.python.org/ から入れてください' }
# pythonw.exe なら実行中に黒い窓が出ない（出力は scan.py が reports\schedule.log に書く）
$pyw = Join-Path (Split-Path -Parent $exe) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pyw)) { $pyw = $exe }

New-Item -ItemType Directory -Force -Path (Join-Path $Root 'reports') | Out-Null
$action = New-ScheduledTaskAction -Execute $pyw -Argument ('"' + (Join-Path $Root 'scan.py') + '" --notify') -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At $Time
# 寝ていた・電源が落ちていた週は、次に起動したときに実行する
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Description '読み取り専用のセキュリティスキャン（claude-security-scan）' -Force | Out-Null

Write-Host "登録しました: 毎週 $Day $Time（タスクスケジューラ $TaskPath$TaskName）"
Write-Host "今すぐ1回: Start-ScheduledTask -TaskPath '$TaskPath' -TaskName '$TaskName'"
