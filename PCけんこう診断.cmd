<# : PC kenko shindan - batch part (PowerShell treats this block as a comment)
@echo off
setlocal
set "PCCHECK_SELF=%~f0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:PCCHECK_SELF,[Text.Encoding]::UTF8); Invoke-Expression $t"
exit /b
#>
# ============================================================================
# PCけんこう診断（ダブルクリック版）
#   このファイルをダブルクリックすると、このWindows PCのセキュリティの基本を点検して、
#   結果をブラウザで開きます。Python などのインストールは不要です。
#
#   - 読み取りだけ。設定の変更・送信・削除は一切しません（ネットにも何も送りません）
#   - 管理者権限は不要です
#   - 結果は「ドキュメント\PCけんこう診断」フォルダに保存されます
#
#   claude-security-scan（Windows対応版）の一部です: https://github.com/taguro1011/claude-security-scan
#   MIT License
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { $Host.UI.RawUI.WindowTitle = 'PCけんこう診断' } catch { }

# ---- 設定値 -----------------------------------------------------------------

# Windows 11 のバージョンごとの更新終了日（Home/Pro, Enterprise/Education）。Microsoft のライフサイクル情報より
$EOS = @{
    22000 = @('2023-10-10', '2024-10-08')   # 21H2
    22621 = @('2024-10-08', '2025-10-14')   # 22H2
    22631 = @('2025-11-11', '2026-11-10')   # 23H2
    26100 = @('2026-10-13', '2027-10-12')   # 24H2
    26200 = @('2027-10-12', '2028-10-10')   # 25H2
}
$WIN10_EOS = '2025-10-14'
$SUSPICIOUS_DIRS = @('\appdata\local\temp\', '\windows\temp\', '\downloads\', '\users\public\', '\$recycle.bin\')
$SCRIPT_HOSTS = @('mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe')
$RISKY_PORTS = @{ 21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 1433 = 'SQL Server'; 3306 = 'MySQL'; 5432 = 'PostgreSQL';
    5900 = '画面共有ソフト（VNC）'; 5985 = 'リモート管理（WinRM）'; 5986 = 'リモート管理（WinRM）'; 6379 = 'Redis'; 27017 = 'MongoDB' }
$DEFINITION_CATEGORY = 'e0789628-ce08-4437-be74-2495b842f43b'

# ---- 情報を集める（読み取りだけ） -------------------------------------------

function RegVal([string]$path, [string]$name) {
    $p = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    return $p.$name
}
# キー自体が読めないときは「設定なし＝安全」と誤判定しないよう、エラーにする
function Need([string]$path) { if (-not (Test-Path -LiteralPath $path)) { throw "レジストリを読めない: $path" } }
function Expand([string]$s) { if ($s) { [Environment]::ExpandEnvironmentVariables($s) } else { $s } }

function Collect-Facts {
    $out = [ordered]@{}
    $errs = [ordered]@{}
    $steps = [ordered]@{
        os = {
            $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            [ordered]@{ build = [int](RegVal $cv 'CurrentBuildNumber'); ubr = RegVal $cv 'UBR'; display = RegVal $cv 'DisplayVersion'; edition = RegVal $cv 'EditionID' }
        }
        last_update = {
            $h = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
            if ($h) { [ordered]@{ kb = [string]$h.HotFixID; date = $h.InstalledOn.ToString('yyyy-MM-dd') } } else { $null }
        }
        bitlocker = {
            $r = [ordered]@{ drive = $env:SystemDrive; source = $null; protection = $null; volume = $null; shell = $null }
            $v = $null
            try { $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch { $v = $null }   # 管理者でないと通常は拒否される
            if ($v -and $null -ne $v.ProtectionStatus) {
                $r.source = 'cmdlet'; $r.protection = [string]$v.ProtectionStatus; $r.volume = [string]$v.VolumeStatus
            }
            else {
                # 管理者なしで読める、エクスプローラーのドライブ表示と同じ値
                $sh = New-Object -ComObject Shell.Application
                $r.source = 'shell'; $r.shell = $sh.NameSpace($env:SystemDrive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection')
            }
            $r
        }
        defender = {
            $m = Get-MpComputerStatus -ErrorAction Stop
            if ($null -eq $m) { throw 'Defender の状態が空で返った' }
            [ordered]@{ av = [bool]$m.AntivirusEnabled; realtime = [bool]$m.RealTimeProtectionEnabled; sig_age = [int]$m.AntivirusSignatureAge; mode = [string]$m.AMRunningMode }
        }
        av_products = {
            , @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
                ForEach-Object { [ordered]@{ name = [string]$_.displayName; state = [int]$_.productState } })
        }
        fw_products = {
            , @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop |
                ForEach-Object { [ordered]@{ name = [string]$_.displayName; state = [int]$_.productState } })
        }
        firewall = {
            try { $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) } catch { $p = @(Get-NetFirewallProfile -ErrorAction Stop) }
            if ($p.Count -eq 0) { throw 'ファイアウォールの情報が空で返った' }
            , @($p | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled } })
        }
        uac = {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Need $k
            [ordered]@{ lua = RegVal $k 'EnableLUA'; admin = RegVal $k 'ConsentPromptBehaviorAdmin' }
        }
        autologon = {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Need $k
            # パスワードは「保存されているか」だけを見て、値は読み出さない
            [ordered]@{ enabled = [string](RegVal $k 'AutoAdminLogon'); has_password = (-not [string]::IsNullOrEmpty([string](RegVal $k 'DefaultPassword'))) }
        }
        screenlock = {
            $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            $r = [ordered]@{ wake_ac = $null; wake_dc = $null; delay_lock = (RegVal 'HKCU:\Control Panel\Desktop' 'DelayLockInterval')
                pol_wake_ac = (RegVal $pk 'ACSettingIndex'); pol_wake_dc = (RegVal $pk 'DCSettingIndex') }
            # スリープ復帰時にサインインを求めるか（表示は日本語でも 0x... の値は共通）
            $q = & { $ErrorActionPreference = 'Continue'; powercfg /query SCHEME_CURRENT SUB_NONE CONSOLELOCK 2>$null }
            $vals = @($q | Select-String -Pattern '0x([0-9a-fA-F]{8})\s*$' | ForEach-Object { [Convert]::ToInt64($_.Matches[0].Groups[1].Value, 16) })
            if ($vals.Count -ge 2) { $r.wake_ac = $vals[$vals.Count - 2]; $r.wake_dc = $vals[$vals.Count - 1] }
            $r
        }
        listening = {
            $names = @{}; Get-Process -ErrorAction Stop | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
            $conns = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
            if ($conns.Count -eq 0) { throw '待ち受けの一覧が空で返った' }
            , @($conns | ForEach-Object { [ordered]@{ addr = [string]$_.LocalAddress; port = [int]$_.LocalPort; proc = [string]$names[[int]$_.OwningProcess] } })
        }
        rdp = {
            $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            Need $ts
            [ordered]@{ deny = RegVal $ts 'fDenyTSConnections'; pol_deny = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
                nla = RegVal "$ts\WinStations\RDP-Tcp" 'UserAuthentication' }
        }
        smb1 = {
            $cl = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
            $sv = 'HKLM:\SYSTEM\CurrentControlSet\Services\srv'
            Need 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer'
            [ordered]@{ client_present = (Test-Path -LiteralPath $cl); client_start = RegVal $cl 'Start'
                server = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
                server_present = (Test-Path -LiteralPath $sv); server_start = RegVal $sv 'Start' }
        }
        accounts = {
            $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
            [ordered]@{ guest_enabled = if ($guest) { [bool]$guest.Enabled } else { $false } }
        }
        startup = {
            $items = @()
            foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
                $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
                if (-not $p) { continue }
                foreach ($prop in $p.PSObject.Properties) {
                    if ($prop.Name -like 'PS*') { continue }
                    $items += [ordered]@{ kind = 'run'; name = $prop.Name; cmd = (Expand ([string]$prop.Value)); account = ''; encoded = $false }
                }
            }
            $wsh = New-Object -ComObject WScript.Shell
            foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
                if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
                foreach ($f in Get-ChildItem -LiteralPath $folder -File -Force) {
                    if ($f.Name -eq 'desktop.ini') { continue }
                    $target = $f.FullName
                    if ($f.Extension -eq '.lnk') { $target = $wsh.CreateShortcut($f.FullName).TargetPath }   # 読むだけ（保存しない）
                    $items += [ordered]@{ kind = 'startup'; name = $f.Name; cmd = ('"' + $target + '"'); account = ''; encoded = $false }
                }
            }
            foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
                if ($t.TaskPath -like '\Microsoft\*') { continue }
                $a = $t.Actions | Where-Object { $_.Execute } | Select-Object -First 1
                if (-not $a) { continue }
                # 引数は記録しない。難読化された PowerShell かどうかだけ判定する
                $enc = ([string]$a.Arguments -match '(?i)(^|\s)[-/]e(c|n[a-z]*)?(\s|$)')
                $items += [ordered]@{ kind = 'task'; name = $t.TaskName; cmd = ('"' + (Expand ($a.Execute.Trim('"'))) + '"'); account = [string]$t.Principal.UserId; encoded = $enc }
            }
            $win = $env:windir.TrimEnd('\') + '\'
            foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
                $path = Expand ([string]$s.PathName)
                if (-not $path -or $path.Trim('"').StartsWith($win, [StringComparison]::OrdinalIgnoreCase)) { continue }
                $items += [ordered]@{ kind = 'service'; name = [string]$s.Name; cmd = $path; account = [string]$s.StartName; encoded = $false }
            }
            , $items
        }
    }
    foreach ($name in $steps.Keys) {
        try { $out[$name] = & $steps[$name] }
        catch { $errs[$name] = (($_.Exception.Message -replace '\s+', ' ').Trim()) }
    }

    # 未適用の Windows 更新（Windows Update への問い合わせ。時間がかかることがあるので最大2分で打ち切る）
    Write-Host '  2/3  Windows Update に未適用の更新がないか確認しています（最大2分）...'
    try {
        $job = Start-Job -ScriptBlock {
            $session = New-Object -ComObject Microsoft.Update.Session
            $res = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
            foreach ($u in $res.Updates) {
                if ($u.BrowseOnly) { continue }   # 「オプションの更新」は数えない
                $cats = @(); foreach ($c in $u.Categories) { $cats += [string]$c.CategoryID }
                [pscustomobject]@{ title = [string]$u.Title; categories = $cats }
            }
        }
        if (Wait-Job $job -Timeout 120) {
            if ($job.State -eq 'Failed') { throw ($job.ChildJobs[0].JobStateInfo.Reason.Message) }
            $out['pending_updates'] = @(Receive-Job $job | ForEach-Object { [ordered]@{ title = $_.title; categories = @($_.categories) } })
        }
        else { $errs['pending_updates'] = '2分以内に Windows Update から返事がありませんでした' }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    catch { $errs['pending_updates'] = (($_.Exception.Message -replace '\s+', ' ').Trim()) }

    $out['errors'] = $errs
    $out['computer'] = $env:COMPUTERNAME
    # JSON を経由して形をそろえる（テスト用の偽データと同じ形で判定するため）
    return ($out | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
}

# ---- 判定 -------------------------------------------------------------------

$Results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$level, [string]$title, [string]$what = '', [string]$how = '') {
    $Results.Add([pscustomobject]@{ level = $level; title = $title; what = $what; how = $how })
}
function HasErr([string]$name) { $e = $F.errors; return ($null -ne $e -and $null -ne $e.PSObject.Properties[$name]) }
function Has([string]$name) { return ($null -ne $F.PSObject.Properties[$name] -and -not (HasErr $name)) }
function AsList($v) {
    if ($null -eq $v) { return @() }
    if ($v -is [array]) { return $v }
    if ($null -ne $v.PSObject.Properties['value'] -and $v.value -is [array]) { return $v.value }   # PS 5.1 の包み方
    return @($v)
}
function ToInt($v) { if ($null -eq $v -or "$v" -eq '') { return $null }; try { return [int64]$v } catch { return $null } }
function DaysSince([string]$d) {
    try { return ($Today - [datetime]::ParseExact($d, 'yyyy-MM-dd', $null)).Days } catch { return $null }
}
function AvOn($p) { $s = [int](ToInt $p.state); return ((($s -shr 12) -band 0xF) -eq 1) }
function AvOld($p) { $s = [int](ToInt $p.state); return ((($s -shr 4) -band 0xF) -eq 1) }
function ThirdParty($list) {
    return @(AsList $list | Where-Object { (AvOn $_) -and ([string]$_.name -notmatch '(?i)(Windows|Microsoft) Defender') } | ForEach-Object { [string]$_.name })
}

function Eval-OS {
    if (-not (Has 'os') -or -not $F.os.build) {
        Add-Result 'unknown' 'Windowsのバージョン' '' '設定 → システム → バージョン情報 で「バージョン」を確認してください'; return
    }
    $b = [int]$F.os.build; $ed = [string]$F.os.edition; $disp = [string]$F.os.display
    $label = 'Windows ' + $(if ($b -ge 22000) { '11' } else { '10' }) + $(if ($disp) { " $disp" } else { '' })
    if ($ed -match 'S$|Server') { Add-Result 'green' "Windowsのサポート：長期サポート版（$label）"; return }
    $recent = DaysSince ([string]$F.last_update.date)
    if ($b -lt 22000) {
        if ($TodayStr -le $WIN10_EOS) { Add-Result 'green' "Windowsのサポート：$label"; return }
        if ($null -ne $recent -and $recent -le 45) {
            Add-Result 'yellow' 'Windows 10 を使っています（通常のサポートは終了済み）' `
                '通常のサポートは 2025年10月14日 に終わっています。最近も更新が届いているので延長サポート（ESU）で守られていますが、いずれ止まります。' `
                '次の買い替えや入れ替えのタイミングで Windows 11 へ。それまでは Windows Update を止めないでください。'
        }
        else {
            Add-Result 'red' 'Windows 10 のサポートが終わっています' `
                'セキュリティの修正がもう届いていません。新しく見つかった弱点が、ずっとふさがれないまま残ります。' `
                'Windows 11 へのアップグレードか、PCの買い替えを検討してください。すぐに無理なら 設定 → Windows Update で「拡張セキュリティ更新（ESU）」に登録してください。'
        }
        return
    }
    $ends = $EOS[$b]
    if (-not $ends) { Add-Result 'green' "Windowsのサポート：$label（サポート中）"; return }
    $end = if ($ed -match '^(Enterprise|Education|IoTEnterprise)N?$') { $ends[1] } else { $ends[0] }
    if ($TodayStr -gt $end) {
        Add-Result 'red' "この Windows 11（$disp）はサポートが終わっています" `
            "$end でセキュリティの修正が止まりました。PC自体は使えますが、弱点がふさがれなくなります。" `
            '設定 → Windows Update で新しいバージョンに更新してください（無料）。「最新の更新プログラムが利用可能になったらすぐに入手する」をオンにすると早く届きます。'
    }
    else { Add-Result 'green' "Windowsのサポート：$label（$end までサポートあり）" }
}

function Eval-Updates {
    if (-not (Has 'last_update')) {
        Add-Result 'unknown' '最後に更新した日' '' '設定 → Windows Update → 更新の履歴 で、最近の日付があるか確認してください'
    }
    else {
        $days = DaysSince ([string]$F.last_update.date)
        if ($null -eq $days) { Add-Result 'unknown' '最後に更新した日' '' '設定 → Windows Update → 更新の履歴 で確認してください' }
        elseif ($days -gt 45) {
            Add-Result $(if ($days -gt 90) { 'red' } else { 'yellow' }) "Windowsの更新が $days 日間止まっています" `
                "最後に更新されたのは $($F.last_update.date) です。毎月届くセキュリティの修正が入っていません。" `
                '設定 → Windows Update →「更新プログラムのチェック」を押して、最後の「再起動」まで済ませてください。'
        }
        else { Add-Result 'green' "Windowsの更新：$days 日前に更新済み" }
    }
    if ((HasErr 'pending_updates') -or $null -eq $F.PSObject.Properties['pending_updates']) {
        Add-Result 'unknown' 'まだ入っていない更新' '' '設定 → Windows Update で「最新の状態です」と表示されるか確認してください'
        return
    }
    $real = @(AsList $F.pending_updates | Where-Object { @($_.categories) -notcontains $DEFINITION_CATEGORY })
    if ($real.Count -gt 0) {
        Add-Result 'yellow' "まだ入っていない Windows の更新が $($real.Count) 件あります" `
            (($real | Select-Object -First 5 | ForEach-Object { '・' + $_.title }) -join "`n") `
            '設定 → Windows Update から入れて、再起動まで済ませてください（作業の区切りでOK）。'
    }
    else { Add-Result 'green' 'まだ入っていない更新：なし' }
}

function Eval-Encryption {
    $howCheck = '設定 → プライバシーとセキュリティ →「デバイスの暗号化」（無い場合はコントロールパネルの「BitLocker ドライブ暗号化」）が「オン」か確認してください。'
    if (-not (Has 'bitlocker')) { Add-Result 'unknown' 'ディスクの暗号化' '' $howCheck; return }
    $v = $F.bitlocker; $state = $null
    if ($v.source -eq 'cmdlet') {
        if ($v.protection -eq 'On' -or $v.volume -eq 'EncryptionInProgress') { $state = 'on' }
        elseif ($v.volume -eq 'FullyDecrypted') { $state = 'off' }
        elseif ($v.volume -eq 'DecryptionInProgress') { $state = 'off' }
        elseif ($v.volume -eq 'FullyEncrypted') { $state = 'paused' }
    }
    elseif ($v.source -eq 'shell') {
        $state = @{ 1 = 'on'; 3 = 'on'; 6 = 'on'; 2 = 'off'; 4 = 'off'; 5 = 'paused'; 8 = 'paused' }[[int](ToInt $v.shell)]
    }
    $fix = 'Windows 11 Home：設定 → プライバシーとセキュリティ →「デバイスの暗号化」をオン。Pro：コントロールパネル →「BitLocker ドライブ暗号化」で有効にする。' +
    'オンにするときは、表示される「回復キー」を必ず Microsoft アカウントか紙に保存してください（無いと故障時に自分でも開けなくなります）。'
    switch ($state) {
        'on' { Add-Result 'green' 'ディスクの暗号化：オン' }
        'off' { Add-Result 'red' 'ディスクが暗号化されていません' 'PCを紛失・盗難されたとき、中のディスクを取り出すだけで、パスワードを知らなくても全部のファイルを読まれてしまいます。' $fix }
        'paused' { Add-Result 'yellow' 'ディスクの暗号化が一時停止しています' '暗号化はされていますが、鍵がかかっていない状態です。この間は暗号化が効いていません。' ('コントロールパネル →「BitLocker ドライブ暗号化」で「保護の再開」を押してください。' ) }
        default { Add-Result 'unknown' 'ディスクの暗号化' '' $howCheck }
    }
}

function Eval-Antivirus {
    $av = AsList $F.av_products
    $other = ThirdParty $av
    $fix = 'Windows セキュリティ → ウイルスと脅威の防止 →「設定の管理」→「リアルタイム保護」をオンにしてください。'
    if (Has 'defender') {
        $d = $F.defender
        if ($d.av -and $d.realtime) {
            Add-Result 'green' 'ウイルス対策：Microsoft Defender が動いています'
            if ([int]$d.sig_age -gt 7) {
                Add-Result 'yellow' "ウイルスの見本帳（定義ファイル）が $($d.sig_age) 日前のままです" '新しいウイルスを見分けられない可能性があります。' 'Windows セキュリティ → ウイルスと脅威の防止 →「保護の更新」から更新してください。'
            }
            return
        }
        if ($other.Count -gt 0) { Add-Result 'green' ('ウイルス対策：' + ($other -join '、') + ' が動いています'); return }
        if (HasErr 'av_products') { Add-Result 'unknown' 'ウイルス対策' 'Defender は止まっていますが、他のウイルス対策ソフトが入っているかを確認できませんでした。' 'タスクバー右下の「Windows セキュリティ」を開いて、ウイルスと脅威の防止が緑のチェックになっているか確認してください。'; return }
        Add-Result 'red' 'ウイルス対策が動いていません' 'ウイルスやランサムウェアが入ってきても、止める仕組みがない状態です。' $fix
        return
    }
    if (-not (HasErr 'av_products') -and $av.Count -gt 0) {
        $on = @($av | Where-Object { AvOn $_ } | ForEach-Object { [string]$_.name })
        if ($on.Count -gt 0) { Add-Result 'green' ('ウイルス対策：' + ($on -join '、') + ' が動いています') }
        else { Add-Result 'red' 'ウイルス対策が動いていません' '登録されているウイルス対策ソフトが、すべて止まっています。' $fix }
        return
    }
    Add-Result 'unknown' 'ウイルス対策' '' 'タスクバー右下の「Windows セキュリティ」を開いて、緑のチェックが並んでいるか確認してください。'
}

function Eval-Firewall {
    if (-not (Has 'firewall')) { Add-Result 'unknown' 'ファイアウォール' '' 'Windows セキュリティ →「ファイアウォールとネットワーク保護」がすべて「オン」か確認してください。'; return }
    $off = @(AsList $F.firewall | Where-Object { "$($_.enabled)" -match '^(False|0)$' } | ForEach-Object { [string]$_.name })
    if ($off.Count -eq 0) { Add-Result 'green' 'ファイアウォール：オン'; return }
    $other = ThirdParty $F.fw_products
    if ($other.Count -gt 0) { Add-Result 'green' ('ファイアウォール：' + ($other -join '、') + ' が動いています'); return }
    if (HasErr 'fw_products') { Add-Result 'unknown' 'ファイアウォール' 'Windows のファイアウォールの一部がオフですが、他社製品が守っているかを確認できませんでした。' 'Windows セキュリティ →「ファイアウォールとネットワーク保護」で確認してください。'; return }
    $ja = @{ Domain = '会社のネットワーク'; Private = '家・事務所のネットワーク'; Public = 'カフェなどの公衆Wi-Fi' }
    $names = ($off | ForEach-Object { if ($ja[$_]) { $ja[$_] } else { $_ } }) -join '・'
    Add-Result $(if ($off -contains 'Public') { 'red' } else { 'yellow' }) 'ファイアウォールがオフになっています' `
        "オフになっている場所：$names。同じネットワークにいる他人のPCから、このPCに接続を試みられる状態です。" `
        'Windows セキュリティ →「ファイアウォールとネットワーク保護」で、オフになっているものをオンにしてください。'
}

function Eval-ScreenLock {
    $how = '設定 → アカウント → サインイン オプション →「しばらく操作しなかった場合に、もう一度サインインを求めるタイミング」を「PCのスリープを解除する時間」にしてください。離席するときは「Windowsキー + L」で鍵をかけるクセを。'
    if (-not (Has 'screenlock')) { Add-Result 'unknown' 'スリープから戻ったときのサインイン' '' $how; return }
    $s = $F.screenlock
    $delay = ToInt $s.delay_lock
    if ($null -ne $delay) {
        if ($delay -eq 4294967295 -or $delay -eq -1) {   # 「しない」= 0xFFFFFFFF（レジストリからは -1 で読める）
        Add-Result 'yellow' 'スリープから戻ったとき、パスワードなしで使えます' '席を外している間に、誰でもそのまま中を見られます。' $how }
        else { Add-Result 'green' 'スリープから戻ったときのサインイン：あり' }
        return
    }
    $ac = if ($null -ne $s.pol_wake_ac) { ToInt $s.pol_wake_ac } else { ToInt $s.wake_ac }
    $dc = if ($null -ne $s.pol_wake_dc) { ToInt $s.pol_wake_dc } else { ToInt $s.wake_dc }
    if ($ac -eq 0 -or $dc -eq 0) { Add-Result 'yellow' 'スリープから戻ったとき、パスワードなしで使えます' '席を外している間に、誰でもそのまま中を見られます。' $how }
    elseif ($null -ne $ac -or $null -ne $dc) { Add-Result 'green' 'スリープから戻ったときのサインイン：あり' }
    else { Add-Result 'unknown' 'スリープから戻ったときのサインイン' '' $how }
}

function Eval-Autologon {
    if (-not (Has 'autologon')) { Add-Result 'unknown' '自動ログオン' '' '電源を入れたときにパスワードを聞かれるか確認してください'; return }
    $a = $F.autologon
    if ($a.has_password) {
        Add-Result 'red' 'パスワードがPCの中にそのまま保存されています（自動ログオン）' `
            '電源を入れるだけで誰でも使えるうえ、保存されたパスワードを他のソフトやウイルスに読まれる可能性があります。' `
            '詳しい人に「自動ログオンの設定（Winlogon の DefaultPassword）を消してほしい」と伝えてください。そのパスワードは他でも使っていたら変更を。'
    }
    elseif ("$($a.enabled)" -eq '1') {
        Add-Result 'yellow' '電源を入れると、パスワードなしで使えます（自動ログオン）' 'PCを持ち出されたら、そのまま中を見られます。' `
            '「Windowsキー + R」→「netplwiz」と入力 →「ユーザーがこのコンピューターを使うには、ユーザー名とパスワードの入力が必要」にチェックを入れてください。'
    }
    else { Add-Result 'green' '自動ログオン：なし（起動時にサインインが必要）' }
}

function Eval-RDP {
    if (-not (Has 'rdp')) { Add-Result 'unknown' 'リモートデスクトップ' '' '設定 → システム → リモートデスクトップ がオフか確認してください'; return }
    $r = $F.rdp
    $deny = if ($null -ne $r.pol_deny) { ToInt $r.pol_deny } else { ToInt $r.deny }
    if ($deny -ne 0) { Add-Result 'green' 'リモートデスクトップ（外からの遠隔操作）：オフ'; return }
    if ((ToInt $r.nla) -eq 0) {
        Add-Result 'red' '遠隔操作の入口（リモートデスクトップ）が、弱い設定で開いています' `
            '外からこのPCを操作する入口が開いていて、ランサムウェアの侵入口としてよく狙われる設定です。' `
            '使っていなければ 設定 → システム → リモートデスクトップ をオフに。使うなら詳しい人に「NLA（ネットワークレベル認証）を必須に」と伝えてください。'
    }
    else {
        Add-Result 'yellow' '遠隔操作の入口（リモートデスクトップ）が開いています' `
            '外からこのPCを操作できる設定です。パスワードが弱いと乗っ取られる入口になります。' `
            '使っていなければ 設定 → システム → リモートデスクトップ をオフに。使っているなら、強いパスワードにして、社外からはVPN経由に限定するよう詳しい人に相談してください。'
    }
}

function Eval-SMB1 {
    if (-not (Has 'smb1')) { Add-Result 'unknown' '古いファイル共有の仕組み（SMBv1）'; return }
    $s = $F.smb1
    $server = ToInt $s.server
    $on = ($s.client_present -and (ToInt $s.client_start) -ne 4) -or $server -eq 1 -or ($server -ne 0 -and $s.server_present -and (ToInt $s.server_start) -ne 4)
    if ($on) {
        Add-Result 'yellow' '古いファイル共有の仕組み（SMBv1）が有効です' `
            '大規模なランサムウェア被害（WannaCry など）で悪用された、古い仕組みです。' `
            '止める前に、古い複合機の「スキャンしてPCに保存」機能などが使っていないか確認が必要です。詳しい人に「SMB 1.0 を無効にしたい」と相談してください。'
    }
    else { Add-Result 'green' '古いファイル共有の仕組み（SMBv1）：オフ' }
}

function Eval-UAC {
    if (-not (Has 'uac')) { Add-Result 'unknown' '大事な変更の前の確認画面（UAC）'; return }
    if ((ToInt $F.uac.lua) -eq 0) {
        Add-Result 'red' '大事な変更の前の確認画面（UAC）が無効です' 'ウイルスが、確認なしでPCの深いところまで書き換えられる状態です。' `
            'コントロールパネル → ユーザーアカウント →「ユーザーアカウント制御設定の変更」で、上から2番目（既定）に戻してください。'
    }
    elseif ((ToInt $F.uac.admin) -eq 0) {
        Add-Result 'yellow' '大事な変更の前の確認画面（UAC）が出ない設定です' 'ソフトが勝手にPCの設定を変えても、気づけません。' `
            'コントロールパネル → ユーザーアカウント →「ユーザーアカウント制御設定の変更」で、上から2番目（既定）に戻してください。'
    }
    else { Add-Result 'green' '大事な変更の前の確認画面（UAC）：有効' }
}

function Eval-Guest {
    if (-not (Has 'accounts')) { Add-Result 'unknown' '誰でも使える共用アカウント（Guest）' '' '設定 → アカウント → その他のユーザー に、見覚えのないアカウントがないか確認してください'; return }
    if ($F.accounts.guest_enabled) {
        Add-Result 'yellow' '誰でも使える共用アカウント（Guest）が有効です' 'パスワードなしでPCに入れる入口になります。' '詳しい人に「Guest アカウントを無効にしたい」と伝えてください。'
    }
    else { Add-Result 'green' '共用アカウント（Guest）：無効' }
}

function Split-Exe([string]$cmd) {
    $s = $cmd.Trim()
    if ($s.StartsWith('"')) {
        $e = $s.IndexOf('"', 1)
        if ($e -gt 0) { return @($s.Substring(1, $e - 1), $s.Substring($e + 1)) }
        $s = $s.Substring(1)
    }
    $first = ($s -split '\s+')[0]
    $m = [regex]::Match($s, '(?i)^.*?\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|dll|lnk)(?=[\s,]|$)')
    $exe = if ($m.Success) { $m.Value } else { $first }
    if ($exe -match '\s[-/]|=|://' -or ($exe -match ' ' -and $exe -notmatch '^([A-Za-z]:\\|\\\\)')) { $exe = $first }
    return @($exe, $s.Substring([Math]::Min($exe.Length, $s.Length)))
}

function Eval-Startup {
    if (-not (Has 'startup')) { Add-Result 'unknown' '自動で起動するプログラム' '' 'タスクマネージャー →「スタートアップ アプリ」に見覚えのないものがないか確認してください'; return }
    $kindJa = @{ run = '自動起動'; startup = 'スタートアップ'; task = 'タスクスケジューラ'; service = 'サービス' }
    $red = @(); $yellow = @(); $n = 0
    foreach ($it in AsList $F.startup) {
        $n++
        $parts = Split-Exe ([string]$it.cmd)
        $low = ([string]$parts[0]).ToLower()
        $base = [IO.Path]::GetFileName($low)
        if ($base -and -not $base.Contains('.')) { $base += '.exe' }
        $acct = ([string]$it.account).ToLower()
        $system = ($it.kind -eq 'service' -and ($acct -eq '' -or $acct -eq 'localsystem' -or $acct -eq 'nt authority\system'))
        $label = "$($it.name)（$($kindJa[[string]$it.kind])）"   # 起動コマンドや引数は表示しない（秘密が入りうるため）
        if (@($SUSPICIOUS_DIRS | Where-Object { $low.Contains($_) }).Count -gt 0) { $red += $label }
        elseif (($base -eq 'powershell.exe' -or $base -eq 'pwsh.exe') -and ($it.encoded -or ([string]$parts[1] -match '(?i)(^|\s)[-/]e(c|n[a-z]*)?(\s|$)'))) { $red += $label }
        elseif ($system -and $low.Contains('\users\')) { $red += $label }
        elseif ($SCRIPT_HOSTS -contains $base) { $yellow += $label }
    }
    $how = 'すぐに消さず、まず詳しい人に名前を見せて確認してもらってください。止めるときは タスクマネージャー →「スタートアップ アプリ」で「無効化」できます。念のため Windows セキュリティで「フル スキャン」も。'
    if ($red.Count -gt 0) {
        Add-Result 'red' "怪しい場所から自動で起動するプログラムがあります（$($red.Count)件）" `
            ("ウイルスがよく使う場所や方法で、PCの起動時に自動で動くよう登録されています。`n" + (($red | ForEach-Object { '・' + $_ }) -join "`n")) $how
    }
    if ($yellow.Count -gt 0) {
        Add-Result 'yellow' "注意が必要な方法で自動起動するプログラムがあります（$($yellow.Count)件）" `
            ("スクリプトを動かす仕組みを使って自動起動しています。正規のソフトのこともあります。`n" + (($yellow | ForEach-Object { '・' + $_ }) -join "`n")) $how
    }
    if ($red.Count -eq 0 -and $yellow.Count -eq 0) { Add-Result 'green' "自動で起動するプログラム：怪しいものなし（$n 件を確認）" }
}

function Eval-Ports {
    if (-not (Has 'listening')) { Add-Result 'unknown' '外から接続できる入口'; return }
    $hits = @{}
    foreach ($c in AsList $F.listening) {
        $addr = [string]$c.addr; $port = [int](ToInt $c.port)
        if ($addr.StartsWith('127.') -or $addr -eq '::1') { continue }
        if ($RISKY_PORTS.ContainsKey($port)) { $hits[$port] = "$($RISKY_PORTS[$port])（ポート $port・$($c.proc)）" }
    }
    if ($hits.Count -gt 0) {
        Add-Result 'yellow' '外から接続できる入口が開いています' `
            ("同じネットワークの他人から、接続を試みられる状態です。`n" + (($hits.Keys | Sort-Object | ForEach-Object { '・' + $hits[$_] }) -join "`n")) `
            '心当たりがなければ、詳しい人に見てもらって、使っていないソフトなら止めてください。'
    }
    else { Add-Result 'green' '外から接続できる危険な入口：なし' }
}

# ---- 結果のページを作る -----------------------------------------------------

# 注意: 名前を「H」にすると Get-History の別名（h）が優先されてしまう
function Encode-Html([string]$s) { return [System.Net.WebUtility]::HtmlEncode($s) -replace "`n", '<br>' }

function Build-Html {
    $red = @($Results | Where-Object level -eq 'red')
    $yellow = @($Results | Where-Object level -eq 'yellow')
    $unknown = @($Results | Where-Object level -eq 'unknown')
    $green = @($Results | Where-Object level -eq 'green')
    if ($red.Count -gt 0) { $verdict = "すぐに対応してほしいところが $($red.Count) つあります"; $vclass = 'red' }
    elseif ($yellow.Count -gt 0) { $verdict = "大きな問題はありませんが、できれば直したいところが $($yellow.Count) つあります"; $vclass = 'yellow' }
    elseif ($unknown.Count -gt 0) { $verdict = "大きな問題は見つかりませんでしたが、確認できなかったところが $($unknown.Count) つあります"; $vclass = 'unknown' }
    else { $verdict = '大きな問題は見つかりませんでした'; $vclass = 'green' }

    function Cards($items, [string]$cls) {
        ($items | ForEach-Object {
                $body = ''
                if ($_.what) { $body += '<p class="what"><b>何が起きる？</b>' + (Encode-Html $_.what) + '</p>' }
                if ($_.how) { $body += '<p class="how"><b>どうすればいい？</b>' + (Encode-Html $_.how) + '</p>' }
                "<div class=""card $cls""><h3>$(Encode-Html $_.title)</h3>$body</div>"
            }) -join "`n"
    }
    $sections = ''
    if ($red.Count) { $sections += "<h2>🔴 すぐに対応してほしいこと</h2>`n" + (Cards $red 'red') }
    if ($yellow.Count) { $sections += "<h2>🟡 できれば対応したいこと</h2>`n" + (Cards $yellow 'yellow') }
    if ($unknown.Count) { $sections += "<h2>❔ 確認できなかったこと</h2><p class=""note"">「問題なし」という意味ではありません。お手数ですが、下の方法で目で確認してください。</p>`n" + (Cards $unknown 'unknown') }
    if ($green.Count) { $sections += "<h2>🟢 問題なかったこと（$($green.Count)項目）</h2><ul class=""ok"">" + (($green | ForEach-Object { '<li>' + (Encode-Html $_.title) + '</li>' }) -join '') + '</ul>' }

    $pc = Encode-Html ([string]$F.computer)
    $when = $Now.ToString('yyyy年M月d日 HH:mm')
    return @"
<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PCけんこう診断の結果</title>
<style>
body{font-family:"Yu Gothic UI","Meiryo","Hiragino Sans","Noto Sans JP",sans-serif;background:#f6f7f9;color:#1d2330;margin:0;padding:24px 16px;line-height:1.75}
main{max-width:820px;margin:auto}
h1{font-size:28px;margin:0}
.sub{color:#5b6475;font-size:14px;margin:4px 0 20px}
.verdict{border-radius:16px;padding:22px 24px;font-size:22px;font-weight:700;margin-bottom:8px}
.verdict.red{background:#fdecec;color:#a8201a;border:2px solid #e5a3a0}
.verdict.yellow{background:#fff6e0;color:#8a5a00;border:2px solid #f0d08a}
.verdict.green{background:#e8f6ee;color:#1d6b3a;border:2px solid #9fd5b3}
.verdict.unknown{background:#eef0f4;color:#3c4454;border:2px solid #c3c9d4}
.count{font-size:15px;color:#5b6475;margin-bottom:24px}
h2{font-size:20px;margin:32px 0 12px}
.card{background:#fff;border-radius:14px;padding:16px 20px;margin:12px 0;border-left:8px solid #ccc;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.card.red{border-left-color:#d93025}.card.yellow{border-left-color:#f2a600}.card.unknown{border-left-color:#8a93a3}
.card h3{font-size:18px;margin:0 0 8px}
.card p{margin:6px 0;font-size:15.5px}
.card b{display:block;font-size:13px;color:#5b6475}
.how{background:#f1f6ff;border-radius:10px;padding:8px 12px}
.note{color:#5b6475;font-size:14px;margin-top:-4px}
ul.ok{background:#fff;border-radius:14px;padding:14px 20px 14px 40px;font-size:15px}
footer{margin-top:40px;font-size:13px;color:#5b6475;border-top:1px solid #dde1e7;padding-top:16px}
</style></head>
<body><main>
<h1>PCけんこう診断の結果</h1>
<div class="sub">$when ・ PC名：$pc</div>
<div class="verdict $vclass">$(Encode-Html $verdict)</div>
<div class="count">🔴 $($red.Count)　🟡 $($yellow.Count)　❔ $($unknown.Count)　🟢 $($green.Count)</div>
$sections
<footer>
この診断はPCの設定を「見る」だけで、何も変更していません。インターネットにも何も送っていません。<br>
この結果にはPCの弱点が書かれています。相談する相手以外には、むやみに送らないでください。<br>
PCけんこう診断（claude-security-scan Windows対応版）https://github.com/taguro1011/claude-security-scan
</footer>
</main></body></html>
"@
}

# ---- 実行 -------------------------------------------------------------------

try {
    $Now = Get-Date
    $Today = if ($env:PCCHECK_TODAY) { [datetime]::ParseExact($env:PCCHECK_TODAY, 'yyyy-MM-dd', $null) } else { $Now.Date }
    $TodayStr = $Today.ToString('yyyy-MM-dd')

    Write-Host ''
    Write-Host '  ======================================'
    Write-Host '    PCけんこう診断'
    Write-Host '  ======================================'
    Write-Host '  このPCのセキュリティの基本を確認します。設定は何も変えません。'
    Write-Host ''
    if ($env:PCCHECK_FACTS) {
        # テスト用：偽の診断データで判定とページ作りだけを行う
        $F = [IO.File]::ReadAllText($env:PCCHECK_FACTS, [Text.Encoding]::UTF8) | ConvertFrom-Json
    }
    else {
        Write-Host '  1/3  Windows の設定を確認しています...'
        $F = Collect-Facts
    }
    Write-Host '  3/3  結果をまとめています...'
    Eval-OS; Eval-Updates; Eval-Encryption; Eval-Antivirus; Eval-Firewall; Eval-ScreenLock
    Eval-Autologon; Eval-RDP; Eval-SMB1; Eval-UAC; Eval-Guest; Eval-Startup; Eval-Ports

    $dir = if ($env:PCCHECK_OUT) { $env:PCCHECK_OUT } else { Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PCけんこう診断' }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir ('PCけんこう診断_' + $Now.ToString('yyyyMMdd_HHmm') + '.html')
    [IO.File]::WriteAllText($file, (Build-Html), (New-Object System.Text.UTF8Encoding $false))
    if ($env:PCCHECK_RESULTS) { [IO.File]::WriteAllText($env:PCCHECK_RESULTS, (ConvertTo-Json -InputObject ([object[]]$Results.ToArray()) -Depth 3), (New-Object System.Text.UTF8Encoding $false)) }   # テスト用

    $r = @($Results | Where-Object level -eq 'red').Count; $y = @($Results | Where-Object level -eq 'yellow').Count; $u = @($Results | Where-Object level -eq 'unknown').Count
    Write-Host ''
    Write-Host "  完了！ すぐ対応 $r 件 / できれば対応 $y 件 / 確認できなかった $u 件"
    Write-Host "  結果：$file"
    if (-not $env:PCCHECK_NOOPEN) { Start-Process -FilePath $file; Write-Host '  ブラウザで結果を開きました。' }
}
catch {
    Write-Host ''
    Write-Host '  うまく診断できませんでした。この画面を撮影して、相談相手に送ってください。' -ForegroundColor Yellow
    Write-Host ('  ' + $_.Exception.Message) -ForegroundColor Yellow
}
if (-not $env:PCCHECK_NOPAUSE) { Write-Host ''; Read-Host '  Enterキーを押すと閉じます' | Out-Null }
