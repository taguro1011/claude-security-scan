# windows.py から呼ばれる情報収集スクリプト（Windows PowerShell 5.1 で動く書き方）。
# 読み取りだけ。設定の変更・送信・削除はしない。管理者権限は不要（無いと見えない項目は errors に理由を残す）。
# 判定（重要度・直し方）は Python 側で行い、ここは事実を JSON で返すだけ。
# 秘密になりうる値（自動ログオンのパスワード、常駐の引数など）は返さない。
param([ValidateSet('base', 'updates')][string]$Part = 'base')

$ErrorActionPreference = 'Stop'   # PS 5.1 ではモジュールのコマンドに届かないので、各コマンドにも -ErrorAction Stop を付ける
$ProgressPreference = 'SilentlyContinue'
$out = [ordered]@{}
$errs = [ordered]@{}

function Collect([string]$name, [scriptblock]$sb) {
    try { $out[$name] = & $sb }
    catch { $errs[$name] = (($_.Exception.Message -replace '\s+', ' ').Trim()) }
}

function RegVal([string]$path, [string]$name) {
    $p = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    return $p.$name
}

# 本人以外の広いグループ（Everyone / Users / Authenticated Users / Anonymous）に読み取りを許しているか
$BroadSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-7')
function BroadReaders([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    $hits = @()
    foreach ($a in $acl.Access) {
        if ($a.AccessControlType -ne 'Allow') { continue }
        if (([int]$a.FileSystemRights -band 1) -eq 0) { continue }   # ReadData
        try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ($BroadSids -contains $sid) { $hits += $sid }
    }
    return @($hits | Select-Object -Unique)
}

# キー自体が読めないときは「設定なし＝安全」と誤判定しないよう、エラーとして返す
function Need([string]$path) { if (-not (Test-Path -LiteralPath $path)) { throw "レジストリを読めない: $path" } }

function Expand([string]$s) { if ($s) { [Environment]::ExpandEnvironmentVariables($s) } else { $s } }

if ($Part -eq 'updates') {
    Collect 'pending_updates' {
        # 管理者でなくても検索はできる。インストールはしない
        $session = New-Object -ComObject Microsoft.Update.Session
        $res = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $list = @()
        foreach ($u in $res.Updates) {
            $cats = @(); foreach ($c in $u.Categories) { $cats += [string]$c.CategoryID }
            if ($u.BrowseOnly) { continue }   # 「オプションの更新」（プレビュー版など）は数えない
            $rel = $null; try { $rel = $u.LastDeploymentChangeTime.ToString('yyyy-MM-dd') } catch { }
            $list += [ordered]@{ title = [string]$u.Title; msrc = [string]$u.MsrcSeverity; categories = $cats; released = $rel }
        }
        , $list
    }
}
else {
    Collect 'os' {
        $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        [ordered]@{
            build   = [int](RegVal $cv 'CurrentBuildNumber')
            ubr     = RegVal $cv 'UBR'
            display = RegVal $cv 'DisplayVersion'
            edition = RegVal $cv 'EditionID'
        }
    }

    Collect 'last_update' {
        $h = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($h) { [ordered]@{ kb = [string]$h.HotFixID; date = $h.InstalledOn.ToString('yyyy-MM-dd') } } else { $null }
    }

    Collect 'bitlocker' {
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

    Collect 'defender' {
        $m = Get-MpComputerStatus -ErrorAction Stop
        if ($null -eq $m) { throw 'Defender の状態が空で返った' }
        [ordered]@{
            service   = [bool]$m.AMServiceEnabled
            av        = [bool]$m.AntivirusEnabled
            realtime  = [bool]$m.RealTimeProtectionEnabled
            sig_age   = [int]$m.AntivirusSignatureAge
            tamper    = $m.IsTamperProtected
            mode      = [string]$m.AMRunningMode
        }
    }

    Collect 'av_products' {
        , @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
            ForEach-Object { [ordered]@{ name = [string]$_.displayName; state = [int]$_.productState } })
    }

    Collect 'fw_products' {
        , @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop |
            ForEach-Object { [ordered]@{ name = [string]$_.displayName; state = [int]$_.productState } })
    }

    Collect 'firewall' {
        # ActiveStore = グループポリシーも反映した実際に効いている値
        try { $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) } catch { $p = @(Get-NetFirewallProfile -ErrorAction Stop) }
        if ($p.Count -eq 0) { throw 'ファイアウォールのプロファイルが空で返った' }
        , @($p | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled } })
    }

    Collect 'uac' {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Need $k
        [ordered]@{
            lua        = RegVal $k 'EnableLUA'
            admin      = RegVal $k 'ConsentPromptBehaviorAdmin'
            secure     = RegVal $k 'PromptOnSecureDesktop'
            inactivity = RegVal $k 'InactivityTimeoutSecs'
        }
    }

    Collect 'autologon' {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Need $k
        [ordered]@{
            enabled      = [string](RegVal $k 'AutoAdminLogon')
            user         = [string](RegVal $k 'DefaultUserName')
            has_password = (-not [string]::IsNullOrEmpty([string](RegVal $k 'DefaultPassword')))   # 値そのものは返さない（空文字はOEMの残骸なので数えない）
        }
    }

    Collect 'screenlock' {
        $d = 'HKCU:\Control Panel\Desktop'
        $pd = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
        $r = [ordered]@{
            ss_active  = RegVal $d 'ScreenSaveActive'; ss_secure = RegVal $d 'ScreenSaverIsSecure'; ss_timeout = RegVal $d 'ScreenSaveTimeOut'
            pol_active = RegVal $pd 'ScreenSaveActive'; pol_secure = RegVal $pd 'ScreenSaverIsSecure'; pol_timeout = RegVal $pd 'ScreenSaveTimeOut'
            wake_ac = $null; wake_dc = $null
            delay_lock = RegVal $d 'DelayLockInterval'   # Modern Standby のPCはこちらが「再度サインインを求めるタイミング」
            pol_wake_ac = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'ACSettingIndex'
            pol_wake_dc = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'DCSettingIndex'
        }
        # スリープ復帰時にサインインを求めるか（CONSOLELOCK）。表示は日本語でも 0x... の値は共通
        # PS 5.1 は外部コマンドの標準エラーを Stop 扱いで例外にするので、この呼び出しだけ Continue にする
        $q = & { $ErrorActionPreference = 'Continue'; powercfg /query SCHEME_CURRENT SUB_NONE CONSOLELOCK 2>$null }
        $vals = @($q | Select-String -Pattern '0x([0-9a-fA-F]{8})\s*$' | ForEach-Object { [Convert]::ToInt32($_.Matches[0].Groups[1].Value, 16) })
        if ($vals.Count -ge 2) { $r.wake_ac = $vals[$vals.Count - 2]; $r.wake_dc = $vals[$vals.Count - 1] }
        $r
    }

    Collect 'listening' {
        $names = @{}; Get-Process -ErrorAction Stop | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
        $conns = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        if ($conns.Count -eq 0) { throw '待ち受けポートの一覧が空で返った' }
        , @($conns | ForEach-Object {
                [ordered]@{ addr = [string]$_.LocalAddress; port = [int]$_.LocalPort; proc = [string]$names[[int]$_.OwningProcess] }
            })
    }

    Collect 'rdp' {
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        Need $ts
        [ordered]@{
            deny     = RegVal $ts 'fDenyTSConnections'
            pol_deny = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
            nla      = RegVal "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
            port     = RegVal "$ts\WinStations\RDP-Tcp" 'PortNumber'
        }
    }

    Collect 'smb1' {
        $cl = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
        Need 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer'
        [ordered]@{
            client_present = (Test-Path -LiteralPath $cl)
            client_start   = RegVal $cl 'Start'
            server         = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
            # SMBv1 サーバーのドライバ（機能を外すと消える）
            server_present = (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\srv')
            server_start   = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\srv' 'Start'
        }
    }

    Collect 'secureboot' {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
        if (Test-Path -LiteralPath $k) { [ordered]@{ enabled = RegVal $k 'UEFISecureBootEnabled' } } else { $null }
    }

    Collect 'accounts' {
        # 管理者グループ(S-1-5-32-544)のメンバーか。UACで制限中でもトークンにSIDは載っている
        $g = (& { $ErrorActionPreference = 'Continue'; whoami /groups /fo csv 2>$null }) -join "`n"
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
        [ordered]@{
            is_admin      = ($g -match 'S-1-5-32-544')
            guest_enabled = if ($guest) { [bool]$guest.Enabled } else { $null }
        }
    }

    Collect 'secret_files' {
        $ssh = Join-Path $HOME '.ssh'
        $skip = @('known_hosts', 'known_hosts.old', 'config', 'authorized_keys')
        $keys = @()
        if (Test-Path -LiteralPath $ssh) {
            foreach ($f in Get-ChildItem -LiteralPath $ssh -File -Force) {
                if ($f.Extension -eq '.pub' -or $skip -contains $f.Name) { continue }
                $keys += [ordered]@{ path = $f.FullName; broad = @(BroadReaders $f.FullName) }
            }
        }
        $ak = Join-Path $ssh 'authorized_keys'
        $akCount = 0
        if (Test-Path -LiteralPath $ak) { $akCount = @(Get-Content -LiteralPath $ak | Where-Object { $_.Trim() -and -not $_.StartsWith('#') }).Count }
        $others = @()
        foreach ($n in @('.aws\credentials', '.git-credentials', '.netrc', '_netrc', '.npmrc', '.pypirc')) {
            $p = Join-Path $HOME $n
            if (Test-Path -LiteralPath $p -PathType Leaf) { $others += [ordered]@{ name = $n; path = $p; broad = @(BroadReaders $p) } }
        }
        [ordered]@{ ssh_dir = (Test-Path -LiteralPath $ssh); ssh_keys = $keys; authorized_keys = $akCount; files = $others }
    }

    Collect 'startup' {
        $items = @()
        $runKeys = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
        foreach ($k in $runKeys) {
            $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
            if (-not $p) { continue }
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }
                $items += [ordered]@{ kind = 'run'; where = $k; name = $prop.Name; cmd = (Expand ([string]$prop.Value)); account = $null }
            }
        }
        $wsh = New-Object -ComObject WScript.Shell
        foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
            foreach ($f in Get-ChildItem -LiteralPath $folder -File -Force) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $target = $f.FullName
                if ($f.Extension -eq '.lnk') { $target = $wsh.CreateShortcut($f.FullName).TargetPath }   # 読むだけ（Saveしない）
                $items += [ordered]@{ kind = 'startup'; where = $folder; name = $f.Name; cmd = ('"' + $target + '"'); account = $null }
            }
        }
        try {
            foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
                if ($t.TaskPath -like '\Microsoft\*') { continue }
                $exe = ($t.Actions | Where-Object { $_.Execute } | Select-Object -First 1).Execute
                if (-not $exe) { continue }
                $cmd = '"' + (Expand ($exe.Trim('"'))) + '"'
                # 引数は記録しないが、難読化されたPowerShellかどうかだけは判定する
                $args0 = [string](($t.Actions | Where-Object { $_.Execute } | Select-Object -First 1).Arguments)
                $enc = ($args0 -match '(?i)(^|\s)[-/]e(c|n[a-z]*)?(\s|$)')
                $items += [ordered]@{ kind = 'task'; where = $t.TaskPath; name = $t.TaskName; cmd = $cmd; account = [string]$t.Principal.UserId; encoded = $enc }
            }
        }
        catch { $errs['tasks'] = (($_.Exception.Message -replace '\s+', ' ').Trim()) }
        $win = $env:windir.TrimEnd('\') + '\'
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            $path = Expand ([string]$s.PathName)
            if (-not $path -or $path.Trim('"').StartsWith($win, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $items += [ordered]@{ kind = 'service'; where = [string]$s.StartMode; name = [string]$s.Name; cmd = $path; account = [string]$s.StartName }
        }
        , $items
    }
}

$out['errors'] = $errs
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$json = $out | ConvertTo-Json -Depth 6 -Compress
[Console]::Out.Write($json)
