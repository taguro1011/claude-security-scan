"""windows.py の判定ロジックのテスト。probe の JSON を偽物にして、Windows 以外でも回せるようにしてある。

  python -m unittest discover -s tests
"""
from __future__ import annotations

import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sscan import windows  # noqa: E402
from sscan.common import Result  # noqa: E402

TODAY = date(2026, 10, 20)

# 問題の無い Windows 11 25H2 の見本
GOOD = {
    "os": {"build": 26200, "ubr": 6899, "display": "25H2", "edition": "Professional"},
    "last_update": {"kb": "KB5099999", "date": "2026-10-15"},
    "bitlocker": {"drive": "C:", "source": "shell", "shell": 1},
    "defender": {"service": True, "av": True, "realtime": True, "sig_age": 0, "tamper": True, "mode": "Normal"},
    "av_products": [{"name": "Windows Defender", "state": 397568}],
    "fw_products": [],
    "firewall": [{"name": "Domain", "enabled": "True"}, {"name": "Private", "enabled": "True"}, {"name": "Public", "enabled": "True"}],
    "uac": {"lua": 1, "admin": 5, "secure": 1, "inactivity": None},
    "autologon": {"enabled": "0", "user": "taro", "has_password": False},
    "screenlock": {"wake_ac": 1, "wake_dc": 1},
    "listening": [{"addr": "0.0.0.0", "port": 135, "proc": "svchost"}, {"addr": "::", "port": 445, "proc": "System"},
                  {"addr": "127.0.0.1", "port": 3000, "proc": "node"}],
    "rdp": {"deny": 1, "nla": 1, "port": 3389},
    "smb1": {"client_present": False, "client_start": None, "server": None},
    "secureboot": {"enabled": 1},
    "accounts": {"is_admin": False, "guest_enabled": False},
    "secret_files": {"ssh_dir": False, "ssh_keys": [], "authorized_keys": 0, "files": []},
    "startup": [],
    "errors": {},
}


def run(**over) -> Result:
    data = {**GOOD, **over}
    r = Result()
    windows.evaluate(r, data, TODAY)
    return r


def titles(r: Result, sev: str | None = None) -> list[str]:
    return [f.title for f in r.findings if sev is None or f.severity == sev]


class Healthy(unittest.TestCase):
    def test_no_findings(self):
        r = run()
        self.assertEqual(titles(r), [])
        self.assertTrue(all(c.status == "ok" for c in r.coverage), [(c.item, c.message) for c in r.coverage if c.status != "ok"])


class OsSupport(unittest.TestCase):
    def test_24h2_home_pro_ended(self):
        r = run(os={"build": 26100, "ubr": 1, "display": "24H2", "edition": "Core"})
        self.assertIn("サポートが終了したWindows 11のバージョン（24H2）", titles(r, "high"))

    def test_24h2_enterprise_still_supported(self):
        r = run(os={"build": 26100, "ubr": 1, "display": "24H2", "edition": "Enterprise"})
        self.assertEqual(titles(r), [])

    def test_win10_with_recent_updates_is_esu(self):
        r = run(os={"build": 19045, "ubr": 1, "display": "22H2", "edition": "Professional"})
        self.assertIn("Windows 10（サポートが終了したOS）", titles(r, "medium"))

    def test_win10_without_updates(self):
        r = run(os={"build": 19045, "ubr": 1, "display": "22H2", "edition": "Professional"},
                last_update={"kb": "KB1", "date": "2025-09-01"})
        self.assertIn("Windows 10（サポートが終了したOS）", titles(r, "high"))
        self.assertIn("Windowsの更新が長く適用されていない", titles(r, "high"))

    def test_ltsc_skipped(self):
        r = run(os={"build": 19044, "ubr": 1, "display": "21H2", "edition": "EnterpriseS"})
        self.assertEqual(titles(r), [])

    def test_pending_updates(self):
        r = run(pending_updates=[{"title": "2026-10 累積更新プログラム", "msrc": "", "categories": ["0fa1201d-4330-4fa8-8ae9-b877473b6441"]}])
        self.assertIn("未適用のWindows更新プログラムがある", titles(r, "high"))
        r = run(pending_updates=[{"title": "定義", "msrc": "", "categories": [windows.DEFINITION_CATEGORY]}])
        self.assertEqual(titles(r), [])


class Protection(unittest.TestCase):
    def test_bitlocker_off(self):
        self.assertIn("ディスク暗号化（BitLocker / デバイスの暗号化）がオフ", titles(run(bitlocker={"source": "shell", "shell": 2}), "critical"))

    def test_bitlocker_waiting(self):
        self.assertTrue(any("ディスク暗号化が効いていない" in t for t in titles(run(bitlocker={"source": "shell", "shell": 8}), "high")))

    def test_bitlocker_unknown_is_not_ok(self):
        r = run(bitlocker={"source": "shell", "shell": None})
        self.assertEqual(titles(r), [])
        self.assertTrue(any(c.item == "ディスク暗号化" and c.status == "error" for c in r.coverage))

    def test_bitlocker_admin_cmdlet(self):
        self.assertEqual(titles(run(bitlocker={"source": "cmdlet", "protection": "On"})), [])

    def test_defender_off(self):
        r = run(defender={**GOOD["defender"], "realtime": False})
        self.assertIn("ウイルス対策のリアルタイム保護がオフ", titles(r, "critical"))

    def test_third_party_av(self):
        r = run(defender={**GOOD["defender"], "realtime": False, "av": False, "mode": "Passive Mode"},
                av_products=[{"name": "Windows Defender", "state": 393472}, {"name": "ESET Security", "state": 266240}])
        self.assertEqual(titles(r), [])

    def test_passive_without_other(self):
        r = run(defender={**GOOD["defender"], "realtime": False, "mode": "Passive Mode"}, av_products=[])
        self.assertIn("ウイルス対策が動いていない", titles(r, "critical"))

    def test_signature_old(self):
        self.assertIn("ウイルス対策の定義ファイルが古い", titles(run(defender={**GOOD["defender"], "sig_age": 12}), "medium"))

    def test_defender_unreadable_uses_products(self):
        r = run(defender=None, errors={"defender": "Access denied"}, av_products=[{"name": "Windows Defender", "state": 393472}])
        self.assertIn("ウイルス対策が動いていない", titles(r, "critical"))

    def test_firewall_public_off(self):
        r = run(firewall=[{"name": "Domain", "enabled": "True"}, {"name": "Private", "enabled": "True"}, {"name": "Public", "enabled": "False"}])
        self.assertIn("ファイアウォールがオフ（パブリック）", titles(r, "high"))

    def test_firewall_off_but_third_party(self):
        r = run(firewall=[{"name": "Public", "enabled": "False"}], fw_products=[{"name": "ESET Firewall", "state": 266256}])
        self.assertEqual(titles(r), [])


class Signin(unittest.TestCase):
    def test_uac_off(self):
        self.assertIn("ユーザーアカウント制御（UAC）が無効", titles(run(uac={"lua": 0, "admin": 0, "secure": 0}), "high"))

    def test_autologon_with_password(self):
        r = run(autologon={"enabled": "1", "user": "taro", "has_password": True})
        self.assertIn("自動ログオンのパスワードがレジストリに平文で保存されている", titles(r, "critical"))
        self.assertIn("自動ログオンが有効", titles(r, "high"))
        self.assertNotIn("secret", " ".join(f.detail for f in r.findings))

    def test_wake_without_signin(self):
        self.assertIn("スリープ復帰時にサインインを求めない設定", titles(run(screenlock={"wake_ac": 0, "wake_dc": 1}), "medium"))

    def test_wake_policy_overrides(self):
        self.assertEqual(titles(run(screenlock={"wake_ac": 0, "wake_dc": 0, "pol_wake_ac": 1, "pol_wake_dc": 1})), [])

    def test_admin_and_guest(self):
        r = run(accounts={"is_admin": True, "guest_enabled": True})
        self.assertIn("Guestアカウントが有効", titles(r, "medium"))
        self.assertIn("普段使いのアカウントが管理者", titles(r, "low"))


class Network(unittest.TestCase):
    def test_ports(self):
        r = run(listening=GOOD["listening"] + [{"addr": "0.0.0.0", "port": 3389, "proc": "svchost"},
                                                {"addr": "::", "port": 5173, "proc": "node"}])
        self.assertIn("外部から接続を受け付けるポート 3389（リモートデスクトップ）", titles(r, "medium"))
        self.assertIn("外部から接続を受け付けるポート 5173", titles(r, "low"))
        self.assertFalse(any("135" in t or "445" in t for t in titles(r)))

    def test_rdp(self):
        self.assertIn("リモートデスクトップがネットワークレベル認証（NLA）なしで有効", titles(run(rdp={"deny": 0, "nla": 0}), "high"))
        self.assertIn("リモートデスクトップが有効", titles(run(rdp={"deny": 0, "nla": 1}), "medium"))
        self.assertEqual(titles(run(rdp={"deny": 0, "pol_deny": 1, "nla": 0})), [])

    def test_smb1(self):
        self.assertIn("SMBv1（古いファイル共有の仕組み）が有効", titles(run(smb1={"client_present": True, "client_start": 3}), "high"))
        self.assertEqual(titles(run(smb1={"client_present": True, "client_start": 4})), [])


class Files(unittest.TestCase):
    def test_secret_files(self):
        r = run(secret_files={"ssh_dir": True, "authorized_keys": 2,
                              "ssh_keys": [{"path": "C:\\Users\\t\\.ssh\\id_ed25519", "broad": ["S-1-5-32-545"]}],
                              "files": [{"name": ".aws\\credentials", "path": "C:\\Users\\t\\.aws\\credentials", "broad": []},
                                        {"name": ".git-credentials", "path": "C:\\Users\\t\\.git-credentials", "broad": ["S-1-1-0"]}]})
        self.assertIn("SSH秘密鍵が他のユーザーからも読める", titles(r, "high"))
        self.assertIn("AWSの長期アクセスキーファイルが存在する", titles(r, "medium"))
        self.assertIn("Gitのパスワード・トークンが平文ファイルに保存されている", titles(r, "medium"))
        self.assertIn("秘密情報を含むファイルが他のユーザーからも読める", titles(r, "medium"))


class Startup(unittest.TestCase):
    def sev(self, **item) -> str:
        r = run(startup=[{"kind": "run", "where": "HKCU:\\...\\Run", "name": "x", "account": None, **item}])
        return r.findings[0].severity

    def test_split_cmd(self):
        self.assertEqual(windows.split_cmd('"C:\\Program Files\\A\\a.exe" --token=abc'), ("C:\\Program Files\\A\\a.exe", " --token=abc", False))
        self.assertEqual(windows.split_cmd("C:\\Program Files\\A\\a.exe -k"), ("C:\\Program Files\\A\\a.exe", " -k", True))
        self.assertEqual(windows.split_cmd("C:\\Windows\\system32\\svchost.exe"), ("C:\\Windows\\system32\\svchost.exe", "", False))

    def test_temp_folder(self):
        self.assertEqual(self.sev(cmd="C:\\Users\\t\\AppData\\Local\\Temp\\upd.exe"), "high")

    def test_encoded_powershell(self):
        self.assertEqual(self.sev(cmd="powershell.exe -w hidden -enc SQBFAFgA"), "high")
        r = run(startup=[{"kind": "task", "where": "\\", "name": "t", "cmd": '"powershell.exe"', "account": "taro", "encoded": True}])
        self.assertEqual(r.findings[0].severity, "high")

    def test_script_host(self):
        self.assertEqual(self.sev(cmd="mshta.exe http://example.invalid/a.hta"), "medium")

    def test_system_service_in_user_folder(self):
        r = run(startup=[{"kind": "service", "where": "Auto", "name": "svc", "cmd": '"C:\\Users\\t\\AppData\\Roaming\\x\\svc.exe"', "account": "LocalSystem"}])
        self.assertEqual(r.findings[0].severity, "high")

    def test_args_not_recorded(self):
        r = run(startup=[{"kind": "run", "where": "HKCU", "name": "x", "cmd": '"C:\\Users\\t\\Downloads\\a.exe" --password=hunter2', "account": None}])
        self.assertNotIn("hunter2", r.findings[0].detail)

    def test_key_stable_for_service_start_mode(self):
        a = run(startup=[{"kind": "service", "where": "Auto", "name": "svc", "cmd": "x.exe", "account": "LocalSystem"}]).findings[0].key
        b = run(startup=[{"kind": "service", "where": "Manual", "name": "svc", "cmd": "x.exe", "account": "LocalSystem"}]).findings[0].key
        self.assertEqual(a, b)


class Errors(unittest.TestCase):
    def test_errors_become_coverage(self):
        r = run(firewall=None, errors={"firewall": "Access is denied"})
        cov = [c for c in r.coverage if c.item == "ファイアウォール"]
        self.assertEqual(cov[0].status, "error")
        self.assertEqual(titles(r), [])

    def test_tasks_error_blocks_only_tasks(self):
        r = run(errors={"tasks": "denied"})
        c = [c for c in r.coverage if c.item == "タスクスケジューラ"][0]
        self.assertEqual(c.blocks, [("常駐", "タスクスケジューラ")])


class ReviewFixes(unittest.TestCase):
    """独立レビューで見つかった穴の再発防止。"""

    def test_args_after_extensionless_exe_are_not_recorded(self):
        r = run(startup=[{"kind": "run", "where": "HKCU", "name": "x", "cmd": "C:\\tools\\agent --token SECRET123 --cfg x.js", "account": None}])
        self.assertNotIn("SECRET123", r.findings[0].detail)
        r = run(startup=[{"kind": "run", "where": "HKCU", "name": "x", "cmd": '"C:\\a b\\x.exe --password=hunter2', "account": None}])
        self.assertNotIn("hunter2", r.findings[0].detail)

    def test_encoded_variants(self):
        for cmd in ("powershell -w hidden -ec SQBFAFgA", "powershell.exe /enc AAA", "pwsh -EncodedCommand AAA", "powershell -e AAA"):
            r = run(startup=[{"kind": "run", "where": "HKCU", "name": "x", "cmd": cmd, "account": None}])
            self.assertEqual(r.findings[0].severity, "high", cmd)
        r = run(startup=[{"kind": "run", "where": "HKCU", "name": "x", "cmd": "powershell -ExecutionPolicy Bypass -File C:\\a.ps1", "account": None}])
        self.assertNotEqual(r.findings[0].severity, "high")
        r = run(startup=[{"kind": "run", "where": "HKCU", "name": "x", "cmd": "mshta http://example.invalid/a.hta", "account": None}])
        self.assertEqual(r.findings[0].severity, "medium")

    def test_fresh_security_update_is_medium(self):
        fresh = (TODAY.replace(day=14)).isoformat()
        sec = ["0fa1201d-4330-4fa8-8ae9-b877473b6441"]
        self.assertIn("未適用のWindows更新プログラムがある",
                      titles(run(pending_updates=[{"title": "a", "categories": sec, "released": fresh}]), "medium"))
        self.assertIn("未適用のWindows更新プログラムがある",
                      titles(run(pending_updates=[{"title": "a", "categories": sec, "released": "2026-09-09"}]), "high"))

    def test_bitlocker_admin_and_non_admin_agree(self):
        admin = titles(run(bitlocker={"source": "cmdlet", "protection": "Off", "volume": "FullyEncrypted"}))
        shell = titles(run(bitlocker={"source": "shell", "shell": 5}))
        self.assertEqual(admin, shell)
        self.assertIn("ディスク暗号化（BitLocker / デバイスの暗号化）がオフ",
                      titles(run(bitlocker={"source": "cmdlet", "protection": "Off", "volume": "FullyDecrypted"}), "critical"))

    def test_modern_standby_never(self):
        self.assertIn("スリープ復帰時にサインインを求めない設定", titles(run(screenlock={"delay_lock": 4294967295, "wake_ac": 1, "wake_dc": 1})))
        self.assertEqual(titles(run(screenlock={"delay_lock": 0, "wake_ac": 0, "wake_dc": 0})), [])

    def test_smb1_server_driver(self):
        self.assertIn("SMBv1（古いファイル共有の仕組み）が有効",
                      titles(run(smb1={"client_present": False, "server": None, "server_present": True, "server_start": 3})))
        self.assertEqual(titles(run(smb1={"client_present": False, "server": 0, "server_present": True, "server_start": 3})), [])

    def test_unknown_third_party_is_not_critical(self):
        r = run(defender={**GOOD["defender"], "realtime": False, "av": False, "mode": "Passive Mode"},
                av_products=None, errors={"av_products": "Invalid namespace"})
        self.assertEqual(titles(r), [])
        self.assertTrue(any(c.item == "ウイルス対策" and c.status == "error" for c in r.coverage))
        r = run(firewall=[{"name": "Public", "enabled": "False"}], fw_products=None, errors={"fw_products": "Invalid namespace"})
        self.assertEqual(titles(r), [])

    def test_ps51_wrapped_arrays(self):
        r = run(listening={"value": [{"addr": "0.0.0.0", "port": 5900, "proc": "vncserver"}], "Count": 1})
        self.assertIn("外部から接続を受け付けるポート 5900（VNC）", titles(r))
        r = run(listening={"addr": "0.0.0.0", "port": 5900, "proc": "vncserver"})  # 要素1つが素のオブジェクト
        self.assertIn("外部から接続を受け付けるポート 5900（VNC）", titles(r))
        r = run(startup="broken")
        self.assertTrue(any(c.item == "常駐プログラム" and c.status == "error" for c in r.coverage))

    def test_pro_education_follows_pro_timeline(self):
        r = run(os={"build": 26100, "ubr": 1, "display": "24H2", "edition": "ProfessionalEducation"})
        self.assertIn("サポートが終了したWindows 11のバージョン（24H2）", titles(r))

    def test_secureboot_value_missing_is_skip(self):
        r = run(secureboot={"enabled": None})
        self.assertTrue(any(c.item == "セキュアブート" and c.status == "skip" for c in r.coverage))


if __name__ == "__main__":
    unittest.main()
