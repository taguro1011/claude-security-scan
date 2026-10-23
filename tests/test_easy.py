"""ダブルクリック版（PCけんこう診断.cmd）の判定とページ作りのテスト。

偽の診断データ（PCCHECK_FACTS）を渡して、判定と HTML の中身を確かめる。
PowerShell（pwsh / powershell）が無い環境ではスキップする。

  python -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "PCけんこう診断.cmd"
PWSH = os.environ.get("PWSH") or shutil.which("pwsh") or shutil.which("powershell")
SEC = "0fa1201d-4330-4fa8-8ae9-b877473b6441"

GOOD = {
    "computer": "TEST-PC",
    "os": {"build": 26300, "ubr": 9711, "display": "26H2", "edition": "Professional"},
    "last_update": {"kb": "KB5099999", "date": "2026-10-14"},
    "bitlocker": {"drive": "C:", "source": "shell", "shell": 1},
    "defender": {"av": True, "realtime": True, "sig_age": 0, "mode": "Normal"},
    "av_products": [{"name": "Windows Defender", "state": 397568}],
    "fw_products": [],
    "firewall": [{"name": "Domain", "enabled": "True"}, {"name": "Private", "enabled": "True"}, {"name": "Public", "enabled": "True"}],
    "uac": {"lua": 1, "admin": 5},
    "autologon": {"enabled": "0", "has_password": False},
    "screenlock": {"wake_ac": 1, "wake_dc": 1, "delay_lock": None, "pol_wake_ac": None, "pol_wake_dc": None},
    "listening": [{"addr": "0.0.0.0", "port": 135, "proc": "svchost"}, {"addr": "::", "port": 3000, "proc": "node"},
                  {"addr": "127.0.0.1", "port": 5900, "proc": "local-only"}],
    "rdp": {"deny": 1, "pol_deny": None, "nla": 1},
    "smb1": {"client_present": False, "client_start": None, "server": None, "server_present": False, "server_start": None},
    "accounts": {"guest_enabled": False},
    "startup": [
        {"kind": "run", "name": "OneDrive", "cmd": '"C:\\Users\\t\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', "account": "", "encoded": False},
        {"kind": "service", "name": "GoogleUpdater", "cmd": '"C:\\Program Files (x86)\\Google\\GoogleUpdater\\updater.exe" --system', "account": "LocalSystem", "encoded": False},
    ],
    "pending_updates": [],
    "errors": {},
}

BAD = {
    **GOOD,
    "os": {"build": 26100, "ubr": 1, "display": "24H2", "edition": "Core"},
    "last_update": {"kb": "KB1", "date": "2026-06-01"},
    "bitlocker": {"drive": "C:", "source": "shell", "shell": 2},
    "defender": {"av": False, "realtime": False, "sig_age": 0, "mode": "Normal"},
    "av_products": [{"name": "Windows Defender", "state": 393472}],
    "firewall": [{"name": "Domain", "enabled": "True"}, {"name": "Private", "enabled": "True"}, {"name": "Public", "enabled": "False"}],
    "uac": {"lua": 0, "admin": 0},
    "autologon": {"enabled": "1", "has_password": True},
    "screenlock": {"wake_ac": 1, "wake_dc": 1, "delay_lock": -1, "pol_wake_ac": None, "pol_wake_dc": None},
    "listening": [{"addr": "0.0.0.0", "port": 5900, "proc": "tvnserver"}],
    "rdp": {"deny": 0, "pol_deny": None, "nla": 0},
    "smb1": {"client_present": True, "client_start": 3, "server": None, "server_present": False, "server_start": None},
    "accounts": {"guest_enabled": True},
    "startup": [
        {"kind": "run", "name": "Updater", "cmd": "C:\\Users\\t\\Downloads\\agent.exe --token SECRET123", "account": "", "encoded": False},
        {"kind": "run", "name": "Hidden", "cmd": "powershell -w hidden -ec SQBFAFgA", "account": "", "encoded": False},
        {"kind": "task", "name": "Helper", "cmd": '"mshta.exe"', "account": "taro", "encoded": False},
        {"kind": "run", "name": "OneDrive", "cmd": '"C:\\Users\\t\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', "account": "", "encoded": False},
    ],
    "pending_updates": [{"title": "2026-10 累積更新プログラム", "categories": [SEC]}],
}

ALL_KEYS = ["os", "last_update", "bitlocker", "defender", "av_products", "fw_products", "firewall", "uac", "autologon",
            "screenlock", "listening", "rdp", "smb1", "accounts", "startup", "pending_updates"]
BROKEN = {"computer": "TEST-PC", "errors": {k: "Access is denied" for k in ALL_KEYS}}


@unittest.skipUnless(PWSH, "PowerShell が無いのでスキップ")
class EasyCheck(unittest.TestCase):
    def run_script(self, facts: dict) -> tuple[list[dict], str]:
        with tempfile.TemporaryDirectory() as d:
            fp, rp = Path(d, "facts.json"), Path(d, "results.json")
            fp.write_text(json.dumps(facts, ensure_ascii=False), encoding="utf-8")
            env = {**os.environ, "PCCHECK_FACTS": str(fp), "PCCHECK_OUT": d, "PCCHECK_RESULTS": str(rp),
                   "PCCHECK_NOOPEN": "1", "PCCHECK_NOPAUSE": "1", "PCCHECK_TODAY": "2026-10-23", "PCCHECK_SELF": str(SCRIPT)}
            # .cmd を実際と同じやり方（ファイル全体を UTF-8 で読んで実行）で動かす
            cmd = "$t=[IO.File]::ReadAllText($env:PCCHECK_SELF,[Text.Encoding]::UTF8); Invoke-Expression $t"
            p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", cmd], env=env,
                               capture_output=True, text=True, encoding="utf-8", timeout=120)
            self.assertTrue(rp.exists(), p.stdout + p.stderr)
            results = json.loads(rp.read_text(encoding="utf-8-sig"))
            html = next(Path(d).glob("PCけんこう診断_*.html")).read_text(encoding="utf-8")
            return results, html

    @staticmethod
    def by(results, level):
        return [r["title"] for r in results if r["level"] == level]

    def test_good_pc(self):
        results, html = self.run_script(GOOD)
        self.assertEqual(self.by(results, "red"), [])
        self.assertEqual(self.by(results, "yellow"), [])
        self.assertEqual(self.by(results, "unknown"), [])
        self.assertIn("大きな問題は見つかりませんでした", html)
        self.assertGreaterEqual(len(self.by(results, "green")), 12)

    def test_bad_pc(self):
        results, html = self.run_script(BAD)
        red = " ".join(self.by(results, "red"))
        yellow = " ".join(self.by(results, "yellow"))
        for t in ["Windows 11（24H2）はサポートが終わっています", "更新が 144 日間止まっています", "ディスクが暗号化されていません",
                  "ウイルス対策が動いていません", "ファイアウォールがオフ", "UAC）が無効", "パスワードがPCの中にそのまま保存",
                  "リモートデスクトップ）が、弱い設定", "怪しい場所から自動で起動するプログラムがあります（2件）"]:
            self.assertIn(t, red)
        for t in ["スリープから戻ったとき", "SMBv1", "Guest", "外から接続できる入口", "注意が必要な方法で自動起動（1件）".replace("（1件）", ""),
                  "まだ入っていない Windows の更新が 1 件"]:
            self.assertIn(t, yellow)
        self.assertNotIn("自動ログオン", yellow)   # パスワード保存（赤）がある時は、同じ話を黄色で重ねない
        self.assertIn("画面共有ソフト（VNC）（ポート 5900・tvnserver）", html)
        self.assertNotIn("local-only", html)      # 127.0.0.1 だけで待っているものは外から入れないので出さない
        self.assertIn("すぐに対応してほしいところが", html)
        self.assertNotIn("SECRET123", html)   # 起動引数は表示しない
        self.assertNotIn("agent.exe", html)   # 起動コマンド自体も表示しない（名前だけ）

    def test_unreadable_is_not_ok(self):
        results, html = self.run_script(BROKEN)
        self.assertEqual(self.by(results, "red"), [])
        self.assertEqual(self.by(results, "green"), [])   # 読めなかったものを「問題なし」にしない
        self.assertGreaterEqual(len(self.by(results, "unknown")), 12)
        self.assertIn("確認できなかったところが", html)

    def test_third_party_av_and_win10_esu(self):
        f = {**GOOD, "os": {"build": 19045, "ubr": 1, "display": "22H2", "edition": "Professional"},
             "defender": {"av": False, "realtime": False, "sig_age": 0, "mode": "Passive Mode"},
             "av_products": [{"name": "Windows Defender", "state": 393472}, {"name": "ESET Security", "state": 266240}],
             "firewall": [{"name": "Public", "enabled": "False"}], "fw_products": [{"name": "ESET Firewall", "state": 266256}]}
        results, _ = self.run_script(f)
        self.assertEqual(self.by(results, "red"), [])
        self.assertEqual(self.by(results, "yellow"), ["Windows 10 を使っています（通常のサポートは終了済み）"])

    def test_batch_header_is_ascii_and_crlf(self):
        b = SCRIPT.read_bytes()
        self.assertFalse(b.startswith(b"\xef\xbb\xbf"))           # BOM があると cmd が1行目を読めない
        head = b.split(b"#>")[0]
        self.assertTrue(all(c < 128 for c in head))               # cmd は UTF-8 を読めないので英数字だけ
        self.assertNotIn(b"\n", b.replace(b"\r\n", b""))          # 改行はすべて CRLF
        self.assertIn(b"%SystemRoot%\\System32\\WindowsPowerShell", head)  # 今いるフォルダの偽 powershell.exe を拾わない


if __name__ == "__main__":
    unittest.main()
