"""common.py の Windows 向けコマンド組み立てのテスト（Windows 以外でも回せる）。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sscan import common  # noqa: E402


class WinArgv(unittest.TestCase):
    def test_exe_is_passed_as_list(self):
        with mock.patch.object(common, "which", return_value="C:\\Program Files\\GitHub CLI\\gh.exe"):
            self.assertEqual(common._win_argv(["gh", "api", "user"]), ["C:\\Program Files\\GitHub CLI\\gh.exe", "api", "user"])

    def test_cmd_is_quoted_for_cmd_exe(self):
        with mock.patch.object(common, "which", return_value="C:\\Users\\t\\AppData\\Roaming\\npm\\vercel.cmd"):
            line = common._win_argv(["vercel", "api", "/v9/projects?limit=100&teamId=team_x"])
        self.assertTrue(line.endswith(' /d /s /c ""C:\\Users\\t\\AppData\\Roaming\\npm\\vercel.cmd" "api" "/v9/projects?limit=100&teamId=team_x""'))
        self.assertTrue(line.startswith('"') and 'cmd.exe" /d' in line)  # cmd.exe は System32 の絶対パスで呼ぶ

    def test_unsafe_args_are_refused(self):
        with mock.patch.object(common, "which", return_value="C:\\x\\az.cmd"):
            for bad in ('a"b', "%PATH%", "a!b", "a\nb"):
                with self.assertRaises(ValueError):
                    common._win_argv(["az", bad])

    def test_missing_command(self):
        with mock.patch.object(common, "which", return_value=None):
            with self.assertRaises(FileNotFoundError):
                common._win_argv(["nope"])

    def test_run_reports_refusal_without_crashing(self):
        with mock.patch.object(common, "IS_WIN", True), mock.patch.object(common, "which", return_value="C:\\x\\az.cmd"):
            rc, out, err = common.run(["az", "%USERPROFILE%"])
        self.assertEqual((rc, out), (126, ""))
        self.assertIn("cmd.exe", err)

    def test_run_missing_on_windows(self):
        with mock.patch.object(common, "IS_WIN", True), mock.patch.object(common, "which", return_value=None):
            self.assertEqual(common.run(["nope"])[0], 127)


class WindowsWhich(unittest.TestCase):
    def test_current_directory_is_not_searched(self):
        with mock.patch.object(common, "IS_WIN", True), \
             mock.patch.dict(common.os.environ, {"PATH": "C:\\Tools;.;relative\\bin"}), \
             mock.patch.object(common.os.path, "isfile", lambda p: p in ("C:\\Tools\\gh.exe", ".\\git.cmd", "git.cmd")), \
             mock.patch.object(common.os, "pathsep", ";"):
            self.assertEqual(common.which("gh"), "C:\\Tools\\gh.exe")
            self.assertIsNone(common.which("git"))          # カレントの git.cmd は拾わない
            self.assertIsNone(common.which(".\\git.cmd"))  # 相対パスも受け付けない

    def test_only_executable_extensions(self):
        with mock.patch.object(common, "IS_WIN", True), mock.patch.dict(common.os.environ, {"PATH": "C:\\T"}), mock.patch.object(common.os, "pathsep", ";"), \
             mock.patch.object(common.os.path, "isfile", lambda p: p == "C:\\T\\az.js"):
            self.assertIsNone(common.which("az"))


class Timeout(unittest.TestCase):
    def test_timeout_kills_and_returns(self):
        rc, out, err = common.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertEqual(rc, 124)


class Tool(unittest.TestCase):
    def test_bundled_exe_found(self):
        with mock.patch.object(Path, "is_file", lambda self: self.name == "gitleaks.exe"):
            self.assertTrue(common.tool("gitleaks").endswith("gitleaks.exe"))


class PathSep(unittest.TestCase):
    def test_path_uses_os_separator(self):
        first = common.os.environ["PATH"].split(common.os.pathsep)[0]
        self.assertEqual(first, str(common.BIN))


if __name__ == "__main__":
    unittest.main()
